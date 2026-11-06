/**
 * The FIRST-PARTY identity service (AUTH_PROVIDER=password).
 *
 * This API IS the identity service — the role the docs otherwise give the
 * Dapta "IAM". It hosts the login page (an HTML form; no cookies of its own
 * needed), and serves the web's IAM contract EXACTLY (verified against
 * apps/web/lib/auth-session*.spec.ts):
 *
 *   GET  /iam/auth/login-url?returnTo=…&state=…  → { loginUrl }
 *   GET  /iam/login?returnTo=…&state=…           → HTML form
 *   POST /iam/login                               → 302 {returnTo}?session=<b64>
 *   POST /iam/auth/refresh {refresh_token}        → {access_token, refresh_token}   (rotates, always)
 *   POST /iam/auth/logout                         → 200 { logoutUrl: null }          (revokes)
 *
 * The platform JWT dialect it mints is the one WorkOsAuthProvider validates
 * (HS256, claims sub/account_id/email/name, exp REQUIRED; iss/aud enforced
 * when configured). `workos_session_id` is THIS row's id — the web reads the
 * claim and hands it back on logout for the revocation.
 */
import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import type { ServerEnv } from '@quill/config/env';
import { sql, type Db } from '@quill/db';
import { ENV } from '../tokens';
import { newRefreshToken, refreshHash, verifyPassword } from './password';
import { signJwtHs256 } from '../jwt';

interface IdentityEnv {
  NODE_ENV: string;
  PUBLIC_APP_URL: string;        // boot-asserted present for this provider
  IDENTITY_PUBLIC_URL: string;   // boot-asserted present for this provider
  IDENTITY_ACCOUNT_ID: string;
  JWT_SECRET: string;            // boot-asserted present for this provider
  JWT_ISSUER?: string;
  JWT_AUDIENCE?: string;
  IDENTITY_ACCESS_TTL_S?: number;
  IDENTITY_REFRESH_TTL_DAYS?: number;
  IDENTITY_REFRESH_GRACE_S?: number;
}

interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  disabled: number;
}

/** Per-IP login throttle + per-email progressive lockout (5 misses ⇒ 15 min). */
const LOGIN_BURST = 5;
const LOGIN_REFILL_PER_SEC = 0.1; // six attempts a minute once the burst drains
const LOCKOUT_MISSES = 5;
const LOCKOUT_MS = 15 * 60_000;

export function encodeSessionBlob(tokens: {
  access_token: string;
  refresh_token: string;
  session_id: string;
}): string {
  return Buffer.from(
    JSON.stringify({ success: true, ...tokens }),
    'utf-8',
  ).toString('base64url');
}

function allowedHost(origin: string): string | null {
  try {
    return new URL(origin).hostname;
  } catch {
    return null;
  }
}

/**
 * Boot-narrowed view of the server env for the password provider: the three
 * legs are REQUIRED here. loadServerEnv already refuses a misconfigured boot;
 * this guard is the second, fail-loud-at-wire line.
 */
function requireIdentityEnv(raw: ServerEnv): IdentityEnv {
  if (!raw.JWT_SECRET || !raw.PUBLIC_APP_URL || !raw.IDENTITY_PUBLIC_URL) {
    throw new Error(
      'Refusing to boot the first-party identity: AUTH_PROVIDER=password needs JWT_SECRET, PUBLIC_APP_URL ' +
        'and IDENTITY_PUBLIC_URL.',
    );
  }
  return raw as IdentityEnv & ServerEnv;
}

@Injectable()
export class IdentityService {
  /** Per-IP attempt bucket for POST /iam/login. In-memory: this is a one-pod deploy. */
  private readonly attempts = new Map<string, { tokens: number; last: number }>();
  /** Progressive per-email lockout (in-memory, same assumption). */
  private readonly lockouts = new Map<string, { misses: number; until: number }>();
  private readonly env: IdentityEnv;

  constructor(
    @Inject(ENV) raw: ServerEnv,
    private readonly db: Db,
  ) {
    this.env = requireIdentityEnv(raw);
  }

  // --- GET /auth/login-url ----------------------------------------------------

  /**
   * The web asks WHERE to send the browser. A returnTo may only leave for the
   * deployment's own web (`PUBLIC_APP_URL`'s host), https in production — an
   * arbitrary address would turn the ?session= blob into a token leak. A
   * refused one answers an EMPTY loginUrl, which the web surfaces as
   * `?error=login` (never a redirect to the bad address).
   */
  loginUrl(query: Record<string, string | string[] | undefined>): { loginUrl: string } {
    const validation = this.validateReturnTo(query);
    if (!validation) return { loginUrl: '' };
    const { returnTo, state } = validation;
    const page = new URL(`${this.env.IDENTITY_PUBLIC_URL.replace(/\/$/, '')}/login`);
    page.searchParams.set('returnTo', returnTo);
    if (state) page.searchParams.set('state', state);
    return { loginUrl: page.toString() };
  }

  /**
   * Same rule the web's own canonical-hop uses: host-only, https-first.
   * Returns null when the address fails — callers answer an empty loginUrl.
   */
  validateReturnTo(
    query: Record<string, string | string[] | undefined>,
  ): { returnTo: string; state?: string } | null {
    const raw = Array.isArray(query.returnTo) ? query.returnTo[0] : query.returnTo;
    if (!raw) return null;
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return null;
    }
    if (this.env.NODE_ENV === 'production' && url.protocol !== 'https:') return null;
    const trusted = allowedHost(this.env.PUBLIC_APP_URL);
    if (!trusted || url.hostname !== trusted) return null;
    const state = Array.isArray(query.state) ? query.state[0] : query.state;
    return { returnTo: raw, state: state || undefined };
  }

  // --- GET /login (hosted page) -----------------------------------------------

  /** The form keeps the hand-off parameters in hidden fields — no extra cookie. */
  loginPageHtml(query: Record<string, string | string[] | undefined>, error = false): string {
    const handoff = this.validateReturnTo(query);
    if (!handoff) {
      return this.htmlPage(`<p role="alert">Invalid login request — start again from the app.</p>`);
    }
    const esc = (value: string): string => value.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
    const errorHtml = error
      ? `<p role="alert" class="error">Wrong email or password.</p>`
      : '';
    return this.htmlPage(`
      ${errorHtml}
      <form method="post" class="card">
        <input type="hidden" name="returnTo" value="${esc(handoff.returnTo)}" />
        ${handoff.state ? `<input type="hidden" name="state" value="${esc(handoff.state)}" />` : ''}
        <label>Email <input type="email" name="email" required autofocus autocomplete="email" /></label>
        <label>Password <input type="password" name="password" required autocomplete="current-password" /></label>
        <button type="submit">Sign in</button>
      </form>`);
  }

  private htmlPage(inner: string): string {
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex" />
<title>Sign in</title>
<style>
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         font-family: system-ui, sans-serif; background: #fafafa; color: #1a1a1a; }
  .card, p[role=alert] { max-width: 320px; width: min(90vw, 320px); }
  .card { display: flex; flex-direction: column; gap: 12px; padding: 24px;
          background: #fff; border: 1px solid #e4e4e4; border-radius: 12px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 14px; color: #555; }
  input { padding: 10px 12px; border: 1px solid #d4d4d4; border-radius: 8px; font-size: 14px; }
  button { padding: 10px 12px; border: 0; border-radius: 8px; background: #171717;
           color: #fff; font-weight: 600; font-size: 14px; cursor: pointer; }
  .error { color: #b91c1c; background: #fef2f2; border: 1px solid #fecaca;
           border-radius: 8px; padding: 10px 12px; font-size: 14px; }
</style>
</head>
<body>
  ${inner}
</body>
</html>`;
  }

  // --- POST /login ------------------------------------------------------------

  /**
   * Verify, mint, redirect. The redirect target carries the WHOLE session
   * base64url'd in `?session=` — exactly what the web's callback parses
   * (apps/web/app/api/auth/callback/route.ts:152-167) — plus the `state` echo
   * it constant-time-matches against its cookie. Failed attempts bounce back
   * to the page with an error banner and never reveal which field was wrong.
   */
  async loginSubmit(
    body: Record<string, string | string[] | undefined>,
    ip: string,
  ): Promise<string | { error: string }> {
    if (!this.throttle(ip)) return { error: 'throttled' };
    const validation = this.validateReturnTo(body);
    if (!validation) return { error: 'handoff' };
    const { returnTo, state } = validation;
    const pick = (value: string | string[] | undefined): string =>
      (Array.isArray(value) ? value[0] : value) ?? '';
    const email = pick(body.email).trim().toLowerCase();
    const password = pick(body.password);
    if (!email || !password) return { error: 'credentials' };
    if (this.locked(email)) return { error: 'locked' };

    const user = (await this.db.get<UserRow>(
      sql`SELECT id, email, name, password_hash, disabled FROM identity_users WHERE email = ${email}`,
    )) as UserRow | null;

    // The SAME delay and message for unknown email and wrong password: nothing
    // distinguishes them from the outside.
    if (!user || user.disabled || !verifyPassword(password, user.password_hash)) {
      this.miss(email);
      return { error: 'credentials' };
    }
    this.lockouts.delete(email);
    const tokens = await this.createSession(user);
    const callback = new URL(returnTo);
    callback.searchParams.set('session', encodeSessionBlob(tokens));
    if (state) callback.searchParams.set('state', state);
    return callback.toString();
  }

  // --- POST /auth/refresh -----------------------------------------------------

  /**
   * Rotates on EVERY success (the web stores the returned pair unconditionally —
   * keeping the old one is what would void the next refresh). The grace window
   * is the single previous pairing: two concurrent server actions that both
   * carry the old token both end on the NEW one. Past the window the previous
   * token is dead, per the web's contract.
   */
  async refresh(rawRefresh: string | undefined): Promise<{ access_token: string; refresh_token: string } | null> {
    if (!rawRefresh) return null;
    const hash = refreshHash(rawRefresh);
    // The current pairing answers normally; the PREVIOUS pairing answers within
    // the grace window (a racer mid-rotation). One query, the branch below
    // decides which side it landed on.
    const row = await this.db.get<SessionRow>(
      sql`SELECT id, user_id, refresh_hash, refresh_raw, refresh_prev_hash, refresh_prev_raw,
                 rotated_at, revoked_at, expires_at
          FROM identity_sessions WHERE refresh_hash = ${hash} OR refresh_prev_hash = ${hash}`,
    );
    if (!row || row.revoked_at) return null;
    const session = row;
    const nowMs = Date.now();
    if (nowMs >= session.expires_at) return null;

    const user = (await this.db.get<UserRow>(
      sql`SELECT id, email, name, password_hash, disabled FROM identity_users WHERE id = ${session.user_id}`,
    )) as UserRow | null;
    if (!user || user.disabled) return null;

    const graceS = this.env.IDENTITY_REFRESH_GRACE_S ?? 90;
    const onPrevPair = session.refresh_prev_hash === hash;
    const withinGrace =
      onPrevPair &&
      session.rotated_at !== null &&
      Date.now() - session.rotated_at <= graceS * 1000;

    // A stale token that missed the grace window does NOT rotate anything — the
    // session's CURRENT pairing stays the only live one; the old caller just
    // signs in again, exactly as the web expects.
    if (onPrevPair && !withinGrace) return null;
    if (withinGrace) {
      // A racer: THE pair already minted in that rotation, not a new rotation —
      // a third racer holding the same stale token gets the same answer.
      return {
        access_token: this.mint(user, session.id, Math.floor(nowMs / 1000)),
        refresh_token: session.refresh_raw,
      };
    }

    const next = newRefreshToken();
    const ttlDays = this.env.IDENTITY_REFRESH_TTL_DAYS ?? 30;
    await this.db.run(
      sql`UPDATE identity_sessions
          SET refresh_prev_hash = ${session.refresh_hash},
              refresh_prev_raw = ${session.refresh_raw},
              refresh_raw = ${next},
              refresh_hash = ${refreshHash(next)},
              rotated_at = ${nowMs},
              expires_at = ${nowMs + ttlDays * 24 * 3600 * 1000}
          WHERE id = ${session.id}`,
    );
    return {
      access_token: this.mint(user, session.id, Math.floor(nowMs / 1000)),
      refresh_token: next,
    };
  }

  // --- POST /auth/logout ------------------------------------------------------

  /**
   * Revokes by the id the web sends — for THIS service the `workos_session_id`
   * claim IS the row id, so `workos_session_id` and `session_id` (the blob's
   * fallback field) select the same session. Idempotent: revoking a revoked
   * session answers 200 either way, exactly the shape every upstream contract
   * tolerates.
   */
  async logout(sessionId: string | undefined): Promise<void> {
    if (!sessionId) return;
    await this.db.run(
      sql`UPDATE identity_sessions SET revoked_at = ${Date.now()}
          WHERE id = ${sessionId} AND revoked_at IS NULL`,
    );
  }

  // --- internals ---------------------------------------------------------------

  /**
   * Where a failed form POST bounces: back to the page, still carrying the
   * hand-off (a retry must be able to complete the login it started) and the
   * error flag the page renders as a banner.
   */
  errorBack(handoff: { returnTo: string; state?: string } | null, _code: string): string {
    const page = new URL(`${this.env.IDENTITY_PUBLIC_URL.replace(/\/$/, '')}/login`);
    page.searchParams.set('error', '1');
    if (handoff) {
      page.searchParams.set('returnTo', handoff.returnTo);
      if (handoff.state) page.searchParams.set('state', handoff.state);
    }
    return page.toString();
  }

  private async createSession(user: UserRow): Promise<{
    access_token: string;
    refresh_token: string;
    session_id: string;
  }> {
    const sessionId = `sess_${randomUUID()}`;
    const nowMs = Date.now();
    const ttlDays = this.env.IDENTITY_REFRESH_TTL_DAYS ?? 30;
    const refresh = newRefreshToken();
    await this.db.run(
      sql`INSERT INTO identity_sessions
            (id, user_id, refresh_raw, refresh_hash, created_at, expires_at)
          VALUES (${sessionId}, ${user.id}, ${refresh}, ${refreshHash(refresh)}, ${nowMs},
                  ${nowMs + ttlDays * 24 * 3600 * 1000})`,
    );
    return {
      access_token: this.mint(user, sessionId, Math.floor(nowMs / 1000)),
      refresh_token: refresh,
      session_id: sessionId,
    };
  }

  /**
   * The dialect WorkOsAuthProvider pins (see its header comment): `sub` and
   * `account_id` drive the JIT account+member provisioning, `iat` carries the
   * authenticated-at stamp, and `workos_session_id` is what the web reads back
   * to authorize the logout revocation.
   */
  private accessTtl(): number {
    return this.env.IDENTITY_ACCESS_TTL_S ?? 600;
  }

  private mint(user: UserRow, sessionId: string, nowSec: number): string {
    const claims: Record<string, unknown> = {
      sub: user.id,
      account_id: this.env.IDENTITY_ACCOUNT_ID,
      email: user.email,
      name: user.name,
      // Unique per mint: two mints inside the same second stay distinct tokens
      // (rotation's output must never equal its input).
      jti: randomUUID(),
      iat: nowSec,
      exp: nowSec + this.accessTtl(),
      // Both names for the same identity slot: workos_user_id is what the
      // validator records as member.idp_subject (MCP sign-in linking), and
      // it passes the regex the provider pins (a dash-free user_ id).
      workos_user_id: user.id,
      workos_session_id: sessionId,
    };
    if (this.env.JWT_ISSUER) claims.iss = this.env.JWT_ISSUER;
    if (this.env.JWT_AUDIENCE) claims.aud = this.env.JWT_AUDIENCE;
    return signJwtHs256(claims, this.env.JWT_SECRET);
  }

  private throttle(ip: string): boolean {
    const now = Date.now();
    const bucket = this.attempts.get(ip) ?? { tokens: LOGIN_BURST, last: now };
    bucket.tokens = Math.min(LOGIN_BURST, bucket.tokens + ((now - bucket.last) / 1000) * LOGIN_REFILL_PER_SEC);
    bucket.last = now;
    if (bucket.tokens < 1) {
      this.attempts.set(ip, bucket);
      return false;
    }
    bucket.tokens -= 1;
    this.attempts.set(ip, bucket);
    return true;
  }

  private locked(email: string): boolean {
    const entry = this.lockouts.get(email);
    return !!entry && Date.now() < entry.until;
  }

  private miss(email: string): void {
    const current = this.lockouts.get(email) ?? { misses: 0, until: 0 };
    const misses = current.misses + 1;
    this.lockouts.set(email, {
      misses,
      until: misses >= LOCKOUT_MISSES ? Date.now() + LOCKOUT_MS : current.until,
    });
  }
}

interface SessionRow {
  id: string;
  user_id: string;
  refresh_hash: string;
  refresh_raw: string;
  refresh_prev_hash: string | null;
  refresh_prev_raw: string | null;
  rotated_at: number | null;
  revoked_at: number | null;
  expires_at: number;
}
