/**
 * The first-party identity (AUTH_PROVIDER=password), tested against the web's
 * ACTUAL contract. The shapes asserted here are the ones apps/web consumes:
 *
 *   - `{ loginUrl }` from /auth/login-url (web/app/api/auth/login/route.ts:109-115);
 *   - a `?session=` blob of base64 JSON { success, access_token, refresh_token,
 *     session_id } with the `state` echo (web/app/api/auth/callback/route.ts:146-167);
 *   - POST /auth/refresh without Authorization, `{access_token, refresh_token}`
 *     rotating EVERY call, the grace pair re-served to a racer carrying the
 *     PREVIOUS token inside the window (web/lib/auth-session.ts:282-322);
 *   - POST /auth/logout revoking via the `workos_session_id` claim's id, always
 *     200 `{ logoutUrl: null }` (web/lib/auth-session-revoke.spec.ts:38-50);
 *   - the minted platform JWT verifying through the REAL validator dialect and
 *     JIT-provisioning an account+member exactly like an upstream token.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createDb, migrate, sql, type Db } from '@quill/db';
import { IdentityService } from './identity.service';
import { hashPassword } from './password';
import { createAuthProvider } from '../auth.provider';
import { verifyJwtHs256 } from '../jwt';
import type { ServerEnv } from '@quill/config/env';

const ID_ENV = {
  NODE_ENV: 'test',
  PUBLIC_APP_URL: 'https://forms.althera.com.ar',
  IDENTITY_PUBLIC_URL: 'https://forms-api.althera.com.ar/iam',
  IDENTITY_ACCOUNT_ID: 'wsp_team_althera',
  JWT_SECRET: 'test-shared-secret-'.repeat(4),
  JWT_ISSUER: 'https://forms-api.althera.com.ar',
  JWT_AUDIENCE: 'althera-forms',
} satisfies Partial<ServerEnv>;

let db: Db;
let identity: IdentityService;

const COMMON = 'correct-horse-42';
const WEB_ORIGIN = 'https://forms.althera.com.ar';

async function insertUser(email = 'santiago@althera.com.ar', password = COMMON, disabled = 0): Promise<string> {
  // 32 hex chars, NO hyphens: the API pins the person id to /^user_([0-9A-Za-z]){10,64}$/
  // (auth.provider.workos.ts) — that regex is what lets the claim also be
  // recorded as member.idp_subject.
  const id = `user_${randomUUID().replace(/-/g, '')}`;
  await db.run(
    sql`INSERT INTO identity_users (id, email, name, password_hash, disabled, created_at)
        VALUES (${id}, ${email.toLowerCase()}, ${'Althera'}, ${hashPassword(password)}, ${disabled}, ${Date.now()})`,
  );
  return id;
}

/** The only returnTo a login may leave for: the deployment's own web callback. */
const WEB_CALLBACK = `${WEB_ORIGIN}/api/auth/callback`;

function loginQuery(state = 'st0ate'): { returnTo: string; state: string } {
  return { returnTo: WEB_CALLBACK, state };
}

function decodedSession(
  urlOrLocation: string,
): { success: boolean; access_token: string; refresh_token: string; session_id: string } {
  const location = new URL(urlOrLocation);
  const encoded = location.searchParams.get('session')!;
  return JSON.parse(Buffer.from(encoded, 'base64').toString('utf-8'));
}

async function login(email = 'santiago@althera.com.ar'): Promise<{
  access: string;
  refresh: string;
  sessionId: string;
}> {
  const out = (await identity.loginSubmit(
    { ...loginQuery(), email, password: COMMON },
    '1.2.3.4',
  )) as string;
  const blob = decodedSession(out);
  return { access: blob.access_token, refresh: blob.refresh_token, sessionId: blob.session_id };
}

beforeEach(async () => {
  db = await createDb('file::memory:');
  await migrate(db);
  identity = new IdentityService({ ...ID_ENV } as never, db);
});

describe('login-url contract (the web login route first hop)', () => {
  it('answers where the browser logs in: the hosted page carrying the hand-off', () => {
    const { loginUrl } = identity.loginUrl(loginQuery());
    const page = new URL(loginUrl);
    expect(page.origin + page.pathname).toBe('https://forms-api.althera.com.ar/iam/login');
    expect(page.searchParams.get('returnTo')).toBe(WEB_CALLBACK);
    expect(page.searchParams.get('state')).toBe('st0ate');
  });

  it('refuses a foreign host with an EMPTY loginUrl — the web lands on ?error=login, never a redirect', () => {
    expect(identity.loginUrl({ returnTo: 'https://evil.example/callback', state: 'x' })).toEqual({ loginUrl: '' });
  });

  it('refuses an https-less returnTo on a production deployment', () => {
    const prod = new IdentityService(
      { ...ID_ENV, NODE_ENV: 'production' } as never,
      db,
    );
    expect(prod.loginUrl({ returnTo: 'http://forms.althera.com.ar/x' })).toEqual({ loginUrl: '' });
  });
});

describe('hosted login POST contract (?session= + state echo)', () => {
  beforeEach(async () => {
    await insertUser();
  });

  it('a correct password redirects to returnTo with ?session= and the state echoed', async () => {
    const out = (await identity.loginSubmit(
      { ...loginQuery(), email: '  Santiago@Althera.com.ar ', password: COMMON },
      '1.2.3.4',
    )) as string;
    const url = new URL(out);
    expect(url.origin + url.pathname).toBe(WEB_CALLBACK);
    expect(url.searchParams.get('state')).toBe('st0ate');
    const blob = decodedSession(out);
    expect(blob.success).toBe(true);
    expect(blob.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(blob.session_id).toMatch(/^sess_/);
  });

  it('a wrong password answers the error code and never mints', async () => {
    const out = await identity.loginSubmit(
      { ...loginQuery(), email: 'santiago@althera.com.ar', password: 'nope-nope-nope' },
      '1.2.3.4',
    );
    expect(out).toEqual({ error: 'credentials' });
  });

  it('a disabled user is refused like a bad password (indistinguishable from outside)', async () => {
    await insertUser('other@althera.com.ar', 'a-12-char-pw', 1);
    const out = await identity.loginSubmit(
      { ...loginQuery(), email: 'other@althera.com.ar', password: 'a-12-char-pw' },
      '1.2.3.4',
    );
    expect(out).toEqual({ error: 'credentials' });
  });

  it('floods are throttled after the burst', async () => {
    for (let i = 0; i < 5; i++) {
      await identity.loginSubmit({ ...loginQuery(), email: 'santiago@althera.com.ar', password: 'nope' }, '5.5.5.5');
    }
    const throttled = await identity.loginSubmit(
      { ...loginQuery(), email: 'santiago@althera.com.ar', password: COMMON },
      '5.5.5.5',
    );
    expect(throttled).toEqual({ error: 'throttled' });
  });
});

describe('the minted platform JWT, verified with the REAL validator dialect', () => {
  beforeEach(async () => {
    await insertUser();
  });

  it('verifies; sub + the pinched regex; claims land exactly', async () => {
    const { access, sessionId } = await login();
    const claims = verifyJwtHs256(access, {
      secret: ID_ENV.JWT_SECRET,
      issuer: ID_ENV.JWT_ISSUER,
      audience: ID_ENV.JWT_AUDIENCE,
    });
    expect(claims.sub).toMatch(/^user_[0-9A-Za-z]{10,64}$/);
    expect(claims.account_id).toBe('wsp_team_althera');
    expect(claims.email).toBe('santiago@althera.com.ar');
    expect(claims.workos_session_id).toBe(sessionId);
    expect(typeof claims.exp).toBe('number');
    expect(typeof claims.iat).toBe('number');
  });

  it('the provider the factory selects for `password` resolves the HOST from it (JIT provisioning)', async () => {
    const { access } = await login();
    const host = createAuthProvider(
      {
        NODE_ENV: 'test',
        AUTH_PROVIDER: 'password',
        JWT_SECRET: ID_ENV.JWT_SECRET,
        SEED_DEMO_FORM: false,
        ONBOARDING_WIZARD: false,
      } as unknown as ServerEnv,
      db,
    );
    await host.resolveHost({ headers: { authorization: `Bearer ${access}` } });
    const account = await db.get<{ id: string }>(
      sql`SELECT id FROM account WHERE external_id = ${'wsp_team_althera'}`,
    );
    expect(account).toBeTruthy();
    const member = await db.get<{ email: string }>(
      sql`SELECT email FROM member WHERE account_id = ${account!.id}`,
    );
    expect(member!.email).toBe('santiago@althera.com.ar');
  });
});

describe('refresh contract (rotation + grace pair + revocation)', () => {
  beforeEach(async () => {
    await insertUser();
  });

  it('rotates on EVERY success and the new token continues the chain', async () => {
    const first = await login();
    const rotated = await identity.refresh(first.refresh);
    expect(rotated).toBeTruthy();
    expect(rotated!.access_token).not.toBe(first.access);
    expect(rotated!.refresh_token).not.toBe(first.refresh);
    // The session id claim the web re-reads survives the rotation.
    const claims = verifyJwtHs256(rotated!.access_token, { secret: ID_ENV.JWT_SECRET });
    expect(claims.workos_session_id).toBe(first.sessionId);
    // And the chain continues with the just-issued token.
    expect(await identity.refresh(rotated!.refresh_token)).toBeTruthy();
  });

  it("the JUST-rotated-out token still answers WITHIN the grace window with the same pairing", async () => {
    const first = await login();
    const rotated = await identity.refresh(first.refresh);
    const grace = await identity.refresh(first.refresh);
    expect(grace).toBeTruthy();
    // The refresh token is THE already-issued pair (a third racer gets the
    // same one); the access token is re-minted (a fresh iat/jti — harmless,
    // the web stores whatever it receives).
    expect(grace!.refresh_token).toBe(rotated!.refresh_token);
    const claims = verifyJwtHs256(grace!.access_token, { secret: ID_ENV.JWT_SECRET });
    expect(claims.workos_session_id).toBe(first.sessionId);
  });

  it('outside the grace window the old token is dead (the web treats null as "sign in again")', async () => {
    const first = await login();
    await identity.refresh(first.refresh); // a rotation happens NOW
    // Deterministic boundary: avoid the same-millisecond flake of a 0-width window.
    await new Promise((resolve) => setTimeout(resolve, 50));
    const zeroGrace = new IdentityService({ ...ID_ENV, IDENTITY_REFRESH_GRACE_S: 0 } as never, db);
    expect(await zeroGrace.refresh(first.refresh)).toBeNull();
  });

  it('a revoked session refuses refresh — logout cuts the whole chain', async () => {
    const first = await login();
    await identity.logout(first.sessionId);
    expect(await identity.refresh(first.refresh)).toBeNull();
    expect(await identity.logout(first.sessionId)).toBeUndefined();
  });
});

describe('logout contract', () => {
  beforeEach(async () => {
    await insertUser();
  });

  it('revokes by the workos_session_id claim id, so a later refresh dies', async () => {
    const { refresh: initialRefresh, sessionId } = await login();
    await identity.logout(sessionId);
    expect(await identity.refresh(initialRefresh)).toBeNull();
  });

  it('is idempotent and tolerates the blob-side fallback id and an empty body', async () => {
    await identity.logout('sess_nope');
    await identity.logout(undefined);
  });
});

describe('boot gate (loadServerEnv refuses a half-configured password identity)', () => {
  it('an HTTP IDENTITY_PUBLIC_URL never boots in production', async () => {
    await insertUser();
    process.env.AUTH_PROVIDER = 'password';
    process.env.NODE_ENV = 'production';
    process.env.IDENTITY_PUBLIC_URL = 'http://api.example.com';
    process.env.JWT_SECRET = 's'.repeat(64);
    process.env.PUBLIC_APP_URL = 'https://forms.example.com';
    const { loadServerEnv } = await import('@quill/config/env');
    expect(() => loadServerEnv()).toThrow(/HTTPS IDENTITY_PUBLIC_URL/);
  });
});
