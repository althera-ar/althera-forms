/**
 * One-shot user bootstrap for the first-party identity (AUTH_PROVIDER=password).
 *
 * WHY: the API image is distroless — no shell, no env binary — so a Coolify
 * "terminal" into the api container can run NOTHING. Users therefore have to
 * arrive with the deploy itself: a JSON manifest in IDENTITY_USERS_JSON, applied
 * idempotently by the `identity-seed` one-shot service (runs after migrate, like
 * the migrations do).
 *
 * Manifest shape (env var IDENTITY_USERS_JSON, a JSON array):
 *   [{"email": "santiago@althera.com.ar", "name": "Santiago", "password": "…",
 *     "reset": false}]                       — `reset: true` rehashes an EXISTING
 *                                              row's password (not needed for a
 *                                              fresh deploy).
 * Missing password on a CREATE is refused loudly (a user who cannot log in is
 * worse than no user). Blank/unset manifest exits 0 with "nothing to do" so the
 * service always completes and the stack starts.
 */
import { randomUUID } from 'node:crypto';
import type { Db } from '@quill/db';
import { sql } from '@quill/db';
import { hashPassword } from './password';

export interface BootstrapUser {
  email: string;
  name?: string;
  password?: string;
  reset?: boolean;
}

export interface BootstrapReport {
  created: string[];
  reset: string[];
  skipped: string[];
  refused: string[];
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Lenient parse: blank/unset → no work; junk shape → an ERROR before any I/O. */
export function parseBootstrapUsers(raw: string | undefined | null): BootstrapUser[] {
  const value = raw?.trim();
  if (!value) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (err) {
    throw new Error(`IDENTITY_USERS_JSON is not valid JSON: ${(err as Error).message}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error('IDENTITY_USERS_JSON must be a JSON array of objects {email, name?, password?}.');
  }
  return parsed.map((entry) => {
    const user = entry as Record<string, unknown>;
    if (typeof user !== 'object' || user === null || typeof user.email !== 'string') {
      throw new Error('IDENTITY_USERS_JSON: every entry needs at least "email" (a string).');
    }
    const out: BootstrapUser = {
      email: user.email.trim(),
      name: typeof user.name === 'string' ? user.name : (user.email as string).trim().split('@')[0],
      password: typeof user.password === 'string' ? user.password : undefined,
      reset: typeof user.reset === 'boolean' ? user.reset : undefined,
    };
    if (out.password !== undefined && (out.password.length === 0 || out.password.length < 12)) {
      throw new Error(`IDENTITY_USERS_JSON: ${out.email} carries a password under 12 characters (refused).`);
    }
    return out;
  });
}

/** Idempotent apply: create missing, rehash only on `reset`, skip the rest. */
export async function applyBootstrapUsers(db: Db, users: BootstrapUser[]): Promise<BootstrapReport> {
  const report: BootstrapReport = { created: [], reset: [], skipped: [], refused: [] };
  for (const user of users) {
    const email = user.email.toLowerCase();
    try {
      if (!EMAIL_RE.test(email)) {
        report.refused.push(`${user.email}: not an email address.`);
        continue;
      }
      const existing = await db.get<{ id: string }>(
        sql`SELECT id FROM identity_users WHERE email = ${email}`,
      );
      if (existing) {
        if (user.reset) {
          if (!user.password) {
            report.refused.push(`${email}: reset: true needs a password.`);
            continue;
          }
          await db.run(
            sql`UPDATE identity_users SET password_hash = ${hashPassword(user.password)}, disabled = 0
                WHERE id = ${existing.id}`,
          );
          report.reset.push(email);
        } else {
          report.skipped.push(email);
        }
        continue;
      }
      if (!user.password) {
        report.refused.push(`${email}: new user needs a "password" (min 12 chars).`);
        continue;
      }
      // Dashless `user_<32 hex>`: passes the platform JWT dialect's pinned
      // regex for sub (auth.provider.workos.ts's `user_[0-9A-Za-z]{10,64}`).
      const id = `user_${randomUUID().replace(/-/g, '')}`;
      await db.run(
        sql`INSERT INTO identity_users (id, email, name, password_hash, disabled, created_at)
            VALUES (${id}, ${email}, ${user.name ?? email.split('@')[0]},
                    ${hashPassword(user.password)}, 0, ${Date.now()})`,
      );
      report.created.push(email);
    } catch (err) {
      report.refused.push(`${email}: ${(err as Error).message}`);
    }
  }
  return report;
}
