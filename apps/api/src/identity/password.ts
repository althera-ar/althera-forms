/**
 * Password primitives for the first-party identity (node:crypto only — the
 * package count of this repo is a design value, see README, and scryptSync is
 * production-grade for a handful of users).
 *
 * Format: `scrypt$16384$8$1$<salt b64url>$<hash b64url>` — parameters inline so
 * a future profile change stays able to verify old rows.
 */
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const N = 16384;
const R = 8;
const P = 1;
const KEYLEN = 32;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

/** Constant-time verify; every non-match decomposition answers false. */
export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, salt, hash] = parts;
  const params = { N: Number(n), r: Number(r), p: Number(p) };
  if (!Number.isInteger(params.N) || params.N < 16384 || !Number.isInteger(params.r) || params.r < 8) {
    // Refuse legacy/degenerate profiles outright rather than compute against them.
    return false;
  }
  let expected: Buffer;
  try {
    expected = Buffer.from(salt!, 'base64url');
    const actual = scryptSync(password, expected, Buffer.from(hash!, 'base64url').length, params);
    return timingSafeEqual(actual, Buffer.from(hash!, 'base64url'));
  } catch {
    return false;
  }
}

/** Refresh tokens are looked up BY HASH — the raw value lives only for the grace racers. */
export function refreshHash(raw: string): string {
  return createHash('sha256').update(raw).digest('base64url');
}

export function newRefreshToken(): string {
  return randomBytes(32).toString('base64url');
}
