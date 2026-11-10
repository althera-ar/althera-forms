/**
 * The deploy-time user manifest (IDENTITY_USERS_JSON): lenient parse, idempotent
 * apply — created / skipped / reset exactly once, refusals printed without any
 * secret. These tests pin the operator contract the distroless deploy runs on.
 */
import { describe, expect, it, beforeEach } from 'vitest';
import { createDb, migrate, sql, type Db } from '@quill/db';
import { applyBootstrapUsers, parseBootstrapUsers } from './bootstrap';
import { verifyPassword } from './password';

let db: Db;

beforeEach(async () => {
  db = await createDb('file::memory:');
  await migrate(db);
});

describe('parseBootstrapUsers', () => {
  it('blank/unset is no work, never an error (the one-shot must always complete)', () => {
    expect(parseBootstrapUsers(undefined)).toEqual([]);
    expect(parseBootstrapUsers('   ')).toEqual([]);
  });

  it('trims emails and defaults the name to the local part', () => {
    const users = parseBootstrapUsers('[{"email":" s@x.com ","password":"0123456789abcdef"}]');
    expect(users).toEqual([{ email: 's@x.com', name: 's', password: '0123456789abcdef', reset: undefined }]);
  });

  it('refuses junk shapes and short passwords loudly, before any I/O', () => {
    expect(() => parseBootstrapUsers('[1,2]')).toThrow(/every entry needs at least "email"/);
    expect(() => parseBootstrapUsers('{"email":"a"}')).toThrow(/JSON array/);
    expect(() => parseBootstrapUsers('nope')).toThrow(/valid JSON/);
    expect(() => parseBootstrapUsers('[{"email":"a@b.c","password":"short"}]')).toThrow(/under 12 characters/);
  });
});

describe('applyBootstrapUsers', () => {
  it('creates with a hashed password; the user can log in through verify', async () => {
    const report = await applyBootstrapUsers(db, parseBootstrapUsers(
      '[{"email":"A@B.COM","name":"A","password":"0123456789abcdef"}]',
    ));
    expect(report).toEqual({
      created: ['a@b.com'],
      reset: [],
      skipped: [],
      refused: [],
    });
    const row = await db.get<{ id: string; password_hash: string; name: string }>(
      sql`SELECT id, password_hash, name FROM identity_users WHERE email = ${'a@b.com'}`,
    );
    expect(row!.id).toMatch(/^user_[0-9A-Za-z]{10,64}$/);
    expect(row!.name).toBe('A');
    expect(verifyPassword('0123456789abcdef', row!.password_hash)).toBe(true);
  });

  it('is idempotent: a second apply SKIPS the same email, no duplicate row', async () => {
    const manifest = '[{"email":"a@b.com","name":"A","password":"0123456789abcdef"}]';
    await applyBootstrapUsers(db, parseBootstrapUsers(manifest));
    const twice = await applyBootstrapUsers(db, parseBootstrapUsers(manifest));
    expect(twice.created).toEqual([]);
    expect(twice.skipped).toEqual(['a@b.com']);
    const count = await db.get<{ n: number }>(sql`SELECT count(*) AS n FROM identity_users`);
    expect(Number(count!.n)).toBe(1);
  });

  it('reset: true rehashes an EXISTING row (old password dies, new works); refused without password', async () => {
    await applyBootstrapUsers(db, parseBootstrapUsers(
      '[{"email":"a@b.com","name":"A","password":"0123456789abcdef"}]',
    ));
    const refuse = await applyBootstrapUsers(db, parseBootstrapUsers('[{"email":"a@b.com","reset":true}]'));
    expect(refuse.refused[0]).toContain('needs a password');
    await applyBootstrapUsers(db, parseBootstrapUsers(
      '[{"email":"a@b.com","password":"fedcba9876543210","reset":true}]',
    ));
    const after = await db.get<{ password_hash: string }>(
      sql`SELECT password_hash FROM identity_users WHERE email = ${'a@b.com'}`,
    );
    expect(verifyPassword('0123456789abcdef', after!.password_hash)).toBe(false);
    expect(verifyPassword('fedcba9876543210', after!.password_hash)).toBe(true);
  });

  it('a new user without password is REFUSED (a login-less user is worse than none)', async () => {
    const report = await applyBootstrapUsers(db, parseBootstrapUsers('[{"email":"a@b.com","name":"A"}]'));
    expect(report.created).toEqual([]);
    expect(report.refused[0]).toContain('new user needs a "password"');
  });

  it('one bad entry never blocks the good ones (refusals ride along)', async () => {
    const report = await applyBootstrapUsers(db, parseBootstrapUsers(
      '[{"email":"not-an-email"},{"email":"a@b.com","name":"A","password":"0123456789abcdef"}]',
    ));
    expect(report.created).toEqual(['a@b.com']);
    expect(report.refused).toHaveLength(1);
  });
});
