/**
 * CLI: manage the first-party identity users (AUTH_PROVIDER=password).
 *
 *   pnpm --filter @quill/api identity:user add-user <email> <name> [--password=…]
 *   pnpm --filter @quill/api identity:user reset-password <email> [--password=…]
 *   pnpm --filter @quill/api identity:user disable <email>
 *   pnpm --filter @quill/api identity:user list
 *
 * No self-service: the people of this deployment are created HERE, by the
 * operator, and log in on the web with that password. A password nobody
 * supplies is generated (printed once, never stored in clear).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { loadDotenv } from '@quill/config/dotenv';
import { createDb, sql, type Db } from '@quill/db';
import { hashPassword } from '../identity/password';

loadDotenv();

function usage(): never {
  console.error(
    'usage: identity-user add-user <email> <name> [--password=…] | reset-password <email> [--password=…] | disable <email> | list',
  );
  process.exit(2);
}

const [, , command, ...rest] = process.argv;
const positional = rest.filter((a) => !a.startsWith('--'));
const flags = Object.fromEntries(
  rest.filter((a) => a.startsWith('--')).map((a) => {
    const eq = a.indexOf('=');
    return eq === -1 ? [a.slice(2), true] : [a.slice(2, eq), a.slice(eq + 1)];
  }),
) as Record<string, string | boolean>;

function randomPassword(): string {
  return randomBytes(18).toString('base64url');
}

function suppliedPassword(): string | undefined {
  const password = flags.password;
  if (typeof password !== 'string' || password.length === 0) return undefined;
  if (password.length < 12) {
    console.error('refusing: passwords shorter than 12 characters are not stored.');
    process.exit(2);
  }
  return password;
}

async function insertUser(db: Db, email: string, name: string, password: string): Promise<void> {
  const normalized = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    console.error(`refusing: ${email} is not an email address.`);
    process.exit(2);
  }
  const exists = await db.get<{ id: string }>(
    sql`SELECT id FROM identity_users WHERE email = ${normalized}`,
  );
  if (exists) {
    console.error(`refusing: ${normalized} already exists.`);
    process.exit(2);
  }
  await db.run(
    sql`INSERT INTO identity_users (id, email, name, password_hash, disabled, created_at)
        VALUES (${`user_${randomUUID().replace(/-/g, '')}`}, ${normalized}, ${name}, ${hashPassword(password)}, 0, ${Date.now()})`,
  );
}

async function main(): Promise<void> {
  const db = await createDb();
  try {
    switch (command) {
      case 'add-user': {
        const [email, name] = positional;
        if (!email || !name) usage();
        const generated = suppliedPassword() ?? randomPassword();
        await insertUser(db, email, name, generated);
        console.log(`[identity-user] created ${email.trim().toLowerCase()}`);
        if (!suppliedPassword()) {
          console.log(`[identity-user] password (shown ONCE): ${generated}`);
        }
        break;
      }
      case 'reset-password': {
        const [email] = positional;
        if (!email) usage();
        const normalized = email.trim().toLowerCase();
        const user = await db.get<{ id: string }>(
          sql`SELECT id FROM identity_users WHERE email = ${normalized}`,
        );
        if (!user) {
          console.error(`no user ${normalized}. (list shows what exists)`);
          process.exit(1);
        }
        const generated = suppliedPassword() ?? randomPassword();
        await db.run(
          sql`UPDATE identity_users SET password_hash = ${hashPassword(generated)} WHERE email = ${normalized}`,
        );
        console.log(`[identity-user] password reset for ${normalized}`);
        if (!suppliedPassword()) {
          console.log(`[identity-user] new password (shown ONCE): ${generated}`);
        }
        break;
      }
      case 'disable': {
        const [email] = positional;
        if (!email) usage();
        const user = await db.get<{ id: string }>(
          sql`SELECT id FROM identity_users WHERE email = ${email.trim().toLowerCase()}`,
        );
        if (!user) {
          console.error(`no user ${email.trim().toLowerCase()}.`);
          process.exit(1);
        }
        await db.run(
          sql`UPDATE identity_users SET disabled = 1 WHERE id = ${user.id}`,
        );
        console.log(`[identity-user] disabled ${email.trim().toLowerCase()} — sessions keep living until refresh/logout.`);
        break;
      }
      case 'list': {
        const rows = (await db.all<{ id: string; email: string; name: string; disabled: number; created_at: number }>(
          sql`SELECT id, email, name, disabled, created_at FROM identity_users ORDER BY created_at`,
        )) as Array<{ id: string; email: string; name: string; disabled: number; created_at: number }>;
        for (const row of rows) {
          console.log(`${row.disabled ? '[disabled]' : '[active]  '}  ${row.email}  ${row.name}  (${row.id})`);
        }
        break;
      }
      default:
        usage();
    }
  } finally {
    await db.close?.();
  }
}

main().catch((err) => {
  console.error('[identity-user] failed:', err);
  process.exitCode = 1;
});
