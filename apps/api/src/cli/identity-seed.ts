/**
 * One-shot CLI twin of `identity-seed` (the compose service). Used inside the
 * API image it reads IDENTITY_USERS_JSON from the environment; usable from a
 * workstation against a dev database too: `pnpm --filter @quill/api identity:seed`.
 *
 * The compose service runs THIS FILE after migrate, so a distroless deploy
 * provisions its team without ever opening a terminal.
 */
import { loadDotenv } from '@quill/config/dotenv';
import { createDb } from '@quill/db';
import { applyBootstrapUsers, parseBootstrapUsers } from '../identity/bootstrap';

loadDotenv();

async function main(): Promise<void> {
  const raw = process.env.IDENTITY_USERS_JSON;
  let users;
  try {
    users = parseBootstrapUsers(raw);
  } catch (err) {
    console.error(`[identity-seed] refusing: ${(err as Error).message}`);
    process.exitCode = 2;
    return;
  }
  if (users.length === 0) {
    console.log('[identity-seed] nothing to do (IDENTITY_USERS_JSON unset/blank).');
    return;
  }
  const db = await createDb();
  try {
    const report = await applyBootstrapUsers(db, users);
    for (const email of report.created) console.log(`[identity-seed] created ${email}`);
    for (const email of report.reset) console.log(`[identity-seed] password reset for ${email}`);
    for (const email of report.skipped) console.log(`[identity-seed] kept existing ${email}`);
    for (const line of report.refused) console.error(`[identity-seed] REFUSED ${line}`);
    if (report.refused.length > 0) process.exitCode = 1;
  } finally {
    await db.close?.();
  }
}

main().catch((err) => {
  console.error('[identity-seed] failed:', err);
  process.exitCode = 1;
});
