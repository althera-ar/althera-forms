-- First-party password identity (AUTH_PROVIDER=password): the API hosts the
-- login and mints the platform JWT itself — no external identity service.
-- Users and their login sessions live in THIS database, next to the product
-- tables, managed by the same one-shot migrator.
--
-- Postgres dialect; the SQLite twin carries the same shapes (migrations/sqlite).
CREATE TABLE identity_users (
  id TEXT PRIMARY KEY,            -- `user_<uuid>`: IS the platform JWT's `sub`
  email TEXT NOT NULL UNIQUE,     -- stored lowercase; lookups lowercase too
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,    -- scrypt$N$r$p$<salt b64url>$<hash b64url>
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL      -- epoch ms
);

CREATE TABLE identity_sessions (
  id TEXT PRIMARY KEY,            -- `sess_<uuid>`: IS the `workos_session_id` claim
  user_id TEXT NOT NULL REFERENCES identity_users(id),
  refresh_raw TEXT NOT NULL,      -- current refresh token (a grace-window racer gets this back)
  refresh_hash TEXT NOT NULL,     -- sha256(refresh_raw); lookup is by hash
  refresh_prev_hash TEXT,         -- the rotation's previous hash, only within the grace window
  refresh_prev_raw TEXT,
  rotated_at BIGINT,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,     -- sliding: extended on every rotation
  revoked_at BIGINT
);

CREATE INDEX identity_sessions_user_idx ON identity_sessions (user_id);
CREATE INDEX identity_sessions_hash_idx ON identity_sessions (refresh_hash);
