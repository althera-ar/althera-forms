-- See migrations/postgres/0028_identity.sql for the rationale.
-- Same shapes as Postgres; INTEGER replaces BIGINT (epoch ms, as everywhere else here).
CREATE TABLE identity_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE identity_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES identity_users(id),
  refresh_raw TEXT NOT NULL,
  refresh_hash TEXT NOT NULL,
  refresh_prev_hash TEXT,
  refresh_prev_raw TEXT,
  rotated_at INTEGER,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX identity_sessions_user_idx ON identity_sessions (user_id);
CREATE INDEX identity_sessions_hash_idx ON identity_sessions (refresh_hash);
