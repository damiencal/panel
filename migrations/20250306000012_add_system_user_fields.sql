-- Add Linux system user tracking for shared hosting isolation.
-- Clients get a dedicated OS user (UID 33000+) with restricted permissions.
ALTER TABLE users ADD COLUMN system_uid INTEGER;
ALTER TABLE users ADD COLUMN system_gid INTEGER;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_system_uid ON users(system_uid);
