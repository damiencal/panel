-- Add HTTP Basic Authentication support to sites table.
-- basic_auth_enabled: when TRUE, HTTP Basic Auth is enforced for the entire site.
-- basic_auth_realm:   the authentication realm string shown to the browser.
ALTER TABLE sites ADD COLUMN basic_auth_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sites ADD COLUMN basic_auth_realm TEXT NOT NULL DEFAULT 'Restricted';

-- Per-site Basic Auth users (username + APR1-MD5 / bcrypt hash in htpasswd format).
CREATE TABLE IF NOT EXISTS basic_auth_users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER NOT NULL,
    username    TEXT NOT NULL,
    -- APR1-MD5 ($apr1$…) or bcrypt ($2y$…) hash in Apache htpasswd format.
    -- Never plaintext; generated server-side and stored here to allow
    -- htpasswd file regeneration if the on-disk file is lost.
    password_hash TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE,
    UNIQUE(site_id, username)
);

CREATE INDEX IF NOT EXISTS idx_basic_auth_users_site_id ON basic_auth_users(site_id);
