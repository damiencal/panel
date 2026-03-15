-- disable-transaction
-- Extend the role CHECK constraint to include 'Developer'.
-- SQLite requires a full table swap to modify a CHECK constraint.

PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE users_new (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    username     TEXT     NOT NULL UNIQUE,
    email        TEXT     NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role         TEXT     NOT NULL CHECK(role IN ('Admin', 'Reseller', 'Client', 'Developer')),
    status       TEXT     NOT NULL CHECK(status IN ('Active', 'Suspended', 'Pending')) DEFAULT 'Active',
    parent_id    INTEGER,
    package_id   INTEGER,
    branding_id  INTEGER,
    totp_secret  TEXT,
    totp_enabled BOOLEAN  DEFAULT FALSE,
    system_uid   INTEGER,
    system_gid   INTEGER,
    company      TEXT,
    address      TEXT,
    phone        TEXT,
    city         TEXT,
    state        TEXT,
    postal_code  TEXT,
    country      TEXT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(parent_id)   REFERENCES users_new(id) ON DELETE CASCADE,
    FOREIGN KEY(package_id)  REFERENCES packages(id),
    FOREIGN KEY(branding_id) REFERENCES reseller_branding(id)
);

INSERT INTO users_new SELECT * FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

COMMIT;

PRAGMA foreign_keys = ON;

CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role      ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_parent_id ON users(parent_id);
