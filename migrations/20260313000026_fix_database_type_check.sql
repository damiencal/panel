-- Fix database_type CHECK constraint to include 'MariaDB'
-- Previous constraint only allowed ('MySQL', 'PostgreSQL') but the app uses MariaDB.

BEGIN;

CREATE TABLE databases_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    database_type TEXT NOT NULL CHECK(database_type IN ('MySQL', 'PostgreSQL', 'MariaDB')) DEFAULT 'MariaDB',
    status TEXT NOT NULL CHECK(status IN ('Active', 'Suspended', 'Inactive')) DEFAULT 'Active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(owner_id, name, database_type)
);

INSERT INTO databases_new SELECT * FROM databases;

DROP TABLE databases;
ALTER TABLE databases_new RENAME TO databases;

CREATE INDEX idx_databases_owner_id ON databases(owner_id);
CREATE INDEX idx_databases_name ON databases(name);

COMMIT;
