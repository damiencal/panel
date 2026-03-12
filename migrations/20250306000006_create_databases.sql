-- Create databases table
CREATE TABLE IF NOT EXISTS databases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    database_type TEXT NOT NULL CHECK(database_type IN ('MySQL', 'PostgreSQL')) DEFAULT 'MySQL',
    status TEXT NOT NULL CHECK(status IN ('Active', 'Suspended', 'Inactive')) DEFAULT 'Active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(owner_id, name, database_type)
);

-- Create database users table
CREATE TABLE IF NOT EXISTS database_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    database_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    privileges TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(database_id) REFERENCES databases(id) ON DELETE CASCADE,
    UNIQUE(database_id, username)
);

CREATE INDEX IF NOT EXISTS idx_databases_owner_id ON databases(owner_id);
CREATE INDEX IF NOT EXISTS idx_databases_name ON databases(name);
CREATE INDEX IF NOT EXISTS idx_database_users_database_id ON database_users(database_id);
