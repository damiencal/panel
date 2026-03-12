-- One-time developer invitation tokens sent by clients.
-- The raw token is shown exactly once; only its SHA-256 hex hash is stored.
CREATE TABLE IF NOT EXISTS team_invitations (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    client_id   INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email       TEXT     NOT NULL,
    token_hash  TEXT     NOT NULL UNIQUE,
    site_ids    TEXT     NOT NULL DEFAULT '[]',  -- JSON array of site IDs
    expires_at  DATETIME NOT NULL,
    consumed_at DATETIME,                         -- NULL = not yet consumed
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_team_inv_client ON team_invitations(client_id);
CREATE INDEX IF NOT EXISTS idx_team_inv_token  ON team_invitations(token_hash);
