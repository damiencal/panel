-- Git repository integration per site.
-- Tracks which remote repo is attached to each site and caches
-- the last-known sync state for display in the UI.
CREATE TABLE IF NOT EXISTS site_git_repos (
    id               INTEGER  PRIMARY KEY AUTOINCREMENT,
    site_id          INTEGER  NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    repo_url         TEXT     NOT NULL,
    branch           TEXT     NOT NULL DEFAULT 'main',
    -- Optional Ed25519 deploy key for private SSH-authenticated repos.
    -- The private key is stored server-side; the public key is shown to
    -- the user so they can add it to their repository.
    deploy_key_priv  TEXT,
    deploy_key_pub   TEXT,
    -- Last-known sync state (updated after every pull/push).
    last_synced_at   DATETIME,
    last_commit_hash TEXT,
    last_commit_msg  TEXT,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_site_git_repos_site ON site_git_repos(site_id);
