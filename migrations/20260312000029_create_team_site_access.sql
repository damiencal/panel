-- Per-site access grants for developer team members.
CREATE TABLE IF NOT EXISTS team_site_access (
    developer_id INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_id      INTEGER  NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    granted_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (developer_id, site_id)
);

CREATE INDEX IF NOT EXISTS idx_team_access_dev  ON team_site_access(developer_id);
CREATE INDEX IF NOT EXISTS idx_team_access_site ON team_site_access(site_id);
