-- FTP session statistics parsed from Pure-FTPd transfer logs.
-- Each row represents one completed transfer (upload or download).
CREATE TABLE IF NOT EXISTS ftp_session_stats (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    account_id    INTEGER  REFERENCES ftp_accounts(id) ON DELETE SET NULL,
    username      TEXT     NOT NULL,
    remote_host   TEXT,
    -- 'Upload' or 'Download'
    direction     TEXT     NOT NULL CHECK(direction IN ('Upload', 'Download')),
    filename      TEXT     NOT NULL,
    bytes_transferred INTEGER NOT NULL DEFAULT 0,
    transfer_time_secs REAL NOT NULL DEFAULT 0,
    completed_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ftp_stats_username    ON ftp_session_stats(username);
CREATE INDEX IF NOT EXISTS idx_ftp_stats_account_id  ON ftp_session_stats(account_id);
CREATE INDEX IF NOT EXISTS idx_ftp_stats_completed   ON ftp_session_stats(completed_at);
