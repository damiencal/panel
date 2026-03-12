-- Add per-domain send limits to email_domains
ALTER TABLE email_domains ADD COLUMN send_limit_per_hour INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_domains ADD COLUMN send_limit_per_day  INTEGER NOT NULL DEFAULT 0;

-- Track rolling send counts per domain (single row per domain, updated in-place)
CREATE TABLE IF NOT EXISTS domain_send_counts (
    domain_id    INTEGER PRIMARY KEY,
    hourly_count INTEGER NOT NULL DEFAULT 0,
    daily_count  INTEGER NOT NULL DEFAULT 0,
    -- YYYY-MM-DD-HH  e.g. "2026-03-09-14"
    hour_window  TEXT    NOT NULL DEFAULT '',
    -- YYYY-MM-DD     e.g. "2026-03-09"
    day_window   TEXT    NOT NULL DEFAULT '',
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE
);
