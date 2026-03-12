-- Anti-spam settings, mailbox rate limits, and email statistics.

-- Global spam filter configuration (single row).
CREATE TABLE IF NOT EXISTS spam_filter_settings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    engine               TEXT    NOT NULL DEFAULT 'none'
                                 CHECK(engine IN ('none','spamassassin','rspamd')),
    spam_threshold       REAL    NOT NULL DEFAULT 5.0,
    add_header_enabled   INTEGER NOT NULL DEFAULT 1,
    quarantine_enabled   INTEGER NOT NULL DEFAULT 0,
    quarantine_mailbox   TEXT,
    reject_score         REAL    NOT NULL DEFAULT 15.0,
    clamav_enabled       INTEGER NOT NULL DEFAULT 0,
    mailscanner_enabled  INTEGER NOT NULL DEFAULT 0,
    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert the single default row.
INSERT OR IGNORE INTO spam_filter_settings (id, engine) VALUES (1, 'none');

-- Per-mailbox send-rate limits.
ALTER TABLE mailboxes ADD COLUMN send_limit_per_hour INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mailboxes ADD COLUMN send_limit_per_day  INTEGER NOT NULL DEFAULT 0;

-- Daily email statistics per domain (populated by log parsing).
CREATE TABLE IF NOT EXISTS email_stats (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_date      DATE    NOT NULL,
    domain         TEXT,
    sent_count     INTEGER NOT NULL DEFAULT 0,
    received_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    spam_count     INTEGER NOT NULL DEFAULT 0,
    bounced_count  INTEGER NOT NULL DEFAULT 0,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stat_date, domain)
);
