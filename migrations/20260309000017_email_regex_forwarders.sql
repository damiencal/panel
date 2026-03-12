-- Regex-based email forwarders (Postfix regexp map).
CREATE TABLE IF NOT EXISTS email_regex_forwarders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id   INTEGER NOT NULL,
    pattern     TEXT    NOT NULL,
    forward_to  TEXT    NOT NULL,
    description TEXT,
    status      TEXT    NOT NULL CHECK(status IN ('Active','Inactive')) DEFAULT 'Active',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_regex_fwd_domain ON email_regex_forwarders(domain_id);
