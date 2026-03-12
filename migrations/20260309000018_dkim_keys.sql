-- DKIM signing keys (one per email domain, one selector per domain).
CREATE TABLE IF NOT EXISTS dkim_keys (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id      INTEGER NOT NULL UNIQUE,
    domain         TEXT    NOT NULL UNIQUE,
    selector       TEXT    NOT NULL DEFAULT 'default',
    public_key_dns TEXT    NOT NULL,
    status         TEXT    NOT NULL CHECK(status IN ('Active','Inactive')) DEFAULT 'Active',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE
);
