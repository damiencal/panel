-- Create email domains table
CREATE TABLE IF NOT EXISTS email_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('Active', 'Suspended', 'Inactive')) DEFAULT 'Active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create mailbox accounts table
CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    local_part TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    quota_mb INTEGER DEFAULT 256,
    status TEXT NOT NULL CHECK(status IN ('Active', 'Suspended')) DEFAULT 'Active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE,
    UNIQUE(domain_id, local_part)
);

-- Create email forwarders table
CREATE TABLE IF NOT EXISTS email_forwarders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    local_part TEXT NOT NULL,
    forward_to TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('Active', 'Inactive')) DEFAULT 'Active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE,
    UNIQUE(domain_id, local_part)
);

CREATE INDEX IF NOT EXISTS idx_email_domains_owner_id ON email_domains(owner_id);
CREATE INDEX IF NOT EXISTS idx_mailboxes_domain_id ON mailboxes(domain_id);
CREATE INDEX IF NOT EXISTS idx_email_forwarders_domain_id ON email_forwarders(domain_id);
