-- Firewall rules table for persisting UFW rule definitions.
CREATE TABLE IF NOT EXISTS firewall_rules (
    id          INTEGER     PRIMARY KEY AUTOINCREMENT,
    rule_number INTEGER,
    action      TEXT        NOT NULL CHECK(action IN ('allow','deny','reject','limit')),
    direction   TEXT        NOT NULL DEFAULT 'in' CHECK(direction IN ('in','out','both')),
    protocol    TEXT        CHECK(protocol IN ('tcp','udp','any')),
    from_ip     TEXT,
    to_port     TEXT,
    comment     TEXT,
    is_active   INTEGER     NOT NULL DEFAULT 1,
    created_at  TEXT        NOT NULL DEFAULT (datetime('now')),
    created_by  INTEGER     REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_firewall_rules_active ON firewall_rules(is_active);
