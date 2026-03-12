-- Create reseller branding configuration table
CREATE TABLE IF NOT EXISTS reseller_branding (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reseller_id INTEGER NOT NULL UNIQUE,
    panel_name TEXT NOT NULL,
    logo_path TEXT,
    accent_color TEXT NOT NULL DEFAULT '#F43F5E',
    custom_domain TEXT,
    custom_ns1 TEXT,
    custom_ns2 TEXT,
    footer_text TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(reseller_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reseller_branding_reseller_id ON reseller_branding(reseller_id);
