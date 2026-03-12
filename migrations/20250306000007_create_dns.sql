-- Create DNS zones table (Cloudflare-backed)
CREATE TABLE IF NOT EXISTS dns_zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    zone_type TEXT NOT NULL CHECK(zone_type IN ('Primary', 'Secondary')) DEFAULT 'Primary',
    status TEXT NOT NULL CHECK(status IN ('Active', 'Inactive')) DEFAULT 'Active',
    nameserver1 TEXT,
    nameserver2 TEXT,
    cf_zone_id TEXT,
    sync_status TEXT NOT NULL CHECK(sync_status IN ('Synced', 'Pending', 'Error')) DEFAULT 'Pending',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create DNS records table (Cloudflare-backed)
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA', 'NS')),
    value TEXT NOT NULL,
    priority INTEGER DEFAULT 10,
    ttl INTEGER DEFAULT 3600,
    cf_record_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(zone_id) REFERENCES dns_zones(id) ON DELETE CASCADE,
    UNIQUE(zone_id, name, type)
);

CREATE INDEX IF NOT EXISTS idx_dns_zones_owner_id ON dns_zones(owner_id);
CREATE INDEX IF NOT EXISTS idx_dns_zones_domain ON dns_zones(domain);
CREATE INDEX IF NOT EXISTS idx_dns_zones_cf_zone_id ON dns_zones(cf_zone_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_zone_id ON dns_records(zone_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_cf_record_id ON dns_records(cf_record_id);
