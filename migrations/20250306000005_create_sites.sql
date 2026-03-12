-- Create websites (virtual hosts) table
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    doc_root TEXT NOT NULL,
    site_type TEXT NOT NULL CHECK(site_type IN ('Static', 'PHP', 'ReverseProxy', 'NodeJS')) DEFAULT 'Static',
    status TEXT NOT NULL CHECK(status IN ('Active', 'Suspended', 'Inactive')) DEFAULT 'Active',
    
    -- SSL/TLS
    ssl_enabled BOOLEAN DEFAULT FALSE,
    ssl_certificate TEXT,
    ssl_private_key TEXT,
    ssl_issuer TEXT,
    ssl_expiry_date DATETIME,
    force_https BOOLEAN DEFAULT FALSE,
    
    -- PHP settings (if applicable)
    php_version TEXT,
    php_handler TEXT,
    
    -- Reverse proxy settings (if applicable)
    proxy_target TEXT,
    
    -- OpenLiteSpeed configuration
    ols_vhost_name TEXT UNIQUE,
    ols_listener_ports TEXT DEFAULT '80,443',
    
    -- Resource limits
    max_connections INTEGER DEFAULT 100,
    
    -- Tracking
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sites_owner_id ON sites(owner_id);
CREATE INDEX IF NOT EXISTS idx_sites_domain ON sites(domain);
CREATE INDEX IF NOT EXISTS idx_sites_status ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_ols_vhost_name ON sites(ols_vhost_name);
