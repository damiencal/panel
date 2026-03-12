-- Add HSTS (HTTP Strict Transport Security) configuration fields to sites table.
-- HSTS is only meaningful when ssl_enabled = TRUE and force_https = TRUE.
-- hsts_max_age: seconds the browser should enforce HTTPS (default 1 year = 31536000).
-- hsts_include_subdomains: apply HSTS to all subdomains of the domain.
-- hsts_preload: signal eligibility for browser HSTS preload lists
--   (requires hsts_max_age >= 31536000 and hsts_include_subdomains = TRUE).

ALTER TABLE sites ADD COLUMN hsts_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sites ADD COLUMN hsts_max_age INTEGER NOT NULL DEFAULT 31536000;
ALTER TABLE sites ADD COLUMN hsts_include_subdomains BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sites ADD COLUMN hsts_preload BOOLEAN NOT NULL DEFAULT FALSE;
