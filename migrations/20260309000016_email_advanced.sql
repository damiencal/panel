-- Add catch-all and plus-addressing support to email domains.
ALTER TABLE email_domains ADD COLUMN catch_all_address TEXT;
ALTER TABLE email_domains ADD COLUMN plus_addressing_enabled INTEGER NOT NULL DEFAULT 0;
