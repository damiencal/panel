-- Add theme_preset field to reseller_branding table.
-- Valid values: 'Default', 'Dark', 'Corporate'
ALTER TABLE reseller_branding ADD COLUMN theme_preset TEXT NOT NULL DEFAULT 'Default';
