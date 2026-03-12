-- Add client contact detail fields to users table.
ALTER TABLE users ADD COLUMN company TEXT;
ALTER TABLE users ADD COLUMN address TEXT;
ALTER TABLE users ADD COLUMN phone TEXT;
