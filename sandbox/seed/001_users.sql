-- =============================================================================
-- 001_users.sql  — Seed test users
--
-- Password for ALL test accounts: TestPass123!
-- Hash generated at container start by seed-panel.sh (argon2id, m=65536, t=3, p=4).
-- This file is run *after* seed-panel.sh injects the ADMIN_HASH / RESELLER_HASH /
-- CLIENT_HASH shell variables by producing a second SQL file. The hash placeholder
-- __ARGON2ID_HASH__ is replaced by the script before applying.
--
-- IDs are explicit so FK references in later seed files are stable.
-- =============================================================================

-- NOTE: seed-panel.sh does variable substitution before sqlite3 runs this file.
-- The actual INSERT statements with computed hashes are emitted by seed-panel.sh.
-- This file is a documentation placeholder.
SELECT 1;
