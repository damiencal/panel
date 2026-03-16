-- =============================================================================
-- 009_git.sql — Seed Git repository records
-- Depends on: 003_sites.sql (site id=1, 2)
-- =============================================================================

INSERT OR IGNORE INTO site_git_repos
    (id, site_id, repo_url, branch, last_commit_hash, last_commit_msg)
VALUES
(1, 1, 'https://github.com/example/wp-theme.git', 'main',
    'abc1234567890abcdef1234567890abcdef123456',
    'Initial commit: add theme files'),
(2, 2, 'https://github.com/example/static-site.git', 'main',
    NULL, NULL);
