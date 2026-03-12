-- Atomic deployment columns for site_git_repos.
-- When atomic_deploy = 1, deploys use the symlink-swap strategy:
--   {doc_root}/repo/           -> live git working tree
--   {doc_root}/releases/{ts}/  -> immutable snapshots
--   {doc_root}/public          -> symlink pointing at the latest release
ALTER TABLE site_git_repos ADD COLUMN atomic_deploy   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE site_git_repos ADD COLUMN retain_releases INTEGER NOT NULL DEFAULT 5;
ALTER TABLE site_git_repos ADD COLUMN deploy_script   TEXT;
