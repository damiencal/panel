use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A Git repository attached to a site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct SiteGitRepo {
    pub id: i64,
    pub site_id: i64,
    pub repo_url: String,
    pub branch: String,
    /// Ed25519 SSH private key (server-side only; never returned to the client).
    pub deploy_key_priv: Option<String>,
    /// Ed25519 SSH public key shown to the user.
    pub deploy_key_pub: Option<String>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_commit_hash: Option<String>,
    pub last_commit_msg: Option<String>,
    /// When true, deploys use the symlink-swap (atomic) strategy.
    pub atomic_deploy: bool,
    /// How many release snapshots to keep under `releases/` (0 = keep all).
    pub retain_releases: i64,
    /// Optional bash script executed after each atomic deploy (max 4096 bytes).
    pub deploy_script: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A single commit entry from `git log`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitCommit {
    pub hash: String,
    pub hash_short: String,
    pub author_name: String,
    pub author_email: String,
    pub date: String,
    pub message: String,
}

/// A branch returned by `git branch -a`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitBranch {
    pub name: String,
    pub is_current: bool,
}

/// The public-facing view of a `SiteGitRepo` (private key stripped out).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiteGitRepoPublic {
    pub id: i64,
    pub site_id: i64,
    pub repo_url: String,
    pub branch: String,
    pub deploy_key_pub: Option<String>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_commit_hash: Option<String>,
    pub last_commit_msg: Option<String>,
    pub atomic_deploy: bool,
    pub retain_releases: i64,
    pub deploy_script: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<SiteGitRepo> for SiteGitRepoPublic {
    fn from(r: SiteGitRepo) -> Self {
        Self {
            id: r.id,
            site_id: r.site_id,
            repo_url: r.repo_url,
            branch: r.branch,
            deploy_key_pub: r.deploy_key_pub,
            last_synced_at: r.last_synced_at,
            last_commit_hash: r.last_commit_hash,
            last_commit_msg: r.last_commit_msg,
            atomic_deploy: r.atomic_deploy,
            retain_releases: r.retain_releases,
            deploy_script: r.deploy_script,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}
