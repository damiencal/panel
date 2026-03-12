use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// FTP virtual account managed by Pure-FTPd.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct FtpAccount {
    pub id: i64,
    pub owner_id: i64,
    pub site_id: Option<i64>,
    pub username: String,
    #[serde(skip)]
    pub password_hash: String,
    pub home_dir: String,
    pub quota_size_mb: i64,
    pub quota_files: i64,
    pub allowed_ip: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Single FTP transfer event stored from Pure-FTPd transfer logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct FtpSessionStat {
    pub id: i64,
    pub account_id: Option<i64>,
    pub username: String,
    pub remote_host: Option<String>,
    /// "Upload" or "Download"
    pub direction: String,
    pub filename: String,
    pub bytes_transferred: i64,
    pub transfer_time_secs: f64,
    pub completed_at: DateTime<Utc>,
}

/// Aggregated per-account FTP usage summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpAccountStats {
    pub username: String,
    pub total_uploads: i64,
    pub total_downloads: i64,
    pub bytes_uploaded: i64,
    pub bytes_downloaded: i64,
    pub last_active: Option<DateTime<Utc>>,
}

/// Overall FTP statistics for a user's accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpUsageStats {
    pub total_accounts: i64,
    pub active_accounts: i64,
    pub total_uploads: i64,
    pub total_downloads: i64,
    pub bytes_uploaded: i64,
    pub bytes_downloaded: i64,
    pub per_account: Vec<FtpAccountStats>,
    /// Most recent transfer entries (up to 20).
    pub recent_transfers: Vec<FtpSessionStat>,
}
