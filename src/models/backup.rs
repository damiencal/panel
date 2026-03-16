use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What the backup covers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BackupTarget {
    /// Files + database for a hosted site.
    Site { site_id: i64, domain: String },
    /// Maildir for a single mailbox.
    Mailbox { mailbox_id: i64, address: String },
}

/// Storage back-end for backup archives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum StorageType {
    #[serde(rename = "local")]
    #[cfg_attr(feature = "server", sqlx(rename = "local"))]
    Local,
    #[serde(rename = "s3")]
    #[cfg_attr(feature = "server", sqlx(rename = "s3"))]
    S3,
    #[serde(rename = "sftp")]
    #[cfg_attr(feature = "server", sqlx(rename = "sftp"))]
    Sftp,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageType::Local => write!(f, "Local"),
            StorageType::S3 => write!(f, "S3"),
            StorageType::Sftp => write!(f, "SFTP"),
        }
    }
}

/// A scheduled backup for one domain or mailbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct BackupSchedule {
    pub id: i64,
    pub owner_id: i64,
    pub site_id: Option<i64>,
    pub mailbox_id: Option<i64>,
    pub name: String,
    /// 5-field cron expression or @daily / @weekly / @monthly.
    pub schedule: String,
    pub storage_type: String,
    pub destination: String,
    pub retention_count: i32,
    pub compress: bool,
    pub enabled: bool,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Status values for a backup run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunStatus {
    Running,
    Success,
    Failed,
}

impl RunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Success => "success",
            RunStatus::Failed => "failed",
        }
    }
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Single backup execution record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct BackupRun {
    pub id: i64,
    pub schedule_id: i64,
    pub owner_id: i64,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// "running" | "success" | "failed"
    pub status: String,
    pub size_bytes: Option<i64>,
    pub archive_path: Option<String>,
    pub error_message: Option<String>,
}

// ─── Request / response DTOs ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBackupScheduleRequest {
    /// Null ⟹ mailbox backup; set ⟹ domain backup.
    pub site_id: Option<i64>,
    pub mailbox_id: Option<i64>,
    pub name: String,
    pub schedule: String,
    pub storage_type: String,
    pub destination: String,
    pub retention_count: i32,
    pub compress: bool,
}

/// Aggregate stats shown on the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackupStats {
    pub total_schedules: i64,
    pub enabled_schedules: i64,
    pub total_runs: i64,
    pub successful_runs: i64,
    pub failed_runs: i64,
    /// Aggregate bytes of all successful backup archives.
    pub total_size_bytes: i64,
}

/// A schedule joined with its latest run, for the dashboard table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupScheduleWithLatest {
    pub schedule: BackupSchedule,
    pub latest_run: Option<BackupRun>,
    /// Resolved domain name for site_id (if any).
    pub site_domain: Option<String>,
}
