use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Web statistics tool variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum StatsTool {
    #[serde(rename = "Webalizer")]
    Webalizer,
    #[serde(rename = "GoAccess")]
    GoAccess,
    #[serde(rename = "AwStats")]
    AwStats,
}

impl std::fmt::Display for StatsTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatsTool::Webalizer => write!(f, "Webalizer"),
            StatsTool::GoAccess => write!(f, "GoAccess"),
            StatsTool::AwStats => write!(f, "AWStats"),
        }
    }
}

/// Last-run status for a stats job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum StatsRunStatus {
    #[serde(rename = "Success")]
    Success,
    #[serde(rename = "Failed")]
    Failed,
    #[serde(rename = "Running")]
    Running,
}

impl std::fmt::Display for StatsRunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatsRunStatus::Success => write!(f, "Success"),
            StatsRunStatus::Failed => write!(f, "Failed"),
            StatsRunStatus::Running => write!(f, "Running"),
        }
    }
}

/// Per-domain web statistics configuration record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct StatsConfig {
    pub id: i64,
    pub site_id: i64,
    pub domain: String,
    pub tool: StatsTool,
    pub enabled: bool,
    pub output_dir: String,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_status: Option<StatsRunStatus>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Installed-tool availability report returned to the UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatsToolAvailability {
    pub webalizer: bool,
    pub goaccess: bool,
    pub awstats: bool,
}
