use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A scheduled cron job scoped to a specific website.
///
/// Jobs are stored in the panel database and installed into the site owner's
/// system-user crontab when enabled.  The panel maintains a dedicated
/// "panel-managed" section inside the crontab so that any manually added
/// entries are preserved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct CronJob {
    pub id: i64,
    pub owner_id: i64,
    pub site_id: i64,
    /// Standard 5-field cron expression or @alias (e.g. `*/5 * * * *`, `@daily`).
    pub schedule: String,
    /// Command to execute.  Must not contain newlines.
    pub command: String,
    /// Optional human-readable description.
    pub description: String,
    pub enabled: bool,
    pub last_run: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
