use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Status of a background task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "Pending"),
            TaskStatus::Running => write!(f, "Running"),
            TaskStatus::Completed => write!(f, "Completed"),
            TaskStatus::Failed => write!(f, "Failed"),
        }
    }
}

/// A tracked background operation (SSL issuance, git pull, janitor run, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct BackgroundTask {
    pub id: i64,
    pub name: String,
    pub status: TaskStatus,
    pub log_output: Option<String>,
    /// The user who triggered this task, if any.
    pub triggered_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
