/// Background task database operations.
use crate::models::task::{BackgroundTask, TaskStatus};
use chrono::Utc;
use sqlx::SqlitePool;

/// Create a new pending task.
pub async fn create(
    pool: &SqlitePool,
    name: &str,
    triggered_by: Option<i64>,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO background_tasks (name, status, triggered_by, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(name)
    .bind(TaskStatus::Pending)
    .bind(triggered_by)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Update the status of a task (also sets `completed_at` for terminal states).
pub async fn update_status(
    pool: &SqlitePool,
    task_id: i64,
    status: TaskStatus,
) -> Result<(), sqlx::Error> {
    let completed_at = matches!(status, TaskStatus::Completed | TaskStatus::Failed).then(Utc::now);

    sqlx::query("UPDATE background_tasks SET status = ?, completed_at = ? WHERE id = ?")
        .bind(status)
        .bind(completed_at)
        .bind(task_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Append a log line to the task's output buffer.
pub async fn append_log(pool: &SqlitePool, task_id: i64, line: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE background_tasks
         SET log_output = COALESCE(log_output || char(10), '') || ?
         WHERE id = ?",
    )
    .bind(line)
    .bind(task_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fetch a single task by ID.
pub async fn get(pool: &SqlitePool, task_id: i64) -> Result<BackgroundTask, sqlx::Error> {
    sqlx::query_as::<_, BackgroundTask>("SELECT * FROM background_tasks WHERE id = ?")
        .bind(task_id)
        .fetch_one(pool)
        .await
}

/// List the most recent tasks, newest first.
pub async fn list_recent(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<BackgroundTask>, sqlx::Error> {
    sqlx::query_as::<_, BackgroundTask>(
        "SELECT * FROM background_tasks ORDER BY created_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}
