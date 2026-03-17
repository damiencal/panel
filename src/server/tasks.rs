/// Background task server functions.
use crate::models::task::BackgroundTask;
use dioxus::prelude::*;

/// Get a single background task (including its log output) by ID.
///
/// Admins may read any task. Non-admins may only read tasks they triggered.
#[server]
pub async fn server_get_task(task_id: i64) -> Result<BackgroundTask, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let task = crate::db::tasks::get(pool, task_id)
        .await
        .map_err(|_| ServerFnError::new("Task not found"))?;

    // Scope non-admin reads to tasks they triggered.
    if claims.role != crate::models::user::Role::Admin && task.triggered_by != Some(claims.sub) {
        return Err(ServerFnError::new("Access denied"));
    }

    Ok(task)
}

/// List the most recent background tasks (admin only).
#[server]
pub async fn server_list_tasks(limit: i64) -> Result<Vec<BackgroundTask>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    if !(1..=200).contains(&limit) {
        return Err(ServerFnError::new("limit must be between 1 and 200"));
    }

    crate::db::tasks::list_recent(pool, limit)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Trigger a named janitor task asynchronously and return a task ID for polling.
///
/// Allowed `task_type` values: `"disk_refresh"`, `"log_cleanup"`, `"tmp_cleanup"`.
/// The task runs in background via `tokio::spawn`; callers should poll
/// `server_get_task` to follow progress.
#[server]
pub async fn server_run_janitor(task_type: String) -> Result<i64, ServerFnError> {
    use super::helpers::*;
    use crate::models::task::TaskStatus;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    // Allowlist: only permit known safe task types.
    match task_type.as_str() {
        "disk_refresh" | "log_cleanup" | "tmp_cleanup" => {}
        _ => return Err(ServerFnError::new("Unknown task type")),
    }

    let task_id = crate::db::tasks::create(pool, &task_type, Some(claims.sub))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "run_janitor",
        None,
        Some(task_id),
        Some(&task_type),
        "Queued",
        None,
    )
    .await;

    // Execute in the background without blocking the HTTP response.
    let pool_clone = pool.clone();
    let task_type_clone = task_type.clone();
    tokio::spawn(async move {
        if let Err(e) =
            crate::db::tasks::update_status(&pool_clone, task_id, TaskStatus::Running).await
        {
            tracing::error!("Failed to update task {} status to Running: {e}", task_id);
        }

        let (result_msg, final_status) = match task_type_clone.as_str() {
            "disk_refresh" => {
                let updated = crate::services::janitor::refresh_all_disk_usage(&pool_clone).await;
                (
                    format!("Refreshed disk usage for {updated} user(s)."),
                    TaskStatus::Completed,
                )
            }
            "log_cleanup" => {
                let rotated = crate::services::janitor::cleanup_large_error_logs(
                    crate::services::janitor::DEFAULT_LOG_ROTATE_MB,
                )
                .await;
                let names = rotated.join(", ");
                (
                    format!(
                        "Rotated {} log file(s){}",
                        rotated.len(),
                        if names.is_empty() {
                            String::new()
                        } else {
                            format!(": {names}")
                        }
                    ),
                    TaskStatus::Completed,
                )
            }
            "tmp_cleanup" => {
                let count = crate::services::janitor::cleanup_orphaned_tmp(
                    crate::services::janitor::DEFAULT_TMP_MAX_AGE_HOURS,
                )
                .await;
                (
                    format!("Removed {count} orphaned /tmp file(s)."),
                    TaskStatus::Completed,
                )
            }
            _ => (
                "Unknown task type — no action taken.".to_string(),
                TaskStatus::Failed,
            ),
        };

        if let Err(e) = crate::db::tasks::append_log(&pool_clone, task_id, &result_msg).await {
            tracing::error!("Failed to append log for task {}: {e}", task_id);
        }
        if let Err(e) = crate::db::tasks::update_status(&pool_clone, task_id, final_status).await {
            tracing::error!("Failed to update final status for task {}: {e}", task_id);
        }
    });

    Ok(task_id)
}
