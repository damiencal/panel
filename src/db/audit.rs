use chrono::Utc;
/// Audit log operations.
use sqlx::SqlitePool;

/// Record an action in the audit log.
#[allow(clippy::too_many_arguments)]
pub async fn log_action(
    pool: &SqlitePool,
    user_id: i64,
    action: String,
    target_type: Option<String>,
    target_id: Option<i64>,
    target_name: Option<String>,
    description: Option<String>,
    status: String,
    error_message: Option<String>,
    ip_address: Option<String>,
    impersonation_by: Option<i64>,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO audit_logs 
        (user_id, action, target_type, target_id, target_name, description, status, error_message, ip_address, impersonation_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(target_name)
    .bind(description)
    .bind(status)
    .bind(error_message)
    .bind(ip_address)
    .bind(impersonation_by)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// List recent audit logs.
pub async fn list_recent(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?")
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// List audit logs for a specific user.
pub async fn list_for_user(
    pool: &SqlitePool,
    user_id: i64,
    limit: i64,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?")
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Search audit logs.
pub async fn search(
    pool: &SqlitePool,
    action: Option<String>,
    target_type: Option<String>,
    limit: i64,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    let query = match (action, target_type) {
        (Some(a), Some(t)) => {
            sqlx::query(
                "SELECT * FROM audit_logs WHERE action = ? AND target_type = ? ORDER BY created_at DESC LIMIT ?"
            )
            .bind(a)
            .bind(t)
            .bind(limit)
            .fetch_all(pool)
            .await
        },
        (Some(a), None) => {
            sqlx::query(
                "SELECT * FROM audit_logs WHERE action = ? ORDER BY created_at DESC LIMIT ?"
            )
            .bind(a)
            .bind(limit)
            .fetch_all(pool)
            .await
        },
        (None, Some(t)) => {
            sqlx::query(
                "SELECT * FROM audit_logs WHERE target_type = ? ORDER BY created_at DESC LIMIT ?"
            )
            .bind(t)
            .bind(limit)
            .fetch_all(pool)
            .await
        },
        (None, None) => {
            sqlx::query(
                "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?"
            )
            .bind(limit)
            .fetch_all(pool)
            .await
        },
    };

    query
}

/// Delete old audit logs beyond a specified retention period (days).
pub async fn cleanup_old_logs(pool: &SqlitePool, retention_days: i64) -> Result<u64, sqlx::Error> {
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);

    let result = sqlx::query("DELETE FROM audit_logs WHERE created_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}
