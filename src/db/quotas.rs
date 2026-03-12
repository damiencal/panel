/// Resource quota database operations.
use crate::models::quota::{ResourceQuota, ResourceUsage};
use chrono::Utc;
use sqlx::SqlitePool;

/// Get quota for a user.
pub async fn get_quota(pool: &SqlitePool, user_id: i64) -> Result<ResourceQuota, sqlx::Error> {
    sqlx::query_as::<_, ResourceQuota>("SELECT * FROM resource_quotas WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// Get usage for a user.
pub async fn get_usage(pool: &SqlitePool, user_id: i64) -> Result<ResourceUsage, sqlx::Error> {
    sqlx::query_as::<_, ResourceUsage>("SELECT * FROM resource_usage WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// Allocate quota to a user.
#[allow(clippy::too_many_arguments)]
pub async fn allocate_quota(
    pool: &SqlitePool,
    user_id: i64,
    max_clients: Option<i32>,
    max_sites: i32,
    max_databases: i32,
    max_email_accounts: i32,
    disk_limit_mb: i64,
    bandwidth_limit_mb: i64,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO resource_quotas (user_id, max_clients, max_sites, max_databases, 
            max_email_accounts, disk_limit_mb, bandwidth_limit_mb, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
            max_clients=excluded.max_clients, max_sites=excluded.max_sites,
            max_databases=excluded.max_databases, max_email_accounts=excluded.max_email_accounts,
            disk_limit_mb=excluded.disk_limit_mb, bandwidth_limit_mb=excluded.bandwidth_limit_mb,
            updated_at=excluded.updated_at",
    )
    .bind(user_id)
    .bind(max_clients)
    .bind(max_sites)
    .bind(max_databases)
    .bind(max_email_accounts)
    .bind(disk_limit_mb)
    .bind(bandwidth_limit_mb)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Initialize usage tracking for a user.
pub async fn init_usage(pool: &SqlitePool, user_id: i64) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT OR IGNORE INTO resource_usage (user_id, sites_used, databases_used, 
            email_accounts_used, disk_used_mb, bandwidth_used_mb, updated_at)
         VALUES (?, 0, 0, 0, 0, 0, ?)",
    )
    .bind(user_id)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Update site count for a user.
pub async fn increment_sites(
    pool: &SqlitePool,
    user_id: i64,
    amount: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE resource_usage SET sites_used = sites_used + ?, updated_at = ? WHERE user_id = ?",
    )
    .bind(amount)
    .bind(Utc::now())
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update database count for a user.
pub async fn increment_databases(
    pool: &SqlitePool,
    user_id: i64,
    amount: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE resource_usage SET databases_used = databases_used + ?, updated_at = ? WHERE user_id = ?"
    )
    .bind(amount)
    .bind(Utc::now())
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update email account count for a user.
pub async fn increment_email_accounts(
    pool: &SqlitePool,
    user_id: i64,
    amount: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE resource_usage SET email_accounts_used = email_accounts_used + ?, updated_at = ? WHERE user_id = ?"
    )
    .bind(amount)
    .bind(Utc::now())
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}
