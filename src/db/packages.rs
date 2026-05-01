/// Hosting package database operations.
use crate::models::package::Package;
use chrono::Utc;
use sqlx::SqlitePool;

/// Get a package by ID.
pub async fn get(pool: &SqlitePool, package_id: i64) -> Result<Package, sqlx::Error> {
    sqlx::query_as::<_, Package>("SELECT * FROM packages WHERE id = ?")
        .bind(package_id)
        .fetch_one(pool)
        .await
}

/// List all active packages created by a user (Admin or Reseller).
pub async fn list_by_creator(
    pool: &SqlitePool,
    creator_id: i64,
) -> Result<Vec<Package>, sqlx::Error> {
    sqlx::query_as::<_, Package>(
        "SELECT * FROM packages WHERE created_by = ? AND is_active = 1 ORDER BY name",
    )
    .bind(creator_id)
    .fetch_all(pool)
    .await
}

/// List all packages (Admin only).
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Package>, sqlx::Error> {
    sqlx::query_as::<_, Package>(
        "SELECT * FROM packages WHERE is_active = 1 ORDER BY created_by, name",
    )
    .fetch_all(pool)
    .await
}

/// Create a new package.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &SqlitePool,
    name: String,
    description: Option<String>,
    created_by: i64,
    max_sites: i32,
    max_databases: i32,
    max_email_accounts: i32,
    max_ftp_accounts: i32,
    disk_limit_mb: i64,
    bandwidth_limit_mb: i64,
    max_subdomains: i32,
    max_addon_domains: i32,
    php_enabled: bool,
    ssl_enabled: bool,
    shell_access: bool,
    backup_enabled: bool,
    cpu_quota_percent: i32,
    memory_max_mb: i64,
    tasks_max: i32,
    io_weight: i32,
    max_db_connections: i32,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO packages (name, description, created_by, max_sites, max_databases,
            max_email_accounts, max_ftp_accounts, disk_limit_mb, bandwidth_limit_mb,
            max_subdomains, max_addon_domains, php_enabled, ssl_enabled,
            shell_access, backup_enabled, is_active,
            cpu_quota_percent, memory_max_mb, tasks_max, io_weight, max_db_connections,
            created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
    )
    .bind(name)
    .bind(description)
    .bind(created_by)
    .bind(max_sites)
    .bind(max_databases)
    .bind(max_email_accounts)
    .bind(max_ftp_accounts)
    .bind(disk_limit_mb)
    .bind(bandwidth_limit_mb)
    .bind(max_subdomains)
    .bind(max_addon_domains)
    .bind(php_enabled)
    .bind(ssl_enabled)
    .bind(shell_access)
    .bind(backup_enabled)
    .bind(cpu_quota_percent)
    .bind(memory_max_mb)
    .bind(tasks_max)
    .bind(io_weight)
    .bind(max_db_connections)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Count active packages with the given name owned by the same creator.
/// Used to enforce per-creator package name uniqueness.
pub async fn count_by_name_and_creator(
    pool: &SqlitePool,
    name: &str,
    creator_id: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM packages WHERE name = ? AND created_by = ? AND is_active = 1",
    )
    .bind(name)
    .bind(creator_id)
    .fetch_one(pool)
    .await
}

/// Deactivate a package.
pub async fn deactivate(pool: &SqlitePool, package_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE packages SET is_active = 0 WHERE id = ?")
        .bind(package_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a package.
pub async fn delete(pool: &SqlitePool, package_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM packages WHERE id = ?")
        .bind(package_id)
        .execute(pool)
        .await?;
    Ok(())
}
