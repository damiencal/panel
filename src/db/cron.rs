/// Cron job database operations.
use chrono::Utc;
use sqlx::SqlitePool;

use crate::models::cron::CronJob;

/// Fetch a single cron job by ID.
pub async fn get(pool: &SqlitePool, job_id: i64) -> Result<CronJob, sqlx::Error> {
    sqlx::query_as::<_, CronJob>("SELECT * FROM cron_jobs WHERE id = ?")
        .bind(job_id)
        .fetch_one(pool)
        .await
}

/// List all cron jobs for a specific site.
pub async fn list_for_site(pool: &SqlitePool, site_id: i64) -> Result<Vec<CronJob>, sqlx::Error> {
    sqlx::query_as::<_, CronJob>("SELECT * FROM cron_jobs WHERE site_id = ? ORDER BY id")
        .bind(site_id)
        .fetch_all(pool)
        .await
}

/// List all cron jobs owned by a user.
pub async fn list_for_owner(pool: &SqlitePool, owner_id: i64) -> Result<Vec<CronJob>, sqlx::Error> {
    sqlx::query_as::<_, CronJob>("SELECT * FROM cron_jobs WHERE owner_id = ? ORDER BY site_id, id")
        .bind(owner_id)
        .fetch_all(pool)
        .await
}

/// List only enabled cron jobs for a user (used when syncing the crontab).
pub async fn list_enabled_for_owner(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<Vec<CronJob>, sqlx::Error> {
    sqlx::query_as::<_, CronJob>(
        "SELECT * FROM cron_jobs WHERE owner_id = ? AND enabled = 1 ORDER BY site_id, id",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
}

/// Create a new cron job.
pub async fn create(
    pool: &SqlitePool,
    owner_id: i64,
    site_id: i64,
    schedule: String,
    command: String,
    description: String,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO cron_jobs
            (owner_id, site_id, schedule, command, description, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(owner_id)
    .bind(site_id)
    .bind(schedule)
    .bind(command)
    .bind(description)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Delete a cron job.
pub async fn delete(pool: &SqlitePool, job_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM cron_jobs WHERE id = ?")
        .bind(job_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Enable or disable a cron job.
pub async fn set_enabled(pool: &SqlitePool, job_id: i64, enabled: bool) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE cron_jobs SET enabled = ?, updated_at = ? WHERE id = ?")
        .bind(enabled)
        .bind(now)
        .bind(job_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update the last_run timestamp for a job.
pub async fn update_last_run(pool: &SqlitePool, job_id: i64) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE cron_jobs SET last_run = ?, updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(now)
        .bind(job_id)
        .execute(pool)
        .await?;
    Ok(())
}
