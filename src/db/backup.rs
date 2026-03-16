/// Backup database operations.
use chrono::Utc;
use sqlx::SqlitePool;

use crate::models::backup::{BackupRun, BackupSchedule, BackupScheduleWithLatest, BackupStats};

// ─── Schedules ────────────────────────────────────────────────────────────────

/// Fetch a single schedule by ID.
pub async fn get_schedule(pool: &SqlitePool, id: i64) -> Result<BackupSchedule, sqlx::Error> {
    sqlx::query_as::<_, BackupSchedule>("SELECT * FROM backup_schedules WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
}

/// List all schedules for an owner.
pub async fn list_schedules(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<Vec<BackupSchedule>, sqlx::Error> {
    sqlx::query_as::<_, BackupSchedule>(
        "SELECT * FROM backup_schedules WHERE owner_id = ? ORDER BY created_at DESC",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
}

/// List all schedules across all owners (admin view).
pub async fn list_all_schedules(pool: &SqlitePool) -> Result<Vec<BackupSchedule>, sqlx::Error> {
    sqlx::query_as::<_, BackupSchedule>(
        "SELECT * FROM backup_schedules ORDER BY owner_id, created_at DESC",
    )
    .fetch_all(pool)
    .await
}

/// Create a new backup schedule.
#[allow(clippy::too_many_arguments)]
pub async fn create_schedule(
    pool: &SqlitePool,
    owner_id: i64,
    site_id: Option<i64>,
    mailbox_id: Option<i64>,
    name: &str,
    schedule: &str,
    storage_type: &str,
    destination: &str,
    retention_count: i32,
    compress: bool,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO backup_schedules
            (owner_id, site_id, mailbox_id, name, schedule, storage_type, destination,
             retention_count, compress, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(owner_id)
    .bind(site_id)
    .bind(mailbox_id)
    .bind(name)
    .bind(schedule)
    .bind(storage_type)
    .bind(destination)
    .bind(retention_count)
    .bind(compress)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Toggle enabled/disabled for a schedule.
pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE backup_schedules SET enabled = ?, updated_at = ? WHERE id = ?")
        .bind(enabled)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a schedule (cascades to runs).
pub async fn delete_schedule(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM backup_schedules WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update last_run / next_run after execution.
pub async fn update_run_times(
    pool: &SqlitePool,
    id: i64,
    last_run: chrono::DateTime<Utc>,
    next_run: Option<chrono::DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE backup_schedules SET last_run = ?, next_run = ?, updated_at = ? WHERE id = ?",
    )
    .bind(last_run)
    .bind(next_run)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Runs ─────────────────────────────────────────────────────────────────────

/// List recent runs for a schedule (newest first).
pub async fn list_runs(
    pool: &SqlitePool,
    schedule_id: i64,
    limit: i64,
) -> Result<Vec<BackupRun>, sqlx::Error> {
    sqlx::query_as::<_, BackupRun>(
        "SELECT * FROM backup_runs WHERE schedule_id = ? ORDER BY started_at DESC LIMIT ?",
    )
    .bind(schedule_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// List recent runs across all schedules for an owner.
pub async fn list_runs_for_owner(
    pool: &SqlitePool,
    owner_id: i64,
    limit: i64,
) -> Result<Vec<BackupRun>, sqlx::Error> {
    sqlx::query_as::<_, BackupRun>(
        "SELECT * FROM backup_runs WHERE owner_id = ? ORDER BY started_at DESC LIMIT ?",
    )
    .bind(owner_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// List recent runs across ALL owners (admin).
pub async fn list_all_runs(pool: &SqlitePool, limit: i64) -> Result<Vec<BackupRun>, sqlx::Error> {
    sqlx::query_as::<_, BackupRun>("SELECT * FROM backup_runs ORDER BY started_at DESC LIMIT ?")
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Insert a new run record (status = 'running').
pub async fn start_run(
    pool: &SqlitePool,
    schedule_id: i64,
    owner_id: i64,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO backup_runs (schedule_id, owner_id, started_at, status)
         VALUES (?, ?, ?, 'running')",
    )
    .bind(schedule_id)
    .bind(owner_id)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Mark a run as successful.
pub async fn finish_run_success(
    pool: &SqlitePool,
    run_id: i64,
    size_bytes: i64,
    archive_path: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE backup_runs
         SET finished_at = ?, status = 'success', size_bytes = ?, archive_path = ?
         WHERE id = ?",
    )
    .bind(now)
    .bind(size_bytes)
    .bind(archive_path)
    .bind(run_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark a run as failed.
pub async fn finish_run_failed(
    pool: &SqlitePool,
    run_id: i64,
    error: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE backup_runs SET finished_at = ?, status = 'failed', error_message = ? WHERE id = ?",
    )
    .bind(now)
    .bind(error)
    .bind(run_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch aggregate stats for an owner.
pub async fn get_stats_for_owner(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<BackupStats, sqlx::Error> {
    let total_schedules: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM backup_schedules WHERE owner_id = ?")
            .bind(owner_id)
            .fetch_one(pool)
            .await?;

    let enabled_schedules: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM backup_schedules WHERE owner_id = ? AND enabled = 1",
    )
    .bind(owner_id)
    .fetch_one(pool)
    .await?;

    let total_runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backup_runs WHERE owner_id = ?")
        .bind(owner_id)
        .fetch_one(pool)
        .await?;

    let successful_runs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM backup_runs WHERE owner_id = ? AND status = 'success'",
    )
    .bind(owner_id)
    .fetch_one(pool)
    .await?;

    let failed_runs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM backup_runs WHERE owner_id = ? AND status = 'failed'",
    )
    .bind(owner_id)
    .fetch_one(pool)
    .await?;

    let total_size_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM backup_runs WHERE owner_id = ? AND status = 'success'",
    )
    .bind(owner_id)
    .fetch_one(pool)
    .await?;

    Ok(BackupStats {
        total_schedules,
        enabled_schedules,
        total_runs,
        successful_runs,
        failed_runs,
        total_size_bytes,
    })
}

/// Fetch aggregate stats across ALL owners (admin).
pub async fn get_global_stats(pool: &SqlitePool) -> Result<BackupStats, sqlx::Error> {
    let total_schedules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backup_schedules")
        .fetch_one(pool)
        .await?;

    let enabled_schedules: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM backup_schedules WHERE enabled = 1")
            .fetch_one(pool)
            .await?;

    let total_runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backup_runs")
        .fetch_one(pool)
        .await?;

    let successful_runs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM backup_runs WHERE status = 'success'")
            .fetch_one(pool)
            .await?;

    let failed_runs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM backup_runs WHERE status = 'failed'")
            .fetch_one(pool)
            .await?;

    let total_size_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM backup_runs WHERE status = 'success'",
    )
    .fetch_one(pool)
    .await?;

    Ok(BackupStats {
        total_schedules,
        enabled_schedules,
        total_runs,
        successful_runs,
        failed_runs,
        total_size_bytes,
    })
}

/// Fetch all schedules for an owner joined with their latest run.
pub async fn list_schedules_with_latest(
    pool: &SqlitePool,
    owner_id: i64,
) -> Result<Vec<BackupScheduleWithLatest>, sqlx::Error> {
    let schedules = list_schedules(pool, owner_id).await?;
    let mut out = Vec::with_capacity(schedules.len());
    for sched in schedules {
        let latest = sqlx::query_as::<_, BackupRun>(
            "SELECT * FROM backup_runs WHERE schedule_id = ? ORDER BY started_at DESC LIMIT 1",
        )
        .bind(sched.id)
        .fetch_optional(pool)
        .await?;
        let site_domain = if let Some(sid) = sched.site_id {
            sqlx::query_scalar::<_, String>("SELECT domain FROM sites WHERE id = ?")
                .bind(sid)
                .fetch_optional(pool)
                .await?
        } else {
            None
        };
        out.push(BackupScheduleWithLatest {
            schedule: sched,
            latest_run: latest,
            site_domain,
        });
    }
    Ok(out)
}

/// Enforce retention: delete old runs beyond retention_count for a schedule.
pub async fn prune_old_runs(
    pool: &SqlitePool,
    schedule_id: i64,
    retention_count: i32,
) -> Result<(), sqlx::Error> {
    if retention_count <= 0 {
        return Ok(());
    }
    sqlx::query(
        "DELETE FROM backup_runs
         WHERE schedule_id = ?
           AND id NOT IN (
             SELECT id FROM backup_runs
             WHERE schedule_id = ?
             ORDER BY started_at DESC
             LIMIT ?
           )",
    )
    .bind(schedule_id)
    .bind(schedule_id)
    .bind(retention_count)
    .execute(pool)
    .await?;
    Ok(())
}
