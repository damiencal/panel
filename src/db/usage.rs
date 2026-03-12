/// Usage tracking and billing operations.
use crate::models::billing::{DailyAggregate, MetricType, MonthlySnapshot};
use chrono::{NaiveDate, Utc};
use sqlx::SqlitePool;

/// Log a usage entry.
pub async fn log_usage(
    pool: &SqlitePool,
    user_id: i64,
    site_id: Option<i64>,
    metric_type: MetricType,
    value_mb: i64,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO usage_logs (user_id, site_id, metric_type, value_mb, recorded_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(site_id)
    .bind(metric_type)
    .bind(value_mb)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get daily aggregate for a specific date.
pub async fn get_daily_aggregate(
    pool: &SqlitePool,
    user_id: i64,
    date: NaiveDate,
) -> Result<Option<DailyAggregate>, sqlx::Error> {
    sqlx::query_as::<_, DailyAggregate>(
        "SELECT * FROM daily_usage_aggregates WHERE user_id = ? AND date = ?",
    )
    .bind(user_id)
    .bind(date)
    .fetch_optional(pool)
    .await
}

/// Get monthly snapshot.
pub async fn get_monthly_snapshot(
    pool: &SqlitePool,
    user_id: i64,
    year: i32,
    month: i32,
) -> Result<Option<MonthlySnapshot>, sqlx::Error> {
    sqlx::query_as::<_, MonthlySnapshot>(
        "SELECT * FROM monthly_usage_snapshots WHERE user_id = ? AND year = ? AND month = ?",
    )
    .bind(user_id)
    .bind(year)
    .bind(month)
    .fetch_optional(pool)
    .await
}

/// Record a daily aggregate.
pub async fn record_daily_aggregate(
    pool: &SqlitePool,
    user_id: i64,
    date: NaiveDate,
    bandwidth_mb: i64,
    storage_mb: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO daily_usage_aggregates (user_id, date, bandwidth_used_mb, storage_used_mb)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(user_id, date) DO UPDATE SET
            bandwidth_used_mb = excluded.bandwidth_used_mb,
            storage_used_mb = excluded.storage_used_mb",
    )
    .bind(user_id)
    .bind(date)
    .bind(bandwidth_mb)
    .bind(storage_mb)
    .execute(pool)
    .await?;

    Ok(())
}

/// Record a monthly snapshot.
pub async fn record_monthly_snapshot(
    pool: &SqlitePool,
    user_id: i64,
    year: i32,
    month: i32,
    bandwidth_mb: i64,
    storage_peak_mb: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO monthly_usage_snapshots (user_id, year, month, bandwidth_used_mb, storage_peak_mb)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id, year, month) DO UPDATE SET
            bandwidth_used_mb = excluded.bandwidth_used_mb,
            storage_peak_mb = excluded.storage_peak_mb"
    )
    .bind(user_id)
    .bind(year)
    .bind(month)
    .bind(bandwidth_mb)
    .bind(storage_peak_mb)
    .execute(pool)
    .await?;

    Ok(())
}
