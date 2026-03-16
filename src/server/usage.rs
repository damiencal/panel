#[cfg(feature = "server")]
use crate::models::billing::MetricType;
/// Usage analytics server functions.
use crate::models::billing::{DailyAggregate, MonthlySnapshot, UsageStats};
use crate::models::quota::QuotaStatus;
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Get the current quota utilisation for the caller (or a specific user for admins).
#[server]
pub async fn server_get_quota_status(user_id: Option<i64>) -> Result<QuotaStatus, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let target_id = match claims.role {
        crate::models::user::Role::Admin => user_id.unwrap_or(claims.sub),
        _ => {
            // Non-admins can only view their own quota
            if let Some(id) = user_id {
                if id != claims.sub {
                    return Err(ServerFnError::new("Access denied"));
                }
            }
            claims.sub
        }
    };

    let quota = crate::db::quotas::get_quota(pool, target_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let usage = crate::db::quotas::get_usage(pool, target_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(QuotaStatus::new(quota, usage))
}

/// Get daily bandwidth and storage aggregates for the last N days.
#[server]
pub async fn server_get_usage_history(
    days: i64,
    user_id: Option<i64>,
) -> Result<Vec<DailyAggregate>, ServerFnError> {
    use super::helpers::*;
    use chrono::{Duration, Utc};

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    if !(1..=365).contains(&days) {
        return Err(ServerFnError::new("days must be between 1 and 365"));
    }

    let target_id = match claims.role {
        crate::models::user::Role::Admin => user_id.unwrap_or(claims.sub),
        _ => claims.sub,
    };

    let since = (Utc::now() - Duration::days(days)).date_naive();

    let rows = sqlx::query_as::<_, DailyAggregate>(
        "SELECT * FROM daily_usage_aggregates
         WHERE user_id = ? AND date >= ?
         ORDER BY date ASC",
    )
    .bind(target_id)
    .bind(since)
    .fetch_all(pool)
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(rows)
}

/// Get the monthly usage snapshot for a given month.
#[server]
pub async fn server_get_monthly_snapshot(
    year: i32,
    month: i32,
    user_id: Option<i64>,
) -> Result<Option<MonthlySnapshot>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    if !(1..=12).contains(&month) {
        return Err(ServerFnError::new("month must be 1–12"));
    }

    let target_id = match claims.role {
        crate::models::user::Role::Admin => user_id.unwrap_or(claims.sub),
        _ => claims.sub,
    };

    crate::db::usage::get_monthly_snapshot(pool, target_id, year, month)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Aggregate usage stats summary for the current month (reseller: sum of all clients).
#[server]
pub async fn server_get_reseller_usage_summary() -> Result<UsageStats, ServerFnError> {
    use super::helpers::*;
    use chrono::Utc;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_reseller(&claims)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let now = Utc::now();
    let _current_month = now.format("%Y-%m").to_string();

    // Sum bandwidth and storage across all direct clients of this reseller
    let row: (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(r.bandwidth_used_mb), 0),
                COALESCE(SUM(r.storage_used_mb), 0)
         FROM resource_usage r
         JOIN users u ON u.id = r.user_id
         WHERE u.id = ? OR u.parent_id = ?",
    )
    .bind(claims.sub)
    .bind(claims.sub)
    .fetch_one(pool)
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Monthly snapshot for the reseller itself
    let month_snap = crate::db::usage::get_monthly_snapshot(
        pool,
        claims.sub,
        now.format("%Y").to_string().parse::<i32>().unwrap_or(2026),
        now.format("%m").to_string().parse::<i32>().unwrap_or(1),
    )
    .await
    .unwrap_or(None);

    Ok(UsageStats {
        current_bandwidth_gb: row.0 as f64 / 1024.0,
        current_storage_gb: row.1 as f64 / 1024.0,
        month_bandwidth_gb: month_snap
            .as_ref()
            .map(|s| s.bandwidth_used_mb as f64 / 1024.0)
            .unwrap_or(0.0),
        month_storage_peak_gb: month_snap
            .as_ref()
            .map(|s| s.storage_peak_mb as f64 / 1024.0)
            .unwrap_or(0.0),
    })
}

/// Record a bandwidth usage event (called internally by site access log processing).
#[server]
pub async fn server_record_bandwidth_event(
    user_id: i64,
    site_id: Option<i64>,
    value_mb: i64,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use chrono::Utc;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    // Bandwidth recording is an internal/administrative operation — admin only.
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    // Sanity bounds: each event must be 1–100_000 MB to prevent counter manipulation.
    if value_mb <= 0 || value_mb > 100_000 {
        return Err(ServerFnError::new("value_mb must be between 1 and 100000"));
    }
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    crate::db::usage::log_usage(pool, user_id, site_id, MetricType::Bandwidth, value_mb)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Update daily aggregate for today
    let today = Utc::now().date_naive();
    // Increment existing row or insert new row via upsert
    sqlx::query(
        "INSERT INTO daily_usage_aggregates (user_id, date, bandwidth_used_mb, storage_used_mb)
         VALUES (?, ?, ?, 0)
         ON CONFLICT(user_id, date) DO UPDATE SET
            bandwidth_used_mb = bandwidth_used_mb + excluded.bandwidth_used_mb",
    )
    .bind(user_id)
    .bind(today)
    .bind(value_mb)
    .execute(pool)
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Keep resource_usage.bandwidth_used_mb in sync
    sqlx::query(
        "UPDATE resource_usage SET bandwidth_used_mb = bandwidth_used_mb + ?, updated_at = ? WHERE user_id = ?",
    )
    .bind(value_mb)
    .bind(Utc::now())
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
}

/// Per-user disk quota warning summary (admin only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaWarningInfo {
    pub user_id: i64,
    pub username: String,
    pub disk_used_mb: i64,
    pub disk_limit_mb: i64,
    pub pct_used: f32,
}

/// Return all users whose disk usage has crossed `threshold_pct` percent of their
/// quota limit. This also refreshes real disk usage from the filesystem first,
/// so the results are always fresh.
#[server]
pub async fn server_get_quota_warnings(
    threshold_pct: u8,
) -> Result<Vec<QuotaWarningInfo>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    if threshold_pct == 0 || threshold_pct > 100 {
        return Err(ServerFnError::new(
            "threshold_pct must be between 1 and 100",
        ));
    }

    // Refresh disk usage from the filesystem before querying.
    crate::services::janitor::refresh_all_disk_usage(pool).await;

    let warnings = crate::services::janitor::get_quota_warnings(pool, threshold_pct).await;

    Ok(warnings
        .into_iter()
        .map(|w| QuotaWarningInfo {
            user_id: w.user_id,
            username: w.username,
            disk_used_mb: w.disk_used_mb,
            disk_limit_mb: w.disk_limit_mb,
            pct_used: w.pct_used,
        })
        .collect())
}
