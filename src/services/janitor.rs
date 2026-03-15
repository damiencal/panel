/// Background janitor tasks inspired by Coolify's cleanup and monitoring jobs.
///
/// Handles periodic maintenance operations:
///  - Refreshing real disk usage from the filesystem and updating the quota DB
///  - Warning when users approach their disk limit
///  - Cleaning up oversized OLS error logs (prevents runaway logs from filling disk)
///  - Removing orphaned panel-owned files from /tmp
///
/// None of these functions interact with user-controlled paths unless the username
/// has first been validated; all path construction is done with explicit base
/// directory checks.
#[cfg(feature = "server")]
use sqlx::SqlitePool;
use tokio::process::Command;
use tracing::{info, warn};

/// Threshold at which a user's disk usage is considered a warning, in percent.
pub const DEFAULT_WARNING_THRESHOLD_PCT: u8 = 80;

/// Maximum age after which orphaned panel /tmp files are removed, in hours.
pub const DEFAULT_TMP_MAX_AGE_HOURS: u32 = 24;

/// OLS error log size at which rotation (truncation) is triggered, in megabytes.
pub const DEFAULT_LOG_ROTATE_MB: u64 = 50;

/// A user whose disk usage has crossed the warning threshold.
#[derive(Debug, Clone)]
pub struct QuotaWarning {
    pub user_id: i64,
    pub username: String,
    pub disk_used_mb: i64,
    pub disk_limit_mb: i64,
    pub pct_used: f32,
}

// ── Disk usage refresh ────────────────────────────────────────────────────────

/// Measure a single user's home directory disk usage via `du` and persist it.
///
/// `username` must pass the `validate_username` validator; the resulting path
/// must start with `/home/`. Any deviation returns an `Err` without touching
/// the filesystem.
#[cfg(feature = "server")]
pub async fn refresh_user_disk_usage(
    pool: &SqlitePool,
    user_id: i64,
    username: &str,
) -> Result<i64, String> {
    // Defense-in-depth: validate even though callers should also validate.
    crate::utils::validators::validate_username(username)
        .map_err(|e| format!("Invalid username: {e}"))?;

    let home_dir = format!("/home/{username}");

    // Extra guard: ensure the composed path stays inside /home/ so a crafted
    // username (e.g. "../../etc") cannot escape, even if the regex were relaxed.
    if !home_dir.starts_with("/home/") {
        return Err("Computed home path is outside /home/".into());
    }

    let output = Command::new("du")
        .args(["-s", "--block-size=1M", &home_dir])
        .output()
        .await
        .map_err(|e| format!("du invocation failed: {e}"))?;

    if !output.status.success() {
        // Directory does not exist yet (new user); record 0 and return.
        update_disk_used(pool, user_id, 0).await?;
        return Ok(0);
    }

    let out_str = String::from_utf8_lossy(&output.stdout);
    let used_mb: i64 = out_str
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    update_disk_used(pool, user_id, used_mb).await?;

    Ok(used_mb)
}

#[cfg(feature = "server")]
async fn update_disk_used(pool: &SqlitePool, user_id: i64, used_mb: i64) -> Result<(), String> {
    sqlx::query("UPDATE resource_usage SET disk_used_mb = ?, updated_at = ? WHERE user_id = ?")
        .bind(used_mb)
        .bind(chrono::Utc::now())
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| format!("DB update failed: {e}"))
        .map(|_| ())
}

/// Refresh disk usage for all active Client-role users.
/// Returns the number of successfully updated users.
#[cfg(feature = "server")]
pub async fn refresh_all_disk_usage(pool: &SqlitePool) -> usize {
    let users = match sqlx::query_as::<_, (i64, String)>(
        "SELECT id, username FROM users WHERE role = 'Client' AND status = 'Active'",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "janitor: failed to list users for disk refresh");
            return 0;
        }
    };

    let mut updated = 0usize;
    for (uid, uname) in &users {
        match refresh_user_disk_usage(pool, *uid, uname).await {
            Ok(mb) => {
                info!(user_id = uid, disk_mb = mb, "janitor: disk usage refreshed");
                updated += 1;
            }
            Err(e) => {
                warn!(user_id = uid, error = %e, "janitor: disk refresh failed");
            }
        }
    }
    updated
}

// ── Quota warnings ────────────────────────────────────────────────────────────

/// Return all users whose `disk_used_mb / disk_limit_mb` is at or above
/// `threshold_pct`. This is a pure-DB read; call `refresh_all_disk_usage`
/// first to ensure the numbers are fresh.
#[cfg(feature = "server")]
pub async fn get_quota_warnings(pool: &SqlitePool, threshold_pct: u8) -> Vec<QuotaWarning> {
    let pct = threshold_pct.clamp(1, 100) as f64 / 100.0;

    let rows: Vec<(i64, String, i64, i64)> = match sqlx::query_as(
        "SELECT u.id, u.username, ru.disk_used_mb, rq.disk_limit_mb
         FROM users u
         JOIN resource_usage ru ON ru.user_id = u.id
         JOIN resource_quotas rq ON rq.user_id = u.id
         WHERE rq.disk_limit_mb > 0
           AND CAST(ru.disk_used_mb AS REAL) / rq.disk_limit_mb >= ?",
    )
    .bind(pct)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "janitor: quota warnings query failed");
            return vec![];
        }
    };

    rows.into_iter()
        .map(|(user_id, username, disk_used_mb, disk_limit_mb)| {
            let pct_used = if disk_limit_mb > 0 {
                disk_used_mb as f32 / disk_limit_mb as f32 * 100.0
            } else {
                0.0
            };
            QuotaWarning {
                user_id,
                username,
                disk_used_mb,
                disk_limit_mb,
                pct_used,
            }
        })
        .collect()
}

// ── Error log rotation ────────────────────────────────────────────────────────

/// Truncate (rotate) any OLS log file inside `/usr/local/lsws/logs/` that
/// exceeds `threshold_mb` megabytes. Truncation preserves the open file
/// descriptor so OLS does not need a restart.
///
/// Returns the paths of files that were rotated.
pub async fn cleanup_large_error_logs(threshold_mb: u64) -> Vec<String> {
    use tokio::fs;

    const LOG_DIR: &str = "/usr/local/lsws/logs";
    let threshold_bytes = threshold_mb * 1024 * 1024;
    let mut rotated = Vec::new();

    let mut read_dir = match fs::read_dir(LOG_DIR).await {
        Ok(d) => d,
        Err(_) => return rotated, // log dir doesn't exist yet; not an error
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let path = entry.path();

        // Defense-in-depth: only operate inside the expected log directory.
        if !path.starts_with(LOG_DIR) {
            continue;
        }

        // Only touch `.log` files.
        if path.extension().and_then(|e| e.to_str()) != Some("log") {
            continue;
        }

        let meta = match fs::metadata(&path).await {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.len() > threshold_bytes {
            // Open with truncate=true so the inode/fd stays valid for OLS.
            if let Ok(file) = tokio::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .await
            {
                drop(file);
                let path_str = path.display().to_string();
                info!(
                    path = %path_str,
                    size_mb = meta.len() / 1024 / 1024,
                    "janitor: rotated oversized log"
                );
                rotated.push(path_str);
            }
        }
    }

    rotated
}

// ── Orphaned /tmp cleanup ────────────────────────────────────────────────────

/// Delete regular files under `/tmp` that:
///   - are prefixed with `panel-` (written only by this application), and
///   - have not been modified in at least `max_age_hours` hours.
///
/// Uses `find -maxdepth 2` and `-name "panel-*"` to scope the deletion tightly.
/// Returns the number of files removed.
pub async fn cleanup_orphaned_tmp(max_age_hours: u32) -> usize {
    // find's -mtime N matches files modified more than N*24h ago.
    // We compute the equivalent days, clamped to at least 1.
    let mtime_days = format!("+{}", (max_age_hours / 24).max(1));

    let output = Command::new("find")
        .args([
            "/tmp",
            "-maxdepth",
            "2",
            "-name",
            "panel-*",
            "-mtime",
            &mtime_days,
            "-type",
            "f",
            "-delete",
            "-print",
        ])
        .output()
        .await;

    match output {
        Ok(out) => {
            let count = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .count();
            if count > 0 {
                info!(count, "janitor: removed orphaned /tmp files");
            }
            count
        }
        Err(e) => {
            warn!(error = %e, "janitor: /tmp cleanup failed");
            0
        }
    }
}
