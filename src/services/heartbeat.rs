/// Heartbeat System — proactive background monitoring and maintenance.
///
/// The `HeartbeatRunner` spawns a single async loop that fires three independent
/// timed beats:
///
/// | Beat          | Interval | Purpose                                        |
/// |---------------|----------|------------------------------------------------|
/// | `pulse`       | 60 s     | Probe all managed services; audit transitions  |
/// | `quotas`      | 30 min   | Find users over disk-quota threshold           |
/// | `maintenance` | 60 min   | Janitor: disk-usage refresh, log rotation, tmp |
///
/// Results are written to the existing `background_tasks` table so they are
/// visible in the admin dashboard. Service state transitions (down / recovered)
/// are recorded in `audit_logs` as well.
///
/// Security notes
/// ──────────────
/// • Uses `db::get_pool_ref()` which panics on uninitialized pool; the caller
///   (`main.rs`) is responsible for ensuring the pool is initialized first via
///   `ensure_init()`.
/// • All janitor calls delegate to `services::janitor` which performs its own
///   input validation (defense-in-depth).
/// • No user-supplied data reaches shell commands from this module.
use std::collections::HashMap;

use sqlx::SqlitePool;
use tracing::{error, info, warn};

use crate::models::service::ServiceHealthState;
use crate::services::janitor::{
    self, DEFAULT_LOG_ROTATE_MB, DEFAULT_TMP_MAX_AGE_HOURS, DEFAULT_WARNING_THRESHOLD_PCT,
};
use crate::services::system;

// ── Intervals ────────────────────────────────────────────────────────────────

/// How often the service-health pulse fires (seconds).
pub const PULSE_INTERVAL_SECS: u64 = 60;

/// How often the quota-warning beat fires (seconds).
pub const QUOTA_INTERVAL_SECS: u64 = 30 * 60; // 30 minutes

/// How often the janitor maintenance beat fires (seconds).
pub const MAINTENANCE_INTERVAL_SECS: u64 = 60 * 60; // 60 minutes

// ── Runner ────────────────────────────────────────────────────────────────────

/// Owns the pool and the last-known health state for transition diffing.
pub struct HeartbeatRunner {
    pool: SqlitePool,
    /// Keyed by the string representation of `ServiceType`.
    prev_health: HashMap<String, ServiceHealthState>,
}

impl HeartbeatRunner {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            prev_health: HashMap::new(),
        }
    }

    /// Entry point — never returns under normal operation.
    ///
    /// Spawn with `tokio::spawn(HeartbeatRunner::new(pool).run())`.
    pub async fn run(mut self) {
        use tokio::time::{interval, sleep, Duration};

        // Small delay so the DB pool and migrations finish before the first beat.
        sleep(Duration::from_secs(5)).await;

        info!(
            "Heartbeat system started (pulse={}s, quota={}s, maintenance={}s)",
            PULSE_INTERVAL_SECS, QUOTA_INTERVAL_SECS, MAINTENANCE_INTERVAL_SECS
        );

        let mut pulse_tick = interval(Duration::from_secs(PULSE_INTERVAL_SECS));
        let mut quota_tick = interval(Duration::from_secs(QUOTA_INTERVAL_SECS));
        let mut maintenance_tick = interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECS));

        // Tick the intervals immediately so the first beat fires right away.
        pulse_tick.tick().await;
        quota_tick.tick().await;
        maintenance_tick.tick().await;

        loop {
            tokio::select! {
                _ = pulse_tick.tick() => {
                    self.beat_pulse().await;
                }
                _ = quota_tick.tick() => {
                    self.beat_quotas().await;
                }
                _ = maintenance_tick.tick() => {
                    self.beat_maintenance().await;
                }
            }
        }
    }

    // ── Individual beats ──────────────────────────────────────────────────────

    /// Service-health pulse: probe all managed services, diff state, audit transitions.
    async fn beat_pulse(&mut self) {
        let task_id = match crate::db::tasks::create(&self.pool, "heartbeat:pulse", None).await {
            Ok(id) => id,
            Err(e) => {
                error!("heartbeat:pulse — failed to create task record: {e}");
                return;
            }
        };

        let _ = crate::db::tasks::update_status(
            &self.pool,
            task_id,
            crate::models::task::TaskStatus::Running,
        )
        .await;

        let services = system::get_all_services_status().await;

        let mut log_lines: Vec<String> = Vec::new();
        let mut errors_encountered = false;

        for info in &services {
            let key = info.service_type.to_string();
            let current = info.health_state;
            let prev = self
                .prev_health
                .get(&key)
                .copied()
                .unwrap_or(ServiceHealthState::Unknown);

            let line = format!("{}: {:?}", key, current);
            log_lines.push(line);

            // Detect transitions that warrant an audit entry.
            let became_down =
                current == ServiceHealthState::Down && prev != ServiceHealthState::Down;
            let recovered = current != ServiceHealthState::Down
                && current != ServiceHealthState::Unknown
                && (prev == ServiceHealthState::Down);

            if became_down {
                warn!("heartbeat:pulse — {} went DOWN", key);
                if let Err(e) = crate::db::audit::log_action(
                    &self.pool,
                    0, // system action, no user
                    "service_down".to_string(),
                    Some("service".to_string()),
                    None,
                    Some(key.clone()),
                    Some(format!("Service {} is no longer responding", key)),
                    "failure".to_string(),
                    None,
                    None,
                    None,
                )
                .await
                {
                    error!("heartbeat:pulse — audit log write failed for {key}: {e}");
                    errors_encountered = true;
                }
            } else if recovered {
                info!("heartbeat:pulse — {} recovered", key);
                if let Err(e) = crate::db::audit::log_action(
                    &self.pool,
                    0,
                    "service_recovered".to_string(),
                    Some("service".to_string()),
                    None,
                    Some(key.clone()),
                    Some(format!("Service {} is back online", key)),
                    "success".to_string(),
                    None,
                    None,
                    None,
                )
                .await
                {
                    error!("heartbeat:pulse — audit log write failed for {key}: {e}");
                    errors_encountered = true;
                }
            }

            // Update prev_health regardless of whether an audit was written.
            self.prev_health.insert(key, current);
        }

        let summary = format!("Checked {} services. Transitions audited.", services.len());
        log_lines.push(summary);

        // Write summary lines to the task log.
        for line in &log_lines {
            let _ = crate::db::tasks::append_log(&self.pool, task_id, line).await;
        }

        let final_status = if errors_encountered {
            crate::models::task::TaskStatus::Failed
        } else {
            crate::models::task::TaskStatus::Completed
        };
        let _ = crate::db::tasks::update_status(&self.pool, task_id, final_status).await;
    }

    /// Quota beat: find users above their disk-usage threshold and audit-log them.
    async fn beat_quotas(&mut self) {
        let task_id = match crate::db::tasks::create(&self.pool, "heartbeat:quotas", None).await {
            Ok(id) => id,
            Err(e) => {
                error!("heartbeat:quotas — failed to create task record: {e}");
                return;
            }
        };

        let _ = crate::db::tasks::update_status(
            &self.pool,
            task_id,
            crate::models::task::TaskStatus::Running,
        )
        .await;

        let warnings = janitor::get_quota_warnings(&self.pool, DEFAULT_WARNING_THRESHOLD_PCT).await;
        let count = warnings.len();
        for w in &warnings {
            let description = format!(
                "User '{}' is using {:.1}% of their disk quota ({} MB used / {} MB limit)",
                w.username, w.pct_used, w.disk_used_mb, w.disk_limit_mb
            );
            warn!("heartbeat:quotas — {description}");
            if let Err(e) = crate::db::audit::log_action(
                &self.pool,
                w.user_id,
                "quota_warning".to_string(),
                Some("user".to_string()),
                Some(w.user_id),
                Some(w.username.clone()),
                Some(description),
                "warning".to_string(),
                None,
                None,
                None,
            )
            .await
            {
                error!(
                    "heartbeat:quotas — audit write failed for user {}: {e}",
                    w.user_id
                );
            }
        }

        let summary = format!("{count} quota warning(s) found.");
        let _ = crate::db::tasks::append_log(&self.pool, task_id, &summary).await;
        info!("heartbeat:quotas — {summary}");
        let _ = crate::db::tasks::update_status(
            &self.pool,
            task_id,
            crate::models::task::TaskStatus::Completed,
        )
        .await;
    }

    /// Maintenance beat: refresh disk usage, rotate logs, remove orphaned tmp files.
    async fn beat_maintenance(&mut self) {
        let task_id =
            match crate::db::tasks::create(&self.pool, "heartbeat:maintenance", None).await {
                Ok(id) => id,
                Err(e) => {
                    error!("heartbeat:maintenance — failed to create task record: {e}");
                    return;
                }
            };

        let _ = crate::db::tasks::update_status(
            &self.pool,
            task_id,
            crate::models::task::TaskStatus::Running,
        )
        .await;

        // 1. Refresh disk usage for all active clients.
        {
            let updated = janitor::refresh_all_disk_usage(&self.pool).await;
            let line = format!("Disk usage refreshed for {updated} user(s).");
            info!("heartbeat:maintenance — {line}");
            let _ = crate::db::tasks::append_log(&self.pool, task_id, &line).await;
        }

        // 2. Rotate oversized OLS error logs.
        {
            let rotated = janitor::cleanup_large_error_logs(DEFAULT_LOG_ROTATE_MB).await;
            let line = format!("Log rotation: {} log file(s) truncated.", rotated.len());
            info!("heartbeat:maintenance — {line}");
            let _ = crate::db::tasks::append_log(&self.pool, task_id, &line).await;
        }

        // 3. Remove orphaned panel /tmp files.
        {
            let removed = janitor::cleanup_orphaned_tmp(DEFAULT_TMP_MAX_AGE_HOURS).await;
            let line = format!("Tmp cleanup: {removed} orphaned file(s) removed.");
            info!("heartbeat:maintenance — {line}");
            let _ = crate::db::tasks::append_log(&self.pool, task_id, &line).await;
        }

        let _ = crate::db::tasks::update_status(
            &self.pool,
            task_id,
            crate::models::task::TaskStatus::Completed,
        )
        .await;
    }
}

// ── ServiceType display helper (mirrors models::service::ServiceType::Display) ──
// `ServiceType` already derives Display in models/service.rs so `to_string()` works.
// No additional code needed here.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_are_reasonable() {
        assert!(PULSE_INTERVAL_SECS >= 10, "pulse too frequent");
        assert!(
            QUOTA_INTERVAL_SECS >= PULSE_INTERVAL_SECS,
            "quota should be >= pulse"
        );
        assert!(
            MAINTENANCE_INTERVAL_SECS >= QUOTA_INTERVAL_SECS,
            "maintenance should be >= quota"
        );
    }
}
