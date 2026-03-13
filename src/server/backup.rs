/// Backup server functions — per-domain and per-mailbox scheduled backups.
use crate::models::backup::{
    BackupRun, BackupSchedule, BackupScheduleWithLatest, BackupStats, CreateBackupScheduleRequest,
};
use dioxus::prelude::*;

// ─── Validation ──────────────────────────────────────────────────────────────

#[cfg(feature = "server")]
fn validate_schedule_expr(s: &str) -> Result<(), &'static str> {
    if s.contains('\n') || s.contains('\r') {
        return Err("Schedule must not contain newlines");
    }
    if s.len() > 100 {
        return Err("Schedule expression too long");
    }
    const ALIASES: &[&str] = &[
        "@hourly",
        "@daily",
        "@midnight",
        "@weekly",
        "@monthly",
        "@yearly",
        "@annually",
    ];
    if ALIASES.contains(&s.trim()) {
        return Ok(());
    }
    let fields: Vec<&str> = s.split_whitespace().collect();
    if fields.len() != 5 {
        return Err("Cron schedule requires 5 fields or a @alias like @daily");
    }
    for field in &fields {
        let ok = field
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '*' | ',' | '-' | '/'));
        if !ok {
            return Err("Invalid cron expression field");
        }
    }
    Ok(())
}

#[cfg(feature = "server")]
fn validate_destination(dest: &str) -> Result<(), &'static str> {
    if dest.is_empty() {
        return Err("Destination must not be empty");
    }
    if dest.len() > 512 {
        return Err("Destination path too long");
    }
    // Prevent null bytes or newlines that could be used in injection
    if dest.contains('\0') || dest.contains('\n') || dest.contains('\r') {
        return Err("Destination contains invalid characters");
    }
    Ok(())
}

// ─── Schedule CRUD ────────────────────────────────────────────────────────────

/// List backup schedules (with their latest run) for the current user.
#[server]
pub async fn server_list_backup_schedules() -> Result<Vec<BackupScheduleWithLatest>, ServerFnError>
{
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::db::backup::list_schedules_with_latest(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a backup schedule for a domain (site_id set) or mailbox (mailbox_id set).
#[server]
pub async fn server_create_backup_schedule(
    req: CreateBackupScheduleRequest,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // Exactly one of site_id / mailbox_id must be set.
    match (req.site_id, req.mailbox_id) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(ServerFnError::new(
                "Specify exactly one of site_id or mailbox_id",
            ));
        }
        _ => {}
    }

    // Validate ownership of the referenced resource.
    if let Some(sid) = req.site_id {
        let site = crate::db::sites::get(pool, sid)
            .await
            .map_err(|_| ServerFnError::new("Site not found"))?;
        crate::auth::guards::check_ownership(&claims, site.owner_id, None)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }
    if let Some(mid) = req.mailbox_id {
        let mb: crate::models::email::Mailbox = sqlx::query_as::<_, crate::models::email::Mailbox>(
            "SELECT mb.* FROM mailboxes mb
                 JOIN email_domains ed ON ed.id = mb.domain_id
                 WHERE mb.id = ?",
        )
        .bind(mid)
        .fetch_one(pool)
        .await
        .map_err(|_| ServerFnError::new("Mailbox not found"))?;

        // domain ownership check
        let ed: crate::models::email::EmailDomain =
            sqlx::query_as::<_, crate::models::email::EmailDomain>(
                "SELECT * FROM email_domains WHERE id = ?",
            )
            .bind(mb.domain_id)
            .fetch_one(pool)
            .await
            .map_err(|_| ServerFnError::new("Email domain not found"))?;

        crate::auth::guards::check_ownership(&claims, ed.owner_id, None)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    validate_schedule_expr(&req.schedule).map_err(ServerFnError::new)?;
    validate_destination(&req.destination).map_err(ServerFnError::new)?;

    if req.name.trim().is_empty() || req.name.len() > 128 {
        return Err(ServerFnError::new("Name must be 1–128 characters"));
    }
    if req.retention_count < 0 || req.retention_count > 365 {
        return Err(ServerFnError::new("Retention count must be 0–365"));
    }

    let id = crate::db::backup::create_schedule(
        pool,
        claims.sub,
        req.site_id,
        req.mailbox_id,
        &req.name,
        &req.schedule,
        &req.storage_type,
        &req.destination,
        req.retention_count,
        req.compress,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "create_backup_schedule",
        Some("backup_schedule"),
        Some(id),
        Some(&req.name),
        "success",
        None,
    )
    .await;

    Ok(id)
}

/// Toggle a backup schedule on or off.
#[server]
pub async fn server_toggle_backup_schedule(
    schedule_id: i64,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let sched = crate::db::backup::get_schedule(pool, schedule_id)
        .await
        .map_err(|_| ServerFnError::new("Schedule not found"))?;
    crate::auth::guards::check_ownership(&claims, sched.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::backup::set_enabled(pool, schedule_id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        if enabled {
            "enable_backup_schedule"
        } else {
            "disable_backup_schedule"
        },
        Some("backup_schedule"),
        Some(schedule_id),
        Some(&sched.name),
        "success",
        None,
    )
    .await;

    Ok(())
}

/// Delete a backup schedule and all its run history.
#[server]
pub async fn server_delete_backup_schedule(schedule_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let sched = crate::db::backup::get_schedule(pool, schedule_id)
        .await
        .map_err(|_| ServerFnError::new("Schedule not found"))?;
    crate::auth::guards::check_ownership(&claims, sched.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::backup::delete_schedule(pool, schedule_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_backup_schedule",
        Some("backup_schedule"),
        Some(schedule_id),
        Some(&sched.name),
        "success",
        None,
    )
    .await;

    Ok(())
}

// ─── Run history ─────────────────────────────────────────────────────────────

/// Fetch the 50 most recent backup runs for a specific schedule.
#[server]
pub async fn server_list_backup_runs(schedule_id: i64) -> Result<Vec<BackupRun>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let sched = crate::db::backup::get_schedule(pool, schedule_id)
        .await
        .map_err(|_| ServerFnError::new("Schedule not found"))?;
    crate::auth::guards::check_ownership(&claims, sched.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::backup::list_runs(pool, schedule_id, 50)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Fetch the 100 most recent backup runs for the current user (all schedules).
#[server]
pub async fn server_list_recent_backup_runs() -> Result<Vec<BackupRun>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::db::backup::list_runs_for_owner(pool, claims.sub, 100)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ─── Stats ────────────────────────────────────────────────────────────────────

/// Aggregate backup stats for the current user.
#[server]
pub async fn server_get_backup_stats() -> Result<BackupStats, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::db::backup::get_stats_for_owner(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ─── Manual run ──────────────────────────────────────────────────────────────

/// Trigger an immediate backup for a schedule.
///
/// This executes the backup synchronously in the server function.  For large
/// sites consider running this in a background task; for the MVP the simple
/// synchronous approach is fine.
#[server]
pub async fn server_trigger_backup(schedule_id: i64) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let sched = crate::db::backup::get_schedule(pool, schedule_id)
        .await
        .map_err(|_| ServerFnError::new("Schedule not found"))?;
    crate::auth::guards::check_ownership(&claims, sched.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Record the run start.
    let run_id = crate::db::backup::start_run(pool, schedule_id, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Execute the actual backup.
    match execute_backup(&sched).await {
        Ok((size, path)) => {
            crate::db::backup::finish_run_success(pool, run_id, size, &path)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;

            // Update last_run on the schedule.
            let _ =
                crate::db::backup::update_run_times(pool, schedule_id, chrono::Utc::now(), None)
                    .await;

            // Prune old runs.
            let _ =
                crate::db::backup::prune_old_runs(pool, schedule_id, sched.retention_count).await;

            audit_log(
                claims.sub,
                "trigger_backup",
                Some("backup_run"),
                Some(run_id),
                Some(&sched.name),
                "success",
                None,
            )
            .await;

            Ok(run_id)
        }
        Err(e) => {
            let _ = crate::db::backup::finish_run_failed(pool, run_id, &e).await;
            audit_log(
                claims.sub,
                "trigger_backup",
                Some("backup_run"),
                Some(run_id),
                Some(&sched.name),
                "failed",
                Some(&e),
            )
            .await;
            Err(ServerFnError::new(e))
        }
    }
}

// ─── Admin functions ──────────────────────────────────────────────────────────

/// Admin: aggregate backup stats across all users.
#[server]
pub async fn server_admin_get_backup_stats() -> Result<BackupStats, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    if claims.role != crate::models::user::Role::Admin {
        return Err(ServerFnError::new("Forbidden"));
    }
    let pool = get_pool()?;

    crate::db::backup::get_global_stats(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Admin: 200 most recent backup runs across all users.
#[server]
pub async fn server_admin_list_backup_runs() -> Result<Vec<BackupRun>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    if claims.role != crate::models::user::Role::Admin {
        return Err(ServerFnError::new("Forbidden"));
    }
    let pool = get_pool()?;

    crate::db::backup::list_all_runs(pool, 200)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ─── Backup executor (server-only) ───────────────────────────────────────────

/// Actually run the backup and return (size_bytes, archive_path).
#[cfg(feature = "server")]
async fn execute_backup(sched: &BackupSchedule) -> Result<(i64, String), String> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let safe_name: String = sched
        .name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if sched.site_id.is_some() {
        backup_site(sched, &safe_name, &timestamp.to_string()).await
    } else {
        backup_mailbox(sched, &safe_name, &timestamp.to_string()).await
    }
}

/// Back up a site's document root (and optionally its databases).
#[cfg(feature = "server")]
async fn backup_site(
    sched: &BackupSchedule,
    safe_name: &str,
    timestamp: &str,
) -> Result<(i64, String), String> {
    use tokio::process::Command;

    // Resolve source path from the panel DB.
    let pool = crate::db::pool().map_err(|e| e.to_string())?;
    let site_id = sched.site_id.unwrap();

    let doc_root: String = sqlx::query_scalar("SELECT document_root FROM sites WHERE id = ?")
        .bind(site_id)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("Could not resolve document root: {e}"))?;

    if !tokio::fs::try_exists(&doc_root).await.unwrap_or(false) {
        return Err(format!("Document root does not exist: {doc_root}"));
    }

    // Sanitise and resolve destination directory.
    let dest_dir = shellexpand::tilde(&sched.destination).into_owned();
    tokio::fs::create_dir_all(&dest_dir)
        .await
        .map_err(|e| format!("Cannot create destination directory: {e}"))?;

    let archive_name = format!("{dest_dir}/site_{safe_name}_{timestamp}.tar");
    let archive_path = if sched.compress {
        format!("{archive_name}.gz")
    } else {
        archive_name.clone()
    };

    // Build the tar command.
    let compress_flag = if sched.compress { "-czf" } else { "-cf" };
    let status = Command::new("tar")
        .args([compress_flag, &archive_path, "-C", &doc_root, "."])
        .status()
        .await
        .map_err(|e| format!("tar failed to start: {e}"))?;

    if !status.success() {
        return Err(format!("tar exited with status: {}", status));
    }

    let meta = tokio::fs::metadata(&archive_path)
        .await
        .map_err(|e| format!("Cannot stat archive: {e}"))?;

    Ok((meta.len() as i64, archive_path))
}

/// Back up a mailbox's Maildir.
#[cfg(feature = "server")]
async fn backup_mailbox(
    sched: &BackupSchedule,
    safe_name: &str,
    timestamp: &str,
) -> Result<(i64, String), String> {
    use tokio::process::Command;

    let pool = crate::db::pool().map_err(|e| e.to_string())?;
    let mailbox_id = sched.mailbox_id.unwrap();

    // Resolve local_part + domain for the mailbox path.
    let row: (String, String) = sqlx::query_as(
        "SELECT mb.local_part, ed.domain
         FROM mailboxes mb
         JOIN email_domains ed ON ed.id = mb.domain_id
         WHERE mb.id = ?",
    )
    .bind(mailbox_id)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("Mailbox not found: {e}"))?;

    let (local_part, domain) = row;
    // Standard Dovecot maildir layout: /var/mail/vhosts/<domain>/<local_part>
    let maildir = format!("/var/mail/vhosts/{domain}/{local_part}");

    if !tokio::fs::try_exists(&maildir).await.unwrap_or(false) {
        // Gracefully handle empty accounts: create the run as success with 0 bytes.
        tracing::warn!("Maildir not found at {maildir}, recording empty backup");
        let dest_dir = shellexpand::tilde(&sched.destination).into_owned();
        tokio::fs::create_dir_all(&dest_dir)
            .await
            .map_err(|e| format!("Cannot create destination directory: {e}"))?;
        let archive_path = format!(
            "{dest_dir}/mail_{safe_name}_{timestamp}.tar{}",
            if sched.compress { ".gz" } else { "" }
        );
        tokio::fs::write(&archive_path, b"")
            .await
            .map_err(|e| format!("Cannot write placeholder: {e}"))?;
        return Ok((0, archive_path));
    }

    let dest_dir = shellexpand::tilde(&sched.destination).into_owned();
    tokio::fs::create_dir_all(&dest_dir)
        .await
        .map_err(|e| format!("Cannot create destination directory: {e}"))?;

    let archive_ext = if sched.compress { ".tar.gz" } else { ".tar" };
    let archive_path = format!("{dest_dir}/mail_{safe_name}_{timestamp}{archive_ext}");
    let compress_flag = if sched.compress { "-czf" } else { "-cf" };

    let status = Command::new("tar")
        .args([compress_flag, &archive_path, "-C", &maildir, "."])
        .status()
        .await
        .map_err(|e| format!("tar failed to start: {e}"))?;

    if !status.success() {
        return Err(format!("tar exited with status: {}", status));
    }

    let meta = tokio::fs::metadata(&archive_path)
        .await
        .map_err(|e| format!("Cannot stat archive: {e}"))?;

    Ok((meta.len() as i64, archive_path))
}

// Stub for WASM compilation (server functions are never called client-side).
#[cfg(target_arch = "wasm32")]
#[allow(dead_code)]
async fn execute_backup(_sched: &BackupSchedule) -> Result<(i64, String), String> {
    unreachable!()
}
