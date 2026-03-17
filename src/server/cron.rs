/// Cron job management server functions.
///
/// Cron jobs are stored in the panel database and installed into the site
/// owner's system-user crontab.  The panel maintains a
/// `# BEGIN PANEL CRON JOBS` … `# END PANEL CRON JOBS` section inside the
/// crontab so that any entries the user added manually are preserved.
use crate::models::cron::CronJob;
use dioxus::prelude::*;

// ─── Validation helpers ──────────────────────────────────────────────────────

/// Validate a standard 5-field cron expression or @alias.
/// Rejects newlines and obviously malformed schedules that could corrupt the
/// crontab file.
#[cfg(feature = "server")]
fn validate_schedule(schedule: &str) -> Result<(), &'static str> {
    if schedule.contains('\n') || schedule.contains('\r') {
        return Err("Schedule must not contain newlines");
    }
    if schedule.len() > 100 {
        return Err("Schedule too long (max 100 characters)");
    }

    const ALIASES: &[&str] = &[
        "@yearly",
        "@annually",
        "@monthly",
        "@weekly",
        "@daily",
        "@midnight",
        "@hourly",
        "@reboot",
    ];
    if ALIASES.contains(&schedule.trim()) {
        return Ok(());
    }

    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(
            "Cron schedule must have exactly 5 fields (min hour dom month dow) or use a @alias",
        );
    }
    for field in &fields {
        let valid = !field.is_empty()
            && field
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '*' | ',' | '-' | '/'));
        if !valid {
            return Err(
                "Invalid cron field: use digits, *, ranges (n-m), steps (*/n), or lists (n,m)",
            );
        }
    }
    Ok(())
}

/// Validate a cron command.
/// Newlines are the only hard requirement since they would break the crontab
/// file format.  The command runs as the site's system user, which already
/// limits what it can do.
#[cfg(feature = "server")]
fn validate_command(command: &str) -> Result<(), &'static str> {
    if command.trim().is_empty() {
        return Err("Command cannot be empty");
    }
    if command.len() > 1024 {
        return Err("Command too long (max 1024 characters)");
    }
    if command.contains('\n') || command.contains('\r') {
        return Err("Command must not contain newlines");
    }
    // In crontab format '%' is treated as a newline; text after it is piped as stdin.
    // Reject it to prevent silent command alteration by the cron daemon.
    if command.contains('%') {
        return Err(
            "Command must not contain '%' (crontab treats it as a newline/stdin delimiter)",
        );
    }
    Ok(())
}

// ─── Crontab sync (server-only) ──────────────────────────────────────────────

/// Regenerate the panel-managed section of a user's crontab.
///
/// Existing entries outside the panel section are preserved.
/// Uses `crontab -u <username> <file>` via sudo to install the updated file.
#[cfg(feature = "server")]
async fn sync_user_crontab(
    pool: &sqlx::SqlitePool,
    owner_id: i64,
    username: &str,
) -> Result<(), String> {
    use tokio::process::Command;

    // Defense-in-depth: re-validate username at this layer even though callers
    // already do so, to guard against future refactors that bypass the caller checks.
    crate::utils::validators::validate_username(username)
        .map_err(|e| format!("Invalid username: {}", e))?;

    // 1. Read the existing crontab (exit 1 = no crontab yet; treat as empty).
    let existing = match Command::new("sudo")
        .args(["--non-interactive", "crontab", "-u", username, "-l"])
        .output()
        .await
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        _ => String::new(),
    };

    // 2. Strip previous panel section.
    let preserved = {
        let mut out = String::new();
        let mut in_section = false;
        for line in existing.lines() {
            if line.trim() == "# BEGIN PANEL CRON JOBS - DO NOT EDIT THIS SECTION" {
                in_section = true;
            } else if line.trim() == "# END PANEL CRON JOBS" {
                in_section = false;
            } else if !in_section {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    };

    // 3. Get enabled cron jobs for this user.
    let jobs = crate::db::cron::list_enabled_for_owner(pool, owner_id)
        .await
        .map_err(|e| e.to_string())?;

    // 4. Build new crontab content.
    let mut content = preserved.trim_end().to_string();
    if !jobs.is_empty() {
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str("\n# BEGIN PANEL CRON JOBS - DO NOT EDIT THIS SECTION\n");
        for job in &jobs {
            // CRON-NOREVALIDATE-01: re-validate stored values before writing to
            // the system crontab.  Skips any job that fails validation (e.g. was
            // inserted directly into the DB via a migration/backup restore).
            if validate_schedule(&job.schedule).is_err() || validate_command(&job.command).is_err()
            {
                tracing::error!(
                    "Cron job {} for owner {} failed re-validation; skipping crontab entry",
                    job.id,
                    owner_id
                );
                continue;
            }
            if !job.description.is_empty() {
                // Prevent comment injection via the description field.
                let safe_desc = job.description.replace('\n', " ").replace('\r', "");
                content.push_str(&format!("# Job {}: {}\n", job.id, safe_desc));
            }
            content.push_str(&format!("{} {}\n", job.schedule, job.command));
        }
        content.push_str("# END PANEL CRON JOBS\n");
    }

    // 5. Write to a randomly-named temp file.
    let temp_path = format!("/tmp/.panel_cron_{}", uuid::Uuid::new_v4());
    tokio::fs::write(&temp_path, content.as_bytes())
        .await
        .map_err(|e| format!("Failed to write temporary crontab file: {}", e))?;

    // 6. Install via `crontab -u username /tmp/file`.
    let result = Command::new("sudo")
        .args(["--non-interactive", "crontab", "-u", username, &temp_path])
        .output()
        .await;

    // 7. Always clean up the temp file.
    if let Err(e) = tokio::fs::remove_file(&temp_path).await {
        tracing::warn!("Failed to remove temporary crontab file {temp_path}: {e}");
    }

    match result {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(format!("crontab install failed: {}", stderr))
        }
        Err(e) => Err(format!("Failed to run crontab: {}", e)),
    }
}

// ─── Server functions ─────────────────────────────────────────────────────────

/// List cron jobs for a specific site.
#[server]
pub async fn server_list_cron_jobs(site_id: i64) -> Result<Vec<CronJob>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Verify site ownership before exposing cron jobs.
    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::cron::list_for_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a new cron job for the given site.
#[server]
pub async fn server_create_cron_job(
    site_id: i64,
    schedule: String,
    command: String,
    description: String,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    validate_schedule(&schedule).map_err(ServerFnError::new)?;
    validate_command(&command).map_err(ServerFnError::new)?;

    if description.len() > 255 {
        return Err(ServerFnError::new(
            "Description too long (max 255 characters)",
        ));
    }

    // Verify that this site belongs to the calling user.
    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Enforce a per-user cap to prevent resource exhaustion via massive crontabs.
    const MAX_CRON_JOBS_PER_USER: usize = 50;
    let existing = crate::db::cron::list_for_owner(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    if existing.len() >= MAX_CRON_JOBS_PER_USER {
        return Err(ServerFnError::new(format!(
            "Cron job limit reached ({MAX_CRON_JOBS_PER_USER} jobs per user)"
        )));
    }

    let job_id = crate::db::cron::create(pool, claims.sub, site_id, schedule, command, description)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Sync crontab (best-effort; log failure but don't roll back the DB record).
    if let Err(e) = sync_user_crontab(pool, claims.sub, &claims.username).await {
        tracing::warn!("Failed to sync crontab for {}: {}", claims.username, e);
    }

    audit_log(
        claims.sub,
        "create_cron_job",
        Some("cron_job"),
        Some(job_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(job_id)
}

/// Delete a cron job.
#[server]
pub async fn server_delete_cron_job(job_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let job = crate::db::cron::get(pool, job_id)
        .await
        .map_err(|_| ServerFnError::new("Cron job not found"))?;
    crate::auth::guards::check_ownership(&claims, job.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::cron::delete(pool, job_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // CRON-SYNC-01: sync the *job owner's* crontab, not the caller's.
    // When an Admin deletes a client's job, claims.sub != job.owner_id.
    let sync_user_id;
    let sync_username;
    if claims.sub == job.owner_id {
        sync_user_id = claims.sub;
        sync_username = claims.username.clone();
    } else {
        let owner = crate::db::users::get(pool, job.owner_id)
            .await
            .map_err(|_| ServerFnError::new("Job owner not found"))?;
        sync_user_id = owner.id;
        sync_username = owner.username.clone();
    }
    if let Err(e) = sync_user_crontab(pool, sync_user_id, &sync_username).await {
        tracing::warn!("Failed to sync crontab for {}: {}", sync_username, e);
    }

    audit_log(
        claims.sub,
        "delete_cron_job",
        Some("cron_job"),
        Some(job_id),
        None,
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Enable or disable a cron job.
#[server]
pub async fn server_toggle_cron_job(job_id: i64, enabled: bool) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let job = crate::db::cron::get(pool, job_id)
        .await
        .map_err(|_| ServerFnError::new("Cron job not found"))?;
    crate::auth::guards::check_ownership(&claims, job.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::cron::set_enabled(pool, job_id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // CRON-SYNC-01: sync the *job owner's* crontab, not the caller's.
    let sync_user_id;
    let sync_username;
    if claims.sub == job.owner_id {
        sync_user_id = claims.sub;
        sync_username = claims.username.clone();
    } else {
        let owner = crate::db::users::get(pool, job.owner_id)
            .await
            .map_err(|_| ServerFnError::new("Job owner not found"))?;
        sync_user_id = owner.id;
        sync_username = owner.username.clone();
    }
    if let Err(e) = sync_user_crontab(pool, sync_user_id, &sync_username).await {
        tracing::warn!("Failed to sync crontab for {}: {}", sync_username, e);
    }

    audit_log(
        claims.sub,
        if enabled {
            "enable_cron_job"
        } else {
            "disable_cron_job"
        },
        Some("cron_job"),
        Some(job_id),
        None,
        "Success",
        None,
    )
    .await;

    Ok(())
}
