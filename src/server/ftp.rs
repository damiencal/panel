/// FTP account management server functions.
use crate::models::ftp::{FtpAccount, FtpUsageStats};
use dioxus::prelude::*;

/// List FTP accounts visible to the current user.
#[server]
pub async fn server_list_ftp_accounts(
    site_id: Option<i64>,
) -> Result<Vec<FtpAccount>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let accounts = if let Some(sid) = site_id {
        // Verify the caller owns (or administers) this site before listing its accounts.
        let site = crate::db::sites::get(pool, sid)
            .await
            .map_err(|_| ServerFnError::new("Site not found"))?;
        crate::auth::guards::check_ownership(&claims, site.owner_id, None)
            .map_err(|_| ServerFnError::new("Access denied"))?;
        crate::db::ftp::list_for_site(pool, sid).await
    } else {
        crate::db::ftp::list_for_owner(pool, claims.sub).await
    };

    accounts.map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a new FTP account.
/// Provisions the virtual user in Pure-FTPd and records it in the panel database.
#[server]
pub async fn server_create_ftp_account(
    username: String,
    password: String,
    home_dir: String,
    site_id: Option<i64>,
    quota_size_mb: Option<i64>,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Validate username: alphanumeric + underscore + dot, 3-64 chars.
    // Following the opencli convention, FTP usernames MUST end with
    // ".<owner_username>" (e.g. "media.alice" for user "alice").  This
    // namespacing prevents account-name collisions between tenants that would
    // otherwise result in one user being able to overwrite another's Pure-FTPd
    // passwd entry.
    let expected_suffix = format!(".{}", claims.username);
    if !username.ends_with(&expected_suffix) {
        return Err(ServerFnError::new(format!(
            "FTP username must end with '.{}' (e.g. 'media.{}')",
            claims.username, claims.username
        )));
    }
    // Validate the prefix part (everything before the dot+owner suffix).
    let prefix = &username[..username.len() - expected_suffix.len()];
    if prefix.is_empty() || prefix.len() > 32 {
        return Err(ServerFnError::new(
            "FTP username prefix must be 1-32 characters",
        ));
    }
    let username_re =
        regex::Regex::new(r"^[a-zA-Z0-9_]+$").map_err(|e| ServerFnError::new(e.to_string()))?;
    if !username_re.is_match(prefix) {
        return Err(ServerFnError::new(
            "FTP username prefix must contain only alphanumeric characters or underscores",
        ));
    }
    // Full username length guard: prefix + "." + owner_username ≤ 64 chars.
    if username.len() > 64 {
        return Err(ServerFnError::new(
            "FTP username too long (max 64 characters)",
        ));
    }

    // FTP credentials are exposed over a network protocol, so apply the same
    // strength policy as panel account passwords (12+ chars, mixed case, digit, special).
    crate::utils::validators::validate_password(&password).map_err(ServerFnError::new)?;

    // Validate home_dir at the server layer before any DB write to prevent
    // malformed paths being stored (service layer will reject them too, but
    // an early rejection avoids orphan DB records).
    // Restrict to the caller's own home subtree to prevent IDOR via FTP chroot
    // (FTP-02): user A must not be able to chroot into user B's directory.
    let caller_home = format!("/home/{}/", claims.username);
    crate::utils::validators::validate_safe_path(&home_dir, &caller_home)
        .map_err(ServerFnError::new)?;

    // Cap quota: minimum 1 MB, hard ceiling of 102_400 MB (100 GiB) to prevent
    // users from self-granting effectively unlimited disk outside their plan limits.
    let quota_mb = quota_size_mb.unwrap_or(1024).clamp(1, 102_400);

    // FIND-27-01: verify the caller owns the site before associating the FTP
    // account with it — prevents IDOR injection into another user's FTP listing.
    if let Some(sid) = site_id {
        let site = crate::db::sites::get(pool, sid)
            .await
            .map_err(|_| ServerFnError::new("Site not found"))?;
        crate::auth::guards::check_ownership(&claims, site.owner_id, None)
            .map_err(|_| ServerFnError::new("Access denied"))?;
    }

    // Determine system uid/gid from the owning user
    let owner = crate::db::users::get(pool, claims.sub)
        .await
        .map_err(|_| ServerFnError::new("Owner account not found"))?;

    let uid = owner.system_uid.unwrap_or(33333) as u32;
    let gid = owner.system_gid.unwrap_or(33333) as u32;

    // Hash the password with Argon2id before acquiring the DB lock to avoid
    // holding the write lock during CPU-intensive work.
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ServerFnError::new(format!("Password hashing failed: {}", e)))?
        .to_string();

    // QUOTA-FTP-01: enforce a hard per-user FTP account limit using a
    // BEGIN IMMEDIATE transaction so the COUNT and INSERT are serialised.
    // A DEFERRED transaction would allow two concurrent requests to both read
    // count=99 and both succeed, bypassing the cap (TOCTOU).
    const MAX_FTP_ACCOUNTS_PER_USER: i64 = 100;
    let account_id = {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| ServerFnError::new(format!("DB acquire failed: {}", e)))?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to begin transaction: {}", e)))?;

        let count_result: Result<i64, _> =
            sqlx::query_scalar("SELECT COUNT(*) FROM ftp_accounts WHERE owner_id = ?")
                .bind(claims.sub)
                .fetch_one(&mut *conn)
                .await;
        let ftp_count = match count_result {
            Ok(c) => c,
            Err(e) => {
                if let Err(rb) = sqlx::query("ROLLBACK").execute(&mut *conn).await {
                    tracing::warn!(
                        "Failed to rollback FTP quota transaction after count error: {rb}"
                    );
                }
                return Err(ServerFnError::new(format!(
                    "Failed to check FTP quota: {}",
                    e
                )));
            }
        };
        if ftp_count >= MAX_FTP_ACCOUNTS_PER_USER {
            if let Err(rb) = sqlx::query("ROLLBACK").execute(&mut *conn).await {
                tracing::warn!("Failed to rollback FTP quota transaction after limit check: {rb}");
            }
            return Err(ServerFnError::new(format!(
                "FTP account limit reached ({} accounts). Please contact support to increase your limit.",
                MAX_FTP_ACCOUNTS_PER_USER
            )));
        }

        let now = chrono::Utc::now();
        let insert_result = sqlx::query(
            "INSERT INTO ftp_accounts
                (owner_id, site_id, username, password_hash, home_dir, quota_size_mb, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 'Active', ?, ?)",
        )
        .bind(claims.sub)
        .bind(site_id)
        .bind(&username)
        .bind(&password_hash)
        .bind(&home_dir)
        .bind(quota_mb)
        .bind(now)
        .bind(now)
        .execute(&mut *conn)
        .await;

        match insert_result {
            Ok(r) => {
                let id = r.last_insert_rowid();
                if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
                    return Err(ServerFnError::new(format!("Failed to commit: {}", e)));
                }
                id
            }
            Err(e) => {
                if let Err(rb) = sqlx::query("ROLLBACK").execute(&mut *conn).await {
                    tracing::warn!("Failed to rollback FTP insert transaction: {rb}");
                }
                return Err(ServerFnError::new(e.to_string()));
            }
        }
    };

    // Provision in Pure-FTPd; roll back the DB record on failure so we don't
    // leave an orphan row with a potentially-malformed home_dir.
    let ftpd = crate::services::pureftpd::PureFtpdService;
    if let Err(e) = ftpd
        .create_user(&username, &password, &home_dir, uid, gid)
        .await
    {
        let _ = crate::db::ftp::delete(pool, account_id).await;
        audit_log(
            claims.sub,
            "create_ftp_account",
            Some("ftp_account"),
            Some(account_id),
            Some(&username),
            "PartialSuccess",
            Some(&e.to_string()),
        )
        .await;
        return Err(ServerFnError::new(format!(
            "Pure-FTPd provisioning failed: {}",
            e
        )));
    }

    audit_log(
        claims.sub,
        "create_ftp_account",
        Some("ftp_account"),
        Some(account_id),
        Some(&username),
        "Success",
        None,
    )
    .await;

    Ok(account_id)
}

/// Change the password for an FTP account.
#[server]
pub async fn server_change_ftp_password(
    account_id: i64,
    new_password: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Apply the same strength policy as panel account passwords.
    crate::utils::validators::validate_password(&new_password).map_err(ServerFnError::new)?;

    let account = crate::db::ftp::get(pool, account_id)
        .await
        .map_err(|_| ServerFnError::new("FTP account not found"))?;

    crate::auth::guards::check_ownership(&claims, account.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Hash new password
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|e| ServerFnError::new(format!("Password hashing failed: {}", e)))?
        .to_string();

    // Update panel DB
    crate::db::ftp::update_password(pool, account_id, password_hash)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Update Pure-FTPd. If this fails, roll back the DB to the old hash so
    // the panel DB and Pure-FTPd do not diverge (users would be unable to log
    // in via FTP while the panel shows a successful change).
    let ftpd = crate::services::pureftpd::PureFtpdService;
    if let Err(e) = ftpd.update_password(&account.username, &new_password).await {
        // Best-effort rollback; if the rollback itself fails, log the incident
        // so an operator can reconcile manually.
        if let Err(rb_err) =
            crate::db::ftp::update_password(pool, account_id, account.password_hash.clone()).await
        {
            tracing::error!(
                account_id = account_id,
                rollback_err = %rb_err,
                "FTP password DB rollback failed after Pure-FTPd update error; manual reconciliation required"
            );
        }
        return Err(ServerFnError::new(format!(
            "Pure-FTPd update failed: {}",
            e
        )));
    }

    audit_log(
        claims.sub,
        "change_ftp_password",
        Some("ftp_account"),
        Some(account_id),
        Some(&account.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Delete an FTP account.
#[server]
pub async fn server_delete_ftp_account(account_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let account = crate::db::ftp::get(pool, account_id)
        .await
        .map_err(|_| ServerFnError::new("FTP account not found"))?;

    crate::auth::guards::check_ownership(&claims, account.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Delete DB record first. If this fails the operation aborts cleanly and
    // Pure-FTPd is untouched, so the account remains fully functional.
    crate::db::ftp::delete(pool, account_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Remove from Pure-FTPd. Best-effort: if this fails the passwd entry is a
    // harmless stale entry with no panel record pointing to it.
    let ftpd = crate::services::pureftpd::PureFtpdService;
    if let Err(e) = ftpd.delete_user(&account.username).await {
        tracing::warn!(
            account_id,
            username = %account.username,
            "Pure-FTPd removal failed after DB delete; stale passwd entry may remain: {e}"
        );
    }

    audit_log(
        claims.sub,
        "delete_ftp_account",
        Some("ftp_account"),
        Some(account_id),
        Some(&account.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Return aggregated FTP usage statistics for the authenticated user.
///
/// Also ingests any unprocessed lines from the Pure-FTPd transfer log so
/// stats stay current without a background job.
#[server]
pub async fn server_get_ftp_stats() -> Result<FtpUsageStats, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Parse the transfer log and persist new entries (best-effort).
    let ftpd = crate::services::pureftpd::PureFtpdService;
    if let Ok(entries) = ftpd.parse_transfer_log(500).await {
        for entry in &entries {
            // Only ingest records that belong to this user's accounts — do not
            // pollute stats tables with entries from other owners.
            if let Ok(acct) = crate::db::ftp::get_by_username(pool, &entry.username).await {
                if acct.owner_id != claims.sub {
                    continue;
                }
                if let Err(e) = crate::db::ftp::insert_session_stat(
                    pool,
                    Some(acct.id),
                    &entry.username,
                    entry.remote_host.as_deref(),
                    &entry.direction,
                    &entry.filename,
                    entry.bytes_transferred,
                    entry.transfer_time_secs,
                )
                .await
                {
                    tracing::warn!(
                        username = %entry.username,
                        "Failed to persist FTP session stat: {e}"
                    );
                }
            }
        }
    }

    // Gather aggregates.
    let total_accounts = crate::db::ftp::count_total(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let active_accounts = crate::db::ftp::count_active(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let per_account = crate::db::ftp::aggregate_per_account(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let recent_transfers = crate::db::ftp::list_recent_stats(pool, claims.sub, 20)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let total_uploads: i64 = per_account.iter().map(|a| a.total_uploads).sum();
    let total_downloads: i64 = per_account.iter().map(|a| a.total_downloads).sum();
    let bytes_uploaded: i64 = per_account.iter().map(|a| a.bytes_uploaded).sum();
    let bytes_downloaded: i64 = per_account.iter().map(|a| a.bytes_downloaded).sum();

    Ok(FtpUsageStats {
        total_accounts,
        active_accounts,
        total_uploads,
        total_downloads,
        bytes_uploaded,
        bytes_downloaded,
        per_account,
        recent_transfers,
    })
}
