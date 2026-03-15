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

    // Validate username: alphanumeric + underscore, 3-32 chars
    let username_re = regex::Regex::new(r"^[a-zA-Z0-9_]{3,32}$")
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    if !username_re.is_match(&username) {
        return Err(ServerFnError::new(
            "FTP username must be 3-32 alphanumeric characters or underscores",
        ));
    }

    // FTP credentials are exposed over a network protocol, so apply the same
    // strength policy as panel account passwords (12+ chars, mixed case, digit, special).
    crate::utils::validators::validate_password(&password).map_err(ServerFnError::new)?;

    // Validate home_dir at the server layer before any DB write to prevent
    // malformed paths being stored (service layer will reject them too, but
    // an early rejection avoids orphan DB records).
    crate::utils::validators::validate_safe_path(&home_dir, "/home/")
        .map_err(ServerFnError::new)?;

    let quota_mb = quota_size_mb.unwrap_or(1024).max(1);

    // Determine system uid/gid from the owning user
    let owner = crate::db::users::get(pool, claims.sub)
        .await
        .map_err(|_| ServerFnError::new("Owner account not found"))?;

    let uid = owner.system_uid.unwrap_or(33333) as u32;
    let gid = owner.system_gid.unwrap_or(33333) as u32;

    // Hash the password with Argon2id
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

    // Insert into panel DB first to get the ID
    let account_id = crate::db::ftp::create(
        pool,
        claims.sub,
        site_id,
        username.clone(),
        password_hash,
        home_dir.clone(),
        quota_mb,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

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

    // Update Pure-FTPd
    let ftpd = crate::services::pureftpd::PureFtpdService;
    ftpd.update_password(&account.username, &new_password)
        .await
        .map_err(|e| ServerFnError::new(format!("Pure-FTPd update failed: {}", e)))?;

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

    let account = crate::db::ftp::get(pool, account_id)
        .await
        .map_err(|_| ServerFnError::new("FTP account not found"))?;

    crate::auth::guards::check_ownership(&claims, account.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Remove from Pure-FTPd first
    let ftpd = crate::services::pureftpd::PureFtpdService;
    ftpd.delete_user(&account.username)
        .await
        .map_err(|e| ServerFnError::new(format!("Pure-FTPd removal failed: {}", e)))?;

    // Remove from panel DB
    crate::db::ftp::delete(pool, account_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

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
                let _ = crate::db::ftp::insert_session_stat(
                    pool,
                    Some(acct.id),
                    &entry.username,
                    entry.remote_host.as_deref(),
                    &entry.direction,
                    &entry.filename,
                    entry.bytes_transferred,
                    entry.transfer_time_secs,
                )
                .await;
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
