//! Package management server functions.
#![allow(clippy::too_many_arguments)]
use crate::models::package::Package;
use crate::models::user::User;
use dioxus::prelude::*;

/// List packages visible to the caller.
#[server]
pub async fn server_list_packages() -> Result<Vec<Package>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let packages = match claims.role {
        crate::models::user::Role::Admin => crate::db::packages::list_all(pool).await,
        _ => crate::db::packages::list_by_creator(pool, claims.sub).await,
    };

    packages.map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a new package (admin or reseller).
#[server]
pub async fn server_create_package(
    name: String,
    description: Option<String>,
    max_sites: i32,
    max_databases: i32,
    max_email_accounts: i32,
    max_ftp_accounts: i32,
    disk_limit_mb: i64,
    bandwidth_limit_mb: i64,
    max_subdomains: i32,
    max_addon_domains: i32,
    php_enabled: bool,
    ssl_enabled: bool,
    shell_access: bool,
    backup_enabled: bool,
    #[allow(unused)]
    cpu_quota_percent: Option<i32>,
    #[allow(unused)]
    memory_max_mb: Option<i64>,
    #[allow(unused)]
    tasks_max: Option<i32>,
    #[allow(unused)]
    io_weight: Option<i32>,
    #[allow(unused)]
    max_db_connections: Option<i32>,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_reseller(&claims)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Input validation
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > 128 {
        return Err(ServerFnError::new(
            "Package name must be 1\u{2013}128 characters",
        ));
    }
    if description.as_deref().map(|d| d.len()).unwrap_or(0) > 1024 {
        return Err(ServerFnError::new(
            "Description too long (max 1024 characters)",
        ));
    }
    if max_sites < 0
        || max_databases < 0
        || max_email_accounts < 0
        || max_ftp_accounts < 0
        || max_subdomains < 0
        || max_addon_domains < 0
    {
        return Err(ServerFnError::new("Quota limits cannot be negative"));
    }
    if disk_limit_mb < 0 || bandwidth_limit_mb < 0 {
        return Err(ServerFnError::new(
            "Disk/bandwidth limits cannot be negative",
        ));
    }

    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Reject duplicate package name within the same creator's account.
    // opencli `plan-create` also rejects plans with a name that already exists
    // in the DB — enforce the same constraint here to prevent confusion when
    // multiple identically-named plans appear in client drop-downs.
    let existing = crate::db::packages::count_by_name_and_creator(pool, &name, claims.sub)
        .await
        .map_err(|e| {
            ServerFnError::new(format!("Failed to check for duplicate package name: {e}"))
        })?;
    if existing > 0 {
        return Err(ServerFnError::new(
            "A package with that name already exists; choose a different name",
        ));
    }

    // FIND-28-05: cap each quota field at a sane maximum to prevent a
    // reseller from creating packages that advertise more resources than
    // any plan could legitimately provide (business-logic bypass).
    const MAX_DISK_MB: i64 = 1_048_576; // 1 TiB
    const MAX_BW_MB: i64 = 10_485_760; // 10 TiB bandwidth
    const MAX_SITES: i32 = 10_000;
    const MAX_DBS: i32 = 10_000;
    const MAX_EMAILS: i32 = 100_000;
    const MAX_FTP: i32 = 10_000;
    const MAX_SUBDOMAINS: i32 = 10_000;
    const MAX_ADDON: i32 = 10_000;
    if disk_limit_mb > MAX_DISK_MB {
        return Err(ServerFnError::new("disk_limit_mb exceeds 1 TiB maximum"));
    }
    if bandwidth_limit_mb > MAX_BW_MB {
        return Err(ServerFnError::new(
            "bandwidth_limit_mb exceeds 10 TiB maximum",
        ));
    }
    if max_sites > MAX_SITES
        || max_databases > MAX_DBS
        || max_email_accounts > MAX_EMAILS
        || max_ftp_accounts > MAX_FTP
        || max_subdomains > MAX_SUBDOMAINS
        || max_addon_domains > MAX_ADDON
    {
        return Err(ServerFnError::new(
            "One or more quota fields exceeds the allowed maximum",
        ));
    }

    let pkg_id = crate::db::packages::create(
        pool,
        name.clone(),
        description,
        claims.sub,
        max_sites,
        max_databases,
        max_email_accounts,
        max_ftp_accounts,
        disk_limit_mb,
        bandwidth_limit_mb,
        max_subdomains,
        max_addon_domains,
        php_enabled,
        ssl_enabled,
        shell_access,
        backup_enabled,
        cpu_quota_percent.unwrap_or(50),
        memory_max_mb.unwrap_or(512),
        tasks_max.unwrap_or(40),
        io_weight.unwrap_or(50),
        max_db_connections.unwrap_or(5),
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "create_package",
        Some("package"),
        Some(pkg_id),
        Some(&name),
        "Success",
        None,
    )
    .await;

    Ok(pkg_id)
}

/// Deactivate a package.
#[server]
pub async fn server_deactivate_package(package_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_reseller(&claims)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // IDOR guard: verify the caller owns this package.
    let pkg = crate::db::packages::get(pool, package_id)
        .await
        .map_err(|_| ServerFnError::new("Package not found"))?;
    if pkg.created_by != claims.sub && claims.role != crate::models::user::Role::Admin {
        return Err(ServerFnError::new("Access denied"));
    }

    crate::db::packages::deactivate(pool, package_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "deactivate_package",
        Some("package"),
        Some(package_id),
        None,
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Delete a package permanently.
#[server]
pub async fn server_delete_package(package_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_reseller(&claims)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // IDOR guard: verify the caller owns this package.
    let pkg = crate::db::packages::get(pool, package_id)
        .await
        .map_err(|_| ServerFnError::new("Package not found"))?;
    if pkg.created_by != claims.sub && claims.role != crate::models::user::Role::Admin {
        return Err(ServerFnError::new("Access denied"));
    }

    // Block deletion if any users are still assigned to this package —
    // matching the behaviour of `opencli plan-delete` which lists the
    // affected accounts and aborts.  Admins must reassign or delete those
    // accounts first; otherwise the FK reference becomes dangling and the
    // affected users have no recorded limits.
    let assigned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE package_id = ? AND status != 'Deleted'",
    )
    .bind(package_id)
    .fetch_one(pool)
    .await
    .map_err(|e| ServerFnError::new(format!("Failed to count assigned users: {e}")))?;
    if assigned > 0 {
        return Err(ServerFnError::new(format!(
            "Cannot delete package: {assigned} user(s) are currently assigned to it. \
             Reassign or remove those accounts first."
        )));
    }

    crate::db::packages::delete(pool, package_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_package",
        Some("package"),
        Some(package_id),
        None,
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// List users currently assigned to a package.
/// Admins may query any package; Resellers may only query their own packages.
///
/// Mirrors `opencli plan-usage $plan_name` which lists all accounts on a plan.
#[server]
pub async fn server_list_users_on_package(package_id: i64) -> Result<Vec<User>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_reseller(&claims)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // IDOR guard: only admins may inspect packages they do not own.
    let pkg = crate::db::packages::get(pool, package_id)
        .await
        .map_err(|_| ServerFnError::new("Package not found"))?;
    if pkg.created_by != claims.sub && claims.role != crate::models::user::Role::Admin {
        return Err(ServerFnError::new("Access denied"));
    }

    let users = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE package_id = ? AND status != 'Deleted' ORDER BY username",
    )
    .bind(package_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "list_users_on_package",
        Some("package"),
        Some(package_id),
        None,
        "Success",
        None,
    )
    .await;

    Ok(users)
}
