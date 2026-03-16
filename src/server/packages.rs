//! Package management server functions.
#![allow(clippy::too_many_arguments)]
use crate::models::package::Package;
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
