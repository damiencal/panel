/// Site management server functions.
use crate::models::site::{Site, SiteStatus, SiteType};
use dioxus::prelude::*;

/// List sites visible to the caller.
#[server]
pub async fn server_list_sites() -> Result<Vec<Site>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let sites = match claims.role {
        crate::models::user::Role::Admin => crate::db::sites::list_all(pool).await,
        crate::models::user::Role::Reseller => {
            crate::db::sites::list_for_reseller(pool, claims.sub).await
        }
        crate::models::user::Role::Client => {
            crate::db::sites::list_for_owner(pool, claims.sub).await
        }
    };

    sites.map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a new site.
#[server]
pub async fn server_create_site(domain: String, site_type: SiteType) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::utils::validators::validate_domain(&domain).map_err(ServerFnError::new)?;

    let doc_root = format!("/home/{}/sites/{}", claims.username, domain);

    let site_id = crate::db::sites::create(pool, claims.sub, domain.clone(), doc_root, site_type)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Update usage counter
    let _ = crate::db::quotas::increment_sites(pool, claims.sub, 1).await;

    audit_log(
        claims.sub,
        "create_site",
        Some("site"),
        Some(site_id),
        Some(&domain),
        "Success",
        None,
    )
    .await;

    Ok(site_id)
}

/// Update site status.
#[server]
pub async fn server_update_site_status(
    site_id: i64,
    status: SiteStatus,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::sites::update_status(pool, site_id, status)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "update_site_status",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Delete a site.
#[server]
pub async fn server_delete_site(site_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::sites::delete(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let _ = crate::db::quotas::increment_sites(pool, claims.sub, -1).await;

    audit_log(
        claims.sub,
        "delete_site",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Update SSL and HSTS settings for a site.
#[server]
pub async fn server_update_site_ssl(
    site_id: i64,
    ssl_enabled: bool,
    force_https: bool,
    hsts_enabled: bool,
    hsts_max_age: i64,
    hsts_include_subdomains: bool,
    hsts_preload: bool,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Validate HSTS max-age: must be positive; preload requires >= 1 year.
    if hsts_max_age <= 0 {
        return Err(ServerFnError::new(
            "HSTS max-age must be a positive number of seconds",
        ));
    }

    crate::db::sites::update_ssl(
        pool,
        site_id,
        ssl_enabled,
        force_https,
        hsts_enabled,
        hsts_max_age,
        hsts_include_subdomains,
        hsts_preload,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Regenerate the OLS vhost config to apply HTTPS redirect and HSTS header.
    #[cfg(feature = "server")]
    {
        let ols = crate::services::openlitespeed::OpenLiteSpeedService;
        let _ = ols
            .update_vhost_config(
                &site.domain,
                &site.doc_root,
                site.site_type == crate::models::site::SiteType::Php,
                force_https,
                hsts_enabled && ssl_enabled && force_https,
                hsts_max_age,
                hsts_include_subdomains,
                hsts_preload && hsts_include_subdomains && hsts_max_age >= 31536000,
            )
            .await;
    }

    audit_log(
        claims.sub,
        "update_site_ssl",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Update site type.
#[server]
pub async fn server_update_site_type(
    site_id: i64,
    site_type: SiteType,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::sites::update_site_type(pool, site_id, site_type)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "update_site_type",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Return the last 500 lines of the access or error log for a domain.
/// `log_type` must be exactly "access" or "error".
#[server]
pub async fn server_get_site_logs(site_id: i64, log_type: String) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // Reject any value other than the two allowed log types (prevents path traversal).
    if log_type != "access" && log_type != "error" {
        return Err(ServerFnError::new("Invalid log type"));
    }

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // The domain comes from the database, but we sanitise it anyway to ensure
    // the resulting path stays strictly inside the OLS log directory.
    let safe_domain: String = site
        .domain
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();

    let log_path = format!("/usr/local/lsws/logs/{safe_domain}.{log_type}.log");

    // Belt-and-suspenders path traversal check.
    if !log_path.starts_with("/usr/local/lsws/logs/") {
        return Err(ServerFnError::new("Invalid log path"));
    }

    let content = match tokio::fs::read_to_string(&log_path).await {
        Ok(s) => s,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(format!(
                "Log file not found: {log_path}\n\
                 The file is created once the site receives traffic."
            ));
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ok(format!(
                "Cannot read log file: insufficient permissions.\n\
                 Path: {log_path}\n\
                 Try running the panel process as a user with read access to the OLS log directory."
            ));
        }
        Err(e) => return Err(ServerFnError::new(e.to_string())),
    };

    // Return the last 500 lines to keep the payload small.
    let lines: Vec<&str> = content.lines().collect();
    let tail = if lines.len() > 500 {
        lines[lines.len() - 500..].join("\n")
    } else {
        content.trim_end().to_string()
    };

    Ok(if tail.is_empty() {
        "Log file is empty.".to_string()
    } else {
        tail
    })
}
