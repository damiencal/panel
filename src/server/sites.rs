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
        // Developers see only the sites they have been granted access to.
        crate::models::user::Role::Developer => {
            let site_ids = crate::db::team::get_developer_sites(pool, claims.sub)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
            let mut acc = Vec::new();
            for sid in site_ids {
                if let Ok(s) = crate::db::sites::get(pool, sid).await {
                    acc.push(s);
                }
            }
            return Ok(acc);
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

    // check_and_increment_sites performs the quota check and counter increment
    // atomically inside a single SQLite transaction, eliminating the TOCTOU race
    // that exists when check and increment are separate operations.
    crate::db::quotas::check_and_increment_sites(pool, claims.sub)
        .await
        .map_err(ServerFnError::new)?;

    let site_id = match crate::db::sites::create(pool, claims.sub, domain.clone(), doc_root, site_type)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            // Roll back the quota counter since site creation failed.
            let _ = crate::db::quotas::increment_sites(pool, claims.sub, -1).await;
            return Err(ServerFnError::new(e.to_string()));
        }
    };

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
                site.site_type,
                force_https,
                hsts_enabled && ssl_enabled && force_https,
                hsts_max_age,
                hsts_include_subdomains,
                hsts_preload && hsts_include_subdomains && hsts_max_age >= 31536000,
                site.php_version.as_deref(),
                site.ssl_certificate.as_deref(),
                site.ssl_private_key.as_deref(),
                site.basic_auth_enabled,
                &site.basic_auth_realm,
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

/// Return the list of PHP versions that are currently installed on the server.
/// Any authenticated user may call this (needed to populate the version picker).
#[server]
pub async fn server_list_php_versions() -> Result<Vec<String>, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let _claims = verify_auth()?;

    #[cfg(feature = "server")]
    {
        let ols = crate::services::openlitespeed::OpenLiteSpeedService;
        return ols
            .list_installed_php_versions()
            .await
            .map_err(|e| ServerFnError::new(e.to_string()));
    }
    #[cfg(not(feature = "server"))]
    Ok(Vec::new())
}

/// Install a PHP version from the official LiteSpeed repository.
/// Admin-only.  Only versions in `SUPPORTED_PHP_VERSIONS` are accepted.
#[server]
pub async fn server_install_php_version(version: String) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;

    if claims.role != crate::models::user::Role::Admin {
        return Err(ServerFnError::new("Unauthorized"));
    }

    // Server-layer defence: only accept known versions.
    if !crate::services::openlitespeed::SUPPORTED_PHP_VERSIONS.contains(&version.as_str()) {
        return Err(ServerFnError::new("Unsupported PHP version"));
    }

    #[cfg(feature = "server")]
    {
        let ols = crate::services::openlitespeed::OpenLiteSpeedService;
        ols.install_php_version(&version)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    audit_log(
        claims.sub,
        "install_php_version",
        Some("server"),
        None,
        Some(&version),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Update the PHP version for a specific site and regenerate its vhost config.
#[server]
pub async fn server_update_site_php_version(
    site_id: i64,
    php_version: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // Validate version is in the known-good list.
    if !crate::services::openlitespeed::SUPPORTED_PHP_VERSIONS.contains(&php_version.as_str()) {
        return Err(ServerFnError::new("Unsupported PHP version"));
    }

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::sites::update_php_version(pool, site_id, Some(&php_version))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Regenerate the vhost config so the new binary path is active immediately.
    #[cfg(feature = "server")]
    {
        let ols = crate::services::openlitespeed::OpenLiteSpeedService;
        let _ = ols
            .update_vhost_config(
                &site.domain,
                &site.doc_root,
                site.site_type,
                site.force_https,
                site.hsts_enabled && site.ssl_enabled && site.force_https,
                site.hsts_max_age,
                site.hsts_include_subdomains,
                site.hsts_preload && site.hsts_include_subdomains && site.hsts_max_age >= 31536000,
                Some(&php_version),
                site.ssl_certificate.as_deref(),
                site.ssl_private_key.as_deref(),
                site.basic_auth_enabled,
                &site.basic_auth_realm,
            )
            .await;
    }

    audit_log(
        claims.sub,
        "update_site_php_version",
        Some("site"),
        Some(site_id),
        Some(&format!("{} -> {php_version}", site.domain)),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ─── SSL Certificate Management ───────────────────────────────────────────────

/// Issue a Let's Encrypt certificate for a site via Certbot (webroot method).
/// Sets `ssl_enabled = true` and stores the cert/key paths after issuance.
#[server]
pub async fn server_issue_site_certificate(
    site_id: i64,
    email: String,
    include_www: bool,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::utils::validators::validate_email(&email).map_err(ServerFnError::new)?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Webroot must exist so Certbot can write the ACME challenge file.
    let webroot = format!("{}/public", site.doc_root);

    #[cfg(feature = "server")]
    {
        let certbot = crate::services::certbot::CertbotService::default();

        let cert_info = if include_www {
            certbot
                .issue_certificate_with_www(&site.domain, &email, Some(&webroot))
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?
        } else {
            certbot
                .issue_certificate(&site.domain, &email, Some(&webroot))
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?
        };

        // Persist cert paths and enable SSL in the DB.
        crate::db::sites::update_cert_info(
            pool,
            site_id,
            &cert_info.cert_path,
            &cert_info.key_path,
            &cert_info.issuer,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Also enable force_https for convenience (Let's Encrypt implies HTTPS).
        crate::db::sites::update_ssl(
            pool,
            site_id,
            true,
            site.force_https,
            site.hsts_enabled,
            site.hsts_max_age,
            site.hsts_include_subdomains,
            site.hsts_preload,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Regenerate the vhost config so the SSL block is written immediately.
        let ols = crate::services::openlitespeed::OpenLiteSpeedService;
        let _ = ols
            .update_vhost_config(
                &site.domain,
                &site.doc_root,
                site.site_type,
                site.force_https,
                site.hsts_enabled && site.force_https,
                site.hsts_max_age,
                site.hsts_include_subdomains,
                site.hsts_preload && site.hsts_include_subdomains && site.hsts_max_age >= 31536000,
                site.php_version.as_deref(),
                Some(&cert_info.cert_path),
                Some(&cert_info.key_path),
                site.basic_auth_enabled,
                &site.basic_auth_realm,
            )
            .await;
    }

    audit_log(
        claims.sub,
        "issue_site_certificate",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Upload a custom SSL certificate (PEM format) for a site.
/// Writes the cert/key files to disk and stores the paths in the DB.
#[server]
pub async fn server_set_custom_cert(
    site_id: i64,
    cert_pem: String,
    key_pem: String,
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

    #[cfg(feature = "server")]
    {
        // Write cert/key files to disk and get the resulting paths.
        let (cert_path, key_path) =
            crate::services::basic_auth::write_custom_cert(&site.domain, &cert_pem, &key_pem)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Optionally verify the cert/key pair match.
        let _ = crate::services::basic_auth::verify_cert_key_pair(&cert_path, &key_path).await;

        // Persist paths and enable SSL.
        crate::db::sites::update_cert_info(pool, site_id, &cert_path, &key_path, "Custom")
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Regenerate the vhost config.
        let ols = crate::services::openlitespeed::OpenLiteSpeedService;
        let _ = ols
            .update_vhost_config(
                &site.domain,
                &site.doc_root,
                site.site_type,
                site.force_https,
                site.hsts_enabled && site.ssl_enabled && site.force_https,
                site.hsts_max_age,
                site.hsts_include_subdomains,
                site.hsts_preload && site.hsts_include_subdomains && site.hsts_max_age >= 31536000,
                site.php_version.as_deref(),
                Some(&cert_path),
                Some(&key_path),
                site.basic_auth_enabled,
                &site.basic_auth_realm,
            )
            .await;
    }

    audit_log(
        claims.sub,
        "set_custom_cert",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ─── HTTP Basic Authentication ─────────────────────────────────────────────────

/// Enable or disable HTTP Basic Auth for a site and set the realm label.
/// When enabling, the caller must add at least one user via
/// `server_add_basic_auth_user` for the protection to take effect.
#[server]
pub async fn server_toggle_basic_auth(
    site_id: i64,
    enabled: bool,
    realm: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // Sanitise realm: max 64 chars, alphanumeric + spaces/hyphens/underscores.
    let safe_realm: String = realm
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'))
        .take(64)
        .collect();
    if safe_realm.is_empty() {
        return Err(ServerFnError::new("Realm must not be empty"));
    }

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::sites::update_basic_auth_settings(pool, site_id, enabled, &safe_realm)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    #[cfg(feature = "server")]
    {
        if !enabled {
            // Remove the htpasswd file when Basic Auth is disabled.
            let _ = crate::services::basic_auth::remove_htpasswd(&site.domain).await;
        } else {
            // Regenerate the htpasswd file from the DB users.
            let users = crate::db::basic_auth::list_users(pool, site_id)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
            let entries: Vec<(String, String)> = users
                .into_iter()
                .map(|u| (u.username, u.password_hash))
                .collect();
            let _ = crate::services::basic_auth::write_htpasswd(&site.domain, &entries).await;
        }

        // Regenerate the vhost config to add or remove the realm block.
        let ols = crate::services::openlitespeed::OpenLiteSpeedService;
        let _ = ols
            .update_vhost_config(
                &site.domain,
                &site.doc_root,
                site.site_type,
                site.force_https,
                site.hsts_enabled && site.ssl_enabled && site.force_https,
                site.hsts_max_age,
                site.hsts_include_subdomains,
                site.hsts_preload && site.hsts_include_subdomains && site.hsts_max_age >= 31536000,
                site.php_version.as_deref(),
                site.ssl_certificate.as_deref(),
                site.ssl_private_key.as_deref(),
                enabled,
                &safe_realm,
            )
            .await;
    }

    audit_log(
        claims.sub,
        if enabled {
            "enable_basic_auth"
        } else {
            "disable_basic_auth"
        },
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// List the Basic Auth users for a site.
#[server]
pub async fn server_list_basic_auth_users(
    site_id: i64,
) -> Result<Vec<crate::models::site::BasicAuthUser>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::basic_auth::list_users(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Add a Basic Auth user for a site.  The password is hashed server-side using
/// APR1-MD5 (compatible with Apache htpasswd and OpenLiteSpeed).
#[server]
pub async fn server_add_basic_auth_user(
    site_id: i64,
    username: String,
    password: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::utils::validators::validate_username(&username).map_err(ServerFnError::new)?;

    if password.len() < 8 {
        return Err(ServerFnError::new("Password must be at least 8 characters"));
    }

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Reject duplicate usernames.
    let exists = crate::db::basic_auth::user_exists(pool, site_id, &username)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    if exists {
        return Err(ServerFnError::new("Username already exists for this site"));
    }

    #[cfg(feature = "server")]
    {
        // Hash the password using APR1-MD5 via openssl (password never passed as CLI arg).
        let hash = crate::services::basic_auth::hash_password(&password)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Persist the user record.
        crate::db::basic_auth::add_user(pool, site_id, &username, &hash)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        // Regenerate the htpasswd file from all DB users.
        let users = crate::db::basic_auth::list_users(pool, site_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let entries: Vec<(String, String)> = users
            .into_iter()
            .map(|u| (u.username, u.password_hash))
            .collect();
        crate::services::basic_auth::write_htpasswd(&site.domain, &entries)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    #[cfg(not(feature = "server"))]
    {
        // On WASM, we won't reach this branch; the server function runs server-side.
        // Silencing "unused variable" warnings.
        let _ = (username, password, site, site_id);
    }

    audit_log(
        claims.sub,
        "add_basic_auth_user",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Remove a Basic Auth user from a site.
#[server]
pub async fn server_remove_basic_auth_user(
    site_id: i64,
    username: String,
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

    crate::db::basic_auth::remove_user(pool, site_id, &username)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    #[cfg(feature = "server")]
    {
        // Regenerate the htpasswd file (or remove it if no users remain).
        let users = crate::db::basic_auth::list_users(pool, site_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        if users.is_empty() {
            let _ = crate::services::basic_auth::remove_htpasswd(&site.domain).await;
        } else {
            let entries: Vec<(String, String)> = users
                .into_iter()
                .map(|u| (u.username, u.password_hash))
                .collect();
            let _ = crate::services::basic_auth::write_htpasswd(&site.domain, &entries).await;
        }
    }

    audit_log(
        claims.sub,
        "remove_basic_auth_user",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}
