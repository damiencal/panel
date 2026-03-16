/// SSL/TLS certificate management server functions.
///
/// Covers two features:
///   1. SSL for the panel's own hostname — issues a cert and configures the
///      OpenLiteSpeed SSL listener so the control panel itself is served over
///      HTTPS on port 8443.
///   2. SSL for the mail server — issues a cert for the mail hostname and
///      updates Postfix (main.cf) and Dovecot (10-ssl.conf) to use it, so
///      email clients no longer see self-signed certificate warnings.
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Summary of the current SSL state for both panel and mail services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslStatus {
    /// Whether a valid Let's Encrypt cert exists for the panel hostname.
    pub panel_ssl_active: bool,
    /// Hostname the panel cert is issued for (empty if none).
    pub panel_hostname: String,
    /// Path to the panel's fullchain.pem (empty if none).
    pub panel_cert_path: String,
    /// Whether a valid Let's Encrypt cert exists for the mail hostname.
    pub mail_ssl_active: bool,
    /// Hostname the mail cert is issued for (empty if none).
    pub mail_hostname: String,
    /// Path to the mail fullchain.pem (empty if none).
    pub mail_cert_path: String,
}

/// Retrieve the current SSL status for the panel and mail server.
#[server]
pub async fn server_get_ssl_status() -> Result<SslStatus, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let config = crate::utils::config::PanelConfig::load(Some("panel.toml"))
        .await
        .unwrap_or_default();

    let panel_hostname = config.server.host.clone();
    let mail_hostname = config.postfix.hostname.clone();

    let certbot = crate::services::certbot::CertbotService::default();

    let _panel_cert_path = format!("/etc/letsencrypt/live/{}/fullchain.pem", panel_hostname);
    let _mail_cert_path = format!("/etc/letsencrypt/live/{}/fullchain.pem", mail_hostname);

    let panel_ssl_active = certbot.has_certificate(&panel_hostname).await;
    let mail_ssl_active = certbot.has_certificate(&mail_hostname).await;

    Ok(SslStatus {
        panel_ssl_active,
        panel_hostname,
        // Return the well-known relative cert name rather than the internal
        // filesystem path — the absolute path is not needed by the UI and
        // should not be exposed to clients (information disclosure).
        panel_cert_path: if panel_ssl_active {
            "fullchain.pem".to_string()
        } else {
            String::new()
        },
        mail_ssl_active,
        mail_hostname,
        mail_cert_path: if mail_ssl_active {
            "fullchain.pem".to_string()
        } else {
            String::new()
        },
    })
}

/// Issue a Let's Encrypt certificate for the panel hostname and configure the
/// OpenLiteSpeed SSL listener so the panel is reachable over HTTPS on port 8443.
///
/// `hostname` — fully-qualified domain name pointing to this server.
/// `email`    — contact address for expiry notifications from Let's Encrypt.
///
/// Admin only. Uses the certbot webroot method against the OLS document root.
#[server]
pub async fn server_issue_panel_ssl(hostname: String, email: String) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Input validation — domain and email must be well-formed.
    crate::utils::validators::validate_domain(&hostname).map_err(ServerFnError::new)?;
    crate::utils::validators::validate_email(&email).map_err(ServerFnError::new)?;

    let certbot = crate::services::certbot::CertbotService::default();

    // Issue certificate via webroot.
    let cert_info = certbot
        .issue_certificate(&hostname, &email, None)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Configure OLS panel-level SSL proxy listener.
    let ols = crate::services::openlitespeed::OpenLiteSpeedService;
    let config = crate::utils::config::PanelConfig::load(Some("panel.toml"))
        .await
        .unwrap_or_default();
    let panel_port = config.server.port;

    ols.configure_panel_ssl(
        &hostname,
        &cert_info.cert_path,
        &cert_info.key_path,
        panel_port,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Graceful-restart OLS to activate the new listener.
    crate::services::shell::exec("/usr/local/lsws/bin/lswsctrl", &["restart"])
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "issue_panel_ssl",
        Some("ssl"),
        None,
        Some(&hostname),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Issue a Let's Encrypt certificate for the mail hostname and update Postfix
/// and Dovecot to use it, replacing the default self-signed snakeoil cert.
///
/// `hostname` — the mail server FQDN (e.g. `mail.example.com`).
/// `email`    — contact address for expiry notifications from Let's Encrypt.
///
/// Admin only.
#[server]
pub async fn server_issue_mail_ssl(hostname: String, email: String) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    crate::utils::validators::validate_domain(&hostname).map_err(ServerFnError::new)?;
    crate::utils::validators::validate_email(&email).map_err(ServerFnError::new)?;

    let certbot = crate::services::certbot::CertbotService::default();

    let cert_info = certbot
        .issue_certificate(&hostname, &email, None)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Update Postfix main.cf TLS cert/key references.
    let postfix = crate::services::postfix::PostfixService;
    postfix
        .update_tls_cert(&cert_info.cert_path, &cert_info.key_path)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Update Dovecot 10-ssl.conf cert/key references.
    let dovecot = crate::services::dovecot::DovecotService;
    dovecot
        .update_ssl_cert(&cert_info.cert_path, &cert_info.key_path)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "issue_mail_ssl",
        Some("ssl"),
        None,
        Some(&hostname),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Repair the mail server TLS configuration without re-issuing a certificate.
///
/// Useful when the Postfix / Dovecot config has drifted (e.g. after a manual
/// edit) and the services no longer reference the correct certificate paths.
/// If no Let's Encrypt certificate exists for `hostname` the function returns
/// an actionable error telling the user to run `server_issue_mail_ssl` first.
///
/// Admin only.
#[server]
pub async fn server_fix_mail_ssl(hostname: String) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    crate::utils::validators::validate_domain(&hostname).map_err(ServerFnError::new)?;

    let certbot = crate::services::certbot::CertbotService::default();

    if !certbot.has_certificate(&hostname).await {
        return Err(ServerFnError::new(format!(
            "No Let's Encrypt certificate found for '{}'. \
             Please issue one first with 'Issue Mail SSL'.",
            hostname
        )));
    }

    let cert_path = format!("/etc/letsencrypt/live/{}/fullchain.pem", hostname);
    let key_path = format!("/etc/letsencrypt/live/{}/privkey.pem", hostname);

    // Re-link certificate in Postfix.
    let postfix = crate::services::postfix::PostfixService;
    postfix
        .update_tls_cert(&cert_path, &key_path)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Re-link certificate in Dovecot.
    let dovecot = crate::services::dovecot::DovecotService;
    dovecot
        .update_ssl_cert(&cert_path, &key_path)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Reload both services.
    crate::services::shell::exec("systemctl", &["reload", "postfix"])
        .await
        .ok();
    crate::services::shell::exec("systemctl", &["reload", "dovecot"])
        .await
        .ok();

    audit_log(
        claims.sub,
        "fix_mail_ssl",
        Some("ssl"),
        None,
        Some(&hostname),
        "Success",
        None,
    )
    .await;

    Ok(())
}
