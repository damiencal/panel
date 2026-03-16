/// Service management server functions.
/// Allows admins to start/stop/restart services and view overall status.
use crate::models::service::{ServiceAction, ServiceInfo};
#[cfg(feature = "server")]
use crate::models::service::{ServiceCommand, ServiceType};
use dioxus::prelude::*;

/// Get the status of all managed services (admin only).
#[server]
pub async fn server_get_services_status() -> Result<Vec<ServiceInfo>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let services = crate::services::system::get_all_services_status().await;
    Ok(services)
}

/// Execute a service action (start/stop/restart) — admin only.
#[server]
pub async fn server_manage_service(action: ServiceAction) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let result = match action.service {
        ServiceType::OpenLiteSpeed => {
            let svc = crate::services::openlitespeed::OpenLiteSpeedService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::MariaDB => {
            let svc = crate::services::mariadb::MariaDbService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::Postfix => {
            let svc = crate::services::postfix::PostfixService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::Dovecot => {
            let svc = crate::services::dovecot::DovecotService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::Ftpd => {
            let svc = crate::services::pureftpd::PureFtpdService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::Certbot => {
            let svc = crate::services::certbot::CertbotService::default();
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::PhpMyAdmin => {
            // phpMyAdmin is a web app, not a daemon — restart OLS instead
            let svc = crate::services::openlitespeed::OpenLiteSpeedService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::PHP => {
            // PHP runs inside OLS — restart OLS to restart PHP
            let svc = crate::services::openlitespeed::OpenLiteSpeedService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::SpamAssassin => {
            let svc = crate::services::spamassassin::SpamAssassinService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::Rspamd => {
            let svc = crate::services::rspamd::RspamdService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::ClamAV => {
            let svc = crate::services::rspamd::ClamAvService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::MailScanner => {
            let svc = crate::services::mailscanner::MailScannerService;
            execute_service_command(&svc, &action.action).await
        }
        ServiceType::Redis => {
            // Redis managed separately via systemctl; delegate to postfix service shell for consistency
            use crate::services::ServiceError;
            match action.action {
                crate::models::service::ServiceCommand::Start => {
                    crate::services::shell::exec("systemctl", &["start", "redis-server"])
                        .await
                        .map(|_| "Redis started".to_string())
                        .map_err(|e| ServiceError::CommandFailed(e.to_string()))
                }
                crate::models::service::ServiceCommand::Stop => {
                    crate::services::shell::exec("systemctl", &["stop", "redis-server"])
                        .await
                        .map(|_| "Redis stopped".to_string())
                        .map_err(|e| ServiceError::CommandFailed(e.to_string()))
                }
                crate::models::service::ServiceCommand::Restart => {
                    crate::services::shell::exec("systemctl", &["restart", "redis-server"])
                        .await
                        .map(|_| "Redis restarted".to_string())
                        .map_err(|e| ServiceError::CommandFailed(e.to_string()))
                }
                crate::models::service::ServiceCommand::Status => {
                    crate::services::shell::exec("systemctl", &["is-active", "redis-server"])
                        .await
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .map_err(|e| ServiceError::CommandFailed(e.to_string()))
                }
            }
        }
    };

    let status_str = match &result {
        Ok(msg) => {
            audit_log(
                claims.sub,
                &format!("service_{}", action.action),
                Some("service"),
                None,
                Some(&action.service.to_string()),
                "Success",
                None,
            )
            .await;
            msg.clone()
        }
        Err(e) => {
            audit_log(
                claims.sub,
                &format!("service_{}", action.action),
                Some("service"),
                None,
                Some(&action.service.to_string()),
                "Error",
                Some(&e.to_string()),
            )
            .await;
            return Err(ServerFnError::new(e.to_string()));
        }
    };

    Ok(status_str)
}

/// Issue an SSL certificate for a domain (admin or site owner).
#[server]
pub async fn server_issue_ssl_certificate(
    domain: String,
    email: String,
) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::utils::validators::validate_domain(&domain).map_err(ServerFnError::new)?;
    crate::utils::validators::validate_email(&email).map_err(ServerFnError::new)?;

    // Ownership guard: verify the caller owns a site with this domain, or is an admin.
    let site = crate::db::sites::get_by_domain(pool, &domain)
        .await
        .map_err(|_| ServerFnError::new("Domain not found or not managed by this panel"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let certbot = crate::services::certbot::CertbotService::default();
    let cert_info = certbot
        .issue_certificate_with_www(&domain, &email, None)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "issue_ssl_certificate",
        Some("certificate"),
        None,
        Some(&domain),
        "Success",
        None,
    )
    .await;

    Ok(format!("Certificate issued: {}", cert_info.cert_path))
}

/// Helper to execute start/stop/restart on any ManagedService.
#[cfg(feature = "server")]
async fn execute_service_command(
    svc: &dyn crate::services::ManagedService,
    command: &ServiceCommand,
) -> Result<String, crate::services::ServiceError> {
    match command {
        ServiceCommand::Start => {
            svc.start().await?;
            Ok(format!("{} started", svc.service_type()))
        }
        ServiceCommand::Stop => {
            svc.stop().await?;
            Ok(format!("{} stopped", svc.service_type()))
        }
        ServiceCommand::Restart => {
            svc.restart().await?;
            Ok(format!("{} restarted", svc.service_type()))
        }
        ServiceCommand::Status => {
            let status = svc.status().await?;
            Ok(format!("{}: {}", svc.service_type(), status))
        }
    }
}
