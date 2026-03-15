/// Certbot / Let's Encrypt certificate management.
/// Handles certificate issuance, renewal, and lifecycle.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const CERTBOT_BIN: &str = "/usr/bin/certbot";
const CERTBOT_LIVE_DIR: &str = "/etc/letsencrypt/live";
const CERTBOT_WEBROOT: &str = "/usr/local/lsws/html";

/// Certbot / Let's Encrypt service manager.
pub struct CertbotService {
    pub webroot: String,
}

impl Default for CertbotService {
    fn default() -> Self {
        Self {
            webroot: CERTBOT_WEBROOT.to_string(),
        }
    }
}

#[async_trait]
impl ManagedService for CertbotService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Certbot
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing Certbot...");

        shell::exec("apt-get", &["install", "-y", "certbot"]).await?;

        // Enable auto-renewal timer
        shell::exec("systemctl", &["enable", "certbot.timer"]).await?;
        shell::exec("systemctl", &["start", "certbot.timer"]).await?;

        info!("Certbot installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        // Certbot is not a daemon — start the renewal timer
        shell::exec("systemctl", &["start", "certbot.timer"]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["stop", "certbot.timer"]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["restart", "certbot.timer"]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        // Check if the renewal timer is active
        match shell::exec("systemctl", &["is-active", "certbot.timer"]).await {
            Ok(output) => {
                let status_str = String::from_utf8_lossy(&output.stdout);
                if status_str.trim() == "active" {
                    Ok(ServiceStatus::Running)
                } else {
                    Ok(ServiceStatus::Stopped)
                }
            }
            Err(_) => Ok(ServiceStatus::Unknown),
        }
    }

    async fn is_installed(&self) -> Result<bool, ServiceError> {
        Ok(Path::new(CERTBOT_BIN).exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let output = shell::exec("certbot", &["--version"]).await?;
        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }
}

impl CertbotService {
    /// Issue an SSL certificate for one or more domains using the webroot method.
    pub async fn issue_certificate(
        &self,
        domain: &str,
        email: &str,
        webroot: Option<&str>,
    ) -> Result<CertificateInfo, ServiceError> {
        let webroot_path = webroot.unwrap_or(&self.webroot);

        info!("Issuing SSL certificate for: {}", domain);

        let output = shell::exec(
            "certbot",
            &[
                "certonly",
                "--webroot",
                "--webroot-path",
                webroot_path,
                "-d",
                domain,
                "--email",
                email,
                "--agree-tos",
                "--non-interactive",
                "--quiet",
            ],
        )
        .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServiceError::CommandFailed(format!(
                "Certbot failed: {}",
                stderr
            )));
        }

        let cert_path = format!("{}/{}/fullchain.pem", CERTBOT_LIVE_DIR, domain);
        let key_path = format!("{}/{}/privkey.pem", CERTBOT_LIVE_DIR, domain);

        info!("Certificate issued for: {}", domain);

        Ok(CertificateInfo {
            domain: domain.to_string(),
            cert_path,
            key_path,
            issuer: "Let's Encrypt".to_string(),
            expires_at: None,
        })
    }

    /// Issue a certificate for a domain with optional www subdomain.
    pub async fn issue_certificate_with_www(
        &self,
        domain: &str,
        email: &str,
        webroot: Option<&str>,
    ) -> Result<CertificateInfo, ServiceError> {
        let webroot_path = webroot.unwrap_or(&self.webroot);
        let www_domain = format!("www.{}", domain);

        info!("Issuing SSL certificate for: {} + {}", domain, www_domain);

        let output = shell::exec(
            "certbot",
            &[
                "certonly",
                "--webroot",
                "--webroot-path",
                webroot_path,
                "-d",
                domain,
                "-d",
                &www_domain,
                "--email",
                email,
                "--agree-tos",
                "--non-interactive",
                "--quiet",
            ],
        )
        .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServiceError::CommandFailed(format!(
                "Certbot failed: {}",
                stderr
            )));
        }

        let cert_path = format!("{}/{}/fullchain.pem", CERTBOT_LIVE_DIR, domain);
        let key_path = format!("{}/{}/privkey.pem", CERTBOT_LIVE_DIR, domain);

        Ok(CertificateInfo {
            domain: domain.to_string(),
            cert_path,
            key_path,
            issuer: "Let's Encrypt".to_string(),
            expires_at: None,
        })
    }

    /// Revoke a certificate.
    pub async fn revoke_certificate(&self, domain: &str) -> Result<(), ServiceError> {
        info!("Revoking certificate for: {}", domain);

        let cert_path = format!("{}/{}/fullchain.pem", CERTBOT_LIVE_DIR, domain);
        let output = shell::exec(
            "certbot",
            &["revoke", "--cert-path", &cert_path, "--non-interactive"],
        )
        .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServiceError::CommandFailed(format!(
                "Certificate revocation failed: {}",
                stderr
            )));
        }

        info!("Certificate revoked for: {}", domain);
        Ok(())
    }

    /// Force-renew all certificates.
    pub async fn renew_all(&self) -> Result<(), ServiceError> {
        info!("Renewing all certificates...");

        let output = shell::exec("certbot", &["renew", "--quiet"]).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServiceError::CommandFailed(format!(
                "Certificate renewal failed: {}",
                stderr
            )));
        }

        info!("All certificates renewed");
        Ok(())
    }

    /// Check if a certificate exists for a domain.
    pub async fn has_certificate(&self, domain: &str) -> bool {
        let cert_path = format!("{}/{}/fullchain.pem", CERTBOT_LIVE_DIR, domain);
        Path::new(&cert_path).exists()
    }

    /// Get certificate info for a domain.
    pub async fn get_certificate_info(
        &self,
        domain: &str,
    ) -> Result<CertificateInfo, ServiceError> {
        let cert_path = format!("{}/{}/fullchain.pem", CERTBOT_LIVE_DIR, domain);
        let key_path = format!("{}/{}/privkey.pem", CERTBOT_LIVE_DIR, domain);

        if !Path::new(&cert_path).exists() {
            return Err(ServiceError::CommandFailed(format!(
                "No certificate found for: {}",
                domain
            )));
        }

        // Get certificate expiry via openssl (e.g. "notAfter=May 14 12:00:00 2026 GMT")
        let output = shell::exec(
            "openssl",
            &["x509", "-in", &cert_path, "-noout", "-enddate"],
        )
        .await?;

        let expiry_line = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let expires_at = expiry_line.strip_prefix("notAfter=").and_then(|s| {
            let s = s.trim().trim_end_matches(" GMT").trim();
            // Try space-padded day (%e) first, then zero-padded (%d).
            chrono::NaiveDateTime::parse_from_str(s, "%b %e %H:%M:%S %Y")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%b %d %H:%M:%S %Y"))
                .ok()
                .map(|dt| {
                    chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc)
                })
        });

        Ok(CertificateInfo {
            domain: domain.to_string(),
            cert_path,
            key_path,
            issuer: "Let's Encrypt".to_string(),
            expires_at,
        })
    }

    /// Returns the number of days until the certificate for `domain` expires.
    /// A negative value means the certificate has already expired.
    pub async fn days_until_expiry(&self, domain: &str) -> Result<i64, ServiceError> {
        let info = self.get_certificate_info(domain).await?;
        match info.expires_at {
            Some(expiry) => Ok((expiry - chrono::Utc::now()).num_days()),
            None => Err(ServiceError::CommandFailed(
                "Unable to determine certificate expiry date".to_string(),
            )),
        }
    }

    /// List all managed certificates.
    pub async fn list_certificates(&self) -> Result<Vec<String>, ServiceError> {
        let mut certs = Vec::new();

        if Path::new(CERTBOT_LIVE_DIR).exists() {
            let mut entries = fs::read_dir(CERTBOT_LIVE_DIR)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;

            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                    if let Some(name) = entry.file_name().to_str() {
                        if name != "README" {
                            certs.push(name.to_string());
                        }
                    }
                }
            }
        }

        Ok(certs)
    }
}

/// Information about an SSL certificate.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
    pub issuer: String,
    /// Certificate expiry date, populated by `get_certificate_info`.
    /// `None` when the cert was just issued (call `get_certificate_info` or
    /// `days_until_expiry` to resolve it).
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
