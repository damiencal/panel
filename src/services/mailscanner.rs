/// MailScanner service management.
/// MailScanner sits between Postfix and the real delivery, scanning for spam and viruses.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const MS_SERVICE: &str = "mailscanner";
const MS_CONFIG: &str = "/etc/MailScanner/MailScanner.conf";

pub struct MailScannerService;

#[async_trait]
impl ManagedService for MailScannerService {
    fn service_type(&self) -> ServiceType {
        ServiceType::MailScanner
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing MailScanner...");
        shell::exec("apt-get", &["install", "-y", "mailscanner"]).await?;
        shell::exec("systemctl", &["enable", MS_SERVICE]).await?;
        info!("MailScanner installed");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["start", MS_SERVICE]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["stop", MS_SERVICE]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["restart", MS_SERVICE]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        match shell::exec("systemctl", &["is-active", MS_SERVICE]).await {
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "active" => {
                Ok(ServiceStatus::Running)
            }
            _ => Ok(ServiceStatus::Stopped),
        }
    }

    async fn is_installed(&self) -> Result<bool, ServiceError> {
        Ok(Path::new("/usr/sbin/MailScanner").exists()
            || Path::new("/usr/lib/MailScanner").exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let out = shell::exec("MailScanner", &["--version"]).await?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string())
    }
}

impl MailScannerService {
    /// Enable or disable MailScanner in-transit scanning.
    /// When enabled, Postfix holds incoming mail in the incoming queue and
    /// MailScanner processes it before re-injecting.
    pub async fn configure(&self, enabled: bool) -> Result<(), ServiceError> {
        if !Path::new(MS_CONFIG).exists() {
            return Err(ServiceError::NotInstalled);
        }

        let content = fs::read_to_string(MS_CONFIG)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        let updated: String = content
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("Always Looked Up Last =")
                    || line.trim_start().starts_with("# Always Looked Up Last =")
                {
                    if enabled {
                        "Always Looked Up Last = &MailWatchLogging".to_string()
                    } else {
                        "# Always Looked Up Last =".to_string()
                    }
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let tmp = format!("{}.tmp.{}", MS_CONFIG, std::process::id());
        fs::write(&tmp, updated)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&tmp, MS_CONFIG)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        info!("MailScanner configured: enabled={enabled}");
        Ok(())
    }
}
