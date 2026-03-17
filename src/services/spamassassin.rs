/// SpamAssassin anti-spam service management.
/// Handles installation, configuration, Postfix integration, and lifecycle.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const SA_SERVICE: &str = "spamassassin";
const SA_SPAMD_SERVICE: &str = "spamd";
const SA_CONFIG: &str = "/etc/spamassassin/local.cf";

pub struct SpamAssassinService;

#[async_trait]
impl ManagedService for SpamAssassinService {
    fn service_type(&self) -> ServiceType {
        ServiceType::SpamAssassin
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing SpamAssassin...");
        shell::exec("apt-get", &["install", "-y", "spamassassin", "spamc"]).await?;
        shell::exec("systemctl", &["enable", SA_SERVICE]).await?;
        info!("SpamAssassin installed");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["start", SA_SERVICE]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["stop", SA_SERVICE]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["restart", SA_SERVICE]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        // spamd may be the actual daemon name on some distros
        for svc in &[SA_SERVICE, SA_SPAMD_SERVICE] {
            if let Ok(out) = shell::exec("systemctl", &["is-active", svc]).await {
                if String::from_utf8_lossy(&out.stdout).trim() == "active" {
                    return Ok(ServiceStatus::Running);
                }
            }
        }
        Ok(ServiceStatus::Stopped)
    }

    async fn is_installed(&self) -> Result<bool, ServiceError> {
        Ok(Path::new("/usr/bin/spamassassin").exists() || Path::new("/usr/bin/spamc").exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let out = shell::exec("spamassassin", &["--version"]).await?;
        let v = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
        Ok(v)
    }
}

impl SpamAssassinService {
    /// Write SpamAssassin `local.cf` with the given threshold / quarantine settings.
    pub async fn configure(
        &self,
        spam_threshold: f64,
        add_header: bool,
        reject_score: f64,
    ) -> Result<(), ServiceError> {
        let mut cfg = String::new();
        cfg.push_str(&format!("required_score {spam_threshold:.1}\n"));
        if add_header {
            cfg.push_str("report_safe 0\n");
            cfg.push_str("rewrite_header Subject [SPAM]\n");
        }
        if reject_score > 0.0 {
            cfg.push_str(&format!("score ALL_TRUSTED -{reject_score:.1}\n"));
        }
        cfg.push_str("use_bayes 1\nauto_learn 1\n");

        let tmp = format!("{}.tmp.{}", SA_CONFIG, std::process::id());
        fs::write(&tmp, cfg)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&tmp, SA_CONFIG)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        info!("SpamAssassin config written to {SA_CONFIG}");
        Ok(())
    }

    /// Integrate SpamAssassin into Postfix via a content-filter directive.
    /// Adds `content_filter = spamassassin` and the filter definition to main.cf.
    pub async fn integrate_with_postfix(&self, enabled: bool) -> Result<(), ServiceError> {
        let main_cf = "/etc/postfix/main.cf";
        let master_cf = "/etc/postfix/master.cf";

        let main_content = fs::read_to_string(main_cf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Remove any previous content_filter line for spamassassin
        let cleaned: String = main_content
            .lines()
            .filter(|l| {
                let t = l.trim();
                !(t.starts_with("content_filter") && t.contains("spamassassin"))
            })
            .collect::<Vec<_>>()
            .join("\n");

        let new_content = if enabled {
            format!("{cleaned}\ncontent_filter = spamassassin\n")
        } else {
            cleaned
        };

        let tmp_main = format!("{}.tmp.{}", main_cf, std::process::id());
        fs::write(&tmp_main, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&tmp_main, main_cf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Ensure the filter service is declared in master.cf
        let master_content = fs::read_to_string(master_cf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        if enabled
            && !master_content.lines().any(|l| {
                let t = l.trim();
                t.starts_with("spamassassin unix") && !t.starts_with('#')
            })
        {
            let filter_entry = r#"
spamassassin unix  -       n       n       -       -       pipe
  user=debian-spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
"#;
            let updated = format!("{master_content}{filter_entry}");
            let tmp_master = format!("{}.tmp.{}", master_cf, std::process::id());
            fs::write(&tmp_master, updated)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            fs::rename(&tmp_master, master_cf)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        shell::exec("postfix", &["reload"]).await?;
        info!("SpamAssassin Postfix integration: enabled={enabled}");
        Ok(())
    }
}
