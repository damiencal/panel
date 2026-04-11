/// Rspamd spam-filter + Redis + ClamAV service management.
/// Rspamd acts as the milter content filter for Postfix.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const RSPAMD_SERVICE: &str = "rspamd";
const REDIS_SERVICE: &str = "redis-server";
const CLAMAV_SERVICE: &str = "clamav-freshclam";
const CLAMAV_DAEMON: &str = "clamav-daemon";
const RSPAMD_LOCAL_CFG: &str = "/etc/rspamd/local.d";

pub struct RspamdService;
pub struct ClamAvService;

fn validate_scan_target(path: &str) -> Result<String, ServiceError> {
    if path.contains('\0') || path.contains([';', '|', '&', '\n', '\r']) {
        return Err(ServiceError::CommandFailed("Invalid scan path".to_string()));
    }

    let canonical = std::fs::canonicalize(path)
        .map_err(|_| ServiceError::CommandFailed("Scan path does not exist".to_string()))?;

    let allowed_prefixes = ["/var/www", "/home", "/tmp", "/srv", "/opt"];
    if !allowed_prefixes
        .iter()
        .any(|prefix| canonical.starts_with(prefix))
    {
        return Err(ServiceError::CommandFailed(
            "Scan path must be within /var/www, /home, /tmp, /srv, or /opt".to_string(),
        ));
    }

    Ok(canonical.to_string_lossy().to_string())
}

// ─── Rspamd ──────────────────────────────────────────────────────────────────

#[async_trait]
impl ManagedService for RspamdService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Rspamd
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing Rspamd + Redis...");
        shell::exec("apt-get", &["install", "-y", "rspamd", "redis-server"]).await?;
        shell::exec("systemctl", &["enable", RSPAMD_SERVICE]).await?;
        shell::exec("systemctl", &["enable", REDIS_SERVICE]).await?;
        info!("Rspamd + Redis installed");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["start", REDIS_SERVICE]).await?;
        shell::exec("systemctl", &["start", RSPAMD_SERVICE]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["stop", RSPAMD_SERVICE]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["restart", RSPAMD_SERVICE]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        match shell::exec("systemctl", &["is-active", RSPAMD_SERVICE]).await {
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "active" => {
                Ok(ServiceStatus::Running)
            }
            _ => Ok(ServiceStatus::Stopped),
        }
    }

    async fn is_installed(&self) -> Result<bool, ServiceError> {
        Ok(Path::new("/usr/bin/rspamc").exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let out = shell::exec("rspamd", &["--version"]).await?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string())
    }
}

impl RspamdService {
    /// Write Rspamd local configuration files for the given threshold.
    pub async fn configure(
        &self,
        spam_threshold: f64,
        add_header: bool,
        reject_score: f64,
        clamav_enabled: bool,
    ) -> Result<(), ServiceError> {
        // Ensure local.d directory exists
        fs::create_dir_all(RSPAMD_LOCAL_CFG)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // actions.conf
        let actions = format!(
            r#"actions {{
  reject = {reject_score:.1};
  add_header = {spam_threshold:.1};
  greylist = {greylist:.1};
}}
"#,
            reject_score = if reject_score > 0.0 {
                reject_score
            } else {
                999.0
            },
            spam_threshold = spam_threshold,
            greylist = spam_threshold + 2.0,
        );
        let actions_path = format!("{RSPAMD_LOCAL_CFG}/actions.conf");
        let actions_tmp = format!("{actions_path}.tmp.{}", std::process::id());
        fs::write(&actions_tmp, actions)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&actions_tmp, &actions_path)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        if add_header {
            let milter = "use = [\"x-spam-status\", \"x-spam-score\", \"x-spam-flag\"];\n";
            let milter_path = format!("{RSPAMD_LOCAL_CFG}/milter_headers.conf");
            let milter_tmp = format!("{milter_path}.tmp.{}", std::process::id());
            fs::write(&milter_tmp, milter)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            fs::rename(&milter_tmp, &milter_path)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        // antivirus.conf (ClamAV)
        if clamav_enabled {
            let av = r#"clamav {
  action = "reject";
  symbol = "CLAM_VIRUS";
  type = "clamav";
  log_clean = true;
  servers = "127.0.0.1:3310";
}
"#;
            let av_path = format!("{RSPAMD_LOCAL_CFG}/antivirus.conf");
            let av_tmp = format!("{av_path}.tmp.{}", std::process::id());
            fs::write(&av_tmp, av)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            fs::rename(&av_tmp, &av_path)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        info!("Rspamd config written to {RSPAMD_LOCAL_CFG}");
        Ok(())
    }

    /// Configure Postfix to use Rspamd as a milter.
    pub async fn integrate_with_postfix(&self, enabled: bool) -> Result<(), ServiceError> {
        let main_cf = "/etc/postfix/main.cf";
        let content = fs::read_to_string(main_cf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Remove previous rspamd milter lines
        let cleaned: String = content
            .lines()
            .filter(|l| {
                let t = l.trim();
                !(t.starts_with("milter_default_action")
                    || t.starts_with("milter_protocol")
                    || t.starts_with("smtpd_milters")
                    || t.starts_with("non_smtpd_milters")
                    || (t.starts_with("content_filter") && t.contains("spamassassin")))
            })
            .collect::<Vec<_>>()
            .join("\n");

        let new_content = if enabled {
            format!(
                "{cleaned}\nmilter_default_action = accept\nmilter_protocol = 6\nsmtpd_milters = inet:127.0.0.1:11332\nnon_smtpd_milters = inet:127.0.0.1:11332\n"
            )
        } else {
            cleaned
        };

        let tmp = format!("{}.tmp.{}", main_cf, std::process::id());
        fs::write(&tmp, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&tmp, main_cf)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        shell::exec("postfix", &["reload"]).await?;
        info!("Rspamd Postfix milter integration: enabled={enabled}");
        Ok(())
    }
}

// ─── ClamAV ──────────────────────────────────────────────────────────────────

#[async_trait]
impl ManagedService for ClamAvService {
    fn service_type(&self) -> ServiceType {
        ServiceType::ClamAV
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing ClamAV...");
        shell::exec("apt-get", &["install", "-y", "clamav", "clamav-daemon"]).await?;
        shell::exec("systemctl", &["enable", CLAMAV_SERVICE]).await?;
        shell::exec("systemctl", &["enable", CLAMAV_DAEMON]).await?;
        // Fetch initial virus DB
        shell::exec("freshclam", &[]).await.ok();
        info!("ClamAV installed");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["start", CLAMAV_SERVICE]).await?;
        shell::exec("systemctl", &["start", CLAMAV_DAEMON]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["stop", CLAMAV_DAEMON]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        shell::exec("systemctl", &["restart", CLAMAV_DAEMON]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        match shell::exec("systemctl", &["is-active", CLAMAV_DAEMON]).await {
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "active" => {
                Ok(ServiceStatus::Running)
            }
            _ => Ok(ServiceStatus::Stopped),
        }
    }

    async fn is_installed(&self) -> Result<bool, ServiceError> {
        Ok(Path::new("/usr/bin/clamscan").exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let out = shell::exec("clamscan", &["--version"]).await?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string())
    }
}

impl ClamAvService {
    /// Update the virus database using freshclam.
    pub async fn update_db(&self) -> Result<String, ServiceError> {
        info!("Updating ClamAV virus database…");
        // Stop the freshclam service first to avoid lock conflicts
        shell::exec("systemctl", &["stop", CLAMAV_SERVICE])
            .await
            .ok();
        let out = shell::exec_output("freshclam", &[]).await?;
        // Restart regardless
        shell::exec("systemctl", &["start", CLAMAV_SERVICE])
            .await
            .ok();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        info!("freshclam complete");
        if out.status.success() {
            Ok(stdout)
        } else {
            // freshclam returns non-zero if DB is up to date; treat as success
            if stderr.contains("up to date") || stdout.contains("up to date") {
                Ok("Virus database is up to date".to_string())
            } else {
                Ok(format!("{stdout}\n{stderr}"))
            }
        }
    }

    /// Scan a directory or file. Returns a scan report.
    /// `path` is validated to prevent traversal attacks.
    pub async fn scan_path(&self, path: &str) -> Result<ClamScanReport, ServiceError> {
        let safe_path = validate_scan_target(path)?;

        info!("ClamAV scanning: {safe_path}");
        let out = shell::exec_output(
            "clamscan",
            &["--recursive", "--infected", "--no-summary", &safe_path],
        )
        .await?;

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        Ok(parse_clamscan_output(&stdout))
    }

    /// Scan a path using clamdscan (uses the daemon; faster for large dirs).
    pub async fn scan_path_daemon(&self, path: &str) -> Result<ClamScanReport, ServiceError> {
        let safe_path = validate_scan_target(path)?;

        info!("clamdscan scanning: {safe_path}");
        let out = shell::exec_output("clamdscan", &["--infected", "--no-summary", &safe_path])
            .await?;

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        Ok(parse_clamscan_output(&stdout))
    }

    /// Get ClamAV virus database info.
    pub async fn get_db_info(&self) -> Result<ClamDbInfo, ServiceError> {
        if !std::path::Path::new("/usr/bin/clamscan").exists() {
            return Err(ServiceError::NotInstalled);
        }
        let out = shell::exec_output("clamscan", &["--version"]).await?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        Ok(parse_clam_version(&text))
    }
}

// Re-export shared types from models
pub use crate::models::security::{ClamDbInfo, ClamScanReport, ClamThreat};

fn parse_clamscan_output(text: &str) -> ClamScanReport {
    let mut scanned: usize = 0;
    let mut infected: usize = 0;
    let mut threats = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Infected file lines: "/path/to/file: Virus.Name FOUND"
        if line.ends_with("FOUND") {
            if let Some(colon_pos) = line.rfind(": ") {
                let path = line[..colon_pos].to_string();
                let virus = line[colon_pos + 2..].trim_end_matches(" FOUND").to_string();
                infected += 1;
                threats.push(ClamThreat {
                    path,
                    virus_name: virus,
                });
            }
        } else if line.ends_with("OK") {
            scanned += 1;
        } else if let Some(rest) = line.strip_prefix("Scanned files:") {
            if let Ok(n) = rest.trim().parse::<usize>() {
                scanned = n;
            }
        }
    }

    ClamScanReport {
        scanned_files: scanned,
        infected_files: infected,
        threats,
    }
}

fn parse_clam_version(text: &str) -> ClamDbInfo {
    // Output: "ClamAV 0.103.9/26967/Mon Dec 25 12:00:00 2023"
    let line = text.lines().next().unwrap_or("").trim();
    let parts: Vec<&str> = line.splitn(4, '/').collect();
    ClamDbInfo {
        version: parts
            .first()
            .copied()
            .unwrap_or("unknown")
            .trim()
            .to_string(),
        signatures: parts
            .get(1)
            .copied()
            .unwrap_or("0")
            .trim()
            .parse::<u64>()
            .unwrap_or(0),
        database_date: parts.get(2).copied().unwrap_or("unknown").to_string(),
    }
}
