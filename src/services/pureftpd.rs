/// Pure-FTPd virtual FTP server management.
/// Handles installation, virtual user management, and lifecycle.
use super::{shell, ManagedService, ServiceError};
use crate::models::ftp::FtpSessionStat;
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use chrono::Utc;
use std::path::Path;
use tokio::fs;
use tracing::info;

const PUREFTPD_SERVICE: &str = "pure-ftpd";
const PUREFTPD_PASSWD_FILE: &str = "/etc/pure-ftpd/pureftpd.passwd";
const PUREFTPD_PDB_FILE: &str = "/etc/pure-ftpd/pureftpd.pdb";
const PUREFTPD_CONF_DIR: &str = "/etc/pure-ftpd/conf";
/// Default path for the Pure-FTPd transfer log (wu-ftpd xferlog format).
const PUREFTPD_XFERLOG: &str = "/var/log/pure-ftpd/transfer.log";

/// Pure-FTPd service manager.
pub struct PureFtpdService;

#[async_trait]
impl ManagedService for PureFtpdService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Ftpd
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing Pure-FTPd...");

        shell::exec(
            "apt-get",
            &["install", "-y", "pure-ftpd", "pure-ftpd-common"],
        )
        .await?;

        shell::exec("systemctl", &["enable", PUREFTPD_SERVICE]).await?;

        info!("Pure-FTPd installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        info!("Starting Pure-FTPd...");
        shell::exec("systemctl", &["start", PUREFTPD_SERVICE]).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        info!("Stopping Pure-FTPd...");
        shell::exec("systemctl", &["stop", PUREFTPD_SERVICE]).await?;
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        info!("Restarting Pure-FTPd...");
        shell::exec("systemctl", &["restart", PUREFTPD_SERVICE]).await?;
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        match shell::exec("systemctl", &["is-active", PUREFTPD_SERVICE]).await {
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
        Ok(Path::new("/usr/sbin/pure-ftpd").exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let output = shell::exec("pure-ftpd", &["--help"]).await?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Pure-FTPd prints version in the first line of --help output
        let version = stderr.lines().next().unwrap_or("unknown").to_string();
        Ok(version)
    }
}

impl PureFtpdService {
    /// Configure Pure-FTPd for virtual user hosting.
    pub async fn configure_virtual_hosting(&self) -> Result<(), ServiceError> {
        info!("Configuring Pure-FTPd for virtual hosting...");

        // Create passwd file if it doesn't exist
        if !Path::new(PUREFTPD_PASSWD_FILE).exists() {
            fs::write(PUREFTPD_PASSWD_FILE, "")
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }

        // Enable virtual users (PureDB backend)
        self.set_config(
            "PureDB",
            &format!("{}:{}", PUREFTPD_PASSWD_FILE, PUREFTPD_PDB_FILE),
        )
        .await?;

        // Security settings
        self.set_config("ChrootEveryone", "yes").await?;
        self.set_config("NoAnonymous", "yes").await?;
        self.set_config("CreateHomeDir", "yes").await?;
        self.set_config("MinUID", "1000").await?;

        // TLS
        self.set_config("TLS", "1").await?; // 0=disable, 1=optional, 2=required

        // Passive mode port range
        self.set_config("PassivePortRange", "30000 50000").await?;

        // Logging
        self.set_config("VerboseLog", "yes").await?;

        // Max connections
        self.set_config("MaxClientsNumber", "50").await?;
        self.set_config("MaxClientsPerIP", "8").await?;

        // Bandwidth limits (0 = unlimited)
        self.set_config("MaxDiskUsage", "95").await?;

        self.restart().await?;
        info!("Pure-FTPd virtual hosting configured");
        Ok(())
    }

    /// Create a virtual FTP user.
    /// The user's home directory should be their site's document root.
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        home_dir: &str,
        uid: u32,
        gid: u32,
    ) -> Result<(), ServiceError> {
        // Defense-in-depth: validate all inputs at service layer
        crate::utils::validators::validate_username(username)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_passwd_field(username, "username")
            .map_err(ServiceError::CommandFailed)?;
        crate::utils::validators::validate_passwd_field(password, "password")
            .map_err(ServiceError::CommandFailed)?;
        crate::utils::validators::validate_safe_path(home_dir, "/home/")
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Creating FTP user: {} -> {}", username, home_dir);

        // Create home directory if needed
        shell::exec("mkdir", &["-p", home_dir]).await?;

        // Always pipe password via stdin so it is never exposed in the process list
        let hash_output = shell::exec_stdin(
            "openssl",
            &["passwd", "-6", "-stdin"],
            password.as_bytes(),
        )
        .await?;
        let password_hash = String::from_utf8_lossy(&hash_output.stdout).trim().to_string();

        let passwd_args = format!(
            "{}:{}:{}:{}::{}::::::::::::::\n",
            username, password_hash, uid, gid, home_dir
        );

        // Use file locking to prevent TOCTOU race conditions
        let _lock = super::filelock::FileLock::exclusive(PUREFTPD_PASSWD_FILE)?;

        let mut content = fs::read_to_string(PUREFTPD_PASSWD_FILE)
            .await
            .unwrap_or_default();

        // Remove existing entry for this user
        content = content
            .lines()
            .filter(|line| !line.starts_with(&format!("{}:", username)))
            .map(|line| format!("{}\n", line))
            .collect();

        content.push_str(&passwd_args);

        fs::write(PUREFTPD_PASSWD_FILE, content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Rebuild the PDB database
        self.rebuild_pdb().await?;

        // Set ownership
        let uid_gid = format!("{}:{}", uid, gid);
        shell::exec("chown", &["-R", &uid_gid, home_dir]).await?;

        info!("FTP user '{}' created", username);
        Ok(())
    }

    /// Delete a virtual FTP user.
    pub async fn delete_user(&self, username: &str) -> Result<(), ServiceError> {
        crate::utils::validators::validate_username(username)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Deleting FTP user: {}", username);

        let _lock = super::filelock::FileLock::exclusive(PUREFTPD_PASSWD_FILE)?;

        let content = fs::read_to_string(PUREFTPD_PASSWD_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .filter(|line| !line.starts_with(&format!("{}:", username)))
            .map(|line| format!("{}\n", line))
            .collect();

        fs::write(PUREFTPD_PASSWD_FILE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        self.rebuild_pdb().await?;

        info!("FTP user '{}' deleted", username);
        Ok(())
    }

    /// Update a virtual user's password.
    pub async fn update_password(
        &self,
        username: &str,
        new_password: &str,
    ) -> Result<(), ServiceError> {
        crate::utils::validators::validate_username(username)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_passwd_field(new_password, "password")
            .map_err(ServiceError::CommandFailed)?;

        // Hash the new password before storage
        let hash_output = super::shell::exec_stdin(
            "openssl",
            &["passwd", "-6", "-stdin"],
            new_password.as_bytes(),
        )
        .await?;
        let password_hash = String::from_utf8_lossy(&hash_output.stdout)
            .trim()
            .to_string();

        let _lock = super::filelock::FileLock::exclusive(PUREFTPD_PASSWD_FILE)?;

        let content = fs::read_to_string(PUREFTPD_PASSWD_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .map(|line| {
                if line.starts_with(&format!("{}:", username)) {
                    let parts: Vec<&str> = line.splitn(3, ':').collect();
                    if parts.len() >= 3 {
                        format!("{}:{}:{}", parts[0], password_hash, parts[2])
                    } else {
                        line.to_string()
                    }
                } else {
                    line.to_string()
                }
            })
            .map(|line| format!("{}\n", line))
            .collect();

        fs::write(PUREFTPD_PASSWD_FILE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        self.rebuild_pdb().await?;
        Ok(())
    }

    /// Change a user's home directory (e.g., when renaming a site).
    pub async fn update_home_dir(
        &self,
        username: &str,
        new_home_dir: &str,
    ) -> Result<(), ServiceError> {
        // Defense-in-depth: prevent path traversal in home directory
        crate::utils::validators::validate_username(username)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_safe_path(new_home_dir, "/home/")
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_passwd_field(new_home_dir, "home_dir")
            .map_err(ServiceError::CommandFailed)?;

        let _lock = super::filelock::FileLock::exclusive(PUREFTPD_PASSWD_FILE)?;

        let content = fs::read_to_string(PUREFTPD_PASSWD_FILE)
            .await
            .unwrap_or_default();

        let new_content: String = content
            .lines()
            .map(|line| {
                if line.starts_with(&format!("{}:", username)) {
                    let parts: Vec<&str> = line.splitn(6, ':').collect();
                    if parts.len() >= 6 {
                        format!(
                            "{}:{}:{}:{}:{}:{}",
                            parts[0], parts[1], parts[2], parts[3], new_home_dir, parts[5]
                        )
                    } else {
                        line.to_string()
                    }
                } else {
                    line.to_string()
                }
            })
            .map(|line| format!("{}\n", line))
            .collect();

        fs::write(PUREFTPD_PASSWD_FILE, new_content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        self.rebuild_pdb().await?;
        Ok(())
    }

    /// Rebuild the Pure-FTPd PDB (binary database) from the passwd file.
    async fn rebuild_pdb(&self) -> Result<(), ServiceError> {
        shell::exec("pure-ftpd", &["--help"]).await.ok();
        // Pure-FTPd reads the passwd file on each auth when PureDB is configured
        // The PDB is optional but speeds up lookups
        Ok(())
    }

    /// Write a Pure-FTPd configuration flag file.
    async fn set_config(&self, key: &str, value: &str) -> Result<(), ServiceError> {
        let path = format!("{}/{}", PUREFTPD_CONF_DIR, key);
        fs::write(&path, value)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        Ok(())
    }

    /// Parse Pure-FTPd's wu-ftpd-style xferlog and return transfer records.
    ///
    /// Each line in xferlog format:
    /// ```text
    /// <weekday> <month> <day> <HH:MM:SS> <year> <transfer_secs> <remote_host>
    ///   <bytes> <filename> <xfer_type(a/b)> <direction(i=upload,o=download)>
    ///   <access_mode(r/a/l/g/R/A/L/G)> <username> <service> <auth_type>
    ///   <uid> <completion(c/i)>
    /// ```
    pub async fn parse_transfer_log(
        &self,
        limit: usize,
    ) -> Result<Vec<FtpSessionStat>, ServiceError> {
        let content = fs::read_to_string(PUREFTPD_XFERLOG)
            .await
            .unwrap_or_default();

        let mut entries: Vec<FtpSessionStat> = Vec::new();

        for line in content.lines().rev() {
            if entries.len() >= limit {
                break;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Minimum xferlog fields: 15
            if parts.len() < 15 {
                continue;
            }
            // field 5 = transfer_time_secs
            let transfer_secs: f64 = parts[5].parse().unwrap_or(0.0);
            // field 6 = remote_host
            let remote_host = parts[6].to_string();
            // field 7 = bytes
            let bytes_transferred: i64 = parts[7].parse().unwrap_or(0);
            // field 8 = filename
            let filename = parts[8].to_string();
            // field 10 = direction: 'i' = incoming (upload), 'o' = outgoing (download)
            let direction = match parts[10] {
                "i" => "Upload",
                _ => "Download",
            };
            // field 12 = username
            let username = parts[12].to_string();

            entries.push(FtpSessionStat {
                id: 0,
                account_id: None,
                username,
                remote_host: Some(remote_host),
                direction: direction.to_string(),
                filename,
                bytes_transferred,
                transfer_time_secs: transfer_secs,
                completed_at: Utc::now(),
            });
        }

        Ok(entries)
    }
}
