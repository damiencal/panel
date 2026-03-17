/// phpMyAdmin installation and configuration management.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const PMA_INSTALL_DIR: &str = "/usr/share/phpmyadmin";
const PMA_CONFIG_FILE: &str = "/usr/share/phpmyadmin/config.inc.php";
const PMA_SIGNON_SCRIPT: &str = "/usr/share/phpmyadmin/signon.php";

/// phpMyAdmin service manager.
pub struct PhpMyAdminService;

#[async_trait]
impl ManagedService for PhpMyAdminService {
    fn service_type(&self) -> ServiceType {
        ServiceType::PhpMyAdmin
    }

    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing phpMyAdmin...");

        // Install phpMyAdmin from Ubuntu repos (non-interactive)
        shell::exec("apt-get", &["install", "-y", "phpmyadmin"]).await?;

        // Deploy custom config
        self.deploy_config().await?;

        // Deploy signon bridge script
        self.deploy_signon_script().await?;

        info!("phpMyAdmin installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<(), ServiceError> {
        // phpMyAdmin is a web app served by OLS, no separate daemon
        Ok(())
    }

    async fn stop(&self) -> Result<(), ServiceError> {
        Ok(())
    }

    async fn restart(&self) -> Result<(), ServiceError> {
        Ok(())
    }

    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        if Path::new(&format!("{}/index.php", PMA_INSTALL_DIR)).exists() {
            Ok(ServiceStatus::Running)
        } else {
            Ok(ServiceStatus::Stopped)
        }
    }

    async fn is_installed(&self) -> Result<bool, ServiceError> {
        Ok(Path::new(&format!("{}/index.php", PMA_INSTALL_DIR)).exists())
    }

    async fn version(&self) -> Result<String, ServiceError> {
        let version_file = format!("{}/libraries/classes/Version.php", PMA_INSTALL_DIR);
        if Path::new(&version_file).exists() {
            let content = fs::read_to_string(&version_file)
                .await
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            // Extract version from VERSION constant
            for line in content.lines() {
                if line.contains("VERSION") && line.contains("'") {
                    if let Some(start) = line.find('\'') {
                        if let Some(end) = line[start + 1..].find('\'') {
                            return Ok(line[start + 1..start + 1 + end].to_string());
                        }
                    }
                }
            }
        }
        Ok("unknown".to_string())
    }
}

impl PhpMyAdminService {
    /// Deploy the phpMyAdmin configuration file for signon authentication.
    pub async fn deploy_config(&self) -> Result<(), ServiceError> {
        let blowfish_secret = generate_blowfish_secret();

        let config = format!(
            r#"<?php
/**
 * phpMyAdmin configuration - managed by Hosting Control Panel.
 * Do not edit manually.
 */

$cfg['blowfish_secret'] = '{}';

/* Server configuration */
$i = 0;
$i++;

$cfg['Servers'][$i]['auth_type'] = 'signon';
$cfg['Servers'][$i]['SignonSession'] = 'PMA_single_signon';
$cfg['Servers'][$i]['SignonURL'] = 'signon.php';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['compress'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;

/* Directories */
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';

/* Security settings */
$cfg['LoginCookieValidity'] = 1800;
$cfg['LoginCookieStore'] = 0;
$cfg['LoginCookieDeleteAll'] = true;
$cfg['CheckConfigurationPermissions'] = false;

/* Disable version check (managed by system packages) */
$cfg['VersionCheck'] = false;

/* Temporary directory — under /var/lib to avoid world-writable /tmp symlink attacks */
$cfg['TempDir'] = '/var/lib/phpmyadmin/tmp';
"#,
            blowfish_secret
        );

        // Write config as a temp file, then rename atomically.
        // Use mode 0o640 so that only root and the web-server group can read
        // the blowfish secret; world-readable /usr/share permissions are
        // deliberately not used here.
        let tmp_config = format!("{}.panel_tmp", PMA_CONFIG_FILE);
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o640)
                .open(&tmp_config)
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
            use std::io::Write;
            f.write_all(config.as_bytes())
                .map_err(|e| ServiceError::IoError(e.to_string()))?;
        }
        fs::rename(&tmp_config, PMA_CONFIG_FILE)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Ensure temp directory exists with tight permissions.
        // /var/lib/phpmyadmin/tmp is only accessible by root, preventing other
        // local users from pre-creating a symlink under the world-writable /tmp.
        fs::create_dir_all("/var/lib/phpmyadmin/tmp")
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        shell::exec("chmod", &["700", "/var/lib/phpmyadmin/tmp"])
            .await
            .ok();

        info!("phpMyAdmin configuration deployed");
        Ok(())
    }

    /// Deploy the signon bridge PHP script that validates HMAC tokens
    /// and establishes phpMyAdmin sessions.
    pub async fn deploy_signon_script(&self) -> Result<(), ServiceError> {
        let signon_script = include_str!("../../templates/phpmyadmin_signon.php");

        let tmp_signon = format!("{}.panel_tmp", PMA_SIGNON_SCRIPT);
        fs::write(&tmp_signon, signon_script)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        fs::rename(&tmp_signon, PMA_SIGNON_SCRIPT)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        info!("phpMyAdmin signon script deployed");
        Ok(())
    }

    /// Generate the OpenLiteSpeed context configuration for phpMyAdmin.
    pub fn generate_ols_context_config() -> String {
        format!(
            r#"
context /phpmyadmin/ {{
  location                {}/
  allowBrowse             1
  enableScript            1

  accessControl  {{
    allow                 *
  }}

  rewrite  {{
  }}

  addDefaultCharset       off

  phpIniOverride  {{
  }}
}}
"#,
            PMA_INSTALL_DIR
        )
    }
}

/// Generate a random 32-character blowfish secret for phpMyAdmin cookie encryption.
fn generate_blowfish_secret() -> String {
    use std::fmt::Write;
    use std::io::Read;
    let mut secret = String::with_capacity(64);
    // Use /dev/urandom for secure random bytes (read exactly 32 bytes)
    let mut buf = [0u8; 32];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
    {
        for &b in buf.iter() {
            let _ = write!(secret, "{:02x}", b);
        }
    } else {
        // Fallback: use uuid if /dev/urandom unavailable
        secret = uuid::Uuid::new_v4().to_string().replace('-', "");
        secret.push_str(&uuid::Uuid::new_v4().to_string().replace('-', ""));
        secret.truncate(64);
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blowfish_secret_length() {
        let secret = generate_blowfish_secret();
        assert!(secret.len() >= 32);
    }

    #[test]
    fn test_ols_context_config_contains_phpmyadmin() {
        let config = PhpMyAdminService::generate_ols_context_config();
        assert!(config.contains("/phpmyadmin/"));
        assert!(config.contains(PMA_INSTALL_DIR));
    }
}
