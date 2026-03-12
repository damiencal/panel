/// OpenLiteSpeed web server management.
/// Handles installation, configuration, virtual host management, and lifecycle operations.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const OLS_VHOST_DIR: &str = "/usr/local/lsws/conf/vhosts";
const OLS_BIN: &str = "/usr/local/lsws/bin/lswsctrl";
const LSPHP_BIN: &str = "/usr/local/lsws/lsphp83/bin/lsphp";

/// OpenLiteSpeed service manager.
pub struct OpenLiteSpeedService;

#[async_trait]
impl ManagedService for OpenLiteSpeedService {
    fn service_type(&self) -> ServiceType {
        ServiceType::OpenLiteSpeed
    }

    /// Install OpenLiteSpeed from official LiteSpeed repository.
    async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing OpenLiteSpeed...");

        // Add LiteSpeed repository via apt (no downloading and executing remote scripts).
        shell::exec(
            "wget",
            &[
                "-O",
                "/etc/apt/trusted.gpg.d/lst_debian_repo.gpg",
                "https://repo.litespeed.sh/lst_debian_repo.gpg",
            ],
        )
        .await?;

        // Write the repo source list rather than executing a remote script
        tokio::fs::write(
            "/etc/apt/sources.list.d/lst_debian_repo.list",
            "deb http://rpms.litespeedtech.com/debian/ bookworm main\n",
        )
        .await
        .map_err(|e| ServiceError::IoError(e.to_string()))?;

        shell::exec("apt-get", &["update"]).await?;

        shell::exec(
            "apt-get",
            &[
                "install",
                "-y",
                "openlitespeed",
                "lsphp83",
                "lsphp83-mysql",
                "lsphp83-curl",
                "lsphp83-common",
                "lsphp83-opcache",
            ],
        )
        .await?;

        // Enable as systemd service
        shell::exec("systemctl", &["enable", "lsws"]).await?;

        info!("OpenLiteSpeed installed successfully");
        Ok(())
    }

    /// Start OpenLiteSpeed service.
    async fn start(&self) -> Result<(), ServiceError> {
        info!("Starting OpenLiteSpeed...");
        shell::exec("systemctl", &["start", "lsws"]).await?;
        Ok(())
    }

    /// Stop OpenLiteSpeed service.
    async fn stop(&self) -> Result<(), ServiceError> {
        info!("Stopping OpenLiteSpeed...");
        shell::exec("systemctl", &["stop", "lsws"]).await?;
        Ok(())
    }

    /// Restart OpenLiteSpeed (graceful).
    async fn restart(&self) -> Result<(), ServiceError> {
        info!("Restarting OpenLiteSpeed...");
        // Graceful restart via lswsctrl
        shell::exec(OLS_BIN, &["restart"]).await?;
        Ok(())
    }

    /// Get OpenLiteSpeed service status.
    async fn status(&self) -> Result<ServiceStatus, ServiceError> {
        match shell::exec("systemctl", &["is-active", "lsws"]).await {
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

    /// Check if OpenLiteSpeed is installed.
    async fn is_installed(&self) -> Result<bool, ServiceError> {
        Ok(Path::new(OLS_BIN).exists())
    }

    /// Get OpenLiteSpeed version.
    async fn version(&self) -> Result<String, ServiceError> {
        // Use lshttpd -v which prints the version on the first line
        let output = shell::exec("/usr/local/lsws/bin/lshttpd", &["-v"]).await?;
        let raw = String::from_utf8_lossy(&output.stdout);
        let version = raw.lines().next().unwrap_or("").trim().to_string();
        Ok(version)
    }
}

impl OpenLiteSpeedService {
    /// Create a virtual host configuration.
    pub async fn create_vhost(
        &self,
        domain: &str,
        doc_root: &str,
        php_enabled: bool,
    ) -> Result<(), ServiceError> {
        // Defense-in-depth: validate inputs at the service layer
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_safe_path(doc_root, "/home/")
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        info!("Creating virtual host for domain: {}", domain);

        let vhost_dir = format!("{}/{}", OLS_VHOST_DIR, domain);
        fs::create_dir_all(&vhost_dir)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Generate config without HSTS/force-HTTPS; these are applied later
        // via update_vhost_config once SSL is issued.
        let vhost_config = self.generate_vhost_config(
            domain,
            doc_root,
            php_enabled,
            false,
            false,
            31536000,
            false,
            false,
        )?;
        let config_path = format!("{}/vhconf.conf", vhost_dir);

        fs::write(&config_path, vhost_config)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        // Create document root
        fs::create_dir_all(doc_root)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        info!("Virtual host {} created", domain);
        Ok(())
    }

    /// Regenerate the vhost config for an existing domain, applying updated
    /// force_https and HSTS settings.  Called after SSL settings change.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_vhost_config(
        &self,
        domain: &str,
        doc_root: &str,
        php_enabled: bool,
        force_https: bool,
        hsts_enabled: bool,
        hsts_max_age: i64,
        hsts_include_subdomains: bool,
        hsts_preload: bool,
    ) -> Result<(), ServiceError> {
        // Defense-in-depth: validate at service layer
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_safe_path(doc_root, "/home/")
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        let vhost_config = self.generate_vhost_config(
            domain,
            doc_root,
            php_enabled,
            force_https,
            hsts_enabled,
            hsts_max_age,
            hsts_include_subdomains,
            hsts_preload,
        )?;
        let config_path = format!("{}/{}/vhconf.conf", OLS_VHOST_DIR, domain);
        fs::write(&config_path, vhost_config)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        info!(
            "Updated vhost config for {} (force_https={}, hsts={})",
            domain, force_https, hsts_enabled
        );
        Ok(())
    }

    /// Delete a virtual host.
    pub async fn delete_vhost(&self, domain: &str) -> Result<(), ServiceError> {
        info!("Deleting virtual host for domain: {}", domain);

        let vhost_dir = format!("{}/{}", OLS_VHOST_DIR, domain);
        fs::remove_dir_all(&vhost_dir)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;

        info!("Virtual host {} deleted", domain);
        Ok(())
    }

    /// Generate virtual host configuration.
    ///
    /// - `force_https`: emit a rewrite rule that redirects all HTTP requests to HTTPS.
    /// - `hsts_enabled`: emit a `Strict-Transport-Security` response header.
    ///   Only meaningful when `force_https` is also `true`.
    /// - `hsts_max_age`: `max-age` value in seconds (minimum 31536000 for preload).
    /// - `hsts_include_subdomains`: append `; includeSubDomains` to the header.
    /// - `hsts_preload`: append `; preload` to the header.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_vhost_config(
        &self,
        domain: &str,
        doc_root: &str,
        php_enabled: bool,
        force_https: bool,
        hsts_enabled: bool,
        hsts_max_age: i64,
        hsts_include_subdomains: bool,
        hsts_preload: bool,
    ) -> Result<String, ServiceError> {
        // Defense-in-depth: reject values containing newlines that could inject config directives
        if domain.contains('\n')
            || domain.contains('\r')
            || doc_root.contains('\n')
            || doc_root.contains('\r')
        {
            return Err(ServiceError::CommandFailed(
                "Domain and doc_root must not contain newlines".to_string(),
            ));
        }
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_safe_path(doc_root, "/home/")
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        let vhost_name = format!("vhost_{}", domain.replace(".", "_"));
        let php_handler = if php_enabled {
            format!(
                r#"
  <context /cgi-bin/>
    <location                   /var/www/cgi-bin/>
    <allowBrowse                0
    <enableScript               1
    <cgi>
      <handler>
        <suffix>php</suffix>
        <handlerType>lsapi</handlerType>
        <handlerPath>{}</handlerPath>
      </handler>
    </cgi>
  </context>
"#,
                LSPHP_BIN
            )
        } else {
            String::new()
        };

        // HTTP → HTTPS redirect rewrite block (force_https).
        let force_https_block = if force_https {
            // RewriteCond + RewriteRule on separate lines inside the rules value.
            concat!(
                "rewrite {\n",
                "  enable                  1\n",
                "  rules                   RewriteCond %{HTTPS} !on\n",
                "                          RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]\n",
                "}\n"
            ).to_string()
        } else {
            String::new()
        };

        // HSTS response header inside the root context block.
        let hsts_header = if hsts_enabled {
            let mut value = format!("Strict-Transport-Security: max-age={}", hsts_max_age);
            if hsts_include_subdomains {
                value.push_str("; includeSubDomains");
            }
            if hsts_preload {
                value.push_str("; preload");
            }
            format!("  addHeader               \"{value}\"\n")
        } else {
            String::new()
        };

        let config = format!(
            r#"docRoot                {doc_root}/public
vhName                 {vhost_name}
vhDomain               {domain}
adminEmails            admin@{domain}
enableScript           1
restrained             0
allowSymbolLink        1
enableWebsocket        1

accessLog              /usr/local/lsws/logs/{domain}.access.log {{
  useServer             0
  logFormat             combined
  rollingSize           10M
  keepDays              30
}}

errorLog               /usr/local/lsws/logs/{domain}.error.log {{
  useServer             0
  logLevel              NOTICE
  rollingSize           10M
  keepDays              30
}}

{force_https_block}
<context />
  <location                   />
  <allowBrowse                0
  <handlerType>static</handlerType>
  <indexFiles>index.html, index.php</indexFiles>
{hsts_header}  <cgi>
    <handler>
      <suffix>php</suffix>
      <handlerType>lsapi</handlerType>
      <handlerPath>{lsphp_bin}</handlerPath>
    </handler>
  </cgi>
</context>

<context /images/>
  <location                   images/
  <allowBrowse                1
  <handlerType>static</handlerType>
  <cgi>
    <handler>
      <suffix>php</suffix>
      <handlerType>lsapi</handlerType>
      <handlerPath>{lsphp_bin}</handlerPath>
    </handler>
  </cgi>
</context>

<context /static/>
  <location                   static/
  <allowBrowse                1
  <handlerType>static</handlerType>
</context>
{php_handler}
<errorPages>
  <errorPage404>404.html</errorPage404>
</errorPages>
"#,
            doc_root = doc_root,
            vhost_name = vhost_name,
            domain = domain,
            lsphp_bin = LSPHP_BIN,
            force_https_block = force_https_block,
            hsts_header = hsts_header,
            php_handler = php_handler
        );

        Ok(config)
    }

    /// Generate an OpenLiteSpeed context block for serving phpMyAdmin at /phpmyadmin/.
    pub fn generate_phpmyadmin_context(pma_install_path: &str) -> String {
        format!(
            r#"
context /phpmyadmin/ {{
  location                {}/
  allowBrowse             1
  enableScript            1

  rewrite  {{
  }}

  addDefaultCharset       off

  phpIniOverride  {{
  }}
}}
"#,
            pma_install_path
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_vhost_config() {
        let svc = OpenLiteSpeedService;
        let config = svc
            .generate_vhost_config(
                "example.com",
                "/home/user/sites/example.com",
                true,
                false,
                false,
                31536000,
                false,
                false,
            )
            .expect("Failed to generate config");

        assert!(config.contains("example.com"));
        assert!(config.contains("/home/user/sites/example.com/public"));
        assert!(config.contains("lsphp83"));
    }

    #[test]
    fn test_generate_vhost_config_force_https() {
        let svc = OpenLiteSpeedService;
        let config = svc
            .generate_vhost_config(
                "example.com",
                "/home/user/sites/example.com",
                false,
                true,
                false,
                31536000,
                false,
                false,
            )
            .expect("Failed to generate config");

        assert!(config.contains("RewriteCond %{HTTPS} !on"));
        assert!(config.contains("https://%{HTTP_HOST}%{REQUEST_URI}"));
        assert!(config.contains("R=301"));
        assert!(!config.contains("Strict-Transport-Security"));
    }

    #[test]
    fn test_generate_vhost_config_hsts() {
        let svc = OpenLiteSpeedService;
        // HSTS with includeSubDomains + preload.
        let config = svc
            .generate_vhost_config(
                "example.com",
                "/home/user/sites/example.com",
                false,
                true,
                true,
                63072000,
                true,
                true,
            )
            .expect("Failed to generate config");

        assert!(config
            .contains("Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"));
    }

    #[test]
    fn test_generate_vhost_config_hsts_no_preload() {
        let svc = OpenLiteSpeedService;
        // HSTS without preload, without includeSubDomains.
        let config = svc
            .generate_vhost_config(
                "secure.example.com",
                "/home/user/sites/secure.example.com",
                false,
                true,
                true,
                31536000,
                false,
                false,
            )
            .expect("Failed to generate config");

        assert!(config.contains("Strict-Transport-Security: max-age=31536000\""));
        assert!(!config.contains("includeSubDomains"));
        assert!(!config.contains("preload"));
    }

    #[test]
    fn test_generate_phpmyadmin_context() {
        let config = OpenLiteSpeedService::generate_phpmyadmin_context("/usr/share/phpmyadmin");
        assert!(config.contains("/phpmyadmin/"));
        assert!(config.contains("/usr/share/phpmyadmin/"));
    }
}

impl OpenLiteSpeedService {
    /// Configure an HTTPS listener for the panel itself.
    /// Writes a dedicated SSL virtual host config that proxies to the
    /// panel's backend port and uses the provided Let's Encrypt cert.
    pub async fn configure_panel_ssl(
        &self,
        hostname: &str,
        cert_path: &str,
        key_path: &str,
        backend_port: u16,
    ) -> Result<(), super::ServiceError> {
        let vhost_dir = "/usr/local/lsws/conf/vhosts";
        let config_path = format!("{}/panel_ssl.conf", vhost_dir);
        let config = format!(
            r#"virtualhost panel_ssl {{
  vhDomain                {hostname}
  vhAliases               www.{hostname}
  vhRoot                  /usr/local/lsws/html
  allowSymbolLink         1
  enableScript            1
  restrained              0
  setUIDMode              0
  listener SSL {{
    address                *:8443
    secure                 1
    keyFile                {key_path}
    certFile               {cert_path}
  }}
  rewrite {{
    enable                 1
    rules                  RewriteRule ^(.*)$ http://127.0.0.1:{backend_port}$1 [P,L]
  }}
}}
"#,
            hostname = hostname,
            cert_path = cert_path,
            key_path = key_path,
            backend_port = backend_port,
        );
        tokio::fs::write(&config_path, config)
            .await
            .map_err(|e| super::ServiceError::IoError(e.to_string()))?;
        Ok(())
    }
}
