/// OpenLiteSpeed web server management.
/// Handles installation, configuration, virtual host management, and lifecycle operations.
use super::{shell, ManagedService, ServiceError};
use crate::models::service::{ServiceStatus, ServiceType};
use crate::models::site::SiteType;
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use tracing::info;

const OLS_VHOST_DIR: &str = "/usr/local/lsws/conf/vhosts";
const OLS_BIN: &str = "/usr/local/lsws/bin/lswsctrl";
/// Default lsphp binary — used as a fallback when a site has no php_version set.
const LSPHP_BIN: &str = "/usr/local/lsws/lsphp83/bin/lsphp";

/// PHP versions available from the official LiteSpeed repository for Debian bookworm.
/// Only these values are accepted when installing or assigning a PHP version.
pub const SUPPORTED_PHP_VERSIONS: &[&str] = crate::models::site::SUPPORTED_PHP_VERSIONS;

/// Convert a dot-separated version string (`"8.3"`) to the package/path suffix (`"83"`).
/// Validates that both parts are purely numeric; returns `None` on any invalid input.
fn version_to_pkg_suffix(version: &str) -> Option<String> {
    let (major, minor) = version.split_once('.')?;
    if major.is_empty()
        || minor.is_empty()
        || !major.chars().all(|c| c.is_ascii_digit())
        || !minor.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some(format!("{}{}", major, minor))
}

/// Absolute path to the lsphp binary for `version` (e.g. `"8.3"` →
/// `"/usr/local/lsws/lsphp83/bin/lsphp"`).  Returns `None` for unrecognised formats.
pub fn lsphp_bin_path(version: &str) -> Option<String> {
    version_to_pkg_suffix(version).map(|s| format!("/usr/local/lsws/lsphp{}/bin/lsphp", s))
}

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
        site_type: SiteType,
        php_version: Option<&str>,
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
            site_type,
            false,
            false,
            31536000,
            false,
            false,
            php_version,
            None,
            None,
            false,
            "Restricted",
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
    /// SSL, HSTS, and Basic Auth settings.  Called after any of these change.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_vhost_config(
        &self,
        domain: &str,
        doc_root: &str,
        site_type: SiteType,
        force_https: bool,
        hsts_enabled: bool,
        hsts_max_age: i64,
        hsts_include_subdomains: bool,
        hsts_preload: bool,
        php_version: Option<&str>,
        // Path to the fullchain.pem file (Let's Encrypt or custom cert).
        ssl_cert_path: Option<&str>,
        // Path to the privkey.pem file.
        ssl_key_path: Option<&str>,
        basic_auth_enabled: bool,
        basic_auth_realm: &str,
    ) -> Result<(), ServiceError> {
        // Defense-in-depth: validate at service layer
        crate::utils::validators::validate_domain(domain)
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;
        crate::utils::validators::validate_safe_path(doc_root, "/home/")
            .map_err(|e| ServiceError::CommandFailed(e.to_string()))?;

        let vhost_config = self.generate_vhost_config(
            domain,
            doc_root,
            site_type,
            force_https,
            hsts_enabled,
            hsts_max_age,
            hsts_include_subdomains,
            hsts_preload,
            php_version,
            ssl_cert_path,
            ssl_key_path,
            basic_auth_enabled,
            basic_auth_realm,
        )?;
        let config_path = format!("{}/{}/vhconf.conf", OLS_VHOST_DIR, domain);
        fs::write(&config_path, vhost_config)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        info!(
            "Updated vhost config for {} (force_https={}, hsts={}, basic_auth={})",
            domain, force_https, hsts_enabled, basic_auth_enabled
        );
        Ok(())
    }

    /// Return the list of PHP versions that are currently installed on the system
    /// by checking for the lsphp binary on disk for each supported version.
    pub async fn list_installed_php_versions(&self) -> Result<Vec<String>, ServiceError> {
        let mut installed = Vec::new();
        for &ver in SUPPORTED_PHP_VERSIONS {
            if let Some(bin) = lsphp_bin_path(ver) {
                if Path::new(&bin).exists() {
                    installed.push(ver.to_string());
                }
            }
        }
        Ok(installed)
    }

    /// Install a specific PHP version from the official LiteSpeed repository.
    /// Only versions listed in `SUPPORTED_PHP_VERSIONS` are accepted.
    pub async fn install_php_version(&self, version: &str) -> Result<(), ServiceError> {
        // Defense-in-depth: reject anything not in the known-good list.
        if !SUPPORTED_PHP_VERSIONS.contains(&version) {
            return Err(ServiceError::CommandFailed(format!(
                "Unsupported PHP version: {version}"
            )));
        }
        let s = version_to_pkg_suffix(version).ok_or_else(|| {
            ServiceError::CommandFailed(format!("Invalid PHP version format: {version}"))
        })?;
        info!("Installing PHP {version} (lsphp{s})...");
        shell::exec(
            "apt-get",
            &[
                "install",
                "-y",
                &format!("lsphp{s}"),
                &format!("lsphp{s}-mysql"),
                &format!("lsphp{s}-curl"),
                &format!("lsphp{s}-common"),
                &format!("lsphp{s}-opcache"),
            ],
        )
        .await?;
        info!("PHP {version} installed successfully");
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
    /// - `site_type`: determines rewrite rules, PHP handler, and caching.  Use
    ///   `WordPress` for WP sites (permalink rewrites, security blocks, PHP),
    ///   `Static` for asset-only sites (no PHP, CORS headers, max cache), and
    ///   `Php` (or any other variant) for a generic PHP config.
    /// - `force_https`: redirect all HTTP requests to HTTPS.
    /// - `hsts_enabled`: emit a `Strict-Transport-Security` response header.
    ///   Only meaningful when `force_https` is also `true`.
    /// - `hsts_max_age`: `max-age` value in seconds (minimum 31536000 for preload).
    /// - `hsts_include_subdomains`: append `; includeSubDomains` to the header.
    /// - `hsts_preload`: append `; preload` to the header.
    /// - `php_version`: optional version string (e.g. `"8.3"`). Falls back to `LSPHP_BIN` if `None`.
    /// - `ssl_cert_path`: path to the fullchain PEM (Let's Encrypt or custom).
    ///   When provided together with `ssl_key_path`, an `ssl { }` block is added
    ///   so OLS can use SNI to serve this domain over HTTPS.
    /// - `ssl_key_path`: path to the private key PEM.
    /// - `basic_auth_enabled`: protect the entire site with HTTP Basic Auth.
    /// - `basic_auth_realm`: realm label shown in the browser auth dialog.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_vhost_config(
        &self,
        domain: &str,
        doc_root: &str,
        site_type: SiteType,
        force_https: bool,
        hsts_enabled: bool,
        hsts_max_age: i64,
        hsts_include_subdomains: bool,
        hsts_preload: bool,
        php_version: Option<&str>,
        ssl_cert_path: Option<&str>,
        ssl_key_path: Option<&str>,
        basic_auth_enabled: bool,
        basic_auth_realm: &str,
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

        // Validate SSL cert/key paths if provided.
        if let (Some(cert), Some(key)) = (ssl_cert_path, ssl_key_path) {
            if cert.contains('\n')
                || cert.contains('\r')
                || key.contains('\n')
                || key.contains('\r')
            {
                return Err(ServiceError::CommandFailed(
                    "SSL cert/key paths must not contain newlines".to_string(),
                ));
            }
            // Reject paths that don't look like absolute paths pointing to known cert dirs.
            if !cert.starts_with("/etc/letsencrypt/") && !cert.starts_with("/etc/ssl/panel/") {
                return Err(ServiceError::CommandFailed(format!(
                    "SSL cert path '{}' is outside permitted directories",
                    cert
                )));
            }
            if !key.starts_with("/etc/letsencrypt/") && !key.starts_with("/etc/ssl/panel/") {
                return Err(ServiceError::CommandFailed(format!(
                    "SSL key path '{}' is outside permitted directories",
                    key
                )));
            }
        }

        // Validate Basic Auth realm: no newlines or quotes that could escape the config block.
        let safe_realm: String = basic_auth_realm
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'))
            .collect();

        let vhost_name = format!("vhost_{}", domain.replace('.', "_"));

        // Resolve the lsphp binary path from the requested version, falling back to
        // the compile-time default when no version is stored for this site.
        let lsphp_bin = php_version
            .and_then(lsphp_bin_path)
            .unwrap_or_else(|| LSPHP_BIN.to_string());

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

        // SSL block: added when both cert and key paths are provided.
        // This configures per-vhost SNI-based SSL in OpenLiteSpeed.
        let ssl_block = if let (Some(cert), Some(key)) = (ssl_cert_path, ssl_key_path) {
            format!(
                "ssl {{\n  keyFile                 {key}\n  certFile                {cert}\n  sslProtocol             24\n}}\n\n",
                cert = cert,
                key = key,
            )
        } else {
            String::new()
        };

        // Basic Auth realm block: protects the root context with htpasswd.
        let htpasswd_path = crate::services::basic_auth::htpasswd_path(domain);
        let (basic_auth_realm_block, basic_auth_context_directive) = if basic_auth_enabled {
            let realm_block = format!(
                "<realm {realm}>\n\
                 <userDB>\n\
                 <location     {htpasswd}>\n\
                 <maxCacheSize 200>\n\
                 <cacheTimeout 60>\n\
                 </userDB>\n\
                 </realm>\n\n",
                realm = safe_realm,
                htpasswd = htpasswd_path,
            );
            let ctx_line = format!("  realm                   {}\n", safe_realm);
            (realm_block, ctx_line)
        } else {
            (String::new(), String::new())
        };

        let config = match site_type {
            SiteType::WordPress => Self::wordpress_vhost(
                domain,
                doc_root,
                &vhost_name,
                force_https,
                &hsts_header,
                &lsphp_bin,
                &ssl_block,
                &basic_auth_realm_block,
                &basic_auth_context_directive,
            ),
            SiteType::Static => Self::static_vhost(
                domain,
                doc_root,
                &vhost_name,
                force_https,
                &hsts_header,
                &ssl_block,
                &basic_auth_realm_block,
                &basic_auth_context_directive,
            ),
            _ => Self::php_vhost(
                domain,
                doc_root,
                &vhost_name,
                force_https,
                &hsts_header,
                &lsphp_bin,
                &ssl_block,
                &basic_auth_realm_block,
                &basic_auth_context_directive,
            ),
        };

        Ok(config)
    }

    /// Build a `rewrite { }` block from an ordered list of rule lines.
    /// The first rule is placed inline with the `rules` key; subsequent lines
    /// are indented to the same column.  Returns an empty string if `rules` is
    /// empty.
    fn build_rewrite_block(rules: &[&str]) -> String {
        if rules.is_empty() {
            return String::new();
        }
        let mut iter = rules.iter();
        let first = iter.next().unwrap();
        let rest: String = iter
            .map(|r| format!("\n                          {r}"))
            .collect();
        format!("rewrite {{\n  enable                  1\n  rules                   {first}{rest}\n}}\n\n")
    }

    /// Shared log block used by all vhost types.
    fn log_block(domain: &str) -> String {
        format!(
            "accessLog              /usr/local/lsws/logs/{domain}.access.log {{\n\
  useServer             0\n\
  logFormat             combined\n\
  rollingSize           10M\n\
  keepDays              30\n\
}}\n\n\
errorLog               /usr/local/lsws/logs/{domain}.error.log {{\n\
  useServer             0\n\
  logLevel              NOTICE\n\
  rollingSize           10M\n\
  keepDays              30\n\
}}\n\n",
            domain = domain,
        )
    }

    /// Static-asset cache block used by WordPress and Static site types.
    /// Sets CORS, gzip/brotli compression, and a far-future cache expiry for
    /// all common static file extensions, inspired by the CloudPanel nginx
    /// WordPress and Static vhost templates.
    fn asset_cache_block() -> &'static str {
        concat!(
            "<staticContext>\n",
            "  <suffix>css, js, jpg, jpeg, gif, png, ico, gz, svg, svgz, ttf, otf, woff, woff2, eot, mp4, ogg, ogv, webm, webp, zip, swf</suffix>\n",
            "  <location                   /\n",
            "  <enableBr                   1\n",
            "  <enableGzip               1\n",
            "  <gzipCompLevel            5\n",
            "  <addHeader                \"Access-Control-Allow-Origin: *\"\n",
            "  <cacheExpire              max\n",
            "</staticContext>\n\n",
            "<expires>\n",
            "  <enableExpires             1\n",
            "  <expiresByType>\n",
            "    <type>image/*</type>\n",
            "    <expireSeconds>31536000</expireSeconds>\n",
            "  </expiresByType>\n",
            "  <expiresByType>\n",
            "    <type>text/css</type>\n",
            "    <expireSeconds>31536000</expireSeconds>\n",
            "  </expiresByType>\n",
            "  <expiresByType>\n",
            "    <type>application/javascript</type>\n",
            "    <expireSeconds>31536000</expireSeconds>\n",
            "  </expiresByType>\n",
            "  <expiresByType>\n",
            "    <type>font/*</type>\n",
            "    <expireSeconds>31536000</expireSeconds>\n",
            "  </expiresByType>\n",
            "</expires>\n"
        )
    }

    /// Generate an OLS vhost config optimised for WordPress.
    ///
    /// Inspired by the CloudPanel nginx WordPress vhost template:
    /// - Blocks `xmlrpc.php`, `wp-config.php`, dotfiles, and `.git`.
    /// - WordPress pretty-permalink rewrite (`try_files` equivalent).
    /// - WordPress Multisite subdirectory support.
    /// - PHP via lsapi.
    /// - Far-future cache expiry + CORS for static assets.
    /// - Dedicated `/.well-known/` context for ACME challenges.
    #[allow(clippy::too_many_arguments)]
    fn wordpress_vhost(
        domain: &str,
        doc_root: &str,
        vhost_name: &str,
        force_https: bool,
        hsts_header: &str,
        lsphp_bin: &str,
        ssl_block: &str,
        basic_auth_realm_block: &str,
        basic_auth_context_directive: &str,
    ) -> String {
        let mut rules: Vec<&str> = Vec::new();
        if force_https {
            rules.push("RewriteCond %{HTTPS} !on");
            rules.push("RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]");
        }
        // Security: block sensitive files
        rules.extend(&[
            r"RewriteRule ^xmlrpc\.php$ - [F,L]",
            r"RewriteRule ^wp-config\.php$ - [F,L]",
            r"RewriteRule ^\.env - [F,L]",
            r"RewriteRule ^\.ht - [F,L]",
            r"RewriteRule ^\.git - [F,L]",
            // WordPress Multisite subdirectory support
            r"RewriteRule ^[_0-9a-zA-Z-]+/wp-(.*) wp-$1 [L]",
            r"RewriteRule ^[_0-9a-zA-Z-]+/(.+\.php)$ $1 [L]",
            // WordPress pretty permalinks (try_files equivalent)
            r"RewriteRule ^index\.php$ - [L]",
            r"RewriteCond %{REQUEST_FILENAME} !-f",
            r"RewriteCond %{REQUEST_FILENAME} !-d",
            r"RewriteRule . /index.php [L]",
        ]);
        let rewrite_block = Self::build_rewrite_block(&rules);
        let logs = Self::log_block(domain);
        let cache = Self::asset_cache_block();

        format!(
            r#"docRoot                {doc_root}/public
vhName                 {vhost_name}
vhDomain               {domain}
adminEmails            admin@{domain}
enableScript           1
restrained             0
allowSymbolLink        1
enableWebsocket        1

{ssl_block}{logs}{rewrite_block}{basic_auth_realm_block}<context />
  <location                   />
  <allowBrowse                0
  <handlerType>static</handlerType>
  <indexFiles>index.php, index.html</indexFiles>
{hsts_header}{basic_auth_context_directive}  <cgi>
    <handler>
      <suffix>php</suffix>
      <handlerType>lsapi</handlerType>
      <handlerPath>{lsphp_bin}</handlerPath>
    </handler>
  </cgi>
</context>

<context /.well-known/>
  <location                   .well-known/
  <allowBrowse                1
  <handlerType>static</handlerType>
</context>

{cache}<errorPages>
  <errorPage404>404.html</errorPage404>
</errorPages>
"#,
            doc_root = doc_root,
            vhost_name = vhost_name,
            domain = domain,
            lsphp_bin = lsphp_bin,
            logs = logs,
            rewrite_block = rewrite_block,
            hsts_header = hsts_header,
            ssl_block = ssl_block,
            basic_auth_realm_block = basic_auth_realm_block,
            basic_auth_context_directive = basic_auth_context_directive,
            cache = cache,
        )
    }

    /// Generate an OLS vhost config for a purely static site.
    ///
    /// Inspired by the CloudPanel nginx Static vhost template:
    /// - Script execution disabled (`enableScript 0`).
    /// - `index.html` only; no PHP processing.
    /// - Dotfiles blocked.
    /// - Far-future cache expiry + CORS for static assets.
    /// - Dedicated `/.well-known/` context for ACME challenges.
    #[allow(clippy::too_many_arguments)]
    fn static_vhost(
        domain: &str,
        doc_root: &str,
        vhost_name: &str,
        force_https: bool,
        hsts_header: &str,
        ssl_block: &str,
        basic_auth_realm_block: &str,
        basic_auth_context_directive: &str,
    ) -> String {
        let mut rules: Vec<&str> = Vec::new();
        if force_https {
            rules.push("RewriteCond %{HTTPS} !on");
            rules.push("RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]");
        }
        // Block all dotfiles (hidden files / directories)
        rules.push(r"RewriteRule ^\. - [F,L]");
        let rewrite_block = Self::build_rewrite_block(&rules);
        let logs = Self::log_block(domain);
        let cache = Self::asset_cache_block();

        format!(
            r#"docRoot                {doc_root}/public
vhName                 {vhost_name}
vhDomain               {domain}
adminEmails            admin@{domain}
enableScript           0
restrained             0
allowSymbolLink        1
enableWebsocket        0

{ssl_block}{logs}{rewrite_block}{basic_auth_realm_block}<context />
  <location                   />
  <allowBrowse                0
  <handlerType>static</handlerType>
  <indexFiles>index.html, index.htm</indexFiles>
{hsts_header}{basic_auth_context_directive}</context>

<context /.well-known/>
  <location                   .well-known/
  <allowBrowse                1
  <handlerType>static</handlerType>
</context>

{cache}<errorPages>
  <errorPage404>404.html</errorPage404>
</errorPages>
"#,
            doc_root = doc_root,
            vhost_name = vhost_name,
            domain = domain,
            logs = logs,
            rewrite_block = rewrite_block,
            hsts_header = hsts_header,
            ssl_block = ssl_block,
            basic_auth_realm_block = basic_auth_realm_block,
            basic_auth_context_directive = basic_auth_context_directive,
            cache = cache,
        )
    }

    /// Generate a generic PHP-enabled OLS vhost config (used for `SiteType::Php`,
    /// `SiteType::ReverseProxy`, `SiteType::NodeJs`, and any future variants).
    #[allow(clippy::too_many_arguments)]
    fn php_vhost(
        domain: &str,
        doc_root: &str,
        vhost_name: &str,
        force_https: bool,
        hsts_header: &str,
        lsphp_bin: &str,
        ssl_block: &str,
        basic_auth_realm_block: &str,
        basic_auth_context_directive: &str,
    ) -> String {
        let force_https_block = if force_https {
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

        format!(
            r#"docRoot                {doc_root}/public
vhName                 {vhost_name}
vhDomain               {domain}
adminEmails            admin@{domain}
enableScript           1
restrained             0
allowSymbolLink        1
enableWebsocket        1

{ssl_block}accessLog              /usr/local/lsws/logs/{domain}.access.log {{
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
{basic_auth_realm_block}<context />
  <location                   />
  <allowBrowse                0
  <handlerType>static</handlerType>
  <indexFiles>index.html, index.php</indexFiles>
{hsts_header}{basic_auth_context_directive}  <cgi>
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

  <context /cgi-bin/>
    <location                   /var/www/cgi-bin/>
    <allowBrowse                0
    <enableScript               1
    <cgi>
      <handler>
        <suffix>php</suffix>
        <handlerType>lsapi</handlerType>
        <handlerPath>{lsphp_bin}</handlerPath>
      </handler>
    </cgi>
  </context>

<errorPages>
  <errorPage404>404.html</errorPage404>
</errorPages>
"#,
            doc_root = doc_root,
            vhost_name = vhost_name,
            domain = domain,
            lsphp_bin = lsphp_bin,
            force_https_block = force_https_block,
            hsts_header = hsts_header,
            ssl_block = ssl_block,
            basic_auth_realm_block = basic_auth_realm_block,
            basic_auth_context_directive = basic_auth_context_directive,
        )
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
    fn test_generate_vhost_config_php() {
        let svc = OpenLiteSpeedService;
        let config = svc
            .generate_vhost_config(
                "example.com",
                "/home/user/sites/example.com",
                SiteType::Php,
                false,
                false,
                31536000,
                false,
                false,
                None,
                None,
                None,
                false,
                "Restricted",
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
                SiteType::Static,
                true,
                false,
                31536000,
                false,
                false,
                None,
                None,
                None,
                false,
                "Restricted",
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
                SiteType::Static,
                true,
                true,
                63072000,
                true,
                true,
                None,
                None,
                None,
                false,
                "Restricted",
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
                SiteType::Static,
                true,
                true,
                31536000,
                false,
                false,
                None,
                None,
                None,
                false,
                "Restricted",
            )
            .expect("Failed to generate config");

        assert!(config.contains("Strict-Transport-Security: max-age=31536000\""));
        assert!(!config.contains("includeSubDomains"));
        assert!(!config.contains("preload"));
    }

    #[test]
    fn test_generate_wordpress_vhost() {
        let svc = OpenLiteSpeedService;
        let config = svc
            .generate_vhost_config(
                "blog.example.com",
                "/home/user/sites/blog.example.com",
                SiteType::WordPress,
                true,
                false,
                31536000,
                false,
                false,
                None,
                None,
                None,
                false,
                "Restricted",
            )
            .expect("Failed to generate WordPress config");

        // PHP handler present
        assert!(config.contains("lsphp83"));
        // WordPress permalink rewrite
        assert!(config.contains("RewriteRule ^index\\.php$ - [L]"));
        assert!(config.contains("RewriteCond %{REQUEST_FILENAME} !-f"));
        assert!(config.contains("RewriteCond %{REQUEST_FILENAME} !-d"));
        assert!(config.contains("RewriteRule . /index.php [L]"));
        // Security blocks
        assert!(config.contains("RewriteRule ^xmlrpc\\.php$ - [F,L]"));
        assert!(config.contains("RewriteRule ^wp-config\\.php$ - [F,L]"));
        assert!(config.contains("RewriteRule ^\\.env - [F,L]"));
        assert!(config.contains("RewriteRule ^\\.ht - [F,L]"));
        // WordPress Multisite subdirectory
        assert!(config.contains("RewriteRule ^[_0-9a-zA-Z-]+/wp-"));
        // ACME challenges context
        assert!(config.contains("/.well-known/"));
        // Static asset caching with CORS
        assert!(config.contains("Access-Control-Allow-Origin: *"));
        assert!(config.contains("cacheExpire"));
        // Force HTTPS
        assert!(config.contains("RewriteCond %{HTTPS} !on"));
        assert!(config.contains("R=301"));
        // No script execution disabled
        assert!(!config.contains("enableScript           0"));
    }

    #[test]
    fn test_generate_static_vhost() {
        let svc = OpenLiteSpeedService;
        let config = svc
            .generate_vhost_config(
                "static.example.com",
                "/home/user/sites/static.example.com",
                SiteType::Static,
                false,
                false,
                31536000,
                false,
                false,
                None,
                None,
                None,
                false,
                "Restricted",
            )
            .expect("Failed to generate Static config");

        // No PHP
        assert!(!config.contains("lsphp83"));
        assert!(config.contains("enableScript           0"));
        // Static-only index
        assert!(config.contains("index.html"));
        assert!(!config.contains("index.php"));
        // Dotfile block
        assert!(config.contains("RewriteRule ^\\. - [F,L]"));
        // ACME challenges context
        assert!(config.contains("/.well-known/"));
        // CORS + cache
        assert!(config.contains("Access-Control-Allow-Origin: *"));
        assert!(config.contains("cacheExpire"));
    }

    #[test]
    fn test_generate_vhost_ssl_block() {
        let svc = OpenLiteSpeedService;
        let config = svc
            .generate_vhost_config(
                "secure.example.com",
                "/home/user/sites/secure.example.com",
                SiteType::Php,
                true,
                false,
                31536000,
                false,
                false,
                None,
                Some("/etc/letsencrypt/live/secure.example.com/fullchain.pem"),
                Some("/etc/letsencrypt/live/secure.example.com/privkey.pem"),
                false,
                "Restricted",
            )
            .expect("Failed to generate config with SSL");

        assert!(config.contains("keyFile"));
        assert!(config.contains("certFile"));
        assert!(config.contains("/etc/letsencrypt/live/secure.example.com/privkey.pem"));
        assert!(config.contains("sslProtocol             24"));
    }

    #[test]
    fn test_generate_vhost_basic_auth() {
        let svc = OpenLiteSpeedService;
        let config = svc
            .generate_vhost_config(
                "private.example.com",
                "/home/user/sites/private.example.com",
                SiteType::Static,
                false,
                false,
                31536000,
                false,
                false,
                None,
                None,
                None,
                true,
                "Private Area",
            )
            .expect("Failed to generate config with Basic Auth");

        assert!(config.contains("Private Area"));
        assert!(config.contains("private.example.com.htpasswd"));
        assert!(config.contains("realm"));
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
