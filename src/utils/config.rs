/// Panel configuration management.
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub openlitespeed: OpenLiteSpeedConfig,
    pub certbot: CertbotConfig,
    #[serde(default)]
    pub phpmyadmin: PhpMyAdminConfig,
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    #[serde(default)]
    pub mariadb: MariaDbConfig,
    #[serde(default)]
    pub postfix: PostfixConfig,
    #[serde(default)]
    pub dovecot: DovecotConfig,
    #[serde(default)]
    pub ftp: FtpConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub request_security: RequestSecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenLiteSpeedConfig {
    pub config_dir: String,
    pub vhost_dir: String,
    pub lsphp_bin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertbotConfig {
    pub path: String,
    pub webroot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhpMyAdminConfig {
    pub enabled: bool,
    pub install_path: String,
    pub url_base_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    pub api_token: String,
    pub account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MariaDbConfig {
    pub bind_address: String,
    pub port: u16,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostfixConfig {
    pub hostname: String,
    pub virtual_mailbox_base: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DovecotConfig {
    pub mail_location: String,
    pub users_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpConfig {
    pub passive_port_min: u16,
    pub passive_port_max: u16,
    pub max_clients: u32,
    pub tls_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityConfig {
    /// Optional client IP allowlist for panel API/server-function requests.
    /// Empty means allow all client IPs.
    pub allowed_ips: Vec<String>,
    /// Maximum number of protected requests accepted per IP within the window.
    /// Set to 0 to disable request throttling.
    pub rate_limit_requests: u32,
    /// Rolling window, in seconds, for `rate_limit_requests`.
    pub rate_limit_window_secs: u64,
    /// Set to `true` only when the panel is deployed behind a trusted reverse proxy
    /// (e.g. Nginx or Caddy) that sets `X-Forwarded-For` to the real client IP.
    /// When `false` (default), `X-Forwarded-For` is ignored in the per-IP login rate
    /// limiter to prevent clients from spoofing IPs to bypass rate-limiting.
    #[serde(default)]
    pub trust_proxy_headers: bool,
}

impl Default for MariaDbConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 3306,
            max_connections: 100,
        }
    }
}

impl Default for PostfixConfig {
    fn default() -> Self {
        Self {
            hostname: std::env::var("HOSTNAME").unwrap_or_else(|_| "mail.localhost".to_string()),
            virtual_mailbox_base: "/var/mail/vhosts".to_string(),
        }
    }
}

impl Default for DovecotConfig {
    fn default() -> Self {
        Self {
            mail_location: "maildir:/var/mail/vhosts/%d/%n".to_string(),
            users_file: "/etc/dovecot/users".to_string(),
        }
    }
}

impl Default for FtpConfig {
    fn default() -> Self {
        Self {
            passive_port_min: 30000,
            passive_port_max: 50000,
            max_clients: 50,
            tls_required: false,
        }
    }
}

impl Default for RequestSecurityConfig {
    fn default() -> Self {
        Self {
            allowed_ips: Vec::new(),
            rate_limit_requests: 600,
            rate_limit_window_secs: 60,
            trust_proxy_headers: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Number of days to retain audit log entries. Defaults to 30.
    /// Compliance environments (PCI-DSS, HIPAA) typically require 90–365 days.
    pub log_retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_retention_days: 30,
        }
    }
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            api_token: std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default(),
            account_id: std::env::var("CLOUDFLARE_ACCOUNT_ID").ok(),
        }
    }
}

impl Default for PhpMyAdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            install_path: "/usr/share/phpmyadmin".to_string(),
            url_base_path: "/phpmyadmin".to_string(),
        }
    }
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3030,
                secret_key: std::env::var("PANEL_SECRET_KEY").unwrap_or_else(|_| {
                    // Generate a random key so JWTs are not trivially forgeable with an
                    // empty HMAC key. Sessions will not survive a process restart — operators
                    // must set PANEL_SECRET_KEY to a permanent value for production use.
                    use rand::RngCore;
                    let mut key_bytes = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut key_bytes);
                    let key = hex::encode(key_bytes);
                    eprintln!(
                        "WARNING: PANEL_SECRET_KEY is not set. \
                         A random key is being used — JWT sessions will be lost on restart. \
                         Fix: set PANEL_SECRET_KEY=$(openssl rand -base64 32) in your environment."
                    );
                    key
                }),
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "sqlite:panel.db".to_string()),
            },
            openlitespeed: OpenLiteSpeedConfig {
                config_dir: "/usr/local/lsws/conf".to_string(),
                vhost_dir: "/usr/local/lsws/conf/vhosts".to_string(),
                lsphp_bin: "/usr/local/lsws/lsphp83/bin/lsphp".to_string(),
            },
            certbot: CertbotConfig {
                path: "/usr/bin/certbot".to_string(),
                webroot: "/usr/local/lsws/html".to_string(),
            },
            phpmyadmin: PhpMyAdminConfig::default(),
            cloudflare: CloudflareConfig::default(),
            mariadb: MariaDbConfig::default(),
            postfix: PostfixConfig::default(),
            dovecot: DovecotConfig::default(),
            ftp: FtpConfig::default(),
            audit: AuditConfig::default(),
            request_security: RequestSecurityConfig::default(),
        }
    }
}

impl PanelConfig {
    /// Load configuration from TOML file or use defaults.
    pub async fn load(path: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(path) = path {
            if Path::new(path).exists() {
                let content = fs::read_to_string(path).await?;
                let config: PanelConfig = toml::from_str(&content)?;
                return Ok(config);
            }
        }

        Ok(Self::default())
    }

    /// Save configuration to TOML file.
    pub async fn save(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        let tmp = format!("{}.tmp.{}", path, std::process::id());
        fs::write(&tmp, &content).await?;
        fs::rename(&tmp, path).await?;
        Ok(())
    }
}
