use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// PHP versions supported by the OpenLiteSpeed service layer.
/// Kept here (in models) so both the server and the WASM frontend can access it.
pub const SUPPORTED_PHP_VERSIONS: &[&str] = &["7.4", "8.0", "8.1", "8.2", "8.3", "8.4"];

/// Site type determines how OpenLiteSpeed handles the site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum SiteType {
    #[serde(rename = "Static")]
    Static,
    #[serde(rename = "PHP")]
    #[cfg_attr(feature = "server", sqlx(rename = "PHP"))]
    Php,
    #[serde(rename = "WordPress")]
    #[cfg_attr(feature = "server", sqlx(rename = "WordPress"))]
    WordPress,
    #[serde(rename = "ReverseProxy")]
    ReverseProxy,
    #[serde(rename = "NodeJS")]
    #[cfg_attr(feature = "server", sqlx(rename = "NodeJS"))]
    NodeJs,
}

impl std::fmt::Display for SiteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteType::Static => write!(f, "Static"),
            SiteType::Php => write!(f, "PHP"),
            SiteType::WordPress => write!(f, "WordPress"),
            SiteType::ReverseProxy => write!(f, "Reverse Proxy"),
            SiteType::NodeJs => write!(f, "Node.js"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum SiteStatus {
    #[serde(rename = "Active")]
    Active,
    #[serde(rename = "Suspended")]
    Suspended,
    #[serde(rename = "Inactive")]
    Inactive,
}

impl std::fmt::Display for SiteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteStatus::Active => write!(f, "Active"),
            SiteStatus::Suspended => write!(f, "Suspended"),
            SiteStatus::Inactive => write!(f, "Inactive"),
        }
    }
}

/// Website (OpenLiteSpeed virtual host).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct Site {
    pub id: i64,
    pub owner_id: i64,
    pub domain: String,
    pub doc_root: String,
    pub site_type: SiteType,
    pub status: SiteStatus,
    pub ssl_enabled: bool,
    pub ssl_certificate: Option<String>,
    pub ssl_private_key: Option<String>,
    pub ssl_issuer: Option<String>,
    pub ssl_expiry_date: Option<DateTime<Utc>>,
    pub force_https: bool,
    pub hsts_enabled: bool,
    pub hsts_max_age: i64,
    pub hsts_include_subdomains: bool,
    pub hsts_preload: bool,
    pub basic_auth_enabled: bool,
    pub basic_auth_realm: String,
    pub php_version: Option<String>,
    pub php_handler: Option<String>,
    pub proxy_target: Option<String>,
    pub ols_vhost_name: Option<String>,
    pub ols_listener_ports: Option<String>,
    pub max_connections: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSiteRequest {
    pub domain: String,
    pub site_type: SiteType,
    #[serde(default)]
    pub php_enabled: bool,
    #[serde(default = "default_true")]
    pub ssl_enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSiteRequest {
    pub site_type: Option<SiteType>,
    pub status: Option<SiteStatus>,
    pub ssl_enabled: Option<bool>,
    pub force_https: Option<bool>,
    pub hsts_enabled: Option<bool>,
    pub hsts_max_age: Option<i64>,
    pub hsts_include_subdomains: Option<bool>,
    pub hsts_preload: Option<bool>,
    pub php_version: Option<String>,
    pub max_connections: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SiteDetail {
    pub site: Site,
    pub ssl_days_until_expiry: Option<i64>,
    pub current_users: i32,
    pub bandwidth_this_month: i64,
}

/// A user in a site's HTTP Basic Authentication user database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct BasicAuthUser {
    pub id: i64,
    pub site_id: i64,
    pub username: String,
    /// APR1-MD5 or bcrypt hash in Apache htpasswd format. Never plaintext.
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}
