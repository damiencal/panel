use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Hosting package/plan definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct Package {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    /// User who created this package (Admin or Reseller)
    pub created_by: i64,
    pub max_sites: i32,
    pub max_databases: i32,
    pub max_email_accounts: i32,
    pub max_ftp_accounts: i32,
    pub disk_limit_mb: i64,
    pub bandwidth_limit_mb: i64,
    pub max_subdomains: i32,
    pub max_addon_domains: i32,
    pub php_enabled: bool,
    pub ssl_enabled: bool,
    pub shell_access: bool,
    pub backup_enabled: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Request to create or update a package.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePackageRequest {
    pub name: String,
    pub description: Option<String>,
    pub max_sites: i32,
    pub max_databases: i32,
    pub max_email_accounts: i32,
    pub max_ftp_accounts: i32,
    pub disk_limit_mb: i64,
    pub bandwidth_limit_mb: i64,
    pub max_subdomains: i32,
    pub max_addon_domains: i32,
    pub php_enabled: bool,
    pub ssl_enabled: bool,
    pub shell_access: bool,
    pub backup_enabled: bool,
}

impl From<CreatePackageRequest> for Package {
    fn from(req: CreatePackageRequest) -> Self {
        Self {
            id: 0,
            name: req.name,
            description: req.description,
            created_by: 0,
            max_sites: req.max_sites,
            max_databases: req.max_databases,
            max_email_accounts: req.max_email_accounts,
            max_ftp_accounts: req.max_ftp_accounts,
            disk_limit_mb: req.disk_limit_mb,
            bandwidth_limit_mb: req.bandwidth_limit_mb,
            max_subdomains: req.max_subdomains,
            max_addon_domains: req.max_addon_domains,
            php_enabled: req.php_enabled,
            ssl_enabled: req.ssl_enabled,
            shell_access: req.shell_access,
            backup_enabled: req.backup_enabled,
            is_active: true,
            created_at: Utc::now(),
        }
    }
}
