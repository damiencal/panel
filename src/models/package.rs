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
    /// CPU quota in percent of one core (50 = 0.5 cores, 200 = 2 cores).
    pub cpu_quota_percent: i32,
    /// Maximum resident memory in megabytes (MemorySwapMax is always 0).
    pub memory_max_mb: i64,
    /// Maximum simultaneous OS threads/processes (systemd TasksMax).
    pub tasks_max: i32,
    /// Block IO relative weight 1-10000 (systemd IOWeight).
    pub io_weight: i32,
    /// Maximum simultaneous MariaDB connections for this account.
    pub max_db_connections: i32,
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
    /// CPU quota percent. Default: 50 (Starter).
    #[serde(default = "default_cpu_quota")]
    pub cpu_quota_percent: i32,
    /// Max memory in MB. Default: 512.
    #[serde(default = "default_memory_max_mb")]
    pub memory_max_mb: i64,
    /// Max tasks. Default: 40.
    #[serde(default = "default_tasks_max")]
    pub tasks_max: i32,
    /// IO weight. Default: 50.
    #[serde(default = "default_io_weight")]
    pub io_weight: i32,
    /// Max DB connections. Default: 5.
    #[serde(default = "default_max_db_connections")]
    pub max_db_connections: i32,
}

fn default_cpu_quota() -> i32 { 50 }
fn default_memory_max_mb() -> i64 { 512 }
fn default_tasks_max() -> i32 { 40 }
fn default_io_weight() -> i32 { 50 }
fn default_max_db_connections() -> i32 { 5 }

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
            cpu_quota_percent: req.cpu_quota_percent,
            memory_max_mb: req.memory_max_mb,
            tasks_max: req.tasks_max,
            io_weight: req.io_weight,
            max_db_connections: req.max_db_connections,
        }
    }
}
