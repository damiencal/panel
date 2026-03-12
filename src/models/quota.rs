use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Resource quota allocation for a user (Reseller or Client).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct ResourceQuota {
    pub id: i64,
    pub user_id: i64,
    /// Max clients for Resellers only
    pub max_clients: Option<i32>,
    pub max_sites: i32,
    pub max_databases: i32,
    pub max_email_accounts: i32,
    pub disk_limit_mb: i64,
    pub bandwidth_limit_mb: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Current resource usage for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct ResourceUsage {
    pub id: i64,
    pub user_id: i64,
    pub sites_used: i32,
    pub databases_used: i32,
    pub email_accounts_used: i32,
    pub disk_used_mb: i64,
    pub bandwidth_used_mb: i64,
    pub updated_at: DateTime<Utc>,
}

/// Combined quota and usage information for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaStatus {
    pub quota: ResourceQuota,
    pub usage: ResourceUsage,
    pub sites_percent: f32,
    pub databases_percent: f32,
    pub email_accounts_percent: f32,
    pub disk_percent: f32,
    pub bandwidth_percent: f32,
}

impl QuotaStatus {
    /// Calculate percentages from quota and usage.
    pub fn new(quota: ResourceQuota, usage: ResourceUsage) -> Self {
        let sites_percent = if quota.max_sites > 0 {
            (usage.sites_used as f32 / quota.max_sites as f32) * 100.0
        } else {
            0.0
        };
        let databases_percent = if quota.max_databases > 0 {
            (usage.databases_used as f32 / quota.max_databases as f32) * 100.0
        } else {
            0.0
        };
        let email_accounts_percent = if quota.max_email_accounts > 0 {
            (usage.email_accounts_used as f32 / quota.max_email_accounts as f32) * 100.0
        } else {
            0.0
        };
        let disk_percent = if quota.disk_limit_mb > 0 {
            (usage.disk_used_mb as f32 / quota.disk_limit_mb as f32) * 100.0
        } else {
            0.0
        };
        let bandwidth_percent = if quota.bandwidth_limit_mb > 0 {
            (usage.bandwidth_used_mb as f32 / quota.bandwidth_limit_mb as f32) * 100.0
        } else {
            0.0
        };

        Self {
            quota,
            usage,
            sites_percent,
            databases_percent,
            email_accounts_percent,
            disk_percent,
            bandwidth_percent,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllocateQuotaRequest {
    pub user_id: i64,
    pub max_clients: Option<i32>,
    pub max_sites: i32,
    pub max_databases: i32,
    pub max_email_accounts: i32,
    pub disk_limit_mb: i64,
    pub bandwidth_limit_mb: i64,
}
