use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum MetricType {
    #[serde(rename = "Bandwidth")]
    Bandwidth,
    #[serde(rename = "Storage")]
    Storage,
    #[serde(rename = "CPU")]
    Cpu,
    #[serde(rename = "Memory")]
    Memory,
}

/// Individual usage log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct UsageLog {
    pub id: i64,
    pub user_id: i64,
    pub site_id: Option<i64>,
    pub metric_type: MetricType,
    pub value_mb: i64,
    pub recorded_at: DateTime<Utc>,
}

/// Daily aggregated usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct DailyAggregate {
    pub id: i64,
    pub user_id: i64,
    pub date: NaiveDate,
    pub bandwidth_used_mb: i64,
    pub storage_used_mb: i64,
}

/// Monthly usage snapshot (for billing).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct MonthlySnapshot {
    pub id: i64,
    pub user_id: i64,
    pub year: i32,
    pub month: i32,
    pub bandwidth_used_mb: i64,
    pub storage_peak_mb: i64,
}

/// Billing report/invoice information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingReport {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub bandwidth_gb: f64,
    pub storage_gb: f64,
    pub overages: Vec<Overage>,
    pub total_amount: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overage {
    pub metric: String,
    pub amount: f64,
    pub unit_price: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UsageStats {
    pub current_bandwidth_gb: f64,
    pub current_storage_gb: f64,
    pub month_bandwidth_gb: f64,
    pub month_storage_peak_gb: f64,
}
