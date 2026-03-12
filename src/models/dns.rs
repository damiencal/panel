use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum RecordType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "AAAA")]
    #[cfg_attr(feature = "server", sqlx(rename = "AAAA"))]
    Aaaa,
    #[serde(rename = "CNAME")]
    #[cfg_attr(feature = "server", sqlx(rename = "CNAME"))]
    Cname,
    #[serde(rename = "MX")]
    #[cfg_attr(feature = "server", sqlx(rename = "MX"))]
    Mx,
    #[serde(rename = "TXT")]
    #[cfg_attr(feature = "server", sqlx(rename = "TXT"))]
    Txt,
    #[serde(rename = "SRV")]
    #[cfg_attr(feature = "server", sqlx(rename = "SRV"))]
    Srv,
    #[serde(rename = "CAA")]
    #[cfg_attr(feature = "server", sqlx(rename = "CAA"))]
    Caa,
    #[serde(rename = "NS")]
    #[cfg_attr(feature = "server", sqlx(rename = "NS"))]
    Ns,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::Aaaa => write!(f, "AAAA"),
            RecordType::Cname => write!(f, "CNAME"),
            RecordType::Mx => write!(f, "MX"),
            RecordType::Txt => write!(f, "TXT"),
            RecordType::Srv => write!(f, "SRV"),
            RecordType::Caa => write!(f, "CAA"),
            RecordType::Ns => write!(f, "NS"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum ZoneType {
    #[serde(rename = "Primary")]
    Primary,
    #[serde(rename = "Secondary")]
    Secondary,
}

/// Sync status for Cloudflare operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum SyncStatus {
    #[serde(rename = "Synced")]
    Synced,
    #[serde(rename = "Pending")]
    Pending,
    #[serde(rename = "Error")]
    Error,
}

/// DNS zone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct DnsZone {
    pub id: i64,
    pub owner_id: i64,
    pub domain: String,
    pub zone_type: ZoneType,
    pub status: String,
    pub nameserver1: Option<String>,
    pub nameserver2: Option<String>,
    pub cf_zone_id: Option<String>,
    pub sync_status: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DNS record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct DnsRecord {
    pub id: i64,
    pub zone_id: i64,
    pub name: String,
    pub r#type: RecordType,
    pub value: String,
    pub priority: i32,
    pub ttl: i32,
    pub cf_record_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddDnsRecordRequest {
    pub name: String,
    pub r#type: RecordType,
    pub value: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_ttl")]
    pub ttl: i32,
}

fn default_priority() -> i32 {
    10
}

fn default_ttl() -> i32 {
    3600
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsZoneWithRecords {
    pub zone: DnsZone,
    pub records: Vec<DnsRecord>,
}
