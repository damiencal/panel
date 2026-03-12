use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum DomainType {
    #[serde(rename = "Primary")]
    Primary,
    #[serde(rename = "Addon")]
    Addon,
    #[serde(rename = "Subdomain")]
    Subdomain,
}

/// Domain associated with a site.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct Domain {
    pub id: i64,
    pub site_id: i64,
    pub domain_name: String,
    pub domain_type: DomainType,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddDomainRequest {
    pub domain_name: String,
    pub domain_type: DomainType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DomainWithStats {
    pub domain: Domain,
    pub has_ssl: bool,
    pub ssl_expiry: Option<DateTime<Utc>>,
}
