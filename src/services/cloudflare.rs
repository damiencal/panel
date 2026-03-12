/// Cloudflare DNS API client.
///
/// Uses the Cloudflare v4 API to manage zones and DNS records.
/// API reference: https://developers.cloudflare.com/api/
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

static CF_CLIENT: OnceLock<CloudflareClient> = OnceLock::new();

/// Initialize the global Cloudflare client. Call once at startup.
pub fn init(api_token: String, account_id: Option<String>) {
    let _ = CF_CLIENT.set(CloudflareClient::new(api_token, account_id));
}

/// Get the global Cloudflare client.
pub fn client() -> Result<&'static CloudflareClient, CloudflareError> {
    CF_CLIENT.get().ok_or(CloudflareError::NotConfigured)
}

#[derive(Debug, thiserror::Error)]
pub enum CloudflareError {
    #[error("Cloudflare client not configured — set CLOUDFLARE_API_TOKEN")]
    NotConfigured,
    #[error("Cloudflare API error: {0}")]
    Api(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

pub struct CloudflareClient {
    http: Client,
    api_token: String,
    account_id: Option<String>,
}

// -- Cloudflare API response types ------------------------------------------

#[derive(Debug, Deserialize)]
struct CfResponse<T> {
    success: bool,
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CfError {
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct CfZone {
    pub id: String,
    pub name: String,
    pub status: String,
    pub name_servers: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CfDnsRecord {
    pub id: String,
    pub r#type: String,
    pub name: String,
    pub content: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub proxied: Option<bool>,
}

#[derive(Debug, Serialize)]
struct CreateZoneRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<AccountRef<'a>>,
}

#[derive(Debug, Serialize)]
struct AccountRef<'a> {
    id: &'a str,
}

#[derive(Debug, Serialize)]
struct CreateDnsRecordRequest<'a> {
    r#type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<i32>,
    proxied: bool,
}

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

impl CloudflareClient {
    fn new(api_token: String, account_id: Option<String>) -> Self {
        Self {
            http: Client::new(),
            api_token,
            account_id,
        }
    }

    // -- Zone operations ----------------------------------------------------

    /// Create a new zone in Cloudflare for `domain`.
    /// Returns the Cloudflare zone object including assigned nameservers.
    pub async fn create_zone(&self, domain: &str) -> Result<CfZone, CloudflareError> {
        let body = CreateZoneRequest {
            name: domain,
            account: self.account_id.as_deref().map(|id| AccountRef { id }),
        };

        let resp: CfResponse<CfZone> = self
            .http
            .post(format!("{CF_API_BASE}/zones"))
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        self.unwrap_response(resp)
    }

    /// Get zone details from Cloudflare.
    pub async fn get_zone(&self, cf_zone_id: &str) -> Result<CfZone, CloudflareError> {
        let resp: CfResponse<CfZone> = self
            .http
            .get(format!("{CF_API_BASE}/zones/{cf_zone_id}"))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .json()
            .await?;

        self.unwrap_response(resp)
    }

    /// Delete a zone from Cloudflare.
    pub async fn delete_zone(&self, cf_zone_id: &str) -> Result<(), CloudflareError> {
        let resp: CfResponse<serde_json::Value> = self
            .http
            .delete(format!("{CF_API_BASE}/zones/{cf_zone_id}"))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            let msg = resp
                .errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CloudflareError::Api(msg));
        }
        Ok(())
    }

    // -- DNS record operations -----------------------------------------------

    /// Create a DNS record in the given Cloudflare zone.
    pub async fn create_record(
        &self,
        cf_zone_id: &str,
        record_type: &str,
        name: &str,
        content: &str,
        ttl: i32,
        priority: Option<i32>,
    ) -> Result<CfDnsRecord, CloudflareError> {
        let body = CreateDnsRecordRequest {
            r#type: record_type,
            name,
            content,
            ttl,
            priority,
            proxied: false,
        };

        let resp: CfResponse<CfDnsRecord> = self
            .http
            .post(format!("{CF_API_BASE}/zones/{cf_zone_id}/dns_records"))
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        self.unwrap_response(resp)
    }

    /// List all DNS records in a Cloudflare zone.
    pub async fn list_records(
        &self,
        cf_zone_id: &str,
    ) -> Result<Vec<CfDnsRecord>, CloudflareError> {
        let resp: CfResponse<Vec<CfDnsRecord>> = self
            .http
            .get(format!("{CF_API_BASE}/zones/{cf_zone_id}/dns_records"))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .json()
            .await?;

        self.unwrap_response(resp)
    }

    /// Delete a DNS record from Cloudflare.
    pub async fn delete_record(
        &self,
        cf_zone_id: &str,
        cf_record_id: &str,
    ) -> Result<(), CloudflareError> {
        let resp: CfResponse<serde_json::Value> = self
            .http
            .delete(format!(
                "{CF_API_BASE}/zones/{cf_zone_id}/dns_records/{cf_record_id}"
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            let msg = resp
                .errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CloudflareError::Api(msg));
        }
        Ok(())
    }

    // -- Helpers -------------------------------------------------------------

    fn unwrap_response<T>(&self, resp: CfResponse<T>) -> Result<T, CloudflareError> {
        if resp.success {
            resp.result
                .ok_or_else(|| CloudflareError::Api("Empty result from Cloudflare".into()))
        } else {
            let msg = resp
                .errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            Err(CloudflareError::Api(msg))
        }
    }
}
