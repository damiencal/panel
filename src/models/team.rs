use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A pending (or consumed) invitation to join a client's team as a Developer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct TeamInvitation {
    pub id: i64,
    /// The Client user who created this invitation.
    pub client_id: i64,
    /// Email address the invitation was intended for (informational only).
    pub email: String,
    /// SHA-256 hex hash of the raw one-time token. The raw token is never stored.
    pub token_hash: String,
    /// JSON array of site IDs the developer will be granted access to.
    pub site_ids: String,
    pub expires_at: DateTime<Utc>,
    /// Set when the invitation is accepted. NULL = still valid.
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A per-site access grant linking a Developer to a specific Site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct TeamSiteAccess {
    pub developer_id: i64,
    pub site_id: i64,
    pub granted_at: DateTime<Utc>,
}

/// Request payload for creating a team invitation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    /// Site IDs to grant the developer access to.
    pub site_ids: Vec<i64>,
    /// How many hours until this invitation expires (default 48, max 720).
    pub expires_hours: Option<u32>,
}
