use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// User role in the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(
    feature = "server",
    sqlx(type_name = "TEXT", rename_all = "PascalCase")
)]
pub enum Role {
    #[default]
    Client,
    Reseller,
    Admin,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "Admin"),
            Role::Reseller => write!(f, "Reseller"),
            Role::Client => write!(f, "Client"),
        }
    }
}

/// Account status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(
    feature = "server",
    sqlx(type_name = "TEXT", rename_all = "PascalCase")
)]
pub enum AccountStatus {
    Active,
    Suspended,
    Pending,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountStatus::Active => write!(f, "Active"),
            AccountStatus::Suspended => write!(f, "Suspended"),
            AccountStatus::Pending => write!(f, "Pending"),
        }
    }
}

/// User account in the panel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    #[serde(skip)]
    pub password_hash: String,
    pub role: Role,
    pub status: AccountStatus,
    /// Parent user ID: Reseller → Admin's id, Client → Reseller's id (or Admin's id)
    pub parent_id: Option<i64>,
    /// For clients: assigned hosting package ID
    pub package_id: Option<i64>,
    /// For resellers: custom branding config ID
    pub branding_id: Option<i64>,
    /// TOTP secret (encrypted in practice)
    #[serde(skip)]
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    /// Linux system UID assigned at account creation (clients only).
    pub system_uid: Option<i64>,
    /// Linux system GID assigned at account creation (clients only).
    pub system_gid: Option<i64>,
    /// Optional company / organisation name.
    pub company: Option<String>,
    /// Optional postal / street address.
    pub address: Option<String>,
    /// Optional phone number.
    pub phone: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request/response types for authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub user: User,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Enable2FAResponse {
    pub secret: String,
    pub qr_code_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Verify2FARequest {
    pub code: String,
}

/// Request to update a user's contact/profile details.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UpdateDetailsRequest {
    pub company: Option<String>,
    pub address: Option<String>,
    pub phone: Option<String>,
}
