use crate::models::user::Role;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// JWT token claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: i64, // subject (user_id)
    pub username: String,
    pub email: String,
    pub role: Role,
    pub iat: i64,               // issued at
    pub exp: i64,               // expiration
    pub parent_id: Option<i64>, // For ownership checks
    /// Set when this token was issued via impersonation. Contains the original admin's user_id.
    pub impersonated_by: Option<i64>,
}

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User not found")]
    UserNotFound,
    #[error("User suspended")]
    UserSuspended,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid TOTP code")]
    InvalidTotpCode,
    #[error("2FA not enabled")]
    TotpNotEnabled,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Access denied")]
    AccessDenied,
    #[error("Not found")]
    NotFound,
    #[error("Database error")]
    DatabaseError,
}

/// Session/token response type (internal use for JWT creation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user_id: i64,
    pub username: String,
    pub email: String,
    pub role: crate::models::user::Role,
    /// Set when this token was issued via impersonation. Contains the original admin's user_id.
    pub impersonated_by: Option<i64>,
}

/// Login response sent to the client (token is in HttpOnly cookie, not here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub user_id: i64,
    pub username: String,
    pub email: String,
    pub role: crate::models::user::Role,
    pub expires_at: i64,
    /// Filled when this session is impersonating another user.
    /// Contains the admin's user_id so the UI can show the banner.
    pub impersonated_by: Option<i64>,
}

/// Audit log entry (serializable for display).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: i64,
    pub user_id: i64,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<i64>,
    pub target_name: Option<String>,
    pub description: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
}
