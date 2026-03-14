/// JWT token creation and validation.
use crate::models::auth::{AuthError, JwtClaims};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::sync::OnceLock;

static JWT_KEY: OnceLock<String> = OnceLock::new();

/// Initialize JWT secret from environment.
pub fn init_jwt_key(secret: String) {
    let _ = JWT_KEY.set(secret);
}

/// Get the JWT secret key. Panics if not initialized.
fn get_jwt_key() -> &'static str {
    JWT_KEY.get().expect(
        "FATAL: JWT key not initialized. Call init_jwt_key() with a secure secret (32+ chars).",
    )
}

const TOKEN_EXPIRY_HOURS: i64 = 24;

/// Create a JWT token.
pub fn create_token(
    user_id: i64,
    username: String,
    email: String,
    role: crate::models::user::Role,
    parent_id: Option<i64>,
    impersonated_by: Option<i64>,
) -> Result<String, AuthError> {
    let now = Utc::now();
    let expiry = now + Duration::hours(TOKEN_EXPIRY_HOURS);

    let claims = JwtClaims {
        sub: user_id,
        username,
        email,
        role,
        iat: now.timestamp(),
        exp: expiry.timestamp(),
        parent_id,
        impersonated_by,
    };

    let key = get_jwt_key();
    let encoding_key = EncodingKey::from_secret(key.as_bytes());

    encode(&Header::default(), &claims, &encoding_key).map_err(|_| AuthError::InvalidToken)
}

/// Verify and decode a JWT token.
pub fn verify_token(token: &str) -> Result<JwtClaims, AuthError> {
    let key = get_jwt_key();
    let decoding_key = DecodingKey::from_secret(key.as_bytes());

    let token_data = decode::<JwtClaims>(token, &decoding_key, &Validation::new(Algorithm::HS256))
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::InvalidToken,
        })?;

    Ok(token_data.claims)
}

/// JWT token manager for Dioxus server functions.
pub struct JwtManager;

impl JwtManager {
    /// Extract token from request headers (typically from "Authorization: Bearer <token>").
    pub fn extract_from_headers(auth_header: Option<&str>) -> Result<String, AuthError> {
        auth_header
            .ok_or(AuthError::InvalidToken)
            .and_then(|header| {
                header
                    .strip_prefix("Bearer ")
                    .ok_or(AuthError::InvalidToken)
                    .map(|token| token.to_string())
            })
    }

    /// Create a full auth token response.
    pub fn create_auth_response(
        user_id: i64,
        username: String,
        email: String,
        role: crate::models::user::Role,
        parent_id: Option<i64>,
    ) -> Result<crate::models::auth::AuthToken, AuthError> {
        let access_token = create_token(
            user_id,
            username.clone(),
            email.clone(),
            role,
            parent_id,
            None,
        )?;
        Ok(crate::models::auth::AuthToken {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: TOKEN_EXPIRY_HOURS * 3600,
            user_id,
            username,
            email,
            role,
            impersonated_by: None,
        })
    }

    /// Create an impersonation token: claims belong to `target_user`, but
    /// `impersonated_by` is set to `admin_id` so the JWT stays auditable.
    pub fn create_impersonation_token(
        target_user_id: i64,
        target_username: String,
        target_email: String,
        target_role: crate::models::user::Role,
        target_parent_id: Option<i64>,
        admin_id: i64,
    ) -> Result<crate::models::auth::AuthToken, AuthError> {
        let access_token = create_token(
            target_user_id,
            target_username.clone(),
            target_email.clone(),
            target_role,
            target_parent_id,
            Some(admin_id),
        )?;
        Ok(crate::models::auth::AuthToken {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: TOKEN_EXPIRY_HOURS * 3600,
            user_id: target_user_id,
            username: target_username,
            email: target_email,
            role: target_role,
            impersonated_by: Some(admin_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::Role;

    #[test]
    fn test_create_and_verify_token() {
        init_jwt_key("test-secret-key".to_string());

        let token = create_token(
            1,
            "testuser".to_string(),
            "test@example.com".to_string(),
            Role::Client,
            None,
            None, // impersonated_by
        )
        .expect("Failed to create token");

        let claims = verify_token(&token).expect("Failed to verify token");
        assert_eq!(claims.sub, 1);
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.role, Role::Client);
    }

    #[test]
    fn test_invalid_token() {
        init_jwt_key("test-secret-key".to_string());
        let result = verify_token("invalid.token.here");
        assert!(result.is_err());
    }
}
