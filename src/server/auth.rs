/// Authentication server functions: login, password change, 2FA setup.
use crate::models::auth::LoginResponse;
use crate::models::user::Enable2FAResponse;
use dioxus::prelude::*;
#[cfg(feature = "server")]
use std::collections::HashMap;
#[cfg(feature = "server")]
use std::sync::{Mutex, OnceLock};
#[cfg(feature = "server")]
use std::time::{Duration, Instant};

#[cfg(feature = "server")]
static LOGIN_RATE_LIMITER: OnceLock<Mutex<HashMap<String, Vec<Instant>>>> = OnceLock::new();

#[cfg(feature = "server")]
fn enforce_login_rate_limit(ip: &str, username: &str) -> Result<(), ServerFnError> {
    let mut limits = LOGIN_RATE_LIMITER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let now = Instant::now();
    let window = Duration::from_secs(300); // 5 minutes

    // Opportunistically prune fully-expired entries to prevent unbounded memory growth.
    // Runs under the already-held Mutex so no extra locking is needed.
    limits.retain(|_, v| {
        v.retain(|&t| now.duration_since(t) < window);
        !v.is_empty()
    });

    // Rate limit by IP (max 10 attempts per 5 mins)
    let ip_key = format!("ip:{}", ip);
    let ip_attempts = limits.entry(ip_key).or_default();
    ip_attempts.retain(|&t| now.duration_since(t) < window);
    if ip_attempts.len() >= 10 {
        return Err(ServerFnError::new(
            "Too many attempts from this IP. Please try again later.",
        ));
    }
    ip_attempts.push(now);

    // Rate limit by username (max 5 attempts per 5 mins)
    let user_key = format!("user:{}", username);
    let user_attempts = limits.entry(user_key).or_default();
    user_attempts.retain(|&t| now.duration_since(t) < window);
    if user_attempts.len() >= 5 {
        return Err(ServerFnError::new(
            "Too many attempts for this user. Please try again later.",
        ));
    }
    user_attempts.push(now);

    Ok(())
}

#[cfg(feature = "server")]
fn get_client_ip() -> String {
    #[cfg(feature = "server")]
    if let Some(ctx) = dioxus_fullstack_core::FullstackContext::current() {
        let parts = ctx.parts_mut();
        if let Some(ip) = crate::auth::guards::extract_client_ip_from_headers(&parts.headers) {
            return ip;
        }
    }
    "unknown".to_string()
}

/// Login with username/password (and optional TOTP code for 2FA users).
#[server]
pub async fn server_login(
    username: String,
    password: String,
    totp_code: Option<String>,
) -> Result<LoginResponse, ServerFnError> {
    use super::helpers::*;
    use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};

    ensure_init().await.map_err(ServerFnError::new)?;

    let client_ip = get_client_ip();
    enforce_login_rate_limit(&client_ip, &username)?;

    let pool = get_pool()?;

    // Find user
    let user = match crate::db::users::get_by_username(pool, &username).await {
        Ok(u) => u,
        Err(_) => {
            audit_log_with_ip(
                0,
                "login",
                Some("user"),
                None,
                Some(&username),
                &client_ip,
                "Failure",
                Some("Unknown username"),
            )
            .await;
            return Err(ServerFnError::new("Invalid credentials"));
        }
    };

    // Check account status
    if user.status != crate::models::user::AccountStatus::Active {
        audit_log_with_ip(
            user.id,
            "login",
            Some("user"),
            Some(user.id),
            Some(&user.username),
            &client_ip,
            "Failure",
            Some("Account suspended or pending"),
        )
        .await;
        return Err(ServerFnError::new("Account is suspended or pending"));
    }

    // Verify password
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| ServerFnError::new("Invalid credentials"))?;

    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_err()
    {
        audit_log_with_ip(
            user.id,
            "login",
            Some("user"),
            Some(user.id),
            Some(&user.username),
            &client_ip,
            "Failure",
            Some("Invalid password"),
        )
        .await;
        return Err(ServerFnError::new("Invalid credentials"));
    }

    // Verify TOTP if enabled
    if user.totp_enabled {
        let code = totp_code.ok_or_else(|| ServerFnError::new("2FA code required"))?;
        let secret = user
            .totp_secret
            .as_ref()
            .ok_or_else(|| ServerFnError::new("2FA configuration error"))?;
        if crate::auth::verify_totp(secret, &code).is_err() {
            audit_log_with_ip(
                user.id,
                "login",
                Some("user"),
                Some(user.id),
                Some(&user.username),
                &client_ip,
                "Failure",
                Some("Invalid 2FA code"),
            )
            .await;
            return Err(ServerFnError::new("Invalid 2FA code"));
        }
    }

    // Create JWT token
    let auth_token = crate::auth::jwt::JwtManager::create_auth_response(
        user.id,
        user.username.clone(),
        user.email.clone(),
        user.role,
        user.parent_id,
    )
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Set JWT as HttpOnly cookie (not exposed to JS)
    set_auth_cookie(&auth_token.access_token, auth_token.expires_in);

    audit_log_with_ip(
        user.id,
        "login",
        Some("user"),
        Some(user.id),
        Some(&user.username),
        &client_ip,
        "Success",
        None,
    )
    .await;

    Ok(LoginResponse {
        user_id: auth_token.user_id,
        username: auth_token.username,
        email: auth_token.email,
        role: auth_token.role,
        expires_at: chrono::Utc::now().timestamp() + auth_token.expires_in,
        impersonated_by: None,
    })
}

/// Logout: clear the auth cookie.
#[server]
pub async fn server_logout() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    clear_auth_cookie();
    Ok(())
}

/// Change the current user's password.
#[server]
pub async fn server_change_password(
    old_password: String,
    new_password: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHash, SaltString},
        Argon2, PasswordHasher, PasswordVerifier,
    };

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::utils::validators::validate_password(&new_password).map_err(ServerFnError::new)?;

    let user = crate::db::users::get(pool, claims.sub)
        .await
        .map_err(|_| ServerFnError::new("User not found"))?;

    let parsed_hash =
        PasswordHash::new(&user.password_hash).map_err(|_| ServerFnError::new("Internal error"))?;

    Argon2::default()
        .verify_password(old_password.as_bytes(), &parsed_hash)
        .map_err(|_| ServerFnError::new("Current password is incorrect"))?;

    let salt = SaltString::generate(&mut OsRng);
    let new_hash = Argon2::default()
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|_| ServerFnError::new("Failed to hash password"))?
        .to_string();

    crate::db::users::update_password(pool, claims.sub, new_hash)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "change_password",
        Some("user"),
        Some(claims.sub),
        Some(&claims.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Generate 2FA credentials (secret + QR URL) for setup.
#[server]
pub async fn server_setup_2fa() -> Result<Enable2FAResponse, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;

    let (secret, qr_url) = crate::auth::TotpManager::generate_credentials(&claims.username)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(Enable2FAResponse {
        secret,
        qr_code_url: qr_url,
    })
}

/// Confirm 2FA setup by verifying a code, then persist the secret.
#[server]
pub async fn server_confirm_2fa(secret: String, code: String) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // Rate-limit 2FA attempts to prevent brute-force of 6-digit TOTP codes
    let client_ip = get_client_ip();
    enforce_login_rate_limit(&client_ip, &claims.username)?;

    crate::auth::verify_totp(&secret, &code)
        .map_err(|_| ServerFnError::new("Invalid verification code"))?;

    crate::db::users::enable_totp(pool, claims.sub, secret)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "enable_2fa",
        Some("user"),
        Some(claims.sub),
        Some(&claims.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Disable 2FA (requires password confirmation).
#[server]
pub async fn server_disable_2fa(password: String) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let user = crate::db::users::get(pool, claims.sub)
        .await
        .map_err(|_| ServerFnError::new("User not found"))?;

    let parsed_hash =
        PasswordHash::new(&user.password_hash).map_err(|_| ServerFnError::new("Internal error"))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| ServerFnError::new("Invalid password"))?;

    crate::db::users::disable_totp(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "disable_2fa",
        Some("user"),
        Some(claims.sub),
        Some(&claims.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}
