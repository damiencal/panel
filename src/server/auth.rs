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

/// Set to `true` at startup only when `request_security.trust_proxy_headers = true` in panel.toml.
/// When `false` (default), `X-Forwarded-For` is ignored for rate-limiting to prevent IP spoofing.
#[cfg(feature = "server")]
static TRUST_PROXY_HEADERS: OnceLock<bool> = OnceLock::new();

/// Argon2 hash used to equalize login timing for unknown users.
/// Initialized once per process at runtime to avoid hard-coding a static hash.
#[cfg(feature = "server")]
static DUMMY_LOGIN_HASH: OnceLock<String> = OnceLock::new();

#[cfg(feature = "server")]
fn dummy_login_hash() -> &'static str {
    DUMMY_LOGIN_HASH
        .get_or_init(|| {
            use argon2::{
                password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
                Argon2,
            };

            let salt = SaltString::generate(&mut OsRng);
            Argon2::default()
                .hash_password(b"panel_dummy_login_password", &salt)
                .map(|h| h.to_string())
                .expect("dummy login hash generation must succeed")
        })
        .as_str()
}

/// Called from `ensure_init()` during server startup.
#[cfg(feature = "server")]
pub(crate) fn init_proxy_trust(trust: bool) {
    let _ = TRUST_PROXY_HEADERS.set(trust);
}

#[cfg(feature = "server")]
pub(crate) fn enforce_login_rate_limit(ip: &str, username: &str) -> Result<(), ServerFnError> {
    // SEC-35-04: use unwrap_or_else to recover from a poisoned mutex
    // rather than panicking, which would take down the auth subsystem.
    let mut limits = LOGIN_RATE_LIMITER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    let window = Duration::from_secs(300); // 5 minutes

    // Opportunistically prune fully-expired entries to prevent unbounded memory growth.
    // Runs under the already-held Mutex so no extra locking is needed.
    limits.retain(|_, v| {
        v.retain(|&t| now.duration_since(t) < window);
        !v.is_empty()
    });
    // Hard cap on tracked entries to guard against botnet exhaustion.
    // After pruning, if the map is still over the limit, clear it entirely
    // (extra safety valve: we accept a momentary rate-limit reset over OOM).
    if limits.len() > 50_000 {
        limits.clear();
    }

    // Rate limit by IP (max 10 attempts per 5 mins).
    // Skip when IP is "unknown" — this happens when trust_proxy_headers = false (the default)
    // because X-Forwarded-For is untrusted and we refuse to use it.  The per-username limit
    // below is the primary protection in direct-connection deployments.
    if ip != "unknown" {
        let ip_key = format!("ip:{}", ip);
        let ip_attempts = limits.entry(ip_key).or_default();
        ip_attempts.retain(|&t| now.duration_since(t) < window);
        if ip_attempts.len() >= 10 {
            return Err(ServerFnError::new(
                "Too many attempts from this IP. Please try again later.",
            ));
        }
        ip_attempts.push(now);
    }

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
pub(crate) fn get_client_ip() -> String {
    #[cfg(feature = "server")]
    {
        // Only extract IP from forwarded headers when the operator has explicitly opted in
        // via `request_security.trust_proxy_headers = true` in panel.toml.  Without this,
        // a direct client can spoof X-Forwarded-For to cycle through fake IPs and bypass
        // the per-IP portion of the login rate limiter.
        let trust_proxy = TRUST_PROXY_HEADERS.get().copied().unwrap_or(false);
        if trust_proxy {
            if let Some(ctx) = dioxus_fullstack_core::FullstackContext::current() {
                let parts = ctx.parts_mut();
                if let Some(ip) =
                    crate::auth::guards::extract_client_ip_from_headers(&parts.headers)
                {
                    return ip;
                }
            }
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

    // Reject obviously-invalid inputs early so they never reach Argon2
    // or bloat the rate-limiter HashMap with huge keys.
    if crate::utils::validators::validate_username(&username).is_err() {
        return Err(ServerFnError::new("Invalid credentials"));
    }
    if password.len() > 1024 {
        return Err(ServerFnError::new("Invalid credentials"));
    }

    let client_ip = get_client_ip();
    enforce_login_rate_limit(&client_ip, &username)?;

    let pool = get_pool()?;

    // Find user, but always verify password against *some* Argon2 hash so
    // unknown users and inactive users have comparable timing to valid users.
    let user = crate::db::users::get_by_username(pool, &username)
        .await
        .ok();
    let hash_for_verify = user
        .as_ref()
        .map(|u| u.password_hash.clone())
        .unwrap_or_else(|| dummy_login_hash().to_string());
    let parsed_hash = PasswordHash::new(&hash_for_verify)
        .map_err(|_| ServerFnError::new("Invalid credentials"))?;
    let password_valid = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    let user = if let Some(u) = user {
        u
    } else {
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
    };

    // Return the same generic error for suspended/pending users as wrong password
    // while still paying the same Argon2 verification cost above.
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
        return Err(ServerFnError::new("Invalid credentials"));
    }

    if !password_valid {
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
        let encrypted_secret = user
            .totp_secret
            .as_ref()
            .ok_or_else(|| ServerFnError::new("2FA configuration error"))?;
        // Decrypt the stored secret (SEC-31-03: AES-256-GCM encrypted at rest).
        let secret = crate::auth::decrypt_totp_secret(encrypted_secret)
            .map_err(|_| ServerFnError::new("2FA configuration error — please re-enroll 2FA"))?;
        if crate::auth::verify_totp_persistent(pool, &secret, &code)
            .await
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

    check_token_not_revoked(pool, &claims).await?;

    // SESS-BRUTEFORCE-01: rate-limit password changes to prevent brute-force of
    // the current password by an attacker with a stolen session cookie.
    let client_ip = get_client_ip();
    enforce_login_rate_limit(&client_ip, &claims.username)?;

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
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let (secret, qr_url) = crate::auth::TotpManager::generate_credentials(&claims.username)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Store the pending secret server-side so that server_confirm_2fa can verify
    // against it without trusting the client to echo back the correct secret
    // (SEC-31-04: prevents an attacker with a stolen session from installing their own 2FA secret).
    // The secret is encrypted at rest (SEC-31-03: AES-256-GCM) so a DB dump
    // does not expose the TOTP seed.
    // The secret is only promoted to "active" (totp_enabled = 1) once the code is verified.
    let encrypted_secret = crate::auth::encrypt_totp_secret(&secret)
        .map_err(|e| ServerFnError::new(format!("Failed to secure 2FA secret: {e}")))?;
    sqlx::query("UPDATE users SET totp_secret = ? WHERE id = ? AND totp_enabled = 0")
        .bind(&encrypted_secret)
        .bind(claims.sub)
        .execute(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(Enable2FAResponse {
        secret,
        qr_code_url: qr_url,
    })
}

/// Confirm 2FA setup by verifying a code, then activate the stored secret.
/// The secret is no longer accepted from the client — it is fetched from the
/// server-stored pending enrollment (set by server_setup_2fa) to prevent an
/// attacker with a stolen session from installing an arbitrary TOTP secret.
#[server]
pub async fn server_confirm_2fa(code: String) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    check_token_not_revoked(pool, &claims).await?;

    // Rate-limit 2FA attempts to prevent brute-force of 6-digit TOTP codes
    let client_ip = get_client_ip();
    enforce_login_rate_limit(&client_ip, &claims.username)?;

    // Validate TOTP code format: must be exactly 6 ASCII digits.
    // Reject early to avoid passing arbitrary input to the TOTP verifier.
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(ServerFnError::new("Invalid verification code"));
    }

    // If 2FA is already enabled, reject the re-enrolment to prevent an attacker
    // with a stolen session from overwriting the victim's TOTP secret (which
    // would lock out the victim and grant the attacker persistent 2FA access).
    let user = crate::db::users::get(pool, claims.sub)
        .await
        .map_err(|_| ServerFnError::new("User not found"))?;
    if user.totp_enabled {
        return Err(ServerFnError::new(
            "2FA is already configured. Disable it first before re-enrolling.",
        ));
    }

    // Use the server-stored pending secret; never trust the client-supplied value.
    let encrypted_secret = user
        .totp_secret
        .ok_or_else(|| ServerFnError::new("No 2FA setup in progress. Please restart setup."))?;

    // Decrypt the server-stored secret (SEC-31-03: AES-256-GCM encrypted at rest).
    let secret = crate::auth::decrypt_totp_secret(&encrypted_secret).map_err(|_| {
        ServerFnError::new("2FA secret is invalid or corrupted. Please restart setup.")
    })?;

    crate::auth::verify_totp_persistent(pool, &secret, &code)
        .await
        .map_err(|_| ServerFnError::new("Invalid verification code"))?;

    // Activate 2FA — the secret is already stored; only flip the enabled flag.
    sqlx::query("UPDATE users SET totp_enabled = 1 WHERE id = ?")
        .bind(claims.sub)
        .execute(pool)
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

    check_token_not_revoked(pool, &claims).await?;

    // SESS-BRUTEFORCE-01: rate-limit disable-2FA to prevent brute-force of the
    // password confirmation by an attacker with a stolen session cookie.
    let client_ip = get_client_ip();
    enforce_login_rate_limit(&client_ip, &claims.username)?;

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
