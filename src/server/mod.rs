/// Server functions for the hosting panel.
/// All functions marked with #[server] run on the server and are
/// callable from the Dioxus frontend via serialized HTTP calls.
pub mod antispam;
pub mod auth;
pub mod backup;
pub mod branding;
pub mod cron;
pub mod databases;
pub mod dns;
pub mod email;
pub mod firewall;
pub mod ftp;
pub mod git;
pub mod monitoring;
pub mod packages;
pub mod security;
pub mod services;
pub mod sites;
pub mod ssl;
pub mod stats;
pub mod tickets;
pub mod usage;
pub mod users;

pub use antispam::*;
pub use auth::*;
pub use backup::*;
pub use branding::*;
pub use cron::*;
pub use databases::*;
pub use dns::*;
pub use email::*;
pub use firewall::*;
pub use ftp::*;
pub use git::*;
pub use monitoring::*;
pub use packages::*;
pub use security::*;
pub use services::*;
pub use sites::*;
pub use ssl::*;
pub use stats::*;
pub use tickets::*;
pub use usage::*;
pub use users::*;

/// Server-only helper utilities (DB access, auth verification, rate limiting, audit).
/// These are gated behind cfg so they don't compile for the WASM client.
#[cfg(feature = "server")]
pub(crate) mod helpers {
    use dioxus::prelude::ServerFnError;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    // ─── Lazy Server Initialization ───

    static SERVER_INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

    /// Initialize database and JWT on first server function call.
    pub async fn ensure_init() -> Result<(), String> {
        SERVER_INIT
            .get_or_try_init(|| async {
                let config = crate::utils::PanelConfig::load(Some("panel.toml"))
                    .await
                    .map_err(|e| e.to_string())?;

                if config.server.secret_key.is_empty() || config.server.secret_key.len() < 32 {
                    return Err("FATAL: PANEL_SECRET_KEY must be at least 32 characters. \
                         Generate one with: openssl rand -base64 32"
                        .to_string());
                }

                crate::auth::jwt::init_jwt_key(config.server.secret_key);
                crate::db::init_pool(&config.database.url)
                    .await
                    .map_err(|e| e.to_string())?;

                // Initialize Cloudflare DNS client (optional — warn if not set)
                if !config.cloudflare.api_token.is_empty() {
                    crate::services::cloudflare::init(
                        config.cloudflare.api_token,
                        config.cloudflare.account_id,
                    );
                    tracing::info!("Cloudflare DNS client initialized");
                } else {
                    tracing::warn!(
                        "CLOUDFLARE_API_TOKEN not set — DNS operations will be local-only"
                    );
                }

                tracing::info!("Server initialized successfully");

                // Start the Postfix per-domain send-rate-limit policy daemon.
                let policy_pool = crate::db::get_pool_ref().clone();
                crate::services::postfix_policy::start(policy_pool);

                // Spawn background task for cleaning up old audit logs (runs every 24 hours)
                let audit_pool = crate::db::get_pool_ref().clone();
                tokio::spawn(async move {
                    loop {
                        if let Err(e) = crate::db::audit::cleanup_old_logs(&audit_pool, 30).await {
                            tracing::error!("Error cleaning up old audit logs: {}", e);
                        } else {
                            tracing::info!("Successfully ran cleanup of old audit logs");
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;
                    }
                });

                Ok(())
            })
            .await
            .map(|_| ())
    }

    // ─── In-Memory Rate Limiter ───

    static RATE_LIMITER: std::sync::OnceLock<Mutex<RateLimiter>> = std::sync::OnceLock::new();

    struct RateLimiter {
        attempts: HashMap<String, Vec<Instant>>,
    }

    impl RateLimiter {
        fn new() -> Self {
            Self {
                attempts: HashMap::new(),
            }
        }

        fn record(&mut self, key: &str) {
            self.attempts
                .entry(key.to_string())
                .or_default()
                .push(Instant::now());
        }
    }

    fn rate_limiter() -> &'static Mutex<RateLimiter> {
        RATE_LIMITER.get_or_init(|| Mutex::new(RateLimiter::new()))
    }

    /// Record a failed auth attempt.
    pub fn record_failed_attempt(key: &str) {
        let mut rl = rate_limiter().lock().unwrap();
        rl.record(key);
    }

    // ─── Auth & DB Helpers ───

    /// Extract JWT from the HttpOnly auth cookie and verify it.
    pub fn verify_auth() -> Result<crate::models::auth::JwtClaims, ServerFnError> {
        let ctx = dioxus_fullstack_core::FullstackContext::current()
            .ok_or_else(|| ServerFnError::new("No server context"))?;
        let parts = ctx.parts_mut();
        let cookie_header = parts
            .headers
            .get(http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        drop(parts);
        let token = parse_cookie_value(&cookie_header, "auth_token")
            .ok_or_else(|| ServerFnError::new("Not authenticated"))?;
        crate::auth::jwt::verify_token(token).map_err(|e| ServerFnError::new(e.to_string()))
    }

    /// Parse a single cookie value from a `Cookie` header string.
    fn parse_cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
        for part in cookie_header.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix(name) {
                if let Some(value) = value.strip_prefix('=') {
                    return Some(value);
                }
            }
        }
        None
    }

    /// Set the auth JWT as an HttpOnly cookie on the response.
    pub fn set_auth_cookie(token: &str, max_age_secs: i64) {
        if let Some(ctx) = dioxus_fullstack_core::FullstackContext::current() {
            // Always set Secure flag unless PANEL_INSECURE_COOKIES=1 is explicitly set.
            // This prevents accidental deployment of debug builds without Secure cookies.
            let secure = if std::env::var("PANEL_INSECURE_COOKIES").as_deref() == Ok("1") {
                ""
            } else {
                " Secure;"
            };
            let cookie = format!(
                "auth_token={token}; HttpOnly;{secure} SameSite=Strict; Path=/; Max-Age={max_age_secs}"
            );
            if let Ok(val) = http::HeaderValue::from_str(&cookie) {
                ctx.add_response_header(http::header::SET_COOKIE, val);
            }
        }
    }

    /// Clear the auth cookie by setting it with Max-Age=0.
    pub fn clear_auth_cookie() {
        if let Some(ctx) = dioxus_fullstack_core::FullstackContext::current() {
            let secure = if std::env::var("PANEL_INSECURE_COOKIES").as_deref() == Ok("1") {
                ""
            } else {
                " Secure;"
            };
            let cookie =
                format!("auth_token=; HttpOnly;{secure} SameSite=Strict; Path=/; Max-Age=0");
            if let Ok(val) = http::HeaderValue::from_str(&cookie) {
                ctx.add_response_header(http::header::SET_COOKIE, val);
            }
        }
    }

    /// Get the database pool.
    pub fn get_pool() -> Result<&'static sqlx::SqlitePool, ServerFnError> {
        crate::db::pool().map_err(|e| ServerFnError::new(e.to_string()))
    }

    /// Log an audit action. Errors are logged but do not block the calling operation.
    pub async fn audit_log(
        user_id: i64,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<i64>,
        target_name: Option<&str>,
        status: &str,
        error_msg: Option<&str>,
    ) {
        if let Ok(pool) = get_pool() {
            if let Err(e) = crate::db::audit::log_action(
                pool,
                user_id,
                action.to_string(),
                target_type.map(String::from),
                target_id,
                target_name.map(String::from),
                None,
                status.to_string(),
                error_msg.map(String::from),
                None,
                None,
            )
            .await
            {
                tracing::error!("Audit log write failed: {}", e);
            }
        } else {
            tracing::error!("Audit log skipped: database pool unavailable");
        }
    }

    /// Log an audit action with an explicit `impersonation_by` field.
    /// Errors are logged but do not block the calling operation.
    pub async fn audit_log_impersonated(
        user_id: i64,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<i64>,
        target_name: Option<&str>,
        status: &str,
        error_msg: Option<&str>,
        impersonation_by: Option<i64>,
    ) {
        if let Ok(pool) = get_pool() {
            if let Err(e) = crate::db::audit::log_action(
                pool,
                user_id,
                action.to_string(),
                target_type.map(String::from),
                target_id,
                target_name.map(String::from),
                None,
                status.to_string(),
                error_msg.map(String::from),
                None,
                impersonation_by,
            )
            .await
            {
                tracing::error!("Audit log write failed: {}", e);
            }
        } else {
            tracing::error!("Audit log skipped: database pool unavailable");
        }
    }
}
