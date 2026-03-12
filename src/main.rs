// Hosting Control Panel - Dioxus 0.7 Fullstack App
#![allow(non_snake_case)]
mod lucide;
use lucide::Icon;

use dioxus::prelude::*;
use panel::models::service::{ServiceAction, ServiceCommand, ServiceStatus, ServiceType};
use panel::models::user::Role;
use panel::server::*;
use serde::{Deserialize, Serialize};

/// Shared auth state for UI routing only — NOT a security boundary.
/// The actual JWT lives in an HttpOnly cookie inaccessible to JavaScript.
/// Fields here (role, user_id, etc.) are for display/routing; all authorization
/// is enforced server-side via the cookie-based JWT.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthState {
    pub user_id: i64,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub expires_at: i64,
    /// Set when this session was started via admin impersonation.
    /// Contains the original admin's user_id.
    #[serde(default)]
    pub impersonated_by: Option<i64>,
}

/// Newtype wrapper to avoid context collision with other `Signal<bool>` values.
#[derive(Clone, Copy)]
struct AuthLoaded(bool);

fn main() {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tracing_subscriber::fmt().with_target(false).init();

        dioxus::serve(|| async {
            use dioxus::server::axum;
            let router = dioxus::server::router(App)
                .route(
                    "/phpmyadmin/{*path}",
                    axum::routing::any(phpmyadmin_proxy_handler),
                )
                .route(
                    "/api/mailbox-backup/{token}",
                    axum::routing::get(mailbox_backup_handler),
                )
                .layer(axum::middleware::from_fn(security_headers_middleware));
            Ok(router)
        });
    }

    #[cfg(target_arch = "wasm32")]
    dioxus::launch(App);
}

/// Axum middleware that adds security response headers to every request.
/// Protects against clickjacking (X-Frame-Options), MIME sniffing
/// (X-Content-Type-Options), and cross-site info leakage (Referrer-Policy).
#[cfg(not(target_arch = "wasm32"))]
async fn security_headers_middleware(
    req: dioxus::server::axum::extract::Request,
    next: dioxus::server::axum::middleware::Next,
) -> dioxus::server::axum::response::Response {
    use dioxus::server::http::HeaderValue;
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    response
}

/// Reverse-proxy handler for `/phpmyadmin/*` requests.
/// Forwards requests from the panel's port to OpenLiteSpeed so phpMyAdmin
/// is accessible without requiring a separate port.
#[cfg(not(target_arch = "wasm32"))]
async fn phpmyadmin_proxy_handler(
    req: dioxus::server::axum::extract::Request,
) -> dioxus::server::axum::response::Response {
    use dioxus::server::axum::response::IntoResponse;
    use dioxus::server::http;

    let path = req.uri().path();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let upstream_url = format!("http://127.0.0.1:8088{}{}", path, query);

    // Forward relevant headers (cookies are essential for phpMyAdmin sessions)
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in req.headers() {
        if let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            // Skip hop-by-hop headers
            if !matches!(
                name.as_str(),
                "host" | "connection" | "transfer-encoding" | "upgrade"
            ) {
                headers.insert(n, v);
            }
        }
    }

    let client = reqwest::Client::new();
    let method = match *req.method() {
        http::Method::GET => reqwest::Method::GET,
        http::Method::POST => reqwest::Method::POST,
        http::Method::PUT => reqwest::Method::PUT,
        http::Method::DELETE => reqwest::Method::DELETE,
        _ => reqwest::Method::GET,
    };

    let body_bytes =
        match dioxus::server::axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
            Ok(b) => b,
            Err(_) => return (http::StatusCode::BAD_REQUEST, "Bad request body").into_response(),
        };

    let upstream_resp = match client
        .request(method, &upstream_url)
        .headers(headers)
        .body(body_bytes.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("phpMyAdmin proxy error: {}", e);
            return (
                http::StatusCode::BAD_GATEWAY,
                "phpMyAdmin is not available. Ensure OpenLiteSpeed is running.",
            )
                .into_response();
        }
    };

    // Build response back to client
    let status = http::StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_headers = http::HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(name.as_str().as_bytes()),
            http::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            if !matches!(name.as_str(), "transfer-encoding" | "connection") {
                response_headers.insert(n, v);
            }
        }
    }

    let resp_body = upstream_resp.bytes().await.unwrap_or_default();
    let mut response = (status, resp_body).into_response();
    *response.headers_mut() = response_headers;
    response
}

/// Download handler for one-time mailbox backup archive tokens.
///
/// Route: `GET /api/mailbox-backup/{token}`
///
/// The token is created by `server_create_mailbox_backup` and is valid for
/// 5 minutes and one download.  The requesting user must hold the same JWT
/// that created the token.
#[cfg(not(target_arch = "wasm32"))]
async fn mailbox_backup_handler(
    dioxus::server::axum::extract::Path(token): dioxus::server::axum::extract::Path<String>,
    req: dioxus::server::axum::extract::Request,
) -> dioxus::server::axum::response::Response {
    use dioxus::server::axum::response::IntoResponse;
    use dioxus::server::http;

    // Validate token characters to prevent path traversal.
    if !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return (http::StatusCode::BAD_REQUEST, "Invalid token").into_response();
    }

    // Extract the auth cookie from request headers.
    let cookie_header = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let jwt_token = match parse_cookie_value_str(&cookie_header, "auth_token") {
        Some(t) => t.to_string(),
        None => return (http::StatusCode::UNAUTHORIZED, "Not authenticated").into_response(),
    };

    // Verify the caller's JWT to get their user_id.
    let claims = match panel::auth::jwt::verify_token(&jwt_token) {
        Ok(c) => c,
        Err(_) => {
            return (http::StatusCode::UNAUTHORIZED, "Invalid or expired session").into_response()
        }
    };

    // Consume the one-time token.
    let (file_path, filename) = match panel::server::email::consume_backup_token(&token, claims.sub)
    {
        Some(pair) => pair,
        None => {
            return (
                http::StatusCode::NOT_FOUND,
                "Backup token not found or expired",
            )
                .into_response()
        }
    };

    // Read the archive from disk.
    let data = match tokio::fs::read(&file_path).await {
        Ok(d) => d,
        Err(_) => {
            return (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Backup file missing",
            )
                .into_response()
        }
    };

    // Remove temp file after reading.
    let _ = tokio::fs::remove_file(&file_path).await;

    // Build a safe Content-Disposition filename (ASCII graphics only).
    let safe_filename: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let mut resp = (http::StatusCode::OK, data).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/gzip"),
    );
    if let Ok(v) = http::HeaderValue::from_str(&format!("attachment; filename=\"{safe_filename}\""))
    {
        headers.insert(http::header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// Parse a single named cookie value from a `Cookie:` header string.
#[cfg(not(target_arch = "wasm32"))]
fn parse_cookie_value_str<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
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

/// Try to load saved auth state from localStorage, discarding if expired.
fn load_auth_from_storage() -> Option<AuthState> {
    #[cfg(target_arch = "wasm32")]
    {
        let storage = web_sys::window()?.local_storage().ok()??;
        let json = storage.get_item("auth").ok()??;
        let state: AuthState = serde_json::from_str(&json).ok()?;
        // Discard if the token has expired
        let now = chrono::Utc::now().timestamp();
        if state.expires_at <= now {
            let _ = storage.remove_item("auth");
            return None;
        }
        Some(state)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

/// Save auth state (no token) to localStorage for UI persistence.
#[allow(unused_variables)]
fn save_auth_to_storage(auth: &AuthState) {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten()
        {
            if let Ok(json) = serde_json::to_string(auth) {
                let _ = storage.set_item("auth", &json);
            }
        }
    }
}

/// Clear auth state from localStorage.
fn clear_auth_storage() {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten()
        {
            let _ = storage.remove_item("auth");
        }
    }
}

/// Root app component with auth context and routing.
#[allow(non_snake_case)]
fn App() -> Element {
    use_context_provider(|| Signal::new(None::<AuthState>));
    use_context_provider(|| Signal::new(AuthLoaded(false)));

    let mut auth = use_context::<Signal<Option<AuthState>>>();
    let mut auth_loaded = use_context::<Signal<AuthLoaded>>();

    // Load auth from localStorage on the client after hydration
    use_effect(move || {
        if let Some(state) = load_auth_from_storage() {
            auth.set(Some(state));
        }
        auth_loaded.set(AuthLoaded(true));
    });

    rsx! {
        document::Stylesheet { href: asset!("/assets/tailwind.css") }
        Router::<Route> {}
    }
}

/// Application routes
#[derive(Routable, Clone, PartialEq)]
#[rustfmt::skip]
enum Route {
    // Public routes
    #[route("/login")]
    Login {},

    // Admin Portal
    #[layout(AdminShell)]
        #[route("/admin")]
        AdminDashboard {},
        #[route("/admin/servers")]
        AdminServers {},
        #[route("/admin/resellers")]
        AdminResellers {},
        #[route("/admin/clients")]
        AdminClients {},
        #[route("/admin/packages")]
        AdminPackages {},
        #[route("/admin/sites")]
        AdminAllSites {},
        #[route("/admin/databases")]
        AdminDatabases {},
        #[route("/admin/monitoring")]
        AdminMonitoring {},
        #[route("/admin/email")]
        AdminEmail {},
        #[route("/admin/antispam")]
        AdminAntiSpam {},
        #[route("/admin/mail-queue")]
        AdminMailQueue {},
        #[route("/admin/email-stats")]
        AdminEmailStats {},
        #[route("/admin/email-debug")]
        AdminEmailDebug {},
        #[route("/admin/audit-log")]
        AdminAuditLog {},
        #[route("/admin/settings")]
        AdminSettings {},
        #[route("/admin/firewall")]
        AdminFirewall {},
        #[route("/admin/waf")]
        AdminWaf {},
        #[route("/admin/clamav")]
        AdminClamAv {},
        #[route("/admin/ssh-hardening")]
        AdminSshHardening {},
        #[route("/admin/backups")]
        AdminBackups {},
        #[route("/admin/tickets")]
        AdminSupportTickets {},
    #[end_layout]

    // Reseller Portal
    #[layout(ResellerShell)]
        #[route("/reseller")]
        ResellerDashboard {},
        #[route("/reseller/clients")]
        ResellerClients {},
        #[route("/reseller/packages")]
        ResellerPackages {},
        #[route("/reseller/branding")]
        ResellerBranding {},
        #[route("/reseller/support")]
        ResellerSupportTickets {},
        #[route("/reseller/settings")]
        ResellerSettings {},
    #[end_layout]

    // Client Portal
    #[layout(ClientShell)]
        #[route("/")]
        ClientDashboard {},
        #[route("/sites")]
        ClientSites {},
        #[route("/databases")]
        ClientDatabases {},
        #[route("/dns")]
        ClientDns {},
        #[route("/email")]
        ClientEmail {},
        #[route("/files")]
        ClientFileManager {},
        #[route("/git")]
        ClientGit {},
        #[route("/cron")]
        ClientCron {},
        #[route("/backups")]
        ClientBackups {},
        #[route("/usage")]
        ClientUsage {},
        #[route("/stats")]
        ClientWebStats {},
        #[route("/ftp")]
        ClientFtp {},
        #[route("/support")]
        ClientSupportTickets {},
        #[route("/settings")]
        ClientSettings {},
    #[end_layout]

    #[route("/:..route")]
    PageNotFound { route: Vec<String> },
}

// ──── Layout Components ────
#[component]
fn AdminShell() -> Element {
    let auth = use_context::<Signal<Option<AuthState>>>();
    let auth_loaded = use_context::<Signal<AuthLoaded>>();
    let mut sidebar_open = use_signal(|| false);
    let nav = use_navigator();
    use_effect(move || {
        if auth_loaded().0 && auth().is_none() {
            nav.push(Route::Login {});
        }
    });
    if !auth_loaded().0 || auth().is_none() {
        return rsx! {};
    }
    rsx! {
        div { class: "flex h-screen bg-gray-50/50 overflow-hidden font-sans",
            if sidebar_open() {
                div {
                    class: "fixed inset-0 bg-gray-900/40 backdrop-blur-sm z-40 md:hidden transition-opacity",
                    onclick: move |_| sidebar_open.set(false)
                }
            }
            div { class: "fixed inset-y-0 left-0 z-50 transform transition-transform duration-300 w-64 md:relative", class: if sidebar_open() { "translate-x-0" } else { "-translate-x-full md:translate-x-0" },
                AdminSidebar {}
            }
            div { class: "flex-1 flex flex-col min-w-0 overflow-hidden",
                AdminHeader { on_menu_toggle: move |_| sidebar_open.set(!sidebar_open()) }
                main { class: "flex-1 overflow-auto",
                    ImpersonationBanner {}
                    PanelUpdateBanner {}
                    Outlet::<Route> {}
                }
            }
        }
    }
}

#[component]
fn ResellerShell() -> Element {
    let auth = use_context::<Signal<Option<AuthState>>>();
    let auth_loaded = use_context::<Signal<AuthLoaded>>();
    let mut sidebar_open = use_signal(|| false);
    let nav = use_navigator();
    use_effect(move || {
        if auth_loaded().0 && auth().is_none() {
            nav.push(Route::Login {});
        }
    });
    if !auth_loaded().0 || auth().is_none() {
        return rsx! {};
    }
    rsx! {
        div { class: "flex h-screen bg-gray-50/50 overflow-hidden font-sans",
            if sidebar_open() {
                div {
                    class: "fixed inset-0 bg-gray-900/40 backdrop-blur-sm z-40 md:hidden transition-opacity",
                    onclick: move |_| sidebar_open.set(false)
                }
            }
            div { class: "fixed inset-y-0 left-0 z-50 transform transition-transform duration-300 w-64 md:relative", class: if sidebar_open() { "translate-x-0" } else { "-translate-x-full md:translate-x-0" },
                ResellerSidebar {}
            }
            div { class: "flex-1 flex flex-col min-w-0 overflow-hidden",
                ResellerHeader { on_menu_toggle: move |_| sidebar_open.set(!sidebar_open()) }
                main { class: "flex-1 overflow-auto",
                    ImpersonationBanner {}
                    Outlet::<Route> {}
                }
            }
        }
    }
}

#[component]
fn ClientShell() -> Element {
    let auth = use_context::<Signal<Option<AuthState>>>();
    let auth_loaded = use_context::<Signal<AuthLoaded>>();
    let mut sidebar_open = use_signal(|| false);
    let nav = use_navigator();
    use_effect(move || {
        if auth_loaded().0 && auth().is_none() {
            nav.push(Route::Login {});
        }
    });
    if !auth_loaded().0 || auth().is_none() {
        return rsx! {};
    }
    rsx! {
        div { class: "flex h-screen bg-gray-50/50 overflow-hidden font-sans",
            if sidebar_open() {
                div {
                    class: "fixed inset-0 bg-gray-900/40 backdrop-blur-sm z-40 md:hidden transition-opacity",
                    onclick: move |_| sidebar_open.set(false)
                }
            }
            div { class: "fixed inset-y-0 left-0 z-50 transform transition-transform duration-300 w-64 md:relative", class: if sidebar_open() { "translate-x-0" } else { "-translate-x-full md:translate-x-0" },
                ClientSidebar {}
            }
            div { class: "flex-1 flex flex-col min-w-0 overflow-hidden",
                ClientHeader { on_menu_toggle: move |_| sidebar_open.set(!sidebar_open()) }
                main { class: "flex-1 overflow-auto",
                    ImpersonationBanner {}
                    Outlet::<Route> {}
                }
            }
        }
    }
}

/// Banner shown at the top of every portal when an admin is impersonating
/// another user. Shows the impersonated username and a "Return to Admin" button.
#[component]
fn ImpersonationBanner() -> Element {
    let mut auth = use_context::<Signal<Option<AuthState>>>();
    let nav = use_navigator();

    let Some(ref state) = auth() else {
        return rsx! {};
    };
    if state.impersonated_by.is_none() {
        return rsx! {};
    }
    let username = state.username.clone();

    rsx! {
        div { class: "bg-amber-50 border-b border-amber-200 px-6 py-2.5 flex items-center justify-between text-sm",
            div { class: "flex items-center gap-2 text-amber-800 font-medium",
                span { "⚠ Impersonating " }
                strong { "{username}" }
            }
            button {
                class: "px-3 py-1 bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold rounded-lg transition-colors",
                onclick: move |_| {
                    spawn(async move {
                        match server_end_impersonation().await {
                            Ok(resp) => {
                                let state = AuthState {
                                    user_id: resp.user_id,
                                    username: resp.username.clone(),
                                    email: resp.email.clone(),
                                    role: resp.role,
                                    expires_at: resp.expires_at,
                                    impersonated_by: None,
                                };
                                save_auth_to_storage(&state);
                                auth.set(Some(state));
                                nav.push(Route::AdminDashboard {});
                            }
                            Err(_) => {
                                clear_auth_storage();
                                auth.set(None);
                                nav.push(Route::Login {});
                            }
                        }
                    });
                },
                "Return to Admin"
            }
        }
    }
}

/// Banner shown at the top of the admin portal when a newer panel version is
/// available on GitHub Releases.  Only visible to admins (AdminShell only).
/// The version check is performed once on mount; any network failure is silent.
#[component]
fn PanelUpdateBanner() -> Element {
    let version_info = use_resource(move || async move { server_check_panel_version().await });

    // Local dismiss state (session-scoped, not persisted)
    let mut dismissed = use_signal(|| false);
    let mut show_instructions = use_signal(|| false);
    let mut updating = use_signal(|| false);
    let mut update_result = use_signal(|| None::<Result<String, String>>);

    // Resolve the resource — only render when we know an update is available
    let Some(Ok(ref info)) = version_info
        .read()
        .as_ref()
        .map(|r| r.as_ref().map(|v| v.clone()).map_err(|e| e.to_string()))
    else {
        return rsx! {};
    };

    if !info.update_available || dismissed() {
        return rsx! {};
    }

    let current = info.current.clone();
    let latest = info.latest.clone();
    let release_url = info.release_url.clone();

    rsx! {
        div { class: "bg-blue-50 border-b border-blue-200 px-6 py-2.5 text-sm",
            // Main banner row
            div { class: "flex items-center justify-between gap-4",
                div { class: "flex items-center gap-2 text-blue-800 font-medium",
                    Icon { name: "arrow-up-circle", class: "w-4 h-4 shrink-0".to_string() }
                    span {
                        "Panel update available: "
                        strong { "v{current}" }
                        " → "
                        strong { "v{latest}" }
                    }
                }
                div { class: "flex items-center gap-2 shrink-0",
                    a {
                        href: "{release_url}",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        class: "px-3 py-1 text-blue-700 hover:text-blue-900 hover:bg-blue-100 rounded-lg transition-colors text-xs font-medium",
                        "Release notes"
                    }
                    button {
                        class: "px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg transition-colors",
                        onclick: move |_| show_instructions.set(!show_instructions()),
                        if show_instructions() { "Hide instructions" } else { "Update Panel" }
                    }
                    button {
                        class: "p-1 text-blue-400 hover:text-blue-700 transition-colors",
                        title: "Dismiss",
                        onclick: move |_| dismissed.set(true),
                        Icon { name: "x", class: "w-4 h-4".to_string() }
                    }
                }
            }

            // Expandable instructions section
            if show_instructions() {
                div { class: "mt-3 border-t border-blue-200 pt-3 space-y-3",

                    // Manual SSH update instructions
                    div {
                        p { class: "text-blue-700 font-semibold mb-1", "Manual update (SSH):" }
                        pre { class: "bg-blue-900 text-blue-100 text-xs rounded-lg px-4 py-3 overflow-x-auto select-all",
                            "sudo bash -c \"$(curl -fsSL https://raw.githubusercontent.com/damiencal/panel/main/install.sh)\""
                        }
                        p { class: "text-blue-600 text-xs mt-1",
                            "SSH into your server and run the command above. The installer will detect the latest release, verify the checksum, and restart the panel service."
                        }
                    }

                    // One-click update
                    div { class: "flex items-center gap-3",
                        button {
                            class: "px-4 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2",
                            disabled: updating(),
                            onclick: move |_| {
                                if updating() { return; }
                                updating.set(true);
                                update_result.set(None);
                                spawn(async move {
                                    match server_trigger_panel_update().await {
                                        Ok(res) => {
                                            updating.set(false);
                                            update_result.set(Some(Ok(res.message)));
                                        }
                                        Err(e) => {
                                            updating.set(false);
                                            let msg = e.to_string()
                                                .strip_prefix("error running server function: ")
                                                .unwrap_or(&e.to_string())
                                                .trim_end_matches(" (details: None)")
                                                .to_string();
                                            update_result.set(Some(Err(msg)));
                                        }
                                    }
                                });
                            },
                            if updating() {
                                Icon { name: "loader", class: "w-3.5 h-3.5 animate-spin".to_string() }
                                "Applying update…"
                            } else {
                                Icon { name: "download", class: "w-3.5 h-3.5".to_string() }
                                "Apply Update Now"
                            }
                        }
                        p { class: "text-blue-500 text-xs",
                            "Downloads the latest binary, verifies its SHA-256 checksum, installs it, and restarts the panel."
                        }
                    }

                    // Update result feedback
                    if let Some(ref result) = update_result() {
                        match result {
                            Ok(msg) => rsx! {
                                div { class: "flex items-start gap-2 p-3 bg-green-50 border border-green-200 rounded-lg",
                                    Icon { name: "check-circle", class: "w-4 h-4 text-green-600 mt-0.5 shrink-0".to_string() }
                                    div {
                                        p { class: "text-green-800 font-medium text-xs", "{msg}" }
                                        p { class: "text-green-600 text-xs mt-0.5",
                                            "The panel service is restarting. This page will refresh automatically in a few seconds."
                                        }
                                    }
                                }
                                // Auto-refresh after 8 s to reconnect to the new process
                                script { dangerous_inner_html: "setTimeout(()=>window.location.reload(),8000)" }
                            },
                            Err(err) => rsx! {
                                div { class: "flex items-start gap-2 p-3 bg-red-50 border border-red-200 rounded-lg",
                                    Icon { name: "alert-triangle", class: "w-4 h-4 text-red-600 mt-0.5 shrink-0".to_string() }
                                    div {
                                        p { class: "text-red-800 font-medium text-xs", "Update failed" }
                                        p { class: "text-red-600 text-xs mt-0.5", "{err}" }
                                    }
                                }
                            },
                        }
                    }
                }
            }
        }
    }
}

// ──── Sidebar Components ────

#[component]
fn AdminSidebar() -> Element {
    rsx! {
        aside { class: "w-64 bg-white border-r border-gray-200/80 flex flex-col h-full",
            div { class: "px-5 h-16 flex items-center border-b border-gray-100 shrink-0",
                div { class: "flex items-center gap-3",
                    div { class: "w-8 h-8 rounded-lg bg-gradient-to-br from-rose-500 to-rose-600 flex items-center justify-center shadow-sm",
                        Icon { name: "layers", class: "w-4 h-4 text-white".to_string() }
                    }
                    div {
                        p { class: "text-sm font-bold text-gray-900 leading-none", "Control Panel" }
                        p { class: "text-[0.625rem] text-gray-400 mt-0.5", "Administrator" }
                    }
                }
            }
            nav { class: "flex-1 px-3 py-4 space-y-0.5 overflow-y-auto",
                SidebarLink { to: Route::AdminDashboard {}, label: "Dashboard", icon: "layout-dashboard" }
                SidebarLink { to: Route::AdminServers {}, label: "Server", icon: "server" }
                SidebarSection { label: "Management" }
                SidebarLink { to: Route::AdminResellers {}, label: "Resellers", icon: "users" }
                SidebarLink { to: Route::AdminClients {}, label: "Clients", icon: "briefcase" }
                SidebarLink { to: Route::AdminPackages {}, label: "Packages", icon: "package" }
                SidebarSection { label: "Infrastructure" }
                SidebarLink { to: Route::AdminAllSites {}, label: "All Sites", icon: "globe" }
                SidebarLink { to: Route::AdminDatabases {}, label: "Databases", icon: "database" }
                SidebarLink { to: Route::AdminEmail {}, label: "Email Limits", icon: "mail" }
                SidebarSection { label: "Email Security" }
                SidebarLink { to: Route::AdminAntiSpam {}, label: "Anti-Spam", icon: "shield" }
                SidebarLink { to: Route::AdminMailQueue {}, label: "Mail Queue", icon: "inbox" }
                SidebarLink { to: Route::AdminEmailStats {}, label: "Email Stats", icon: "bar-chart-2" }
                SidebarLink { to: Route::AdminEmailDebug {}, label: "Email Debugger", icon: "terminal" }
                SidebarLink { to: Route::AdminMonitoring {}, label: "Monitoring", icon: "activity" }
                SidebarSection { label: "Security" }
                SidebarLink { to: Route::AdminFirewall {}, label: "Firewall (UFW)", icon: "shield-off" }
                SidebarLink { to: Route::AdminWaf {}, label: "WAF / ModSecurity", icon: "zap" }
                SidebarLink { to: Route::AdminClamAv {}, label: "ClamAV", icon: "bug" }
                SidebarLink { to: Route::AdminSshHardening {}, label: "SSH Hardening", icon: "lock" }
                SidebarSection { label: "System" }
                SidebarLink { to: Route::AdminBackups {}, label: "Backups", icon: "archive" }
                SidebarLink { to: Route::AdminAuditLog {}, label: "Audit Log", icon: "clipboard" }
                SidebarLink { to: Route::AdminSupportTickets {}, label: "Support Tickets", icon: "message-square" }
                SidebarLink { to: Route::AdminSettings {}, label: "Settings", icon: "settings" }
            }
        }
    }
}

#[component]
fn ResellerSidebar() -> Element {
    rsx! {
        aside { class: "w-64 bg-white border-r border-gray-200/80 flex flex-col h-full",
            div { class: "px-5 h-16 flex items-center border-b border-gray-100 shrink-0",
                div { class: "flex items-center gap-3",
                    div { class: "w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center shadow-sm",
                        Icon { name: "briefcase", class: "w-4 h-4 text-white".to_string() }
                    }
                    div {
                        p { class: "text-sm font-bold text-gray-900 leading-none", "Control Panel" }
                        p { class: "text-[0.625rem] text-gray-400 mt-0.5", "Reseller" }
                    }
                }
            }
            nav { class: "flex-1 px-3 py-4 space-y-0.5 overflow-y-auto",
                SidebarLink { to: Route::ResellerDashboard {}, label: "Dashboard", icon: "layout-dashboard" }
                SidebarSection { label: "Management" }
                SidebarLink { to: Route::ResellerClients {}, label: "Clients", icon: "users" }
                SidebarLink { to: Route::ResellerPackages {}, label: "Packages", icon: "package" }
                SidebarLink { to: Route::ResellerBranding {}, label: "Branding", icon: "palette" }
                SidebarSection { label: "Support" }
                SidebarLink { to: Route::ResellerSupportTickets {}, label: "Tickets", icon: "message-square" }
                SidebarLink { to: Route::ResellerSettings {}, label: "Settings", icon: "settings" }
            }
        }
    }
}

#[component]
fn ClientSidebar() -> Element {
    rsx! {
        aside { class: "w-64 bg-white border-r border-gray-200/80 flex flex-col h-full",
            div { class: "px-5 h-16 flex items-center border-b border-gray-100 shrink-0",
                div { class: "flex items-center gap-3",
                    div { class: "w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-500 to-emerald-600 flex items-center justify-center shadow-sm",
                        Icon { name: "globe", class: "w-4 h-4 text-white".to_string() }
                    }
                    div {
                        p { class: "text-sm font-bold text-gray-900 leading-none", "Control Panel" }
                        p { class: "text-[0.625rem] text-gray-400 mt-0.5", "Client" }
                    }
                }
            }
            nav { class: "flex-1 px-3 py-4 space-y-0.5 overflow-y-auto",
                SidebarLink { to: Route::ClientDashboard {}, label: "Dashboard", icon: "layout-dashboard" }
                SidebarSection { label: "Hosting" }
                SidebarLink { to: Route::ClientSites {}, label: "Websites", icon: "globe" }
                SidebarLink { to: Route::ClientDatabases {}, label: "Databases", icon: "database" }
                SidebarLink { to: Route::ClientDns {}, label: "DNS", icon: "link" }
                SidebarLink { to: Route::ClientEmail {}, label: "Email", icon: "mail" }
                SidebarSection { label: "Tools" }
                SidebarLink { to: Route::ClientFileManager {}, label: "Files", icon: "folder" }
                SidebarLink { to: Route::ClientGit {}, label: "Git", icon: "git-branch" }
                SidebarLink { to: Route::ClientCron {}, label: "Cron Jobs", icon: "clock" }
                SidebarLink { to: Route::ClientBackups {}, label: "Backups", icon: "save" }
                SidebarLink { to: Route::ClientUsage {}, label: "Usage", icon: "bar-chart" }
                SidebarLink { to: Route::ClientWebStats {}, label: "Statistics", icon: "activity" }
                SidebarLink { to: Route::ClientFtp {}, label: "FTP Stats", icon: "upload" }
                SidebarSection { label: "Help" }
                SidebarLink { to: Route::ClientSupportTickets {}, label: "Support", icon: "message-square" }
                SidebarLink { to: Route::ClientSettings {}, label: "Settings", icon: "settings" }
            }
        }
    }
}

#[component]
fn SidebarSection(label: &'static str) -> Element {
    rsx! {
        div { class: "pt-5 pb-1 px-3",
            p { class: "text-[0.625rem] font-semibold uppercase tracking-wider text-gray-400 select-none", "{label}" }
        }
    }
}

#[component]
fn SidebarLink(to: Route, label: &'static str, icon: &'static str) -> Element {
    rsx! {
        Link {
            to,
            class: "flex items-center gap-3 px-3 py-2 rounded-lg text-gray-600 hover:bg-gray-50 hover:text-gray-900 transition-all duration-150 text-[0.8125rem] font-medium",
            active_class: "!bg-rose-50 !text-rose-600 !font-semibold".to_string(),
            Icon { name: icon, class: "w-[1.125rem] h-[1.125rem] shrink-0".to_string() }
            span { "{label}" }
        }
    }
}

// ──── Header Components ────

#[derive(PartialEq, Clone, Props)]
struct HeaderProps {
    on_menu_toggle: EventHandler<MouseEvent>,
}

#[component]
fn AdminHeader(props: HeaderProps) -> Element {
    let mut auth = use_context::<Signal<Option<AuthState>>>();
    let nav = use_navigator();
    rsx! {
        header { class: "sticky top-0 z-40 bg-white/80 backdrop-blur-xl border-b border-gray-200/60 px-4 md:px-6 h-16 flex items-center justify-between",
            div { class: "flex items-center gap-3",
                button {
                    class: "md:hidden p-2 text-gray-500 hover:bg-gray-100 rounded-lg transition-colors",
                    onclick: move |e| props.on_menu_toggle.call(e),
                    Icon { name: "menu", class: "w-5 h-5".to_string() }
                }
                h1 { class: "text-base font-semibold text-gray-800 hidden md:block", "Administration" }
            }
            div { class: "flex items-center gap-2",
                if let Some(ref user) = auth() {
                    div { class: "hidden md:flex items-center gap-2.5 px-3 py-1.5 bg-gray-50/80 rounded-lg mr-1",
                        div { class: "w-7 h-7 rounded-full bg-gradient-to-br from-rose-400 to-rose-500 flex items-center justify-center shadow-sm",
                            Icon { name: "user", class: "w-3.5 h-3.5 text-white".to_string() }
                        }
                        div {
                            p { class: "text-sm font-medium text-gray-700 leading-none", "{user.username}" }
                            p { class: "text-[0.625rem] text-gray-400 mt-0.5", "{user.email}" }
                        }
                    }
                }
                button {
                    class: "flex items-center gap-1.5 px-3 py-2 text-sm text-gray-500 hover:bg-red-50 hover:text-red-600 rounded-lg transition-colors",
                    onclick: move |_| {
                        let nav = nav.clone();
                        spawn(async move {
                            let _ = server_logout().await;
                            clear_auth_storage();
                            auth.set(None);
                            nav.push(Route::Login {});
                        });
                    },
                    Icon { name: "log-out", class: "w-4 h-4".to_string() }
                    span { class: "hidden sm:inline", "Logout" }
                }
            }
        }
    }
}

#[component]
fn ResellerHeader(props: HeaderProps) -> Element {
    let mut auth = use_context::<Signal<Option<AuthState>>>();
    let nav = use_navigator();
    rsx! {
        header { class: "sticky top-0 z-40 bg-white/80 backdrop-blur-xl border-b border-gray-200/60 px-4 md:px-6 h-16 flex items-center justify-between",
            div { class: "flex items-center gap-3",
                button {
                    class: "md:hidden p-2 text-gray-500 hover:bg-gray-100 rounded-lg transition-colors",
                    onclick: move |e| props.on_menu_toggle.call(e),
                    Icon { name: "menu", class: "w-5 h-5".to_string() }
                }
                h1 { class: "text-base font-semibold text-gray-800 hidden md:block", "Reseller Portal" }
            }
            div { class: "flex items-center gap-2",
                if let Some(ref user) = auth() {
                    div { class: "hidden md:flex items-center gap-2.5 px-3 py-1.5 bg-gray-50/80 rounded-lg mr-1",
                        div { class: "w-7 h-7 rounded-full bg-gradient-to-br from-blue-400 to-blue-500 flex items-center justify-center shadow-sm",
                            Icon { name: "user", class: "w-3.5 h-3.5 text-white".to_string() }
                        }
                        div {
                            p { class: "text-sm font-medium text-gray-700 leading-none", "{user.username}" }
                            p { class: "text-[0.625rem] text-gray-400 mt-0.5", "{user.email}" }
                        }
                    }
                }
                button {
                    class: "flex items-center gap-1.5 px-3 py-2 text-sm text-gray-500 hover:bg-red-50 hover:text-red-600 rounded-lg transition-colors",
                    onclick: move |_| {
                        let nav = nav.clone();
                        spawn(async move {
                            let _ = server_logout().await;
                            clear_auth_storage();
                            auth.set(None);
                            nav.push(Route::Login {});
                        });
                    },
                    Icon { name: "log-out", class: "w-4 h-4".to_string() }
                    span { class: "hidden sm:inline", "Logout" }
                }
            }
        }
    }
}

#[component]
fn ClientHeader(props: HeaderProps) -> Element {
    let mut auth = use_context::<Signal<Option<AuthState>>>();
    let nav = use_navigator();
    rsx! {
        header { class: "sticky top-0 z-40 bg-white/80 backdrop-blur-xl border-b border-gray-200/60 px-4 md:px-6 h-16 flex items-center justify-between",
            div { class: "flex items-center gap-3",
                button {
                    class: "md:hidden p-2 text-gray-500 hover:bg-gray-100 rounded-lg transition-colors",
                    onclick: move |e| props.on_menu_toggle.call(e),
                    Icon { name: "menu", class: "w-5 h-5".to_string() }
                }
                h1 { class: "text-base font-semibold text-gray-800 hidden md:block", "My Hosting" }
            }
            div { class: "flex items-center gap-2",
                if let Some(ref user) = auth() {
                    div { class: "hidden md:flex items-center gap-2.5 px-3 py-1.5 bg-gray-50/80 rounded-lg mr-1",
                        div { class: "w-7 h-7 rounded-full bg-gradient-to-br from-emerald-400 to-emerald-500 flex items-center justify-center shadow-sm",
                            Icon { name: "user", class: "w-3.5 h-3.5 text-white".to_string() }
                        }
                        div {
                            p { class: "text-sm font-medium text-gray-700 leading-none", "{user.username}" }
                            p { class: "text-[0.625rem] text-gray-400 mt-0.5", "{user.email}" }
                        }
                    }
                }
                button {
                    class: "flex items-center gap-1.5 px-3 py-2 text-sm text-gray-500 hover:bg-red-50 hover:text-red-600 rounded-lg transition-colors",
                    onclick: move |_| {
                        let nav = nav.clone();
                        spawn(async move {
                            let _ = server_logout().await;
                            clear_auth_storage();
                            auth.set(None);
                            nav.push(Route::Login {});
                        });
                    },
                    Icon { name: "log-out", class: "w-4 h-4".to_string() }
                    span { class: "hidden sm:inline", "Logout" }
                }
            }
        }
    }
}

// ──── Page Components ────

#[component]
fn Login() -> Element {
    let mut auth = use_context::<Signal<Option<AuthState>>>();
    let nav = use_navigator();
    let mut username = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut totp_code = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let mut show_totp = use_signal(|| false);
    let mut loading = use_signal(|| false);

    let onsubmit = move |e: FormEvent| {
        e.prevent_default();
        loading.set(true);
        error.set(None);
        let u = username();
        let p = password();
        let t = if show_totp() && !totp_code().is_empty() {
            Some(totp_code())
        } else {
            None
        };
        spawn(async move {
            match server_login(u, p, t).await {
                Ok(resp) => {
                    let state = AuthState {
                        user_id: resp.user_id,
                        username: resp.username.clone(),
                        email: resp.email.clone(),
                        role: resp.role,
                        expires_at: resp.expires_at,
                        impersonated_by: resp.impersonated_by,
                    };
                    save_auth_to_storage(&state);
                    auth.set(Some(state));
                    match resp.role {
                        Role::Admin => nav.push(Route::AdminDashboard {}),
                        Role::Reseller => nav.push(Route::ResellerDashboard {}),
                        Role::Client | Role::Developer => nav.push(Route::ClientDashboard {}),
                    };
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("2FA code required") {
                        show_totp.set(true);
                        error.set(Some(
                            "Enter your 6-digit authentication code to continue.".to_string(),
                        ));
                    } else {
                        error.set(Some(clean_err(&msg)));
                    }
                }
            }
            loading.set(false);
        });
    };

    rsx! {
        div { class: "flex items-center justify-center h-screen bg-gray-50 relative overflow-hidden",
            // Background effect
            div { class: "absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-purple-200/50 rounded-full blur-3xl" }
            div { class: "absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-rose-200/50 rounded-full blur-3xl" }

            div { class: "w-full max-w-md bg-white/70 backdrop-blur-xl border border-white rounded-3xl shadow-xl p-8 lg:p-10 relative z-10 transition-all duration-300",
                h1 { class: "text-3xl lg:text-4xl font-extrabold text-gray-900 mb-2 tracking-tight", "Welcome" }
                p { class: "text-gray-500 mb-6", "Login to your hosting panel" }

                if let Some(err) = error() {
                    div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                }

                form { onsubmit,
                    div { class: "mb-4",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Username" }
                        input {
                            r#type: "text",
                            class: "w-full px-5 py-3 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                            placeholder: "Enter your username",
                            value: "{username}",
                            oninput: move |e| username.set(e.value()),
                            required: true,
                        }
                    }
                    div { class: "mb-4",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Password" }
                        input {
                            r#type: "password",
                            class: "w-full px-5 py-3 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                            placeholder: "Enter your password",
                            value: "{password}",
                            oninput: move |e| password.set(e.value()),
                            required: true,
                        }
                    }

                    if show_totp() {
                        div { class: "mb-4",
                            label { class: "block text-sm font-medium text-gray-700 mb-1", "2FA Code" }
                            input {
                                r#type: "text",
                                class: "w-full px-5 py-3 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                placeholder: "Enter your 6-digit code",
                                value: "{totp_code}",
                                oninput: move |e| totp_code.set(e.value()),
                                maxlength: "6",
                            }
        }
    }

                    button {
                        r#type: "submit",
                        class: "w-full py-3 px-4 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-xl shadow-sm hover:shadow-xl transition-all duration-200 transform hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-sm",
                        disabled: loading(),
                        if loading() { "Signing in..." } else { "Sign In" }
                    }
                }
            }
        }
    }
}

#[component]
fn AdminDashboard() -> Element {
    let auth = use_context::<Signal<Option<AuthState>>>();
    let stats = use_resource(move || async move { server_get_admin_stats().await });

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "mb-8",
                h2 { class: "text-2xl font-bold text-gray-900",
                    if let Some(ref user) = auth() {
                        "Welcome back, {user.username}"
                    } else {
                        "Admin Dashboard"
                    }
                }
                p { class: "text-gray-500 mt-1 text-sm", "Overview of your hosting infrastructure." }
            }
            match &*stats.read() {
                Some(Ok(s)) => rsx! {
                    div { class: "grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5",
                        StatCard { label: "Total Users", value: "{s.total_users}", icon: "users", color: "blue" }
                        StatCard { label: "Resellers", value: "{s.total_resellers}", icon: "briefcase", color: "purple" }
                        StatCard { label: "Clients", value: "{s.total_clients}", icon: "users", color: "emerald" }
                        StatCard { label: "Sites", value: "{s.total_sites}", icon: "globe", color: "amber" }
                    }
                },
                Some(Err(e)) => rsx! { div { class: "text-red-600", "Error: {e}" } },
                None => rsx! {
                    div { class: "grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5",
                        for _ in 0..4 {
                            div { class: "bg-white rounded-2xl border border-gray-100 p-6 animate-pulse",
                                div { class: "h-3 bg-gray-200 rounded w-20 mb-4" }
                                div { class: "h-8 bg-gray-100 rounded w-12" }
                            }
                        }
                    }
                },
            }
        }
    }
}

// ──── Shared UI Components ────

#[component]
fn StatCard(
    label: &'static str,
    value: String,
    icon: &'static str,
    color: Option<&'static str>,
) -> Element {
    let color = color.unwrap_or("rose");
    let (bg, text) = match color {
        "blue" => ("bg-blue-50", "text-blue-500"),
        "emerald" | "green" => ("bg-emerald-50", "text-emerald-500"),
        "amber" | "yellow" => ("bg-amber-50", "text-amber-500"),
        "purple" => ("bg-purple-50", "text-purple-500"),
        _ => ("bg-rose-50", "text-rose-500"),
    };
    rsx! {
        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 hover:shadow-md transition-all duration-200 group",
            div { class: "flex items-center justify-between",
                div {
                    p { class: "text-xs font-medium text-gray-500 uppercase tracking-wider", "{label}" }
                    p { class: "text-3xl font-bold text-gray-900 mt-2", "{value}" }
                }
                div { class: "p-3 {bg} rounded-xl {text} transition-colors duration-200",
                    Icon { name: icon, class: "w-6 h-6".to_string() }
                }
            }
        }
    }
}

#[component]
fn StatusBadge(status: String) -> Element {
    let color = match status.as_str() {
        "Active" | "Running" | "Success" | "Open" => "bg-green-100 text-green-800",
        "Suspended" | "Stopped" | "Error" => "bg-red-100 text-red-800",
        "Pending" | "Unknown" => "bg-yellow-100 text-yellow-800",
        "Closed" | "Inactive" => "bg-gray-100 text-gray-600",
        _ => "bg-blue-100 text-blue-800",
    };
    rsx! {
        span { class: "px-2 py-1 text-xs font-medium rounded-full {color}", "{status}" }
    }
}

#[component]
fn AdminServers() -> Element {
    let mut services = use_resource(move || async move { server_get_services_status().await });
    let mut metrics = use_resource(move || async move { server_get_system_metrics().await });
    let mut server_info = use_resource(move || async move { server_get_server_info().await });
    let mut php_versions = use_resource(move || async move { server_list_php_versions().await });
    let mut action_error = use_signal(|| None::<String>);
    let mut action_loading = use_signal(|| None::<String>);
    let mut update_loading = use_signal(|| false);
    let mut update_result =
        use_signal(|| None::<Result<panel::server::monitoring::OsUpdateResult, String>>);
    let mut php_installing = use_signal(|| None::<String>);
    let mut php_install_error = use_signal(|| None::<String>);

    let mut handle_action =
        move |svc_type: panel::models::service::ServiceType,
              cmd: panel::models::service::ServiceCommand| {
            let label = format!("{}:{}", svc_type, cmd);
            action_loading.set(Some(label));
            action_error.set(None);
            spawn(async move {
                let action = panel::models::service::ServiceAction {
                    service: svc_type,
                    action: cmd,
                };
                match server_manage_service(action).await {
                    Ok(_) => {
                        services.restart();
                    }
                    Err(e) => action_error.set(Some(e.to_string())),
                }
                action_loading.set(None);
            });
        };

    // Helper to format uptime
    let format_uptime = |secs: u64| -> String {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;
        if days > 0 {
            format!("{}d {}h {}m", days, hours, mins)
        } else if hours > 0 {
            format!("{}h {}m", hours, mins)
        } else {
            format!("{}m", mins)
        }
    };

    rsx! {
        div { class: "p-6 lg:p-8 space-y-6",
            div { class: "flex items-center justify-between",
                h2 { class: "text-2xl font-bold text-gray-900", "Server" }
                button {
                    class: "flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors",
                    onclick: move |_| { services.restart(); metrics.restart(); server_info.restart(); },
                    Icon { name: "refresh-cw", class: "w-4 h-4".to_string() }
                    span { "Refresh" }
                }
            }

            // Server hardware & OS info
            match &*server_info.read() {
                Some(Ok(info)) => {
                    let uptime_str = format_uptime(info.uptime_seconds);
                    let cpu_detail = format!("{} cores / {} threads \u{00b7} {}", info.cpu_cores, info.cpu_threads, info.architecture);
                    let mem_detail = format!("{:.1} GB RAM \u{00b7} {:.1} GB Swap", info.total_memory_gb, info.total_swap_gb);
                    let update_class = if info.updates_available > 0 { "p-2 bg-amber-50 rounded-lg" } else { "p-2 bg-emerald-50 rounded-lg" };
                    let update_icon = if info.updates_available > 0 { "alert-circle" } else { "check-circle" };
                    let update_icon_class = if info.updates_available > 0 { "w-5 h-5 text-amber-500".to_string() } else { "w-5 h-5 text-emerald-500".to_string() };
                    let update_text = if info.updates_available > 0 {
                        format!("{} update{} available", info.updates_available, if info.updates_available == 1 { "" } else { "s" })
                    } else {
                        "System is up to date".to_string()
                    };
                    let security_text = format!("{} security update{}", info.security_updates, if info.security_updates == 1 { "" } else { "s" });
                    let last_check_text = info.last_update_check.clone().unwrap_or_default();
                    let has_security = info.security_updates > 0;
                    let has_last_check = info.last_update_check.is_some();
                    rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                            h3 { class: "text-sm font-semibold text-gray-700 uppercase tracking-wider mb-4", "Server Information" }
                            div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-3",
                                div { class: "flex items-center gap-3",
                                    div { class: "p-2 bg-blue-50 rounded-lg",
                                        Icon { name: "monitor", class: "w-4 h-4 text-blue-500".to_string() }
                                    }
                                    div {
                                        p { class: "text-xs text-gray-400 uppercase", "Hostname" }
                                        p { class: "text-sm font-medium text-gray-900", "{info.hostname}" }
                                    }
                                }
                                div { class: "flex items-center gap-3",
                                    div { class: "p-2 bg-purple-50 rounded-lg",
                                        Icon { name: "layers", class: "w-4 h-4 text-purple-500".to_string() }
                                    }
                                    div {
                                        p { class: "text-xs text-gray-400 uppercase", "Operating System" }
                                        p { class: "text-sm font-medium text-gray-900", "{info.os_name}" }
                                    }
                                }
                                div { class: "flex items-center gap-3",
                                    div { class: "p-2 bg-amber-50 rounded-lg",
                                        Icon { name: "terminal", class: "w-4 h-4 text-amber-500".to_string() }
                                    }
                                    div {
                                        p { class: "text-xs text-gray-400 uppercase", "Kernel" }
                                        p { class: "text-sm font-medium text-gray-900", "{info.kernel_version}" }
                                    }
                                }
                                div { class: "flex items-center gap-3",
                                    div { class: "p-2 bg-emerald-50 rounded-lg",
                                        Icon { name: "cpu", class: "w-4 h-4 text-emerald-500".to_string() }
                                    }
                                    div {
                                        p { class: "text-xs text-gray-400 uppercase", "CPU" }
                                        p { class: "text-sm font-medium text-gray-900", "{info.cpu_model}" }
                                        p { class: "text-xs text-gray-500", "{cpu_detail}" }
                                    }
                                }
                                div { class: "flex items-center gap-3",
                                    div { class: "p-2 bg-rose-50 rounded-lg",
                                        Icon { name: "hard-drive", class: "w-4 h-4 text-rose-500".to_string() }
                                    }
                                    div {
                                        p { class: "text-xs text-gray-400 uppercase", "Memory / Swap" }
                                        p { class: "text-sm font-medium text-gray-900", "{mem_detail}" }
                                    }
                                }
                                div { class: "flex items-center gap-3",
                                    div { class: "p-2 bg-blue-50 rounded-lg",
                                        Icon { name: "clock", class: "w-4 h-4 text-blue-500".to_string() }
                                    }
                                    div {
                                        p { class: "text-xs text-gray-400 uppercase", "Uptime" }
                                        p { class: "text-sm font-medium text-gray-900", "{uptime_str}" }
                                    }
                                }
                            }
                        }
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                            div { class: "flex items-start justify-between gap-4",
                                div { class: "flex items-center gap-3",
                                    div { class: "{update_class}",
                                        Icon { name: update_icon, class: update_icon_class }
                                    }
                                    div {
                                        p { class: "text-sm font-semibold text-gray-900", "{update_text}" }
                                        if has_security {
                                            p { class: "text-xs text-amber-600 font-medium", "{security_text}" }
                                        }
                                        if has_last_check {
                                            p { class: "text-xs text-gray-400", "Last checked: {last_check_text}" }
                                        }
                                    }
                                }
                                button {
                                    class: "flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-xl hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap",
                                    disabled: update_loading(),
                                    onclick: move |_| {
                                        update_loading.set(true);
                                        update_result.set(None);
                                        spawn(async move {
                                            let res = server_trigger_os_update().await;
                                            update_result.set(Some(res.map_err(|e| e.to_string())));
                                            update_loading.set(false);
                                            server_info.restart();
                                        });
                                    },
                                    if update_loading() {
                                        Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                                        span { "Updating\u{2026}" }
                                    } else {
                                        Icon { name: "download", class: "w-4 h-4".to_string() }
                                        span { "Run Update" }
                                    }
                                }
                            }
                            match &*update_result.read() {
                                Some(Ok(res)) => rsx! {
                                    div { class: "mt-4 p-3 bg-emerald-50 rounded-xl border border-emerald-100",
                                        p { class: "text-xs font-semibold text-emerald-700 mb-1",
                                            "Update complete \u{2014} {res.packages_upgraded} upgraded, {res.packages_installed} installed, {res.packages_removed} removed"
                                        }
                                        if !res.output_tail.is_empty() {
                                            pre { class: "text-xs text-gray-600 whitespace-pre-wrap break-all max-h-40 overflow-y-auto font-mono",
                                                "{res.output_tail}"
                                            }
                                        }
                                    }
                                },
                                Some(Err(e)) => rsx! {
                                    div { class: "mt-4 p-3 bg-red-50 rounded-xl border border-red-100",
                                        p { class: "text-xs font-semibold text-red-700", "Update failed: {e}" }
                                    }
                                },
                                None => rsx! {},
                            }
                        }
                    }
                },
                Some(Err(_)) => rsx! {},
                None => rsx! {
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 animate-pulse",
                        div { class: "h-4 bg-gray-200 rounded w-40 mb-4" }
                        div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4",
                            for _ in 0..6 {
                                div { class: "h-12 bg-gray-100 rounded-lg" }
                            }
                        }
                    }
                },
            }

            // System metrics cards
            match &*metrics.read() {
                Some(Ok(m)) => {
                    let used_gb = m.total_memory_gb - m.available_memory_gb;
                    let mem_pct = if m.total_memory_gb > 0.0 { (used_gb / m.total_memory_gb * 100.0) as u32 } else { 0 };
                    rsx! {
                        div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6",
                            StatCard { label: "Memory Used", value: format!("{:.1} / {:.1} GB", used_gb, m.total_memory_gb), icon: "server" }
                            StatCard { label: "Memory Usage", value: format!("{}%", mem_pct), icon: "activity" }
                            StatCard { label: "Load (1m)", value: format!("{:.2}", m.load_1), icon: "activity" }
                            StatCard { label: "Load (5m / 15m)", value: format!("{:.2} / {:.2}", m.load_5, m.load_15), icon: "activity" }
                        }
                    }
                },
                Some(Err(_)) => rsx! {},
                None => rsx! {
                    div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6",
                        for _ in 0..4 {
                            div { class: "bg-white rounded-2xl border border-gray-100 p-6 animate-pulse",
                                div { class: "h-4 bg-gray-200 rounded w-24 mb-3" }
                                div { class: "h-8 bg-gray-200 rounded w-32" }
                            }
                        }
                    }
                },
            }

            if let Some(err) = action_error() {
                div { class: "bg-red-50 text-red-700 p-4 rounded-xl text-sm", "{err}" }
            }

            // Services table
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*services.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Service" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Port" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Version" }
                                    th { class: "px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for svc in list.iter() {
                                    {
                                        let svc_type = svc.service_type;
                                        let status_str = svc.status.to_string();
                                        let port_str = svc.port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string());
                                        let version_str = svc.version.clone().unwrap_or_else(|| "—".to_string());
                                        let is_loading_start = action_loading().as_deref() == Some(&format!("{}:start", svc_type));
                                        let is_loading_stop = action_loading().as_deref() == Some(&format!("{}:stop", svc_type));
                                        let is_loading_restart = action_loading().as_deref() == Some(&format!("{}:restart", svc_type));
                                        rsx! {
                                            tr { class: "hover:bg-gray-50/50 transition-colors",
                                                td { class: "px-6 py-4",
                                                    div { class: "flex items-center gap-3",
                                                        div { class: "p-2 bg-gray-50 rounded-lg",
                                                            Icon { name: "server", class: "w-5 h-5 text-gray-600".to_string() }
                                                        }
                                                        span { class: "text-sm font-medium text-gray-900", "{svc_type}" }
                                                    }
                                                }
                                                td { class: "px-6 py-4", StatusBadge { status: status_str } }
                                                td { class: "px-6 py-4 text-sm text-gray-500", "{port_str}" }
                                                td { class: "px-6 py-4 text-sm text-gray-500 max-w-[200px] truncate", "{version_str}" }
                                                td { class: "px-6 py-4",
                                                    div { class: "flex items-center justify-end gap-1",
                                                        button {
                                                            class: "p-1.5 text-green-600 hover:bg-green-50 rounded-lg transition-colors disabled:opacity-40",
                                                            title: "Start",
                                                            disabled: is_loading_start,
                                                            onclick: move |_| handle_action(svc_type, panel::models::service::ServiceCommand::Start),
                                                            Icon { name: "play", class: "w-4 h-4".to_string() }
                                                        }
                                                        button {
                                                            class: "p-1.5 text-red-600 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-40",
                                                            title: "Stop",
                                                            disabled: is_loading_stop,
                                                            onclick: move |_| handle_action(svc_type, panel::models::service::ServiceCommand::Stop),
                                                            Icon { name: "stop-circle", class: "w-4 h-4".to_string() }
                                                        }
                                                        button {
                                                            class: "p-1.5 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors disabled:opacity-40",
                                                            title: "Restart",
                                                            disabled: is_loading_restart,
                                                            onclick: move |_| handle_action(svc_type, panel::models::service::ServiceCommand::Restart),
                                                            Icon { name: "rotate-cw", class: "w-4 h-4".to_string() }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No services detected." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500 animate-pulse", "Loading services..." } },
                }
            }

            // PHP Versions — install lsphp packages from the official LiteSpeed repo.
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                h3 { class: "text-sm font-semibold text-gray-700 uppercase tracking-wider mb-4",
                    "PHP Versions (lsphp)"
                }
                if let Some(err) = php_install_error() {
                    div { class: "mb-4 p-3 bg-red-50 text-red-700 rounded-lg text-sm", "{err}" }
                }
                div { class: "grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3",
                    { const VERSIONS: &[&str] = panel::services::openlitespeed::SUPPORTED_PHP_VERSIONS;
                      let installed: Vec<String> = match &*php_versions.read() {
                          Some(Ok(v)) => v.clone(),
                          _ => Vec::new(),
                      };
                      rsx! {
                        for ver in VERSIONS.iter() {
                            {
                                let ver_str = ver.to_string();
                                let is_installed = installed.contains(&ver_str);
                                let is_busy = php_installing().as_deref() == Some(ver);
                                rsx! {
                                    div { class: "flex flex-col items-center gap-2 p-3 border border-gray-200 rounded-xl",
                                        span { class: "text-sm font-semibold text-gray-800", "PHP {ver_str}" }
                                        if is_installed {
                                            span { class: "text-xs px-2 py-0.5 bg-green-100 text-green-700 rounded-full font-medium",
                                                "Installed"
                                            }
                                        } else {
                                            button {
                                                class: "text-xs px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50",
                                                disabled: is_busy || php_installing().is_some(),
                                                onclick: move |_| {
                                                    let v = ver_str.clone();
                                                    php_installing.set(Some(v.clone()));
                                                    php_install_error.set(None);
                                                    spawn(async move {
                                                        match server_install_php_version(v).await {
                                                            Ok(()) => {
                                                                php_versions.restart();
                                                            }
                                                            Err(e) => php_install_error.set(Some(e.to_string())),
                                                        }
                                                        php_installing.set(None);
                                                    });
                                                },
                                                if is_busy {
                                                    "Installing\u{2026}"
                                                } else {
                                                    "Install"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                      }
                    }
                }
            }
        }
    }
}

#[component]
fn AdminResellers() -> Element {
    let mut resellers = use_resource(move || async move { server_list_resellers().await });
    let nav = use_navigator();
    let mut auth_ctx = use_context::<Signal<Option<AuthState>>>();

    let mut show_create = use_signal(|| false);
    let mut create_username = use_signal(String::new);
    let mut create_email = use_signal(String::new);
    let mut create_password = use_signal(String::new);
    let mut form_error = use_signal(|| None::<String>);
    let mut form_loading = use_signal(|| false);
    let mut action_error = use_signal(|| None::<String>);
    let mut action_loading = use_signal(|| None::<i64>);
    let mut confirm_delete = use_signal(|| None::<i64>);

    let on_create_submit = move |e: FormEvent| {
        e.prevent_default();
        form_loading.set(true);
        form_error.set(None);
        let u = create_username();
        let e = create_email();
        let p = create_password();
        spawn(async move {
            match server_create_user(u, e, p, Role::Reseller, None).await {
                Ok(_) => {
                    show_create.set(false);
                    create_username.set(String::new());
                    create_email.set(String::new());
                    create_password.set(String::new());
                    resellers.restart();
                }
                Err(err) => form_error.set(Some(err.to_string())),
            }
            form_loading.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 space-y-6",
            // Header
            div { class: "flex items-center justify-between",
                h2 { class: "text-2xl font-bold text-gray-900", "Resellers" }
                div { class: "flex gap-3",
                    button {
                        class: "flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors",
                        onclick: move |_| resellers.restart(),
                        Icon { name: "refresh-cw", class: "w-4 h-4".to_string() }
                        span { "Refresh" }
                    }
                    button {
                        class: "flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-rose-500 rounded-xl hover:bg-rose-600 transition-colors shadow-sm hover:shadow-md",
                        onclick: move |_| { show_create.set(true); form_error.set(None); },
                        Icon { name: "plus", class: "w-4 h-4".to_string() }
                        span { "Add Reseller" }
                    }
                }
            }

            // Stats cards
            match &*resellers.read() {
                Some(Ok(list)) => {
                    let total = list.len();
                    let active = list.iter().filter(|r| r.user.status == panel::models::user::AccountStatus::Active).count();
                    let suspended = list.iter().filter(|r| r.user.status == panel::models::user::AccountStatus::Suspended).count();
                    let total_clients: i64 = list.iter().map(|r| r.client_count).sum();
                    rsx! {
                        div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6",
                            StatCard { label: "Total Resellers", value: total.to_string(), icon: "users" }
                            StatCard { label: "Active", value: active.to_string(), icon: "user-check" }
                            StatCard { label: "Suspended", value: suspended.to_string(), icon: "user-x" }
                            StatCard { label: "Total Clients", value: total_clients.to_string(), icon: "briefcase" }
                        }
                    }
                },
                _ => rsx! {
                    div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6",
                        for _ in 0..4 {
                            div { class: "bg-white rounded-2xl border border-gray-100 p-6 animate-pulse",
                                div { class: "h-4 bg-gray-200 rounded w-24 mb-3" }
                                div { class: "h-8 bg-gray-200 rounded w-32" }
                            }
                        }
                    }
                },
            }

            if let Some(err) = action_error() {
                div { class: "bg-red-50 text-red-700 p-4 rounded-xl text-sm flex items-center justify-between",
                    span { "{err}" }
                    button {
                        class: "text-red-500 hover:text-red-700",
                        onclick: move |_| action_error.set(None),
                        Icon { name: "x", class: "w-4 h-4".to_string() }
                    }
                }
            }

            // Create Reseller Form (slide-down panel)
            if show_create() {
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                    div { class: "flex items-center justify-between mb-4",
                        h3 { class: "text-lg font-semibold text-gray-900", "Create New Reseller" }
                        button {
                            class: "text-gray-400 hover:text-gray-600 transition-colors",
                            onclick: move |_| show_create.set(false),
                            Icon { name: "x", class: "w-5 h-5".to_string() }
                        }
                    }

                    if let Some(err) = form_error() {
                        div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                    }

                    form { onsubmit: on_create_submit,
                        div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-4",
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Username" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    placeholder: "reseller_username",
                                    value: "{create_username}",
                                    oninput: move |e| create_username.set(e.value()),
                                    required: true,
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Email" }
                                input {
                                    r#type: "email",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    placeholder: "reseller@example.com",
                                    value: "{create_email}",
                                    oninput: move |e| create_email.set(e.value()),
                                    required: true,
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Password" }
                                div { class: "flex gap-2",
                                    input {
                                        r#type: "text",
                                        class: "flex-1 px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm font-mono",
                                        placeholder: "Strong password",
                                        value: "{create_password}",
                                        oninput: move |e| create_password.set(e.value()),
                                        required: true,
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-3 py-2.5 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl transition-colors text-sm whitespace-nowrap flex items-center gap-1.5",
                                        title: "Generate password & copy to clipboard",
                                        onclick: move |_| {
                                            #[cfg(target_arch = "wasm32")]
                                            {
                                                use web_sys::wasm_bindgen::JsCast;
                                                let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                                                let lower = b"abcdefghijklmnopqrstuvwxyz";
                                                let digits = b"0123456789";
                                                let special = b"!@#$%^&*";
                                                let all = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
                                                let crypto = web_sys::window().unwrap().crypto().unwrap();
                                                let mut buf = [0u8; 20];
                                                let array = js_sys::Uint8Array::new_with_length(20);
                                                crypto.get_random_values_with_array_buffer_view(&array.unchecked_ref()).unwrap();
                                                array.copy_to(&mut buf);
                                                let mut chars: Vec<char> = vec![
                                                    upper[(buf[0] as usize) % upper.len()] as char,
                                                    lower[(buf[1] as usize) % lower.len()] as char,
                                                    digits[(buf[2] as usize) % digits.len()] as char,
                                                    special[(buf[3] as usize) % special.len()] as char,
                                                ];
                                                for b in &buf[4..] {
                                                    chars.push(all[(*b as usize) % all.len()] as char);
                                                }
                                                // Simple shuffle using remaining entropy
                                                for i in (1..chars.len()).rev() {
                                                    let j = (buf[i % buf.len()] as usize) % (i + 1);
                                                    chars.swap(i, j);
                                                }
                                                let pass: String = chars.into_iter().collect();
                                                create_password.set(pass.clone());
                                                if let Some(w) = web_sys::window() {
                                                    let _ = w.navigator().clipboard().write_text(&pass);
                                                }
                                            }
                                        },
                                        Icon { name: "key", class: "w-4 h-4".to_string() }
                                        "Generate"
                                    }
                                }
                            }
                        }
                        div { class: "flex justify-end gap-3",
                            button {
                                r#type: "button",
                                class: "px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-xl hover:bg-gray-200 transition-colors",
                                onclick: move |_| show_create.set(false),
                                "Cancel"
                            }
                            button {
                                r#type: "submit",
                                class: "px-4 py-2 text-sm font-medium text-white bg-rose-500 rounded-xl hover:bg-rose-600 transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed",
                                disabled: form_loading(),
                                if form_loading() { "Creating..." } else { "Create Reseller" }
                            }
                        }
                    }
                }
            }

            // Delete confirmation dialog
            if let Some(delete_id) = confirm_delete() {
                div { class: "fixed inset-0 bg-black/30 backdrop-blur-sm z-50 flex items-center justify-center",
                    onclick: move |_| confirm_delete.set(None),
                    div { class: "bg-white rounded-2xl shadow-xl p-6 max-w-sm w-full mx-4",
                        onclick: move |e| e.stop_propagation(),
                        div { class: "flex items-center gap-3 mb-4",
                            div { class: "p-2 bg-red-100 rounded-xl",
                                Icon { name: "alert-triangle", class: "w-6 h-6 text-red-600".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-900", "Delete Reseller" }
                        }
                        p { class: "text-sm text-gray-600 mb-6",
                            "Are you sure you want to delete this reseller? This action cannot be undone and will affect all their clients."
                        }
                        div { class: "flex justify-end gap-3",
                            button {
                                class: "px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-xl hover:bg-gray-200 transition-colors",
                                onclick: move |_| confirm_delete.set(None),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 text-sm font-medium text-white bg-red-500 rounded-xl hover:bg-red-600 transition-colors shadow-sm",
                                onclick: move |_| {
                                    let uid = delete_id;
                                    confirm_delete.set(None);
                                    action_loading.set(Some(uid));
                                    action_error.set(None);
                                    spawn(async move {
                                        match server_delete_user(uid).await {
                                            Ok(_) => resellers.restart(),
                                            Err(e) => action_error.set(Some(e.to_string())),
                                        }
                                        action_loading.set(None);
                                    });
                                },
                                "Delete"
                            }
                        }
                    }
                }
            }

            // Resellers table
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*resellers.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Username" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Email" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Clients" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Created" }
                                    th { class: "px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for info in list.iter() {
                                    {
                                        let uid = info.user.id;
                                        let is_active = info.user.status == panel::models::user::AccountStatus::Active;
                                        let is_loading = action_loading() == Some(uid);
                                        let created = info.user.created_at.format("%b %d, %Y").to_string();
                                        let avatar_letter = info.user.username.chars().next().unwrap_or('R').to_uppercase().to_string();
                                        let username = info.user.username.clone();
                                        let email = info.user.email.clone();
                                        let client_count = info.client_count;
                                        let status_str = info.user.status.to_string();
                                        rsx! {
                                            tr { class: "hover:bg-gray-50/50 transition-colors",
                                                td { class: "px-6 py-4",
                                                    div { class: "flex items-center gap-3",
                                                        div { class: "w-8 h-8 bg-rose-100 rounded-full flex items-center justify-center text-rose-600 font-semibold text-sm",
                                                            "{avatar_letter}"
                                                        }
                                                        span { class: "text-sm font-medium text-gray-900", "{username}" }
                                                    }
                                                }
                                                td { class: "px-6 py-4 text-sm text-gray-500", "{email}" }
                                                td { class: "px-6 py-4",
                                                    span { class: "inline-flex items-center gap-1 text-sm text-gray-700",
                                                        Icon { name: "users", class: "w-3.5 h-3.5 text-gray-400".to_string() }
                                                        "{client_count}"
                                                    }
                                                }
                                                td { class: "px-6 py-4", StatusBadge { status: status_str } }
                                                td { class: "px-6 py-4 text-sm text-gray-500", "{created}" }
                                                td { class: "px-6 py-4",
                                                    div { class: "flex items-center justify-end gap-2",
                                                        if is_loading {
                                                            span { class: "text-xs text-gray-400 animate-pulse", "Working..." }
                                                        } else {
                                                            if is_active {
                                                                button {
                                                                    class: "p-1.5 text-amber-600 hover:bg-amber-50 rounded-lg transition-colors",
                                                                    title: "Suspend",
                                                                    onclick: move |_| {
                                                                        action_loading.set(Some(uid));
                                                                        action_error.set(None);
                                                                        spawn(async move {
                                                                            match server_update_user_status(uid, panel::models::user::AccountStatus::Suspended).await {
                                                                                Ok(_) => resellers.restart(),
                                                                                Err(e) => action_error.set(Some(e.to_string())),
                                                                            }
                                                                            action_loading.set(None);
                                                                        });
                                                                    },
                                                                    Icon { name: "pause-circle", class: "w-4 h-4".to_string() }
                                                                }
                                                            } else {
                                                                button {
                                                                    class: "p-1.5 text-green-600 hover:bg-green-50 rounded-lg transition-colors",
                                                                    title: "Activate",
                                                                    onclick: move |_| {
                                                                        action_loading.set(Some(uid));
                                                                        action_error.set(None);
                                                                        spawn(async move {
                                                                            match server_update_user_status(uid, panel::models::user::AccountStatus::Active).await {
                                                                                Ok(_) => resellers.restart(),
                                                                                Err(e) => action_error.set(Some(e.to_string())),
                                                                            }
                                                                            action_loading.set(None);
                                                                        });
                                                                    },
                                                                    Icon { name: "play-circle", class: "w-4 h-4".to_string() }
                                                                }
                                                            }
                                                            button {
                                                                class: "p-1.5 text-red-600 hover:bg-red-50 rounded-lg transition-colors",
                                                                title: "Delete",
                                                                onclick: move |_| confirm_delete.set(Some(uid)),
                                                                Icon { name: "trash-2", class: "w-4 h-4".to_string() }
                                                            }
                                                            button {
                                                                class: "p-1.5 text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors",
                                                                title: "Login As",
                                                                onclick: move |_| {
                                                                    action_loading.set(Some(uid));
                                                                    action_error.set(None);
                                                                    spawn(async move {
                                                                        match server_impersonate_user(uid).await {
                                                                            Ok(resp) => {
                                                                                let state = AuthState {
                                                                                    user_id: resp.user_id,
                                                                                    username: resp.username.clone(),
                                                                                    email: resp.email.clone(),
                                                                                    role: resp.role,
                                                                                    expires_at: resp.expires_at,
                                                                                    impersonated_by: resp.impersonated_by,
                                                                                };
                                                                                save_auth_to_storage(&state);
                                                                                auth_ctx.set(Some(state));
                                                                                nav.push(Route::ResellerDashboard {});
                                                                            }
                                                                            Err(e) => action_error.set(Some(e.to_string())),
                                                                        }
                                                                        action_loading.set(None);
                                                                    });
                                                                },
                                                                Icon { name: "log-in", class: "w-4 h-4".to_string() }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if list.is_empty() {
                            div { class: "p-12 text-center",
                                Icon { name: "users", class: "w-12 h-12 text-gray-300 mx-auto mb-3".to_string() }
                                p { class: "text-gray-500 font-medium", "No resellers yet" }
                                p { class: "text-gray-400 text-sm mt-1", "Click \"Add Reseller\" to create the first one." }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! {
                        div { class: "p-6 space-y-3",
                            for _ in 0..3 {
                                div { class: "h-12 bg-gray-100 rounded-lg animate-pulse" }
                            }
                        }
                    },
                }
            }
        }
    }
}

#[component]
fn AdminClients() -> Element {
    let mut users = use_resource(move || async move { server_list_users().await });
    let packages = use_resource(move || async move { server_list_packages().await });
    let mut show_form = use_signal(|| false);
    let mut new_username = use_signal(String::new);
    let mut new_email = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut new_role = use_signal(|| "Client".to_string());
    let mut new_package = use_signal(|| None::<i64>);
    let mut new_company = use_signal(String::new);
    let mut new_address = use_signal(String::new);
    let mut new_phone = use_signal(String::new);
    let mut create_error = use_signal(|| None::<String>);
    let mut creating = use_signal(|| false);
    let action_error = use_signal(|| None::<String>);

    let on_create = move |e: FormEvent| {
        e.prevent_default();
        creating.set(true);
        create_error.set(None);
        let username = new_username();
        let email = new_email();
        let password = new_password();
        let role = match new_role().as_str() {
            "Reseller" => Role::Reseller,
            "Admin" => Role::Admin,
            _ => Role::Client,
        };
        let package_id = new_package();
        let company = new_company();
        let address = new_address();
        let phone = new_phone();
        spawn(async move {
            match server_create_user(username.clone(), email, password, role, package_id).await {
                Ok(user_id) => {
                    // Save optional detail fields if any were provided.
                    let has_details =
                        !company.is_empty() || !address.is_empty() || !phone.is_empty();
                    if has_details {
                        let c = if company.is_empty() {
                            None
                        } else {
                            Some(company)
                        };
                        let a = if address.is_empty() {
                            None
                        } else {
                            Some(address)
                        };
                        let p = if phone.is_empty() { None } else { Some(phone) };
                        let _ = server_update_user_details(user_id, c, a, p).await;
                    }
                    new_username.set(String::new());
                    new_email.set(String::new());
                    new_password.set(String::new());
                    new_role.set("Client".to_string());
                    new_package.set(None);
                    new_company.set(String::new());
                    new_address.set(String::new());
                    new_phone.set(String::new());
                    show_form.set(false);
                    users.restart();
                }
                Err(e) => create_error.set(Some(e.to_string())),
            }
            creating.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            // Header with Add button
            div { class: "flex items-center justify-between mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Clients" }
                button {
                    class: "px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors flex items-center gap-2",
                    onclick: move |_| show_form.set(!show_form()),
                    if show_form() { "✕ Cancel" } else { "+ Add Client" }
                }
            }

            if let Some(err) = action_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            // Stats cards (exclude Admin users)
            if let Some(Ok(list)) = &*users.read() {
                {
                    let total = list.iter().filter(|u| u.role != Role::Admin).count();
                    let active = list.iter().filter(|u| u.role != Role::Admin && u.status == panel::models::user::AccountStatus::Active).count();
                    let suspended = list.iter().filter(|u| u.role != Role::Admin && u.status == panel::models::user::AccountStatus::Suspended).count();
                    let pending = list.iter().filter(|u| u.role != Role::Admin && u.status == panel::models::user::AccountStatus::Pending).count();
                    rsx! {
                        div { class: "grid grid-cols-1 md:grid-cols-4 gap-4 mb-6",
                            StatCard { label: "Total", value: total.to_string(), icon: "users" }
                            StatCard { label: "Active", value: active.to_string(), icon: "user-check" }
                            StatCard { label: "Suspended", value: suspended.to_string(), icon: "user-x" }
                            StatCard { label: "Pending", value: pending.to_string(), icon: "user-plus" }
                        }
                    }
                }
            }

            // Create form
            if show_form() {
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                    h3 { class: "text-lg font-semibold text-gray-800 mb-4", "Add New Client" }
                    if let Some(err) = create_error() {
                        div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                    }
                    form { onsubmit: on_create, class: "space-y-4",
                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Username" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "johndoe",
                                    value: "{new_username}",
                                    oninput: move |e| new_username.set(e.value()),
                                    required: true,
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Email" }
                                input {
                                    r#type: "email",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "john@example.com",
                                    value: "{new_email}",
                                    oninput: move |e| new_email.set(e.value()),
                                    required: true,
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Password" }
                                div { class: "flex gap-2",
                                    input {
                                        r#type: "text",
                                        class: "flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent font-mono",
                                        placeholder: "••••••••",
                                        value: "{new_password}",
                                        oninput: move |e| new_password.set(e.value()),
                                        required: true,
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-3 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition-colors text-sm whitespace-nowrap flex items-center gap-1.5",
                                        title: "Generate password & copy to clipboard",
                                        onclick: move |_| {
                                            #[cfg(target_arch = "wasm32")]
                                            {
                                                use web_sys::wasm_bindgen::JsCast;
                                                let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                                                let lower = b"abcdefghijklmnopqrstuvwxyz";
                                                let digits = b"0123456789";
                                                let special = b"!@#$%^&*";
                                                let all = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
                                                let crypto = web_sys::window().unwrap().crypto().unwrap();
                                                let mut buf = [0u8; 20];
                                                let array = js_sys::Uint8Array::new_with_length(20);
                                                crypto.get_random_values_with_array_buffer_view(&array.unchecked_ref()).unwrap();
                                                array.copy_to(&mut buf);
                                                let mut chars: Vec<char> = vec![
                                                    upper[(buf[0] as usize) % upper.len()] as char,
                                                    lower[(buf[1] as usize) % lower.len()] as char,
                                                    digits[(buf[2] as usize) % digits.len()] as char,
                                                    special[(buf[3] as usize) % special.len()] as char,
                                                ];
                                                for b in &buf[4..] {
                                                    chars.push(all[(*b as usize) % all.len()] as char);
                                                }
                                                for i in (1..chars.len()).rev() {
                                                    let j = (buf[i % buf.len()] as usize) % (i + 1);
                                                    chars.swap(i, j);
                                                }
                                                let pass: String = chars.into_iter().collect();
                                                new_password.set(pass.clone());
                                                if let Some(w) = web_sys::window() {
                                                    let _ = w.navigator().clipboard().write_text(&pass);
                                                }
                                            }
                                        },
                                        Icon { name: "key", class: "w-4 h-4".to_string() }
                                        "Generate"
                                    }
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Role" }
                                select {
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                                    value: "{new_role}",
                                    onchange: move |e| new_role.set(e.value()),
                                    option { value: "Client", "Client" }
                                    option { value: "Reseller", "Reseller" }
                                }
                            }
                        }
                        // Package selector (only for Client role)
                        if new_role() == "Client" {
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Package" }
                                select {
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                                    onchange: move |e| {
                                        let val = e.value();
                                        new_package.set(val.parse::<i64>().ok());
                                    },
                                    option { value: "", "No package" }
                                    if let Some(Ok(pkgs)) = &*packages.read() {
                                        for pkg in pkgs.iter().filter(|p| p.is_active) {
                                            option { value: "{pkg.id}", "{pkg.name}" }
                                        }
                                    }
                                }
                            }
                        }
                        // Optional contact details
                        div { class: "grid grid-cols-1 md:grid-cols-3 gap-4",
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Company (optional)" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "Acme Inc.",
                                    value: "{new_company}",
                                    oninput: move |e| new_company.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Phone (optional)" }
                                input {
                                    r#type: "tel",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "+1 555 000 0000",
                                    value: "{new_phone}",
                                    oninput: move |e| new_phone.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Address (optional)" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "123 Main St, City",
                                    value: "{new_address}",
                                    oninput: move |e| new_address.set(e.value()),
                                }
                            }
                        }
                        div { class: "flex justify-end",
                            button {
                                r#type: "submit",
                                class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50",
                                disabled: creating(),
                                if creating() { "Creating..." } else { "Create Client" }
                            }
                        }
                    }
                }
            }

            // Users table
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*users.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Username" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Email" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Company" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Role" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Created" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for user in list.iter().filter(|u| u.role != Role::Admin) {
                                    AdminClientRow { user: user.clone(), users_resource: users, action_error: action_error }
                                }
                            }
                        }
                        if list.iter().all(|u| u.role == Role::Admin) {
                            p { class: "p-6 text-gray-500 text-center", "No clients found. Click \"Add Client\" to create one." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
        }
    }
}

#[component]
fn AdminClientRow(
    user: panel::models::user::User,
    users_resource: Resource<Result<Vec<panel::models::user::User>, ServerFnError>>,
    action_error: Signal<Option<String>>,
) -> Element {
    let user_id = user.id;
    let is_active = user.status == panel::models::user::AccountStatus::Active;
    let is_suspended = user.status == panel::models::user::AccountStatus::Suspended;
    let mut users_resource = users_resource;
    let mut action_error = action_error;
    let mut confirm_delete = use_signal(|| false);
    let mut loading = use_signal(|| false);
    let created = user.created_at.format("%Y-%m-%d").to_string();
    let mut auth_ctx = use_context::<Signal<Option<AuthState>>>();
    let nav = use_navigator();
    let user_role = user.role;

    let toggle_status = move |_| {
        loading.set(true);
        action_error.set(None);
        let new_status = if is_active {
            panel::models::user::AccountStatus::Suspended
        } else {
            panel::models::user::AccountStatus::Active
        };
        spawn(async move {
            match server_update_user_status(user_id, new_status).await {
                Ok(_) => users_resource.restart(),
                Err(e) => action_error.set(Some(e.to_string())),
            }
            loading.set(false);
        });
    };

    let on_delete = move |_| {
        loading.set(true);
        action_error.set(None);
        spawn(async move {
            match server_delete_user(user_id).await {
                Ok(_) => users_resource.restart(),
                Err(e) => action_error.set(Some(e.to_string())),
            }
            loading.set(false);
            confirm_delete.set(false);
        });
    };

    let on_impersonate = move |_| {
        loading.set(true);
        action_error.set(None);
        spawn(async move {
            match server_impersonate_user(user_id).await {
                Ok(resp) => {
                    let state = AuthState {
                        user_id: resp.user_id,
                        username: resp.username.clone(),
                        email: resp.email.clone(),
                        role: resp.role,
                        expires_at: resp.expires_at,
                        impersonated_by: resp.impersonated_by,
                    };
                    save_auth_to_storage(&state);
                    auth_ctx.set(Some(state));
                    match user_role {
                        Role::Reseller => nav.push(Route::ResellerDashboard {}),
                        _ => nav.push(Route::ClientDashboard {}),
                    };
                }
                Err(e) => action_error.set(Some(e.to_string())),
            }
            loading.set(false);
        });
    };

    rsx! {
        tr { class: "hover:bg-gray-50/50 transition-colors",
            td { class: "px-6 py-4 text-sm font-medium text-gray-900", "{user.username}" }
            td { class: "px-6 py-4 text-sm text-gray-500", "{user.email}" }
            td { class: "px-6 py-4 text-sm text-gray-500",
                if let Some(c) = &user.company {
                    "{c}"
                } else {
                    "—"
                }
            }
            td { class: "px-6 py-4",
                span {
                    class: match user.role {
                        Role::Admin => "px-2 py-1 text-xs font-medium rounded-full bg-purple-100 text-purple-800",
                        Role::Reseller => "px-2 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-800",
                        Role::Client => "px-2 py-1 text-xs font-medium rounded-full bg-gray-100 text-gray-700",
                        Role::Developer => "px-2 py-1 text-xs font-medium rounded-full bg-green-100 text-green-700",
                    },
                    "{user.role}"
                }
            }
            td { class: "px-6 py-4", StatusBadge { status: user.status.to_string() } }
            td { class: "px-6 py-4 text-sm text-gray-500", "{created}" }
            td { class: "px-6 py-4",
                if confirm_delete() {
                    div { class: "flex items-center gap-2",
                        span { class: "text-xs text-red-600 font-medium", "Delete?" }
                        button {
                            class: "px-2 py-1 text-xs bg-red-600 hover:bg-red-700 text-white rounded disabled:opacity-50",
                            disabled: loading(),
                            onclick: on_delete,
                            "Yes"
                        }
                        button {
                            class: "px-2 py-1 text-xs bg-gray-200 hover:bg-gray-300 text-gray-700 rounded",
                            onclick: move |_| confirm_delete.set(false),
                            "No"
                        }
                    }
                } else {
                    div { class: "flex items-center gap-2",
                        button {
                            class: if is_active {
                                "px-3 py-1 text-xs bg-yellow-100 hover:bg-yellow-200 text-yellow-800 rounded-lg font-medium transition-colors disabled:opacity-50"
                            } else if is_suspended {
                                "px-3 py-1 text-xs bg-green-100 hover:bg-green-200 text-green-800 rounded-lg font-medium transition-colors disabled:opacity-50"
                            } else {
                                "px-3 py-1 text-xs bg-green-100 hover:bg-green-200 text-green-800 rounded-lg font-medium transition-colors disabled:opacity-50"
                            },
                            disabled: loading(),
                            onclick: toggle_status,
                            if is_active { "Suspend" } else { "Activate" }
                        }
                        button {
                            class: "px-3 py-1 text-xs bg-red-50 hover:bg-red-100 text-red-600 rounded-lg font-medium transition-colors disabled:opacity-50",
                            disabled: loading(),
                            onclick: move |_| confirm_delete.set(true),
                            "Delete"
                        }
                        button {
                            class: "px-3 py-1 text-xs bg-indigo-50 hover:bg-indigo-100 text-indigo-700 rounded-lg font-medium transition-colors disabled:opacity-50",
                            disabled: loading(),
                            onclick: on_impersonate,
                            "Login As"
                        }
                    }
                }
            }
        }
    }
}

// ──── Shared Packages Page ────

#[component]
fn PackagesPage() -> Element {
    let mut packages = use_resource(move || async move { server_list_packages().await });
    let mut show_create = use_signal(|| false);
    let mut form_error = use_signal(|| None::<String>);
    let mut form_loading = use_signal(|| false);
    let mut confirm_delete = use_signal(|| None::<i64>);

    // Form fields
    let mut pkg_name = use_signal(String::new);
    let mut pkg_description = use_signal(String::new);
    let mut pkg_max_sites = use_signal(|| "1".to_string());
    let mut pkg_max_databases = use_signal(|| "1".to_string());
    let mut pkg_max_email = use_signal(|| "10".to_string());
    let mut pkg_max_ftp = use_signal(|| "1".to_string());
    let mut pkg_disk = use_signal(|| "10240".to_string());
    let mut pkg_bandwidth = use_signal(|| "102400".to_string());
    let mut pkg_max_subdomains = use_signal(|| "5".to_string());
    let mut pkg_max_addons = use_signal(|| "0".to_string());
    let mut pkg_php = use_signal(|| true);
    let mut pkg_ssl = use_signal(|| true);
    let mut pkg_shell = use_signal(|| false);
    let mut pkg_backup = use_signal(|| true);

    let mut reset_form = move || {
        pkg_name.set(String::new());
        pkg_description.set(String::new());
        pkg_max_sites.set("1".to_string());
        pkg_max_databases.set("1".to_string());
        pkg_max_email.set("10".to_string());
        pkg_max_ftp.set("1".to_string());
        pkg_disk.set("10240".to_string());
        pkg_bandwidth.set("102400".to_string());
        pkg_max_subdomains.set("5".to_string());
        pkg_max_addons.set("0".to_string());
        pkg_php.set(true);
        pkg_ssl.set(true);
        pkg_shell.set(false);
        pkg_backup.set(true);
        form_error.set(None);
    };

    let on_create_submit = move |_: FormEvent| {
        form_loading.set(true);
        form_error.set(None);
        let name = pkg_name();
        let description = if pkg_description().is_empty() {
            None
        } else {
            Some(pkg_description())
        };
        let max_sites: i32 = pkg_max_sites().parse().unwrap_or(1);
        let max_databases: i32 = pkg_max_databases().parse().unwrap_or(1);
        let max_email: i32 = pkg_max_email().parse().unwrap_or(10);
        let max_ftp: i32 = pkg_max_ftp().parse().unwrap_or(1);
        let disk: i64 = pkg_disk().parse().unwrap_or(10240);
        let bandwidth: i64 = pkg_bandwidth().parse().unwrap_or(102400);
        let max_sub: i32 = pkg_max_subdomains().parse().unwrap_or(5);
        let max_addon: i32 = pkg_max_addons().parse().unwrap_or(0);
        let php = pkg_php();
        let ssl = pkg_ssl();
        let shell = pkg_shell();
        let backup = pkg_backup();
        spawn(async move {
            match server_create_package(
                name,
                description,
                max_sites,
                max_databases,
                max_email,
                max_ftp,
                disk,
                bandwidth,
                max_sub,
                max_addon,
                php,
                ssl,
                shell,
                backup,
            )
            .await
            {
                Ok(_) => {
                    reset_form();
                    show_create.set(false);
                    packages.restart();
                }
                Err(e) => form_error.set(Some(e.to_string())),
            }
            form_loading.set(false);
        });
    };

    let on_confirm_delete = move |_| {
        if let Some(delete_id) = confirm_delete() {
            confirm_delete.set(None);
            spawn(async move {
                let _ = server_delete_package(delete_id).await;
                packages.restart();
            });
        }
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            // Header
            div { class: "flex items-center justify-between mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Packages" }
                button {
                    class: "px-4 py-2 text-sm font-medium text-white bg-rose-500 rounded-xl hover:bg-rose-600 transition-colors shadow-sm flex items-center gap-2",
                    onclick: move |_| show_create.set(!show_create()),
                    {
                        let icon_name = if show_create() { "x" } else { "plus" };
                        rsx! { Icon { name: icon_name, class: "w-4 h-4".to_string() } }
                    }
                    span { if show_create() { "Cancel" } else { "New Package" } }
                }
            }

            // Create Package Form (slide-down panel)
            if show_create() {
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                    div { class: "flex items-center justify-between mb-4",
                        h3 { class: "text-lg font-semibold text-gray-900", "Create New Package" }
                        button {
                            class: "text-gray-400 hover:text-gray-600 transition-colors",
                            onclick: move |_| show_create.set(false),
                            Icon { name: "x", class: "w-5 h-5".to_string() }
                        }
                    }

                    if let Some(err) = form_error() {
                        div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                    }

                    form { onsubmit: on_create_submit,
                        // Name + Description
                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-4",
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Package Name" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    placeholder: "e.g. Starter, Business, Enterprise",
                                    value: "{pkg_name}",
                                    oninput: move |e| pkg_name.set(e.value()),
                                    required: true,
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Description" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    placeholder: "Optional description",
                                    value: "{pkg_description}",
                                    oninput: move |e| pkg_description.set(e.value()),
                                }
                            }
                        }

                        // Resource Limits
                        h4 { class: "text-sm font-semibold text-gray-600 uppercase tracking-wider mb-3", "Resource Limits" }
                        div { class: "grid grid-cols-2 md:grid-cols-4 gap-4 mb-4",
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Max Sites" }
                                input {
                                    r#type: "number", min: "0",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    value: "{pkg_max_sites}",
                                    oninput: move |e| pkg_max_sites.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Max Databases" }
                                input {
                                    r#type: "number", min: "0",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    value: "{pkg_max_databases}",
                                    oninput: move |e| pkg_max_databases.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Max Email Accounts" }
                                input {
                                    r#type: "number", min: "0",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    value: "{pkg_max_email}",
                                    oninput: move |e| pkg_max_email.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Max FTP Accounts" }
                                input {
                                    r#type: "number", min: "0",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    value: "{pkg_max_ftp}",
                                    oninput: move |e| pkg_max_ftp.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Disk Limit (MB)" }
                                input {
                                    r#type: "number", min: "0",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    value: "{pkg_disk}",
                                    oninput: move |e| pkg_disk.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Bandwidth (MB)" }
                                input {
                                    r#type: "number", min: "0",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    value: "{pkg_bandwidth}",
                                    oninput: move |e| pkg_bandwidth.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Max Subdomains" }
                                input {
                                    r#type: "number", min: "0",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    value: "{pkg_max_subdomains}",
                                    oninput: move |e| pkg_max_subdomains.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Max Addon Domains" }
                                input {
                                    r#type: "number", min: "0",
                                    class: "w-full px-4 py-2.5 bg-white/50 border border-gray-200/50 rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent transition-all duration-200 shadow-sm backdrop-blur-sm",
                                    value: "{pkg_max_addons}",
                                    oninput: move |e| pkg_max_addons.set(e.value()),
                                }
                            }
                        }

                        // Feature Toggles
                        h4 { class: "text-sm font-semibold text-gray-600 uppercase tracking-wider mb-3", "Features" }
                        div { class: "grid grid-cols-2 md:grid-cols-4 gap-4 mb-6",
                            label { class: "flex items-center gap-2 cursor-pointer",
                                input {
                                    r#type: "checkbox",
                                    class: "w-4 h-4 text-rose-500 rounded focus:ring-rose-500",
                                    checked: pkg_php(),
                                    onchange: move |e| pkg_php.set(e.checked()),
                                }
                                span { class: "text-sm text-gray-700", "PHP Enabled" }
                            }
                            label { class: "flex items-center gap-2 cursor-pointer",
                                input {
                                    r#type: "checkbox",
                                    class: "w-4 h-4 text-rose-500 rounded focus:ring-rose-500",
                                    checked: pkg_ssl(),
                                    onchange: move |e| pkg_ssl.set(e.checked()),
                                }
                                span { class: "text-sm text-gray-700", "SSL Enabled" }
                            }
                            label { class: "flex items-center gap-2 cursor-pointer",
                                input {
                                    r#type: "checkbox",
                                    class: "w-4 h-4 text-rose-500 rounded focus:ring-rose-500",
                                    checked: pkg_shell(),
                                    onchange: move |e| pkg_shell.set(e.checked()),
                                }
                                span { class: "text-sm text-gray-700", "Shell Access" }
                            }
                            label { class: "flex items-center gap-2 cursor-pointer",
                                input {
                                    r#type: "checkbox",
                                    class: "w-4 h-4 text-rose-500 rounded focus:ring-rose-500",
                                    checked: pkg_backup(),
                                    onchange: move |e| pkg_backup.set(e.checked()),
                                }
                                span { class: "text-sm text-gray-700", "Backups Enabled" }
                            }
                        }

                        // Submit
                        div { class: "flex justify-end gap-3",
                            button {
                                r#type: "button",
                                class: "px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-xl hover:bg-gray-200 transition-colors",
                                onclick: move |_| show_create.set(false),
                                "Cancel"
                            }
                            button {
                                r#type: "submit",
                                class: "px-4 py-2 text-sm font-medium text-white bg-rose-500 rounded-xl hover:bg-rose-600 transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed",
                                disabled: form_loading(),
                                if form_loading() { "Creating..." } else { "Create Package" }
                            }
                        }
                    }
                }
            }

            // Delete confirmation dialog
            if let Some(_delete_id) = confirm_delete() {
                div { class: "fixed inset-0 bg-black/30 backdrop-blur-sm z-50 flex items-center justify-center",
                    onclick: move |_| confirm_delete.set(None),
                    div { class: "bg-white rounded-2xl shadow-xl p-6 max-w-sm w-full mx-4",
                        onclick: move |e| e.stop_propagation(),
                        div { class: "flex items-center gap-3 mb-4",
                            div { class: "p-2 bg-red-100 rounded-xl",
                                Icon { name: "alert-triangle", class: "w-6 h-6 text-red-600".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-900", "Delete Package" }
                        }
                        p { class: "text-sm text-gray-600 mb-6",
                            "Are you sure you want to delete this package? This action cannot be undone."
                        }
                        div { class: "flex justify-end gap-3",
                            button {
                                class: "px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-xl hover:bg-gray-200 transition-colors",
                                onclick: move |_| confirm_delete.set(None),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-xl hover:bg-red-700 transition-colors",
                                onclick: on_confirm_delete,
                                "Delete"
                            }
                        }
                    }
                }
            }

            // Packages table
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*packages.read() {
                    Some(Ok(list)) => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full",
                                thead { class: "bg-gray-50 border-b border-gray-200/60",
                                    tr {
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Name" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Sites" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "DBs" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Email" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Disk (MB)" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "BW (MB)" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Features" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-100",
                                    for pkg in list.iter() {
                                        PackageRow { pkg: pkg.clone(), packages_resource: packages, confirm_delete: confirm_delete }
                                    }
                                }
                            }
                        }
                        if list.is_empty() {
                            div { class: "p-12 text-center",
                                Icon { name: "package", class: "w-12 h-12 text-gray-300 mx-auto mb-4".to_string() }
                                p { class: "text-gray-500 font-medium", "No packages defined yet." }
                                p { class: "text-gray-400 text-sm mt-1", "Create a package to get started." }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
        }
    }
}

#[component]
fn PackageRow(
    pkg: panel::models::package::Package,
    packages_resource: Resource<Result<Vec<panel::models::package::Package>, ServerFnError>>,
    confirm_delete: Signal<Option<i64>>,
) -> Element {
    let pkg_id = pkg.id;
    let mut packages_resource = packages_resource;
    let mut confirm_delete = confirm_delete;

    let on_deactivate = move |_| {
        spawn(async move {
            if let Ok(()) = server_deactivate_package(pkg_id).await {
                packages_resource.restart();
            }
        });
    };

    rsx! {
        tr { class: "hover:bg-gray-50/50 transition-colors",
            td { class: "px-6 py-4",
                div {
                    span { class: "text-sm font-medium text-gray-900", "{pkg.name}" }
                    if let Some(ref desc) = pkg.description {
                        if !desc.is_empty() {
                            p { class: "text-xs text-gray-400 mt-0.5", "{desc}" }
                        }
                    }
                }
            }
            td { class: "px-6 py-4 text-sm text-gray-600", "{pkg.max_sites}" }
            td { class: "px-6 py-4 text-sm text-gray-600", "{pkg.max_databases}" }
            td { class: "px-6 py-4 text-sm text-gray-600", "{pkg.max_email_accounts}" }
            td { class: "px-6 py-4 text-sm text-gray-600", "{pkg.disk_limit_mb}" }
            td { class: "px-6 py-4 text-sm text-gray-600", "{pkg.bandwidth_limit_mb}" }
            td { class: "px-6 py-4",
                div { class: "flex flex-wrap gap-1",
                    if pkg.php_enabled {
                        span { class: "px-1.5 py-0.5 text-xs bg-blue-100 text-blue-700 rounded", "PHP" }
                    }
                    if pkg.ssl_enabled {
                        span { class: "px-1.5 py-0.5 text-xs bg-green-100 text-green-700 rounded", "SSL" }
                    }
                    if pkg.shell_access {
                        span { class: "px-1.5 py-0.5 text-xs bg-purple-100 text-purple-700 rounded", "Shell" }
                    }
                    if pkg.backup_enabled {
                        span { class: "px-1.5 py-0.5 text-xs bg-amber-100 text-amber-700 rounded", "Backup" }
                    }
                }
            }
            td { class: "px-6 py-4",
                div { class: "flex items-center gap-2",
                    button {
                        class: "text-amber-600 hover:text-amber-800 text-xs font-medium",
                        onclick: on_deactivate,
                        "Deactivate"
                    }
                    button {
                        class: "text-red-600 hover:text-red-800 text-xs font-medium",
                        onclick: move |_| confirm_delete.set(Some(pkg_id)),
                        "Delete"
                    }
                }
            }
        }
    }
}

#[component]
fn AdminPackages() -> Element {
    rsx! { PackagesPage {} }
}

#[component]
fn AdminAllSites() -> Element {
    let mut sites = use_resource(move || async move { server_list_sites().await });
    let mut new_domain = use_signal(String::new);
    let mut new_site_type = use_signal(|| "PHP".to_string());
    let mut create_error = use_signal(|| None::<String>);
    let mut creating = use_signal(|| false);

    let on_create = move |_: FormEvent| {
        creating.set(true);
        create_error.set(None);
        let domain = new_domain();
        let site_type = match new_site_type().as_str() {
            "Static" => panel::models::site::SiteType::Static,
            "ReverseProxy" => panel::models::site::SiteType::ReverseProxy,
            "NodeJS" => panel::models::site::SiteType::NodeJs,
            _ => panel::models::site::SiteType::Php,
        };
        spawn(async move {
            match server_create_site(domain, site_type).await {
                Ok(_) => {
                    new_domain.set(String::new());
                    new_site_type.set("PHP".to_string());
                    sites.restart();
                }
                Err(e) => create_error.set(Some(e.to_string())),
            }
            creating.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "All Sites" }

            // Create site form (admin)
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                h3 { class: "text-lg font-semibold text-gray-800 mb-4", "Add Website" }
                if let Some(err) = create_error() {
                    div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                }
                form { onsubmit: on_create, class: "flex gap-4 items-end flex-wrap",
                    div { class: "flex-1 min-w-[200px]",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Domain" }
                        input {
                            r#type: "text",
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                            placeholder: "example.com",
                            value: "{new_domain}",
                            oninput: move |e| new_domain.set(e.value()),
                            required: true,
                        }
                    }
                    div { class: "w-48",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Site Type" }
                        select {
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                            value: "{new_site_type}",
                            onchange: move |e| new_site_type.set(e.value()),
                            option { value: "PHP", "PHP" }
                            option { value: "Static", "Static" }
                            option { value: "NodeJS", "Node.js" }
                            option { value: "ReverseProxy", "Reverse Proxy" }
                        }
                    }
                    button {
                        r#type: "submit",
                        class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50",
                        disabled: creating(),
                        if creating() { "Adding..." } else { "Add Site" }
                    }
                }
            }

            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*sites.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Domain" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Owner" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Type" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "SSL" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "HTTPS" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "HSTS" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Created" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for site in list.iter() {
                                    AdminSiteRow { site: site.clone(), sites_resource: sites }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No sites found." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
        }
    }
}

// ─── Per-domain log viewer ─────────────────────────────────────────────────────

#[component]
fn SiteLogViewer(site_id: i64, col_span: u32) -> Element {
    let mut log_type = use_signal(|| "access".to_string());

    let mut log_resource = use_resource(move || {
        let lt = log_type();
        async move {
            server_get_site_logs(site_id, lt)
                .await
                .map_err(|e| e.to_string())
        }
    });

    rsx! {
        tr {
            td {
                colspan: "{col_span}",
                class: "px-0 py-0 bg-gray-950",
                div { class: "px-6 py-4",
                    // Tab bar
                    div { class: "flex gap-2 mb-3",
                        button {
                            class: if log_type() == "access" {
                                "text-xs px-3 py-1 rounded bg-indigo-600 text-white font-medium"
                            } else {
                                "text-xs px-3 py-1 rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
                            },
                            onclick: move |_| log_type.set("access".to_string()),
                            "Access Log"
                        }
                        button {
                            class: if log_type() == "error" {
                                "text-xs px-3 py-1 rounded bg-indigo-600 text-white font-medium"
                            } else {
                                "text-xs px-3 py-1 rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
                            },
                            onclick: move |_| log_type.set("error".to_string()),
                            "Error Log"
                        }
                        button {
                            class: "text-xs px-3 py-1 rounded bg-gray-700 text-gray-300 hover:bg-gray-600 ml-auto",
                            onclick: move |_| log_resource.restart(),
                            "↻ Refresh"
                        }
                    }
                    // Log content
                    match log_resource() {
                        None => rsx! {
                            div { class: "text-xs text-gray-400 animate-pulse", "Loading…" }
                        },
                        Some(Ok(text)) => rsx! {
                            pre {
                                class: "text-xs text-green-300 font-mono whitespace-pre-wrap overflow-auto max-h-80 leading-5",
                                "{text}"
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "text-xs text-red-400", "Error: {e}" }
                        },
                    }
                }
            }
        }
    }
}

#[component]
fn AdminSiteRow(
    site: panel::models::site::Site,
    sites_resource: Resource<Result<Vec<panel::models::site::Site>, ServerFnError>>,
) -> Element {
    let site_id = site.id;
    let site_domain = site.domain.clone();
    let current_status = site.status;
    let ssl_on = site.ssl_enabled;
    let https_on = site.force_https;
    let hsts_on = site.hsts_enabled;
    let hsts_age = site.hsts_max_age;
    let hsts_subdoms = site.hsts_include_subdomains;
    let hsts_pre = site.hsts_preload;
    let owner_id = site.owner_id;
    let mut sites_resource = sites_resource;
    let mut confirm_delete = use_signal(|| false);
    let mut row_error = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    let mut show_logs = use_signal(|| false);

    let on_toggle_status = move |_| {
        let new_status = match current_status {
            panel::models::site::SiteStatus::Active => panel::models::site::SiteStatus::Suspended,
            panel::models::site::SiteStatus::Suspended => panel::models::site::SiteStatus::Active,
            panel::models::site::SiteStatus::Inactive => panel::models::site::SiteStatus::Active,
        };
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_update_site_status(site_id, new_status).await {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let on_toggle_ssl = move |_| {
        let new_ssl = !ssl_on;
        let fhttps = if !new_ssl { false } else { https_on };
        // Disabling SSL also clears HSTS.
        let new_hsts = if !new_ssl { false } else { hsts_on };
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_update_site_ssl(
                site_id,
                new_ssl,
                fhttps,
                new_hsts,
                hsts_age,
                hsts_subdoms,
                hsts_pre,
            )
            .await
            {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let on_toggle_https = move |_| {
        let new_https = !https_on;
        // Disabling force-HTTPS also disables HSTS (requires HTTPS redirect to be active).
        let new_hsts = if !new_https { false } else { hsts_on };
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_update_site_ssl(
                site_id,
                ssl_on,
                new_https,
                new_hsts,
                hsts_age,
                hsts_subdoms,
                hsts_pre,
            )
            .await
            {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let on_toggle_hsts = move |_| {
        let new_hsts = !hsts_on;
        // Use 1-year max-age when enabling HSTS for the first time.
        let age = if hsts_age == 0 { 31536000 } else { hsts_age };
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_update_site_ssl(
                site_id,
                ssl_on,
                https_on,
                new_hsts,
                age,
                hsts_subdoms,
                hsts_pre,
            )
            .await
            {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let on_delete = move |_| {
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_delete_site(site_id).await {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
            confirm_delete.set(false);
        });
    };

    let created = site.created_at.format("%Y-%m-%d").to_string();

    let status_btn_class = match current_status {
        panel::models::site::SiteStatus::Active => {
            "text-xs px-2 py-1 rounded bg-yellow-100 text-yellow-800 hover:bg-yellow-200 transition-colors disabled:opacity-50"
        }
        _ => {
            "text-xs px-2 py-1 rounded bg-green-100 text-green-800 hover:bg-green-200 transition-colors disabled:opacity-50"
        }
    };

    let status_btn_label = match current_status {
        panel::models::site::SiteStatus::Active => "Suspend",
        _ => "Activate",
    };

    rsx! {
        tr { class: "hover:bg-gray-50/50 transition-colors",
            td { class: "px-6 py-4",
                div { class: "text-sm font-medium text-gray-900", "{site_domain}" }
                if let Some(err) = row_error() {
                    div { class: "text-xs text-red-500 mt-1", "{err}" }
                }
            }
            td { class: "px-6 py-4 text-sm text-gray-500", "#{owner_id}" }
            td { class: "px-6 py-4 text-sm text-gray-500", "{site.site_type}" }
            td { class: "px-6 py-4", StatusBadge { status: site.status.to_string() } }
            td { class: "px-6 py-4 text-sm",
                button {
                    class: "text-sm cursor-pointer hover:opacity-70 disabled:opacity-50",
                    onclick: on_toggle_ssl,
                    disabled: busy(),
                    title: if ssl_on { "Click to disable SSL" } else { "Click to enable SSL" },
                    if ssl_on { "🔒" } else { "🔓" }
                }
            }
            td { class: "px-6 py-4 text-sm",
                if ssl_on {
                    button {
                        class: "text-xs px-2 py-1 rounded transition-colors disabled:opacity-50",
                        class: if https_on { "bg-green-100 text-green-800 hover:bg-green-200" } else { "bg-gray-100 text-gray-600 hover:bg-gray-200" },
                        onclick: on_toggle_https,
                        disabled: busy(),
                        if https_on { "Forced" } else { "Off" }
                    }
                } else {
                    span { class: "text-xs text-gray-400", "—" }
                }
            }
            td { class: "px-6 py-4 text-sm",
                if ssl_on && https_on {
                    button {
                        class: "text-xs px-2 py-1 rounded transition-colors disabled:opacity-50",
                        class: if hsts_on { "bg-purple-100 text-purple-800 hover:bg-purple-200" } else { "bg-gray-100 text-gray-600 hover:bg-gray-200" },
                        onclick: on_toggle_hsts,
                        disabled: busy(),
                        title: if hsts_on { "HSTS active — click to disable" } else { "Click to enable HSTS" },
                        if hsts_on { "On" } else { "Off" }
                    }
                } else {
                    span { class: "text-xs text-gray-400", "—" }
                }
            }
            td { class: "px-6 py-4 text-xs text-gray-500", "{created}" }
            td { class: "px-6 py-4",
                div { class: "flex items-center gap-2",
                    button {
                        class: "{status_btn_class}",
                        onclick: on_toggle_status,
                        disabled: busy(),
                        "{status_btn_label}"
                    }
                    button {
                        class: if show_logs() {
                            "text-xs px-2 py-1 rounded bg-indigo-200 text-indigo-800 hover:bg-indigo-300"
                        } else {
                            "text-xs px-2 py-1 rounded bg-gray-100 text-gray-700 hover:bg-gray-200"
                        },
                        onclick: move |_| show_logs.toggle(),
                        "Logs"
                    }
                    if confirm_delete() {
                        span { class: "text-xs text-red-600 font-medium", "Sure?" }
                        button {
                            class: "text-xs px-2 py-1 rounded bg-red-600 text-white hover:bg-red-700 disabled:opacity-50",
                            onclick: on_delete,
                            disabled: busy(),
                            "Yes"
                        }
                        button {
                            class: "text-xs px-2 py-1 rounded bg-gray-200 text-gray-700 hover:bg-gray-300",
                            onclick: move |_| confirm_delete.set(false),
                            "No"
                        }
                    } else {
                        button {
                            class: "text-xs px-2 py-1 rounded bg-red-100 text-red-700 hover:bg-red-200 disabled:opacity-50",
                            onclick: move |_| confirm_delete.set(true),
                            disabled: busy(),
                            "Delete"
                        }
                    }
                }
            }
        }
        if show_logs() {
            SiteLogViewer { site_id, col_span: 10 }
        }
    }
}

#[component]
fn AdminDatabases() -> Element {
    let mut pma_error = use_signal(|| None::<String>);
    let mut restart_msg = use_signal(|| None::<String>);
    let mut restarting = use_signal(|| false);
    let mut show_recs = use_signal(|| false);

    let mut status = use_resource(move || async move { server_mysql_status().await });
    let recommendations = use_resource(move || async move { server_mysql_recommendations().await });

    let open_phpmyadmin = move |_| {
        pma_error.set(None);
        spawn(async move {
            match server_get_phpmyadmin_url(None).await {
                Ok(_url) => {
                    #[cfg(target_arch = "wasm32")]
                    {
                        let _ = web_sys::window()
                            .and_then(|w| w.open_with_url_and_target(&_url, "_blank").ok());
                    }
                }
                Err(e) => pma_error.set(Some(e.to_string())),
            }
        });
    };

    let do_restart = move |_| {
        restarting.set(true);
        restart_msg.set(None);
        spawn(async move {
            match server_restart_mysql().await {
                Ok(()) => restart_msg.set(Some("MariaDB restarted successfully.".into())),
                Err(e) => restart_msg.set(Some(format!("Restart failed: {e}"))),
            }
            restarting.set(false);
            status.restart();
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Database Management" }
                div { class: "flex gap-3",
                    button {
                        class: "px-4 py-2 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-white font-medium rounded-lg transition-colors flex items-center gap-2 text-sm",
                        onclick: do_restart,
                        disabled: restarting(),
                        Icon { name: "refresh", class: "w-4 h-4".to_string() }
                        span { if restarting() { "Restarting…" } else { "Restart MySQL" } }
                    }
                    button {
                        class: "px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors flex items-center gap-2 text-sm",
                        onclick: open_phpmyadmin,
                        Icon { name: "database", class: "w-4 h-4".to_string() }
                        span { "Open phpMyAdmin" }
                    }
                }
            }

            if let Some(msg) = restart_msg() {
                div {
                    class: if msg.starts_with("Restart failed") {
                        "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm"
                    } else {
                        "bg-green-50 text-green-700 p-3 rounded-lg mb-4 text-sm"
                    },
                    "{msg}"
                }
            }
            if let Some(err) = pma_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            // ── MySQL Server Status ──
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                h3 { class: "text-lg font-semibold text-gray-800 mb-4 flex items-center gap-2",
                    Icon { name: "server", class: "w-5 h-5 text-blue-500".to_string() }
                    "MySQL Server Status"
                }
                match &*status.read() {
                    Some(Ok(s)) => rsx! {
                        div { class: "grid grid-cols-2 md:grid-cols-4 gap-4",
                            div { class: "bg-gray-50 rounded-xl p-4",
                                p { class: "text-xs text-gray-500 mb-1", "Version" }
                                p { class: "font-semibold text-gray-900 text-sm", "{s.version}" }
                            }
                            div { class: "bg-gray-50 rounded-xl p-4",
                                p { class: "text-xs text-gray-500 mb-1", "Uptime" }
                                p { class: "font-semibold text-gray-900 text-sm",
                                    {
                                        let h = s.uptime_seconds / 3600;
                                        let m = (s.uptime_seconds % 3600) / 60;
                                        format!("{h}h {m}m")
                                    }
                                }
                            }
                            div { class: "bg-gray-50 rounded-xl p-4",
                                p { class: "text-xs text-gray-500 mb-1", "Connections" }
                                p { class: "font-semibold text-gray-900 text-sm",
                                    "{s.threads_connected} / {s.max_connections}"
                                }
                            }
                            div { class: "bg-gray-50 rounded-xl p-4",
                                p { class: "text-xs text-gray-500 mb-1", "Total Queries" }
                                p { class: "font-semibold text-gray-900 text-sm", "{s.questions}" }
                            }
                            div { class: "bg-gray-50 rounded-xl p-4",
                                p { class: "text-xs text-gray-500 mb-1", "Slow Queries" }
                                p { class: "font-semibold text-sm",
                                    class: if s.slow_queries > 0 { "text-amber-600" } else { "text-gray-900" },
                                    "{s.slow_queries}"
                                }
                            }
                            div { class: "bg-gray-50 rounded-xl p-4",
                                p { class: "text-xs text-gray-500 mb-1", "InnoDB Buffer" }
                                p { class: "font-semibold text-gray-900 text-sm",
                                    "{s.innodb_buffer_pool_size_mb} MB"
                                }
                            }
                            div { class: "bg-gray-50 rounded-xl p-4 col-span-2",
                                p { class: "text-xs text-gray-500 mb-1", "Data Directory" }
                                p { class: "font-semibold text-gray-900 text-sm font-mono truncate",
                                    "{s.data_dir}"
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        p { class: "text-red-600 text-sm", "Could not load status: {e}" }
                    },
                    None => rsx! {
                        p { class: "text-gray-400 text-sm", "Loading status…" }
                    },
                }
            }

            // ── Performance Recommendations ──
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                div { class: "flex items-center justify-between mb-4",
                    h3 { class: "text-lg font-semibold text-gray-800 flex items-center gap-2",
                        Icon { name: "lightning-bolt", class: "w-5 h-5 text-amber-500".to_string() }
                        "Performance Recommendations"
                    }
                    button {
                        class: "text-sm text-blue-600 hover:text-blue-800",
                        onclick: move |_| show_recs.set(!show_recs()),
                        if show_recs() { "Hide" } else { "Show" }
                    }
                }
                if show_recs() {
                    match &*recommendations.read() {
                        Some(Ok(recs)) => rsx! {
                            div { class: "space-y-3",
                                for rec in recs.iter() {
                                    div {
                                        class: match rec.severity.as_str() {
                                            "warning" => "flex items-start gap-3 p-3 bg-amber-50 border border-amber-200 rounded-lg",
                                            "info"    => "flex items-start gap-3 p-3 bg-blue-50 border border-blue-200 rounded-lg",
                                            _         => "flex items-start gap-3 p-3 bg-green-50 border border-green-200 rounded-lg",
                                        },
                                        div { class: "shrink-0 mt-0.5",
                                            span {
                                                class: match rec.severity.as_str() {
                                                    "warning" => "inline-block w-2 h-2 rounded-full bg-amber-500",
                                                    "info"    => "inline-block w-2 h-2 rounded-full bg-blue-500",
                                                    _         => "inline-block w-2 h-2 rounded-full bg-green-500",
                                                }
                                            }
                                        }
                                        div { class: "flex-1",
                                            p { class: "text-sm font-medium text-gray-900",
                                                code { class: "font-mono", "{rec.variable}" }
                                                span { class: "ml-2 text-gray-500 font-normal",
                                                    "current: {rec.current}"
                                                }
                                            }
                                            p { class: "text-sm text-gray-600 mt-0.5",
                                                "{rec.recommendation}"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            p { class: "text-red-600 text-sm", "Could not load recommendations: {e}" }
                        },
                        None => rsx! {
                            p { class: "text-gray-400 text-sm", "Loading recommendations…" }
                        },
                    }
                }
            }

            // ── phpMyAdmin info ──
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                div { class: "flex items-start gap-4",
                    div { class: "p-3 bg-blue-50 rounded-xl shrink-0",
                        Icon { name: "database", class: "w-6 h-6 text-blue-500".to_string() }
                    }
                    div {
                        h3 { class: "text-lg font-semibold text-gray-800 mb-2", "phpMyAdmin" }
                        p { class: "text-gray-500 mb-3",
                            "Access phpMyAdmin to manage all MariaDB databases on this server. "
                            "As an administrator, you have full access to all databases."
                        }
                        p { class: "text-sm text-gray-400",
                            "phpMyAdmin opens in a new tab with auto-authentication. "
                            "Sessions expire after 30 minutes of inactivity."
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn AdminEmail() -> Element {
    let domains = use_resource(move || async move { server_admin_list_email_domains().await });
    let mut editing = use_signal(|| None::<i64>);
    let mut edit_hourly = use_signal(|| String::new());
    let mut edit_daily = use_signal(|| String::new());
    let mut save_error = use_signal(|| None::<String>);
    let mut save_ok = use_signal(|| false);

    let save_limits = {
        let mut domains = domains.clone();
        move |_| {
            let domain_id = match editing() {
                Some(id) => id,
                None => return,
            };
            let hourly: i32 = edit_hourly().parse().unwrap_or(0).max(0);
            let daily: i32 = edit_daily().parse().unwrap_or(0).max(0);
            save_error.set(None);
            save_ok.set(false);
            spawn(async move {
                match server_set_send_limits(domain_id, hourly, daily).await {
                    Ok(()) => {
                        save_ok.set(true);
                        editing.set(None);
                        domains.restart();
                    }
                    Err(e) => save_error.set(Some(e.to_string())),
                }
            });
        }
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Email Send Limits" }
                    p { class: "text-sm text-gray-500 mt-1",
                        "Configure per-domain hourly and daily outbound send limits. "
                        "Limits are enforced by the Postfix policy daemon on port 10031. "
                        "Set to 0 for unlimited."
                    }
                }
            }

            if save_ok() {
                div { class: "bg-green-50 text-green-700 p-3 rounded-lg mb-4 text-sm",
                    "Send limits saved successfully."
                }
            }
            if let Some(err) = save_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*domains.read() {
                    Some(Ok(list)) if !list.is_empty() => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Domain" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Owner ID" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Hourly Limit" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Daily Limit" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for domain in list.iter() {
                                    {
                                        let dom_id = domain.id;
                                        let is_editing = editing() == Some(dom_id);
                                        let hourly_str = domain.send_limit_per_hour.to_string();
                                        let daily_str = domain.send_limit_per_day.to_string();
                                        rsx! {
                                            tr { class: "hover:bg-gray-50/50 transition-colors",
                                                td { class: "px-6 py-4 text-sm font-medium text-gray-900", "{domain.domain}" }
                                                td { class: "px-6 py-4 text-sm text-gray-500", "{domain.owner_id}" }
                                                td { class: "px-6 py-4 text-sm text-gray-700",
                                                    if is_editing {
                                                        input {
                                                            r#type: "number",
                                                            min: "0",
                                                            class: "w-24 border border-gray-300 rounded px-2 py-1 text-sm",
                                                            value: "{edit_hourly}",
                                                            oninput: move |e| edit_hourly.set(e.value()),
                                                        }
                                                    } else {
                                                        if domain.send_limit_per_hour == 0 {
                                                            span { class: "text-gray-400 italic", "unlimited" }
                                                        } else {
                                                            "{domain.send_limit_per_hour}/hr"
                                                        }
                                                    }
                                                }
                                                td { class: "px-6 py-4 text-sm text-gray-700",
                                                    if is_editing {
                                                        input {
                                                            r#type: "number",
                                                            min: "0",
                                                            class: "w-24 border border-gray-300 rounded px-2 py-1 text-sm",
                                                            value: "{edit_daily}",
                                                            oninput: move |e| edit_daily.set(e.value()),
                                                        }
                                                    } else {
                                                        if domain.send_limit_per_day == 0 {
                                                            span { class: "text-gray-400 italic", "unlimited" }
                                                        } else {
                                                            "{domain.send_limit_per_day}/day"
                                                        }
                                                    }
                                                }
                                                td { class: "px-6 py-4",
                                                    if is_editing {
                                                        div { class: "flex gap-2",
                                                            button {
                                                                class: "px-3 py-1 bg-rose-500 hover:bg-rose-600 text-white text-xs rounded-lg transition-colors",
                                                                onclick: save_limits.clone(),
                                                                "Save"
                                                            }
                                                            button {
                                                                class: "px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 text-xs rounded-lg transition-colors",
                                                                onclick: move |_| editing.set(None),
                                                                "Cancel"
                                                            }
                                                        }
                                                    } else {
                                                        button {
                                                            class: "px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 text-xs rounded-lg transition-colors",
                                                            onclick: move |_| {
                                                                edit_hourly.set(hourly_str.clone());
                                                                edit_daily.set(daily_str.clone());
                                                                editing.set(Some(dom_id));
                                                                save_error.set(None);
                                                                save_ok.set(false);
                                                            },
                                                            "Edit Limits"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        p { class: "p-6 text-gray-500 text-center", "No email domains found." }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }

            // Info card about the Postfix policy daemon
            div { class: "mt-6 bg-blue-50 border border-blue-100 rounded-2xl p-5",
                div { class: "flex items-start gap-3",
                    div { class: "p-2 bg-blue-100 rounded-lg shrink-0",
                        Icon { name: "info", class: "w-4 h-4 text-blue-600".to_string() }
                    }
                    div {
                        p { class: "text-sm font-medium text-blue-800 mb-1", "How send limits work" }
                        p { class: "text-xs text-blue-700",
                            "Limits are enforced in real-time by a Postfix SMTP policy daemon (port 10031). "
                            "Only authenticated senders are checked. Counters reset automatically each hour/day. "
                            "When a limit is reached, Postfix defers the message with a temporary error so it "
                            "will be retried once the window resets."
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn AdminMonitoring() -> Element {
    let mut services = use_resource(move || async move { server_get_services_status().await });
    let metrics = use_resource(move || async move { server_get_system_metrics().await });
    let mut action_error = use_signal(|| None::<String>);
    let mut action_loading = use_signal(|| None::<String>);
    let mut active_tab = use_signal(|| "overview");

    let _handle_action = move |svc_type: ServiceType, cmd: ServiceCommand| {
        let label = format!("{}_{}", svc_type, cmd);
        action_loading.set(Some(label));
        action_error.set(None);
        spawn(async move {
            let action = ServiceAction {
                service: svc_type,
                action: cmd,
            };
            match server_manage_service(action).await {
                Ok(_) => {
                    services.restart();
                }
                Err(e) => {
                    action_error.set(Some(e.to_string()));
                }
            }
            action_loading.set(None);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 space-y-6",
            // Page header
            div { class: "flex items-center justify-between",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Monitoring" }
                    p { class: "text-sm text-gray-500 mt-1", "Real-time system health and performance metrics" }
                }
                div { class: "flex items-center gap-3",
                    // Uptime badge
                    match &*metrics.read() {
                        Some(Ok(m)) => {
                            let days = m.uptime_seconds / 86400;
                            let hours = (m.uptime_seconds % 86400) / 3600;
                            let mins = (m.uptime_seconds % 3600) / 60;
                            let uptime_str = if days > 0 { format!("{}d {}h {}m", days, hours, mins) } else { format!("{}h {}m", hours, mins) };
                            rsx! {
                                div { class: "flex items-center gap-2 px-3 py-1.5 bg-green-50 text-green-700 rounded-lg text-xs font-medium",
                                    div { class: "w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" }
                                    "Uptime: {uptime_str}"
                                }
                            }
                        },
                        _ => rsx! {},
                    }
                    button {
                        class: "flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors",
                        onclick: move |_| { services.restart(); },
                        Icon { name: "refresh-cw", class: "w-4 h-4".to_string() }
                        span { class: "hidden sm:inline", "Refresh" }
                    }
                }
            }

            // Error banner
            if let Some(err) = action_error() {
                div { class: "bg-red-50 border border-red-200 text-red-700 p-3 rounded-xl text-sm flex items-center justify-between",
                    div { class: "flex items-center gap-2",
                        Icon { name: "alert-triangle", class: "w-4 h-4".to_string() }
                        span { "{err}" }
                    }
                    button {
                        class: "text-red-400 hover:text-red-600 transition-colors",
                        onclick: move |_| action_error.set(None),
                        Icon { name: "x", class: "w-4 h-4".to_string() }
                    }
                }
            }

            // Tab navigation
            div { class: "flex items-center gap-1 p-1 bg-gray-100 rounded-xl w-fit flex-wrap",
                {
                    let tabs: Vec<(&str, &str, &str)> = vec![
                        ("overview", "Overview", "layout-dashboard"),
                        ("history", "History", "trending-up"),
                        ("processes", "Processes", "list"),
                        ("docker", "Docker", "box"),
                        ("network", "Network", "wifi"),
                        ("storage", "Storage", "hard-drive"),
                        ("services", "Services", "server"),
                    ];
                    rsx! {
                        for (key, label, icon) in tabs {
                            {
                                let is_active = active_tab() == key;
                                let cls = if is_active {
                                    "flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-white text-gray-900 shadow-sm transition-all"
                                } else {
                                    "flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg text-gray-500 hover:text-gray-700 transition-all"
                                };
                                rsx! {
                                    button {
                                        class: "{cls}",
                                        onclick: move |_| active_tab.set(key),
                                        Icon { name: icon, class: "w-4 h-4".to_string() }
                                        "{label}"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Tab content
            match active_tab() {
                "overview" => rsx! { MonitoringOverview { metrics: metrics } },
                "history" => rsx! { MonitoringHistory {} },
                "processes" => rsx! { MonitoringProcesses {} },
                "docker" => rsx! { MonitoringDocker { metrics: metrics } },
                "network" => rsx! { MonitoringNetwork { metrics: metrics } },
                "storage" => rsx! { MonitoringStorage { metrics: metrics } },
                "services" => rsx! { MonitoringServicesTab {} },
                _ => rsx! { MonitoringOverview { metrics: metrics } },
            }
        }
    }
}

// ── Overview Tab ─────────────────────────────────────────────────

type MetricsResource = Resource<Result<panel::server::monitoring::SystemMetrics, ServerFnError>>;

#[component]
fn MonitoringOverview(metrics: MetricsResource) -> Element {
    rsx! {
        match &*metrics.read() {
            Some(Ok(m)) => {
                let used_gb = m.total_memory_gb - m.available_memory_gb;
                let mem_pct = if m.total_memory_gb > 0.0 { (used_gb / m.total_memory_gb * 100.0) as u32 } else { 0 };
                let cpu_pct = m.cpu_usage_pct as u32;

                rsx! {
                    // Top gauge cards - CPU, Memory, Load
                    div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5",
                        // CPU Usage
                        GaugeCard {
                            title: "CPU Usage",
                            value: cpu_pct,
                            subtitle: format!("{} cores", m.cpu_cores),
                            icon: "cpu",
                            color: gauge_color(cpu_pct),
                        }
                        // Memory Usage
                        GaugeCard {
                            title: "Memory",
                            value: mem_pct,
                            subtitle: format!("{:.1} / {:.1} GB", used_gb, m.total_memory_gb),
                            icon: "server",
                            color: gauge_color(mem_pct),
                        }
                        // Load Average card
                        div { class: "bg-white rounded-2xl border border-gray-100 p-5",
                            div { class: "flex items-center justify-between mb-4",
                                div { class: "flex items-center gap-2",
                                    div { class: "p-2 bg-violet-50 rounded-lg",
                                        Icon { name: "activity", class: "w-4 h-4 text-violet-600".to_string() }
                                    }
                                    span { class: "text-sm font-medium text-gray-600", "Load Average" }
                                }
                            }
                            div { class: "flex items-end gap-4",
                                div {
                                    p { class: "text-2xl font-bold text-gray-900", "{m.load_1:.2}" }
                                    p { class: "text-xs text-gray-400 mt-0.5", "1 min" }
                                }
                                div {
                                    p { class: "text-lg font-semibold text-gray-500", "{m.load_5:.2}" }
                                    p { class: "text-xs text-gray-400 mt-0.5", "5 min" }
                                }
                                div {
                                    p { class: "text-lg font-semibold text-gray-500", "{m.load_15:.2}" }
                                    p { class: "text-xs text-gray-400 mt-0.5", "15 min" }
                                }
                            }
                        }
                        // Uptime card
                        {
                            let days = m.uptime_seconds / 86400;
                            let hours = (m.uptime_seconds % 86400) / 3600;
                            rsx! {
                                div { class: "bg-white rounded-2xl border border-gray-100 p-5",
                                    div { class: "flex items-center justify-between mb-4",
                                        div { class: "flex items-center gap-2",
                                            div { class: "p-2 bg-emerald-50 rounded-lg",
                                                Icon { name: "clock", class: "w-4 h-4 text-emerald-600".to_string() }
                                            }
                                            span { class: "text-sm font-medium text-gray-600", "Uptime" }
                                        }
                                    }
                                    p { class: "text-2xl font-bold text-gray-900", "{days}d {hours}h" }
                                    p { class: "text-xs text-gray-400 mt-1", "Since last reboot" }
                                }
                            }
                        }
                    }

                    // Disk overview (compact)
                    if !m.disks.is_empty() {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-5",
                            div { class: "flex items-center gap-2 mb-4",
                                Icon { name: "hard-drive", class: "w-4 h-4 text-gray-400".to_string() }
                                h3 { class: "text-sm font-semibold text-gray-900", "Storage Overview" }
                            }
                            div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4",
                                for disk in m.disks.iter() {
                                    {
                                        let pct = disk.use_pct;
                                        let bar_color = gauge_bar_color(pct);
                                        rsx! {
                                            div { class: "p-3 bg-gray-50 rounded-xl",
                                                div { class: "flex items-center justify-between mb-2",
                                                    span { class: "text-sm font-medium text-gray-700 truncate", "{disk.mount}" }
                                                    span { class: "text-xs font-semibold text-gray-500", "{pct}%" }
                                                }
                                                div { class: "w-full bg-gray-200 rounded-full h-1.5 mb-1.5",
                                                    div { class: "h-1.5 rounded-full {bar_color}", style: "width: {pct}%" }
                                                }
                                                p { class: "text-xs text-gray-400", "{disk.used_gb:.1} / {disk.total_gb:.1} GB" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Network + Docker summary side by side
                    div { class: "grid grid-cols-1 lg:grid-cols-2 gap-5",
                        // Network summary
                        div { class: "bg-white rounded-2xl border border-gray-100 p-5",
                            div { class: "flex items-center gap-2 mb-4",
                                Icon { name: "wifi", class: "w-4 h-4 text-gray-400".to_string() }
                                h3 { class: "text-sm font-semibold text-gray-900", "Network Interfaces" }
                            }
                            if m.network.is_empty() {
                                div { class: "text-center py-6",
                                    Icon { name: "wifi", class: "w-8 h-8 text-gray-300 mx-auto mb-2".to_string() }
                                    p { class: "text-sm text-gray-400", "No network data available" }
                                }
                            } else {
                                div { class: "space-y-3",
                                    for iface in m.network.iter() {
                                        div { class: "flex items-center justify-between p-3 bg-gray-50 rounded-xl",
                                            div { class: "flex items-center gap-3",
                                                div { class: "w-8 h-8 bg-blue-50 rounded-lg flex items-center justify-center",
                                                    Icon { name: "wifi", class: "w-4 h-4 text-blue-600".to_string() }
                                                }
                                                div {
                                                    p { class: "text-sm font-medium text-gray-900", "{iface.name}" }
                                                    p { class: "text-xs text-gray-400", "{iface.rx_packets} / {iface.tx_packets} pkts" }
                                                }
                                            }
                                            div { class: "text-right",
                                                div { class: "flex items-center gap-1 text-xs",
                                                    Icon { name: "arrow-down", class: "w-3 h-3 text-green-500".to_string() }
                                                    span { class: "text-green-600 font-medium", "{format_bytes(iface.rx_bytes)}" }
                                                }
                                                div { class: "flex items-center gap-1 text-xs mt-0.5",
                                                    Icon { name: "arrow-up", class: "w-3 h-3 text-blue-500".to_string() }
                                                    span { class: "text-blue-600 font-medium", "{format_bytes(iface.tx_bytes)}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Docker summary
                        div { class: "bg-white rounded-2xl border border-gray-100 p-5",
                            div { class: "flex items-center gap-2 mb-4",
                                Icon { name: "box", class: "w-4 h-4 text-gray-400".to_string() }
                                h3 { class: "text-sm font-semibold text-gray-900", "Docker Containers" }
                                if !m.docker.is_empty() {
                                    span { class: "ml-auto text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full font-medium",
                                        "{m.docker.len()}"
                                    }
                                }
                            }
                            if m.docker.is_empty() {
                                div { class: "text-center py-6",
                                    Icon { name: "box", class: "w-8 h-8 text-gray-300 mx-auto mb-2".to_string() }
                                    p { class: "text-sm text-gray-400", "No containers running" }
                                    p { class: "text-xs text-gray-300 mt-1", "Docker may not be installed" }
                                }
                            } else {
                                div { class: "space-y-2",
                                    for c in m.docker.iter().take(5) {
                                        {
                                            let state_color = match c.state.as_str() {
                                                "running" => "bg-green-500",
                                                "exited" => "bg-red-400",
                                                "paused" => "bg-yellow-400",
                                                _ => "bg-gray-400",
                                            };
                                            rsx! {
                                                div { class: "flex items-center justify-between p-3 bg-gray-50 rounded-xl",
                                                    div { class: "flex items-center gap-3 min-w-0",
                                                        div { class: "w-2 h-2 rounded-full {state_color} shrink-0" }
                                                        div { class: "min-w-0",
                                                            p { class: "text-sm font-medium text-gray-900 truncate", "{c.name}" }
                                                            p { class: "text-xs text-gray-400 truncate", "{c.image}" }
                                                        }
                                                    }
                                                    div { class: "text-right shrink-0 ml-3",
                                                        p { class: "text-xs font-medium text-gray-600", "{c.cpu_pct:.1}% CPU" }
                                                        p { class: "text-xs text-gray-400", "{c.mem_mb:.0} MB" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if m.docker.len() > 5 {
                                        p { class: "text-xs text-gray-400 text-center pt-1",
                                            "+{m.docker.len() - 5} more containers"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            Some(Err(e)) => rsx! {
                div { class: "bg-red-50 border border-red-200 text-red-600 p-6 rounded-2xl text-sm",
                    div { class: "flex items-center gap-2",
                        Icon { name: "alert-triangle", class: "w-5 h-5".to_string() }
                        span { class: "font-medium", "Failed to load metrics" }
                    }
                    p { class: "mt-2 text-red-500", "{e}" }
                }
            },
            None => rsx! {
                div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5",
                    for _ in 0..4 {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-5 animate-pulse",
                            div { class: "flex items-center gap-2 mb-4",
                                div { class: "w-8 h-8 bg-gray-200 rounded-lg" }
                                div { class: "h-4 bg-gray-200 rounded w-20" }
                            }
                            div { class: "h-8 bg-gray-200 rounded w-16 mb-2" }
                            div { class: "h-3 bg-gray-200 rounded w-24" }
                        }
                    }
                }
                div { class: "grid grid-cols-1 lg:grid-cols-2 gap-5",
                    for _ in 0..2 {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-5 animate-pulse h-48" }
                    }
                }
            },
        }
    }
}

// ── Gauge Card Component ─────────────────────────────────────────

#[component]
fn GaugeCard(
    title: String,
    value: u32,
    subtitle: String,
    icon: &'static str,
    color: &'static str,
) -> Element {
    let (ring_color, bg_color, text_color) = match color {
        "green" => ("stroke-emerald-500", "bg-emerald-50", "text-emerald-600"),
        "yellow" => ("stroke-amber-500", "bg-amber-50", "text-amber-600"),
        "red" => ("stroke-red-500", "bg-red-50", "text-red-600"),
        _ => ("stroke-emerald-500", "bg-emerald-50", "text-emerald-600"),
    };
    // SVG circle progress: circumference = 2 * PI * 40 = 251.3
    let circumference = 251.3_f64;
    let offset = circumference - (circumference * value as f64 / 100.0);

    rsx! {
        div { class: "bg-white rounded-2xl border border-gray-100 p-5",
            div { class: "flex items-center justify-between",
                div {
                    div { class: "flex items-center gap-2 mb-3",
                        div { class: "p-2 {bg_color} rounded-lg",
                            Icon { name: icon, class: format!("w-4 h-4 {text_color}") }
                        }
                        span { class: "text-sm font-medium text-gray-600", "{title}" }
                    }
                    p { class: "text-xs text-gray-400", "{subtitle}" }
                }
                // Circular gauge
                div { class: "relative w-16 h-16",
                    svg { class: "w-16 h-16 -rotate-90", "viewBox": "0 0 100 100",
                        circle {
                            cx: "50", cy: "50", r: "40",
                            fill: "none",
                            stroke: "#f3f4f6",
                            "stroke-width": "8",
                        }
                        circle {
                            cx: "50", cy: "50", r: "40",
                            fill: "none",
                            class: "{ring_color}",
                            "stroke-width": "8",
                            "stroke-linecap": "round",
                            "stroke-dasharray": "{circumference}",
                            "stroke-dashoffset": "{offset}",
                        }
                    }
                    div { class: "absolute inset-0 flex items-center justify-center",
                        span { class: "text-sm font-bold text-gray-900", "{value}%" }
                    }
                }
            }
        }
    }
}

fn gauge_color(pct: u32) -> &'static str {
    if pct > 90 {
        "red"
    } else if pct > 70 {
        "yellow"
    } else {
        "green"
    }
}

fn gauge_bar_color(pct: u32) -> &'static str {
    if pct > 90 {
        "bg-red-500"
    } else if pct > 70 {
        "bg-amber-500"
    } else {
        "bg-emerald-500"
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// ── Docker Tab ───────────────────────────────────────────────────

#[component]
fn MonitoringDocker(metrics: MetricsResource) -> Element {
    rsx! {
        match &*metrics.read() {
            Some(Ok(m)) => {
                let running = m.docker.iter().filter(|c| c.state == "running").count();
                let _stopped = m.docker.iter().filter(|c| c.state != "running").count();
                let total_cpu: f64 = m.docker.iter().map(|c| c.cpu_pct).sum();
                let total_mem: f64 = m.docker.iter().map(|c| c.mem_mb).sum();
                rsx! {
                    // Docker summary cards
                    div { class: "grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6",
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            p { class: "text-xs font-medium text-gray-500 uppercase tracking-wide", "Total" }
                            p { class: "text-2xl font-bold text-gray-900 mt-1", "{m.docker.len()}" }
                        }
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            p { class: "text-xs font-medium text-gray-500 uppercase tracking-wide", "Running" }
                            p { class: "text-2xl font-bold text-green-600 mt-1", "{running}" }
                        }
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            p { class: "text-xs font-medium text-gray-500 uppercase tracking-wide", "CPU Usage" }
                            p { class: "text-2xl font-bold text-gray-900 mt-1", "{total_cpu:.1}%" }
                        }
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            p { class: "text-xs font-medium text-gray-500 uppercase tracking-wide", "Memory" }
                            p { class: "text-2xl font-bold text-gray-900 mt-1",
                                {if total_mem >= 1024.0 { format!("{:.1} GB", total_mem / 1024.0) } else { format!("{:.0} MB", total_mem) }}
                            }
                        }
                    }

                    if m.docker.is_empty() {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-12 text-center",
                            div { class: "w-16 h-16 bg-gray-100 rounded-2xl flex items-center justify-center mx-auto mb-4",
                                Icon { name: "box", class: "w-8 h-8 text-gray-400".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-900 mb-2", "No Docker Containers" }
                            p { class: "text-sm text-gray-500", "Docker is not installed or no containers are configured on this server." }
                        }
                    } else {
                        div { class: "bg-white rounded-2xl border border-gray-100 overflow-hidden",
                            table { class: "w-full",
                                thead { class: "bg-gray-50 border-b border-gray-200",
                                    tr {
                                        th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Container" }
                                        th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Image" }
                                        th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                        th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "CPU" }
                                        th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Memory" }
                                        th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Ports" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-100",
                                    for c in m.docker.iter() {
                                        {
                                            let state_color = match c.state.as_str() {
                                                "running" => "bg-green-500",
                                                "exited" => "bg-red-400",
                                                "paused" => "bg-yellow-400",
                                                _ => "bg-gray-400",
                                            };
                                            let badge_cls = match c.state.as_str() {
                                                "running" => "bg-green-50 text-green-700",
                                                "exited" => "bg-red-50 text-red-700",
                                                "paused" => "bg-yellow-50 text-yellow-700",
                                                _ => "bg-gray-100 text-gray-600",
                                            };
                                            rsx! {
                                                tr { class: "hover:bg-gray-50/50 transition-colors",
                                                    td { class: "px-5 py-3.5",
                                                        div { class: "flex items-center gap-2.5",
                                                            div { class: "w-2 h-2 rounded-full {state_color} shrink-0" }
                                                            span { class: "text-sm font-medium text-gray-900", "{c.name}" }
                                                        }
                                                    }
                                                    td { class: "px-5 py-3.5 text-sm text-gray-500 max-w-[200px] truncate", "{c.image}" }
                                                    td { class: "px-5 py-3.5",
                                                        span { class: "text-xs font-medium px-2 py-0.5 rounded-full {badge_cls}", "{c.state}" }
                                                    }
                                                    td { class: "px-5 py-3.5 text-sm text-right font-mono text-gray-700", "{c.cpu_pct:.1}%" }
                                                    td { class: "px-5 py-3.5 text-sm text-right font-mono text-gray-700",
                                                        {if c.mem_mb >= 1024.0 { format!("{:.1} GB", c.mem_mb / 1024.0) } else { format!("{:.0} MB", c.mem_mb) }}
                                                    }
                                                    td { class: "px-5 py-3.5 text-xs text-gray-500 max-w-[180px] truncate",
                                                        {if c.ports.is_empty() { "—".to_string() } else { c.ports.clone() }}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            Some(Err(e)) => rsx! {
                div { class: "bg-red-50 border border-red-200 text-red-600 p-4 rounded-xl text-sm", "Error: {e}" }
            },
            None => rsx! {
                div { class: "grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6",
                    for _ in 0..4 {
                        div { class: "bg-white rounded-xl border border-gray-100 p-4 animate-pulse",
                            div { class: "h-3 bg-gray-200 rounded w-16 mb-2" }
                            div { class: "h-6 bg-gray-200 rounded w-10" }
                        }
                    }
                }
            },
        }
    }
}

// ── Network Tab ──────────────────────────────────────────────────

#[component]
fn MonitoringNetwork(metrics: MetricsResource) -> Element {
    rsx! {
        match &*metrics.read() {
            Some(Ok(m)) => {
                let total_rx: u64 = m.network.iter().map(|n| n.rx_bytes).sum();
                let total_tx: u64 = m.network.iter().map(|n| n.tx_bytes).sum();
                let total_errors: u64 = m.network.iter().map(|n| n.rx_errors + n.tx_errors).sum();
                rsx! {
                    // Summary cards
                    div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-6",
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            div { class: "flex items-center gap-2 mb-2",
                                Icon { name: "arrow-down", class: "w-4 h-4 text-green-500".to_string() }
                                p { class: "text-xs font-medium text-gray-500 uppercase", "Total Received" }
                            }
                            p { class: "text-xl font-bold text-gray-900", "{format_bytes(total_rx)}" }
                        }
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            div { class: "flex items-center gap-2 mb-2",
                                Icon { name: "arrow-up", class: "w-4 h-4 text-blue-500".to_string() }
                                p { class: "text-xs font-medium text-gray-500 uppercase", "Total Sent" }
                            }
                            p { class: "text-xl font-bold text-gray-900", "{format_bytes(total_tx)}" }
                        }
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            div { class: "flex items-center gap-2 mb-2",
                                Icon { name: "alert-triangle", class: "w-4 h-4 text-amber-500".to_string() }
                                p { class: "text-xs font-medium text-gray-500 uppercase", "Total Errors" }
                            }
                            p { class: "text-xl font-bold text-gray-900", "{total_errors}" }
                        }
                    }

                    if m.network.is_empty() {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-12 text-center",
                            div { class: "w-16 h-16 bg-gray-100 rounded-2xl flex items-center justify-center mx-auto mb-4",
                                Icon { name: "wifi", class: "w-8 h-8 text-gray-400".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-900 mb-2", "No Network Data" }
                            p { class: "text-sm text-gray-500", "Network interface information is not available." }
                        }
                    } else {
                        // Interface detail cards
                        div { class: "space-y-4",
                            for iface in m.network.iter() {
                                div { class: "bg-white rounded-2xl border border-gray-100 p-5",
                                    div { class: "flex items-center justify-between mb-4",
                                        div { class: "flex items-center gap-3",
                                            div { class: "w-10 h-10 bg-blue-50 rounded-xl flex items-center justify-center",
                                                Icon { name: "wifi", class: "w-5 h-5 text-blue-600".to_string() }
                                            }
                                            div {
                                                h4 { class: "text-sm font-semibold text-gray-900", "{iface.name}" }
                                                p { class: "text-xs text-gray-400", "Network interface" }
                                            }
                                        }
                                        {
                                            let has_errors = iface.rx_errors + iface.tx_errors > 0;
                                            let badge = if has_errors { "bg-amber-50 text-amber-700" } else { "bg-green-50 text-green-700" };
                                            let label = if has_errors { "Errors detected" } else { "Healthy" };
                                            rsx! {
                                                span { class: "text-xs font-medium px-2.5 py-1 rounded-full {badge}", "{label}" }
                                            }
                                        }
                                    }
                                    div { class: "grid grid-cols-2 md:grid-cols-4 gap-4",
                                        div { class: "p-3 bg-green-50/50 rounded-xl",
                                            p { class: "text-xs text-gray-500 mb-1", "Received" }
                                            p { class: "text-sm font-bold text-gray-900", "{format_bytes(iface.rx_bytes)}" }
                                            p { class: "text-xs text-gray-400 mt-0.5", "{iface.rx_packets} packets" }
                                        }
                                        div { class: "p-3 bg-blue-50/50 rounded-xl",
                                            p { class: "text-xs text-gray-500 mb-1", "Sent" }
                                            p { class: "text-sm font-bold text-gray-900", "{format_bytes(iface.tx_bytes)}" }
                                            p { class: "text-xs text-gray-400 mt-0.5", "{iface.tx_packets} packets" }
                                        }
                                        div { class: "p-3 bg-red-50/50 rounded-xl",
                                            p { class: "text-xs text-gray-500 mb-1", "RX Errors" }
                                            p { class: "text-sm font-bold text-gray-900", "{iface.rx_errors}" }
                                        }
                                        div { class: "p-3 bg-red-50/50 rounded-xl",
                                            p { class: "text-xs text-gray-500 mb-1", "TX Errors" }
                                            p { class: "text-sm font-bold text-gray-900", "{iface.tx_errors}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            Some(Err(e)) => rsx! {
                div { class: "bg-red-50 border border-red-200 text-red-600 p-4 rounded-xl text-sm", "Error: {e}" }
            },
            None => rsx! {
                div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-6",
                    for _ in 0..3 {
                        div { class: "bg-white rounded-xl border border-gray-100 p-4 animate-pulse",
                            div { class: "h-3 bg-gray-200 rounded w-24 mb-2" }
                            div { class: "h-6 bg-gray-200 rounded w-16" }
                        }
                    }
                }
            },
        }
    }
}

// ── Storage Tab ──────────────────────────────────────────────────

#[component]
fn MonitoringStorage(metrics: MetricsResource) -> Element {
    rsx! {
        match &*metrics.read() {
            Some(Ok(m)) => {
                let total_disk: f64 = m.disks.iter().map(|d| d.total_gb).sum();
                let used_disk: f64 = m.disks.iter().map(|d| d.used_gb).sum();
                rsx! {
                    // Summary
                    div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-6",
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            p { class: "text-xs font-medium text-gray-500 uppercase tracking-wide", "Partitions" }
                            p { class: "text-2xl font-bold text-gray-900 mt-1", "{m.disks.len()}" }
                        }
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            p { class: "text-xs font-medium text-gray-500 uppercase tracking-wide", "Total Space" }
                            p { class: "text-2xl font-bold text-gray-900 mt-1", "{total_disk:.1} GB" }
                        }
                        div { class: "bg-white rounded-xl border border-gray-100 p-4",
                            p { class: "text-xs font-medium text-gray-500 uppercase tracking-wide", "Used Space" }
                            p { class: "text-2xl font-bold text-gray-900 mt-1", "{used_disk:.1} GB" }
                        }
                    }

                    if m.disks.is_empty() {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-12 text-center",
                            div { class: "w-16 h-16 bg-gray-100 rounded-2xl flex items-center justify-center mx-auto mb-4",
                                Icon { name: "hard-drive", class: "w-8 h-8 text-gray-400".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-900 mb-2", "No Disk Data" }
                            p { class: "text-sm text-gray-500", "Disk partition information is not available." }
                        }
                    } else {
                        div { class: "space-y-4",
                            for disk in m.disks.iter() {
                                {
                                    let pct = disk.use_pct;
                                    let bar_color = gauge_bar_color(pct);
                                    let color = gauge_color(pct);
                                    let ring_color_cls = match color {
                                        "red" => "text-red-600",
                                        "yellow" => "text-amber-600",
                                        _ => "text-emerald-600",
                                    };
                                    rsx! {
                                        div { class: "bg-white rounded-2xl border border-gray-100 p-5",
                                            div { class: "flex items-start justify-between",
                                                div { class: "flex-1",
                                                    div { class: "flex items-center gap-3 mb-1",
                                                        div { class: "w-10 h-10 bg-gray-100 rounded-xl flex items-center justify-center",
                                                            Icon { name: "hard-drive", class: "w-5 h-5 text-gray-500".to_string() }
                                                        }
                                                        div {
                                                            h4 { class: "text-sm font-semibold text-gray-900", "{disk.mount}" }
                                                            p { class: "text-xs text-gray-400", "{disk.device}" }
                                                        }
                                                    }

                                                    div { class: "mt-4",
                                                        div { class: "flex items-center justify-between mb-1.5",
                                                            span { class: "text-xs text-gray-500", "{disk.used_gb:.1} GB used" }
                                                            span { class: "text-xs font-semibold {ring_color_cls}", "{pct}%" }
                                                        }
                                                        div { class: "w-full bg-gray-100 rounded-full h-2",
                                                            div { class: "h-2 rounded-full {bar_color} transition-all", style: "width: {pct}%" }
                                                        }
                                                        div { class: "flex items-center justify-between mt-1.5",
                                                            span { class: "text-xs text-gray-400", "{disk.avail_gb:.1} GB free" }
                                                            span { class: "text-xs text-gray-400", "{disk.total_gb:.1} GB total" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            Some(Err(e)) => rsx! {
                div { class: "bg-red-50 border border-red-200 text-red-600 p-4 rounded-xl text-sm", "Error: {e}" }
            },
            None => rsx! {
                div { class: "space-y-4",
                    for _ in 0..3 {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-5 animate-pulse h-32" }
                    }
                }
            },
        }
    }
}

// ── History Tab (Load, Disk I/O, Traffic) ────────────────────────

/// A timestamped data point in a ring buffer.
#[derive(Clone, Debug)]
struct HistoryPoint {
    #[allow(dead_code)]
    ts_ms: u64,
    /// CPU load average (1 min)
    load1: f64,
    /// CPU load average (5 min)
    load5: f64,
    /// Disk read bytes/sec (first real device)
    disk_read_bps: f64,
    /// Disk write bytes/sec
    disk_write_bps: f64,
    /// Network RX bytes/sec (first non-lo iface)
    net_rx_bps: f64,
    /// Network TX bytes/sec
    net_tx_bps: f64,
}

const HISTORY_MAX: usize = 60;

/// Platform-agnostic async sleep.
#[cfg(target_arch = "wasm32")]
async fn history_sleep_ms(ms: u32) {
    gloo_timers::future::TimeoutFuture::new(ms).await;
}

#[cfg(not(target_arch = "wasm32"))]
async fn history_sleep_ms(ms: u32) {
    tokio::time::sleep(tokio::time::Duration::from_millis(ms as u64)).await;
}

#[component]
fn MonitoringHistory() -> Element {
    let mut history: Signal<Vec<HistoryPoint>> = use_signal(Vec::new);
    let error: Signal<Option<String>> = use_signal(|| None);
    let loading: Signal<bool> = use_signal(|| false);
    // Whether auto-polling is currently active.
    let mut auto_poll: Signal<bool> = use_signal(|| false);
    // Polling interval in seconds (5, 10, 30, or 60).
    let mut interval_secs: Signal<u32> = use_signal(|| 5);

    // ── shared poll logic ────────────────────────────────────────
    let do_one_sample = {
        let history = history;
        let mut error = error;
        let mut loading = loading;
        move || {
            loading.set(true);
            error.set(None);
            let mut history = history;
            let mut error = error;
            let mut loading = loading;
            spawn(async move {
                let metrics_res = server_get_system_metrics().await;
                let disk_res = server_get_disk_io().await;
                let net_res = server_get_network_rates().await;

                let ts_ms = disk_res.as_ref().map(|d| d.timestamp_ms).unwrap_or(0);

                let disk_read_bps = disk_res
                    .as_ref()
                    .ok()
                    .and_then(|d| d.devices.iter().find(|dev| !dev.name.contains("dm-")))
                    .map(|d| d.read_bps)
                    .unwrap_or(0.0);
                let disk_write_bps = disk_res
                    .as_ref()
                    .ok()
                    .and_then(|d| d.devices.iter().find(|dev| !dev.name.contains("dm-")))
                    .map(|d| d.write_bps)
                    .unwrap_or(0.0);
                let net_rx_bps = net_res
                    .as_ref()
                    .ok()
                    .and_then(|n| n.interfaces.first())
                    .map(|i| i.rx_bps)
                    .unwrap_or(0.0);
                let net_tx_bps = net_res
                    .as_ref()
                    .ok()
                    .and_then(|n| n.interfaces.first())
                    .map(|i| i.tx_bps)
                    .unwrap_or(0.0);
                let (load1, load5) = metrics_res
                    .as_ref()
                    .ok()
                    .map(|m| (m.load_1, m.load_5))
                    .unwrap_or((0.0, 0.0));

                if let Err(e) = &disk_res {
                    error.set(Some(e.to_string()));
                }
                if let Err(e) = &net_res {
                    error.set(Some(e.to_string()));
                }

                let pt = HistoryPoint {
                    ts_ms,
                    load1,
                    load5,
                    disk_read_bps,
                    disk_write_bps,
                    net_rx_bps,
                    net_tx_bps,
                };
                let mut h = history.write();
                h.push(pt);
                let cur_len = h.len();
                if cur_len > HISTORY_MAX {
                    h.drain(0..cur_len - HISTORY_MAX);
                }
                drop(h);
                loading.set(false);
            });
        }
    };

    // ── auto-poll coroutine ───────────────────────────────────────
    // Kick off (or stop) the auto-poll loop whenever auto_poll / interval changes.
    use_effect(move || {
        if !auto_poll() {
            return;
        }
        let interval = interval_secs();
        let auto_poll = auto_poll;
        let mut do_sample = do_one_sample.clone();
        spawn(async move {
            loop {
                if !auto_poll() {
                    break;
                }
                do_sample();
                history_sleep_ms(interval * 1000).await;
                if !auto_poll() {
                    break;
                }
            }
        });
    });

    let data = history.read();

    rsx! {
        div { class: "space-y-6",
            // ── Toolbar ──────────────────────────────────────────
            div { class: "flex flex-wrap items-center justify-between gap-3",
                div { class: "flex items-center gap-2",
                    Icon { name: "trending-up", class: "w-4 h-4 text-gray-400".to_string() }
                    span { class: "text-sm font-medium text-gray-700",
                        "History — last {data.len()} of {HISTORY_MAX} samples"
                    }
                    if let Some(err) = error() {
                        span { class: "text-xs text-red-600 ml-2", "⚠ {err}" }
                    }
                }

                div { class: "flex items-center gap-2 flex-wrap",
                    // Interval selector
                    span { class: "text-xs text-gray-500", "Interval:" }
                    for secs in [5u32, 10, 30, 60] {
                        {
                            let active = interval_secs() == secs;
                            let cls = if active {
                                "px-2.5 py-1 text-xs font-semibold rounded-lg bg-blue-600 text-white"
                            } else {
                                "px-2.5 py-1 text-xs font-medium rounded-lg bg-gray-100 text-gray-600 hover:bg-gray-200 disabled:opacity-50"
                            };
                            let label = if secs < 60 { format!("{secs}s") } else { "1m".to_string() };
                            rsx! {
                                button {
                                    class: "{cls}",
                                    disabled: auto_poll(),
                                    onclick: move |_| { interval_secs.set(secs); },
                                    "{label}"
                                }
                            }
                        }
                    }

                    // Auto-poll toggle
                    {
                        let (cls, icon, label) = if auto_poll() {
                            ("flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-red-100 text-red-700 hover:bg-red-200 transition-colors", "pause", "Stop")
                        } else {
                            ("flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-green-100 text-green-700 hover:bg-green-200 transition-colors", "play", "Auto")
                        };
                        rsx! {
                            button {
                                class: "{cls}",
                                onclick: move |_| {
                                    let new_state = !auto_poll();
                                    auto_poll.set(new_state);
                                },
                                Icon { name: icon, class: "w-3.5 h-3.5".to_string() }
                                "{label}"
                            }
                        }
                    }

                    // Manual sample
                    button {
                        class: "flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-blue-50 text-blue-700 hover:bg-blue-100 transition-colors disabled:opacity-50",
                        disabled: loading(),
                        onclick: {
                            let mut do_sample = do_one_sample.clone();
                            move |_| do_sample()
                        },
                        Icon { name: "activity", class: "w-3.5 h-3.5".to_string() }
                        if loading() { "Sampling…" } else { "Sample" }
                    }

                    // Clear
                    if !data.is_empty() {
                        button {
                            class: "flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-xl bg-gray-100 text-gray-600 hover:bg-gray-200 transition-colors",
                            onclick: move |_| { history.write().clear(); },
                            Icon { name: "trash-2", class: "w-3.5 h-3.5".to_string() }
                            "Clear"
                        }
                    }
                }
            }

            if data.is_empty() {
                div { class: "bg-white rounded-2xl border border-gray-100 p-16 text-center",
                    Icon { name: "trending-up", class: "w-12 h-12 text-gray-200 mx-auto mb-3".to_string() }
                    p { class: "text-gray-500 font-medium", "No history yet" }
                    p { class: "text-sm text-gray-400 mt-1",
                        "Press 'Auto' to start polling every {interval_secs()}s, or 'Sample' to take a single snapshot."
                    }
                }
            } else {
                // ── Historical Load Average Graph ─────────────────
                {
                    let max_load = data.iter().map(|p| p.load1.max(p.load5)).fold(0.0_f64, f64::max).max(1.0);
                    let load1_vals: Vec<f64> = data.iter().map(|p| p.load1).collect();
                    let load5_vals: Vec<f64> = data.iter().map(|p| p.load5).collect();
                    let window_secs = (data.len().saturating_sub(1)) as u32 * interval_secs();
                    rsx! {
                        LineChartCard {
                            title: "CPU Load Average".to_string(),
                            icon: "activity",
                            window_secs,
                            series: vec![
                                ChartSeries { label: "1 min".to_string(), color: "#3b82f6".to_string(), values: load1_vals },
                                ChartSeries { label: "5 min".to_string(), color: "#a78bfa".to_string(), values: load5_vals },
                            ],
                            y_max: max_load,
                            y_unit: "".to_string(),
                            format_y: false,
                        }
                    }
                }

                // ── Historical Disk I/O Graph ─────────────────────
                {
                    let max_io = data.iter().map(|p| p.disk_read_bps.max(p.disk_write_bps)).fold(0.0_f64, f64::max).max(1024.0);
                    let read_vals: Vec<f64> = data.iter().map(|p| p.disk_read_bps).collect();
                    let write_vals: Vec<f64> = data.iter().map(|p| p.disk_write_bps).collect();
                    let window_secs = (data.len().saturating_sub(1)) as u32 * interval_secs();
                    rsx! {
                        LineChartCard {
                            title: "Disk I/O".to_string(),
                            icon: "hard-drive",
                            window_secs,
                            series: vec![
                                ChartSeries { label: "Read".to_string(), color: "#10b981".to_string(), values: read_vals },
                                ChartSeries { label: "Write".to_string(), color: "#f59e0b".to_string(), values: write_vals },
                            ],
                            y_max: max_io,
                            y_unit: "/s".to_string(),
                            format_y: true,
                        }
                    }
                }

                // ── Historical Traffic Graph ──────────────────────
                {
                    let max_net = data.iter().map(|p| p.net_rx_bps.max(p.net_tx_bps)).fold(0.0_f64, f64::max).max(1024.0);
                    let rx_vals: Vec<f64> = data.iter().map(|p| p.net_rx_bps).collect();
                    let tx_vals: Vec<f64> = data.iter().map(|p| p.net_tx_bps).collect();
                    let window_secs = (data.len().saturating_sub(1)) as u32 * interval_secs();
                    rsx! {
                        LineChartCard {
                            title: "Network Traffic".to_string(),
                            icon: "wifi",
                            window_secs,
                            series: vec![
                                ChartSeries { label: "RX".to_string(), color: "#22c55e".to_string(), values: rx_vals },
                                ChartSeries { label: "TX".to_string(), color: "#3b82f6".to_string(), values: tx_vals },
                            ],
                            y_max: max_net,
                            y_unit: "/s".to_string(),
                            format_y: true,
                        }
                    }
                }
            }
        }
    }
}

// ── SVG Line Chart ────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
struct ChartSeries {
    label: String,
    /// Hex color, e.g. "#3b82f6"
    color: String,
    values: Vec<f64>,
}

#[component]
fn LineChartCard(
    title: String,
    icon: &'static str,
    /// Total window duration in seconds (used for the X-axis left label).
    /// Pass 0 to show sample-count-based label instead.
    window_secs: u32,
    series: Vec<ChartSeries>,
    y_max: f64,
    y_unit: String,
    format_y: bool,
) -> Element {
    let w: f64 = 600.0;
    let h: f64 = 140.0;
    let pad_l: f64 = 58.0;
    let pad_r: f64 = 12.0;
    let pad_t: f64 = 12.0;
    let pad_b: f64 = 28.0;

    let n = series.first().map(|s| s.values.len()).unwrap_or(0);
    let chart_w = w - pad_l - pad_r;
    let chart_h = h - pad_t - pad_b;

    // Build SVG polyline path for each series
    let make_path = |values: &[f64]| -> String {
        if values.len() < 2 {
            return String::new();
        }
        values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let x = pad_l + (i as f64 / (values.len() - 1).max(1) as f64) * chart_w;
                let y = pad_t + chart_h - (v / y_max).clamp(0.0, 1.0) * chart_h;
                format!("{:.1},{:.1}", x, y)
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    // Y-axis labels (0, 50%, 100% of max)
    let fmt_val = |v: f64| -> String {
        if format_y {
            format_bytes(v as u64)
        } else {
            format!("{:.2}", v)
        }
    };

    let y_labels: Vec<(f64, String)> = vec![
        (pad_t + chart_h, fmt_val(0.0)),
        (pad_t + chart_h / 2.0, fmt_val(y_max / 2.0)),
        (pad_t, fmt_val(y_max)),
    ];

    // X-axis labels: oldest time on the left, "now" on the right
    let x_labels: Vec<(f64, String)> = if n > 1 {
        let left_label = if window_secs == 0 {
            format!("-{}pts", n - 1)
        } else if window_secs >= 60 {
            format!("-{}m", window_secs / 60)
        } else {
            format!("-{}s", window_secs)
        };
        vec![(pad_l, left_label), (pad_l + chart_w, "now".to_string())]
    } else {
        vec![]
    };

    let latest: Vec<String> = series
        .iter()
        .map(|s| {
            let v = s.values.last().copied().unwrap_or(0.0);
            if format_y {
                format!("{}{}", format_bytes(v as u64), y_unit)
            } else {
                format!("{:.2}{}", v, y_unit)
            }
        })
        .collect();

    rsx! {
        div { class: "bg-white rounded-2xl border border-gray-100 p-5",
            // Header
            div { class: "flex items-center justify-between mb-4",
                div { class: "flex items-center gap-2",
                    Icon { name: icon, class: "w-4 h-4 text-gray-400".to_string() }
                    h3 { class: "text-sm font-semibold text-gray-900", "{title}" }
                }
                // Legend + latest values
                div { class: "flex items-center gap-4 flex-wrap",
                    for (i, s) in series.iter().enumerate() {
                        div { class: "flex items-center gap-1.5",
                            // Colored line swatch using inline style to avoid Tailwind stroke issues
                            div {
                                style: "width: 12px; height: 2px; border-radius: 1px; background: {s.color};",
                            }
                            span { class: "text-xs text-gray-500", "{s.label}" }
                            span { class: "text-xs font-medium text-gray-700",
                                { latest.get(i).cloned().unwrap_or_default() }
                            }
                        }
                    }
                }
            }

            // SVG chart
            svg {
                class: "w-full",
                "viewBox": format!("0 0 {} {}", w, h),
                "preserveAspectRatio": "none",

                // Grid lines
                for i in 0..=4 {
                    {
                        let y = pad_t + (i as f64 / 4.0) * chart_h;
                        rsx! {
                            line {
                                x1: "{pad_l}", y1: "{y}",
                                x2: "{pad_l + chart_w}", y2: "{y}",
                                stroke: "#f3f4f6", "stroke-width": "1",
                            }
                        }
                    }
                }

                // Y-axis labels
                for (y, label) in y_labels.iter() {
                    text {
                        x: "{pad_l - 4.0}",
                        y: "{y + 3.5}",
                        "text-anchor": "end",
                        "font-size": "9",
                        fill: "#9ca3af",
                        "{label}"
                    }
                }

                // X-axis labels
                for (x, label) in x_labels.iter() {
                    {
                        let anchor = if label == "now" { "end" } else { "start" };
                        rsx! {
                            text {
                                x: "{x}",
                                y: "{h - 6.0}",
                                "text-anchor": anchor,
                                "font-size": "9",
                                fill: "#9ca3af",
                                "{label}"
                            }
                        }
                    }
                }

                // Data lines — use inline style for stroke color
                for s in series.iter() {
                    {
                        let path = make_path(&s.values);
                        let stroke_style = format!(
                            "fill: none; stroke: {}; stroke-width: 1.5px; stroke-linejoin: round; stroke-linecap: round;",
                            s.color
                        );
                        if path.is_empty() {
                            rsx! {}
                        } else {
                            rsx! {
                                polyline {
                                    points: "{path}",
                                    style: "{stroke_style}",
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Processes Tab ────────────────────────────────────────────────

#[component]
fn MonitoringProcesses() -> Element {
    let mut procs = use_resource(move || async move { server_get_top_processes(50).await });
    let mut confirm_kill: Signal<Option<(u32, String)>> = use_signal(|| None);
    let mut kill_error = use_signal(|| None::<String>);
    let kill_loading = use_signal(|| false);
    let mut sort_by = use_signal(|| "cpu");

    rsx! {
        div { class: "space-y-5",
            // Toolbar
            div { class: "flex items-center justify-between",
                div { class: "flex items-center gap-2",
                    span { class: "text-sm text-gray-500", "Sort by:" }
                    button {
                        class: if sort_by() == "cpu" { "px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-100 text-blue-700" } else { "px-3 py-1.5 text-xs font-medium rounded-lg bg-gray-100 text-gray-600 hover:bg-gray-200" },
                        onclick: move |_| sort_by.set("cpu"),
                        "CPU %"
                    }
                    button {
                        class: if sort_by() == "mem" { "px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-100 text-blue-700" } else { "px-3 py-1.5 text-xs font-medium rounded-lg bg-gray-100 text-gray-600 hover:bg-gray-200" },
                        onclick: move |_| sort_by.set("mem"),
                        "Memory"
                    }
                }
                button {
                    class: "flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors",
                    onclick: move |_| { procs.restart(); },
                    Icon { name: "refresh-cw", class: "w-4 h-4".to_string() }
                    "Refresh"
                }
            }

            // Kill error banner
            if let Some(err) = kill_error() {
                div { class: "bg-red-50 border border-red-200 text-red-700 p-3 rounded-xl text-sm flex items-center justify-between",
                    div { class: "flex items-center gap-2",
                        Icon { name: "alert-triangle", class: "w-4 h-4".to_string() }
                        span { "{err}" }
                    }
                    button {
                        class: "text-red-400 hover:text-red-600",
                        onclick: move |_| kill_error.set(None),
                        Icon { name: "x", class: "w-4 h-4".to_string() }
                    }
                }
            }

            // Confirm kill dialog
            if let Some((pid, name)) = confirm_kill() {
                div { class: "fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4",
                    div { class: "bg-white rounded-2xl p-6 max-w-sm w-full shadow-2xl",
                        div { class: "flex items-center gap-3 mb-4",
                            div { class: "p-2 bg-red-100 rounded-xl",
                                Icon { name: "alert-triangle", class: "w-5 h-5 text-red-600".to_string() }
                            }
                            h3 { class: "text-base font-semibold text-gray-900", "Kill process?" }
                        }
                        p { class: "text-sm text-gray-600 mb-2",
                            "Send SIGTERM to "
                            span { class: "font-mono font-medium text-gray-900", "{name}" }
                            " (PID {pid})?"
                        }
                        p { class: "text-xs text-gray-400 mb-5", "Use force kill only if the process ignores SIGTERM." }
                        div { class: "flex items-center gap-3 justify-end",
                            button {
                                class: "px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-xl hover:bg-gray-200 transition-colors",
                                onclick: move |_| confirm_kill.set(None),
                                "Cancel"
                            }
                            {
                                let mut procs2 = procs.clone();
                                let mut confirm_kill2 = confirm_kill.clone();
                                let mut kill_error2 = kill_error.clone();
                                let mut kill_loading2 = kill_loading.clone();
                                rsx! {
                                    button {
                                        class: "px-4 py-2 text-sm font-medium text-white bg-amber-500 rounded-xl hover:bg-amber-600 transition-colors disabled:opacity-60",
                                        disabled: kill_loading(),
                                        onclick: move |_| {
                                            kill_loading2.set(true);
                                            let (p, _) = confirm_kill2().unwrap();
                                            spawn(async move {
                                                match server_kill_process(p, false).await {
                                                    Ok(_) => { confirm_kill2.set(None); procs2.restart(); }
                                                    Err(e) => { kill_error2.set(Some(e.to_string())); confirm_kill2.set(None); }
                                                }
                                                kill_loading2.set(false);
                                            });
                                        },
                                        "SIGTERM"
                                    }
                                }
                            }
                            {
                                let mut procs3 = procs.clone();
                                let mut confirm_kill3 = confirm_kill.clone();
                                let mut kill_error3 = kill_error.clone();
                                let mut kill_loading3 = kill_loading.clone();
                                rsx! {
                                    button {
                                        class: "px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-xl hover:bg-red-700 transition-colors disabled:opacity-60",
                                        disabled: kill_loading(),
                                        onclick: move |_| {
                                            kill_loading3.set(true);
                                            let (p, _) = confirm_kill3().unwrap();
                                            spawn(async move {
                                                match server_kill_process(p, true).await {
                                                    Ok(_) => { confirm_kill3.set(None); procs3.restart(); }
                                                    Err(e) => { kill_error3.set(Some(e.to_string())); confirm_kill3.set(None); }
                                                }
                                                kill_loading3.set(false);
                                            });
                                        },
                                        "Force Kill (SIGKILL)"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Process table
            div { class: "bg-white rounded-2xl border border-gray-100 overflow-hidden",
                match &*procs.read() {
                    Some(Ok(list)) => {
                        let mut sorted = list.clone();
                        if sort_by() == "mem" {
                            sorted.sort_by(|a, b| b.mem_mb.partial_cmp(&a.mem_mb).unwrap_or(std::cmp::Ordering::Equal));
                        } else {
                            sorted.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(std::cmp::Ordering::Equal));
                        }
                        rsx! {
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-16", "PID" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Name" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "User" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-10", "St" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase w-20", "CPU %" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase w-24", "Memory" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase w-16", "Threads" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase w-20", "Action" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-50",
                                    for proc in sorted.iter() {
                                        {
                                            let pid = proc.pid;
                                            let name = proc.name.clone();
                                            let name2 = name.clone();
                                            let cpu = proc.cpu_pct;
                                            let mem = proc.mem_mb;
                                            let mem_pct = proc.mem_pct;
                                            let threads = proc.threads;
                                            let user = proc.user.clone();
                                            let state = proc.state.clone();
                                            let cpu_bar_w = (cpu / 200.0 * 100.0).clamp(0.5, 100.0);
                                            let mem_bar_w = mem_pct.clamp(0.5, 100.0);
                                            let state_color = match state.as_str() {
                                                "R" => "text-green-600",
                                                "S" | "I" => "text-gray-400",
                                                "D" => "text-amber-600",
                                                "Z" => "text-red-600",
                                                _ => "text-gray-400",
                                            };
                                            let mut confirm_kill = confirm_kill.clone();
                                            rsx! {
                                                tr { class: "hover:bg-gray-50/60 transition-colors",
                                                    td { class: "px-4 py-2.5 font-mono text-xs text-gray-400", "{pid}" }
                                                    td { class: "px-4 py-2.5 font-medium text-gray-900 max-w-[160px] truncate", "{name}" }
                                                    td { class: "px-4 py-2.5 text-xs text-gray-500", "{user}" }
                                                    td { class: "px-4 py-2.5 text-xs font-bold {state_color}", "{state}" }
                                                    td { class: "px-4 py-2.5 text-right",
                                                        div { class: "flex items-center justify-end gap-2",
                                                            div { class: "w-16 bg-gray-100 rounded-full h-1.5 hidden sm:block",
                                                                div { class: "h-1.5 rounded-full bg-blue-500", style: "width: {cpu_bar_w:.1}%" }
                                                            }
                                                            span { class: "text-xs font-mono text-gray-700 w-12 text-right", "{cpu:.1}%" }
                                                        }
                                                    }
                                                    td { class: "px-4 py-2.5 text-right",
                                                        div { class: "flex items-center justify-end gap-2",
                                                            div { class: "w-16 bg-gray-100 rounded-full h-1.5 hidden sm:block",
                                                                div { class: "h-1.5 rounded-full bg-violet-500", style: "width: {mem_bar_w:.1}%" }
                                                            }
                                                            span { class: "text-xs font-mono text-gray-700",
                                                                {if mem >= 1024.0 { format!("{:.1}G", mem / 1024.0) } else { format!("{:.0}M", mem) }}
                                                            }
                                                        }
                                                    }
                                                    td { class: "px-4 py-2.5 text-xs text-gray-500 text-right", "{threads}" }
                                                    td { class: "px-4 py-2.5 text-right",
                                                        button {
                                                            class: "px-2.5 py-1 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 rounded-lg transition-colors",
                                                            onclick: move |_| { confirm_kill.set(Some((pid, name2.clone()))); },
                                                            "Kill"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if list.is_empty() {
                                p { class: "p-6 text-center text-sm text-gray-400", "No processes found." }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "p-6 text-red-600 text-sm flex items-center gap-2",
                            Icon { name: "alert-triangle", class: "w-4 h-4".to_string() }
                            "Error: {e}"
                        }
                    },
                    None => rsx! {
                        div { class: "p-6 text-gray-500 text-sm animate-pulse", "Loading processes…" }
                    },
                }
            }
        }
    }
}

// ── Services Tab ─────────────────────────────────────────────────

#[component]
fn MonitoringServicesTab() -> Element {
    let services = use_resource(move || async move { server_get_services_status().await });
    let mut action_error = use_signal(|| None::<String>);

    rsx! {
        div { class: "space-y-5",
            if let Some(err) = action_error() {
                div { class: "bg-red-50 border border-red-200 text-red-700 p-3 rounded-xl text-sm flex items-center justify-between",
                    span { "{err}" }
                    button {
                        class: "text-red-400 hover:text-red-600",
                        onclick: move |_| action_error.set(None),
                        Icon { name: "x", class: "w-4 h-4".to_string() }
                    }
                }
            }

            // DNS Provider
            div { class: "bg-white rounded-2xl border border-gray-100 p-5",
                div { class: "flex items-center gap-4",
                    div { class: "p-3 bg-orange-50 rounded-xl text-orange-500",
                        Icon { name: "globe", class: "w-7 h-7".to_string() }
                    }
                    div {
                        h4 { class: "font-semibold text-gray-900", "Cloudflare DNS" }
                        p { class: "text-sm text-gray-500", "DNS zones are managed via the Cloudflare API." }
                    }
                }
            }

            // Services Table
            div { class: "bg-white rounded-2xl border border-gray-100 overflow-hidden",
                match &*services.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200",
                                tr {
                                    th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Service" }
                                    th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Port" }
                                    th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Version" }
                                    th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for svc in list.iter() {
                                    {
                                        let svc_type = svc.service_type;
                                        let status = svc.status;
                                        let port_str = svc.port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string());
                                        let version_str = svc.version.clone().unwrap_or_else(|| "—".to_string());
                                        let is_stoppable = status == ServiceStatus::Running;
                                        let is_startable = status == ServiceStatus::Stopped || status == ServiceStatus::Unknown;
                                        let services = services.clone();
                                        let action_error = action_error.clone();

                                        rsx! {
                                            tr { class: "hover:bg-gray-50/50 transition-colors",
                                                td { class: "px-5 py-3.5",
                                                    div { class: "flex items-center gap-3",
                                                        div { class: "w-2 h-2 rounded-full {status_dot_color(status)}" }
                                                        span { class: "text-sm font-medium text-gray-900", "{svc_type}" }
                                                    }
                                                }
                                                td { class: "px-5 py-3.5",
                                                    StatusBadge { status: status.to_string() }
                                                }
                                                td { class: "px-5 py-3.5 text-sm text-gray-500", "{port_str}" }
                                                td { class: "px-5 py-3.5 text-sm text-gray-500 max-w-[200px] truncate", "{version_str}" }
                                                td { class: "px-5 py-3.5 text-right",
                                                    div { class: "flex items-center justify-end gap-2",
                                                        if is_startable {
                                                            {
                                                                let mut services = services.clone();
                                                                let mut action_error = action_error.clone();
                                                                rsx! {
                                                                    button {
                                                                        class: "px-3 py-1.5 text-xs font-medium text-green-700 bg-green-50 hover:bg-green-100 rounded-lg transition-colors",
                                                                        onclick: move |_| {
                                                                            spawn(async move {
                                                                                let action = ServiceAction { service: svc_type, action: ServiceCommand::Start };
                                                                                match server_manage_service(action).await {
                                                                                    Ok(_) => services.restart(),
                                                                                    Err(e) => action_error.set(Some(e.to_string())),
                                                                                }
                                                                            });
                                                                        },
                                                                        "Start"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if is_stoppable {
                                                            {
                                                                let mut services = services.clone();
                                                                let mut action_error = action_error.clone();
                                                                rsx! {
                                                                    button {
                                                                        class: "px-3 py-1.5 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 rounded-lg transition-colors",
                                                                        onclick: move |_| {
                                                                            spawn(async move {
                                                                                let action = ServiceAction { service: svc_type, action: ServiceCommand::Stop };
                                                                                match server_manage_service(action).await {
                                                                                    Ok(_) => services.restart(),
                                                                                    Err(e) => action_error.set(Some(e.to_string())),
                                                                                }
                                                                            });
                                                                        },
                                                                        "Stop"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        {
                                                            let mut services = services.clone();
                                                            let mut action_error = action_error.clone();
                                                            rsx! {
                                                                button {
                                                                    class: "px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors",
                                                                    onclick: move |_| {
                                                                        spawn(async move {
                                                                            let action = ServiceAction { service: svc_type, action: ServiceCommand::Restart };
                                                                            match server_manage_service(action).await {
                                                                                Ok(_) => services.restart(),
                                                                                Err(e) => action_error.set(Some(e.to_string())),
                                                                            }
                                                                        });
                                                                    },
                                                                    "Restart"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No services detected." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600 text-sm", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500 text-sm", "Loading services..." } },
                }
            }
        }
    }
}

fn status_dot_color(status: ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::Running => "bg-green-500",
        ServiceStatus::Stopped => "bg-red-500",
        ServiceStatus::Error => "bg-red-500",
        ServiceStatus::Unknown => "bg-yellow-500",
    }
}

#[component]
fn AdminAuditLog() -> Element {
    let logs = use_resource(move || async move { server_get_audit_log(50).await });

    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "Audit Log" }
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*logs.read() {
                    Some(Ok(entries)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr { class: "hover:bg-gray-50/50 transition-colors",
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Action" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Target" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Time" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for entry in entries.iter() {
                                    tr { class: "hover:bg-gray-50/50 transition-colors",
                                        td { class: "px-6 py-4 text-sm text-gray-900", "{entry.action}" }
                                        td { class: "px-6 py-4 text-sm text-gray-500",
                                            {entry.target_name.as_deref().unwrap_or("-")}
                                        }
                                        td { class: "px-6 py-4", StatusBadge { status: entry.status.clone() } }
                                        td { class: "px-6 py-4 text-sm text-gray-500",
                            {entry.created_at.get(0..16).unwrap_or(&entry.created_at).replace('T', " ")}
                        }
                                    }
                                }
                            }
                        }
                        if entries.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No audit log entries." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
        }
    }
}

#[component]
fn AdminSettings() -> Element {
    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "Settings" }
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                h3 { class: "text-lg font-semibold text-gray-800 mb-4", "Panel Configuration" }
                p { class: "text-gray-500", "Server settings are configured via panel.toml and environment variables." }
                p { class: "text-gray-500 mt-2", "Key settings: PANEL_SECRET_KEY, DATABASE_URL, server port." }
            }
        }
    }
}

#[component]
fn ResellerDashboard() -> Element {
    let auth = use_context::<Signal<Option<AuthState>>>();
    let clients = use_resource(move || async move { server_list_users().await });

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "mb-8",
                h2 { class: "text-2xl font-bold text-gray-900",
                    if let Some(ref user) = auth() {
                        "Welcome back, {user.username}"
                    } else {
                        "Reseller Dashboard"
                    }
                }
                p { class: "text-gray-500 mt-1 text-sm", "Manage your hosting clients and packages." }
            }
            div { class: "grid grid-cols-1 sm:grid-cols-3 gap-5 mb-8",
                match &*clients.read() {
                    Some(Ok(list)) => rsx! {
                        StatCard { label: "Total Clients", value: list.len().to_string(), icon: "users", color: "blue" }
                        StatCard { label: "Active", value: list.iter().filter(|u| u.status == panel::models::user::AccountStatus::Active).count().to_string(), icon: "check-circle", color: "emerald" }
                        StatCard { label: "Suspended", value: list.iter().filter(|u| u.status == panel::models::user::AccountStatus::Suspended).count().to_string(), icon: "x-circle", color: "amber" }
                    },
                    _ => rsx! {
                        for _ in 0..3 {
                            div { class: "bg-white rounded-2xl border border-gray-100 p-6 animate-pulse",
                                div { class: "h-3 bg-gray-200 rounded w-20 mb-4" }
                                div { class: "h-8 bg-gray-100 rounded w-12" }
                            }
                        }
                    },
                }
            }
        }
    }
}

#[component]
fn ResellerClients() -> Element {
    let mut clients = use_resource(move || async move { server_list_users().await });
    let packages = use_resource(move || async move { server_list_packages().await });
    let mut show_form = use_signal(|| false);
    let mut new_username = use_signal(String::new);
    let mut new_email = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut new_package = use_signal(|| None::<i64>);
    let mut new_company = use_signal(String::new);
    let mut new_address = use_signal(String::new);
    let mut new_phone = use_signal(String::new);
    let mut create_error = use_signal(|| None::<String>);
    let mut creating = use_signal(|| false);
    let action_error = use_signal(|| None::<String>);

    let on_create = move |e: FormEvent| {
        e.prevent_default();
        creating.set(true);
        create_error.set(None);
        let username = new_username();
        let email = new_email();
        let password = new_password();
        let package_id = new_package();
        let company = new_company();
        let address = new_address();
        let phone = new_phone();
        spawn(async move {
            match server_create_user(username.clone(), email, password, Role::Client, package_id)
                .await
            {
                Ok(user_id) => {
                    let has_details =
                        !company.is_empty() || !address.is_empty() || !phone.is_empty();
                    if has_details {
                        let c = if company.is_empty() {
                            None
                        } else {
                            Some(company)
                        };
                        let a = if address.is_empty() {
                            None
                        } else {
                            Some(address)
                        };
                        let p = if phone.is_empty() { None } else { Some(phone) };
                        let _ = server_update_user_details(user_id, c, a, p).await;
                    }
                    new_username.set(String::new());
                    new_email.set(String::new());
                    new_password.set(String::new());
                    new_package.set(None);
                    new_company.set(String::new());
                    new_address.set(String::new());
                    new_phone.set(String::new());
                    show_form.set(false);
                    clients.restart();
                }
                Err(e) => create_error.set(Some(e.to_string())),
            }
            creating.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            // Header with Add button
            div { class: "flex items-center justify-between mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "My Clients" }
                button {
                    class: "px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors flex items-center gap-2",
                    onclick: move |_| show_form.set(!show_form()),
                    if show_form() { "✕ Cancel" } else { "+ Add Client" }
                }
            }

            if let Some(err) = action_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            // Stats cards
            if let Some(Ok(list)) = &*clients.read() {
                div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-6",
                    StatCard { label: "Total", value: list.len().to_string(), icon: "users" }
                    StatCard { label: "Active", value: list.iter().filter(|u| u.status == panel::models::user::AccountStatus::Active).count().to_string(), icon: "user-check" }
                    StatCard { label: "Suspended", value: list.iter().filter(|u| u.status == panel::models::user::AccountStatus::Suspended).count().to_string(), icon: "user-x" }
                }
            }

            // Create form
            if show_form() {
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                    h3 { class: "text-lg font-semibold text-gray-800 mb-4", "Add New Client" }
                    if let Some(err) = create_error() {
                        div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                    }
                    form { onsubmit: on_create, class: "space-y-4",
                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Username" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "johndoe",
                                    value: "{new_username}",
                                    oninput: move |e| new_username.set(e.value()),
                                    required: true,
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Email" }
                                input {
                                    r#type: "email",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "john@example.com",
                                    value: "{new_email}",
                                    oninput: move |e| new_email.set(e.value()),
                                    required: true,
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Password" }
                                div { class: "flex gap-2",
                                    input {
                                        r#type: "text",
                                        class: "flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent font-mono",
                                        placeholder: "••••••••",
                                        value: "{new_password}",
                                        oninput: move |e| new_password.set(e.value()),
                                        required: true,
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-3 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition-colors text-sm whitespace-nowrap flex items-center gap-1.5",
                                        title: "Generate password & copy to clipboard",
                                        onclick: move |_| {
                                            #[cfg(target_arch = "wasm32")]
                                            {
                                                use web_sys::wasm_bindgen::JsCast;
                                                let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                                                let lower = b"abcdefghijklmnopqrstuvwxyz";
                                                let digits = b"0123456789";
                                                let special = b"!@#$%^&*";
                                                let all = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
                                                let crypto = web_sys::window().unwrap().crypto().unwrap();
                                                let mut buf = [0u8; 20];
                                                let array = js_sys::Uint8Array::new_with_length(20);
                                                crypto.get_random_values_with_array_buffer_view(&array.unchecked_ref()).unwrap();
                                                array.copy_to(&mut buf);
                                                let mut chars: Vec<char> = vec![
                                                    upper[(buf[0] as usize) % upper.len()] as char,
                                                    lower[(buf[1] as usize) % lower.len()] as char,
                                                    digits[(buf[2] as usize) % digits.len()] as char,
                                                    special[(buf[3] as usize) % special.len()] as char,
                                                ];
                                                for b in &buf[4..] {
                                                    chars.push(all[(*b as usize) % all.len()] as char);
                                                }
                                                for i in (1..chars.len()).rev() {
                                                    let j = (buf[i % buf.len()] as usize) % (i + 1);
                                                    chars.swap(i, j);
                                                }
                                                let pass: String = chars.into_iter().collect();
                                                new_password.set(pass.clone());
                                                if let Some(w) = web_sys::window() {
                                                    let _ = w.navigator().clipboard().write_text(&pass);
                                                }
                                            }
                                        },
                                        Icon { name: "key", class: "w-4 h-4".to_string() }
                                        "Generate"
                                    }
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Package" }
                                select {
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                                    onchange: move |e| {
                                        let val = e.value();
                                        new_package.set(val.parse::<i64>().ok());
                                    },
                                    option { value: "", "No package" }
                                    if let Some(Ok(pkgs)) = &*packages.read() {
                                        for pkg in pkgs.iter().filter(|p| p.is_active) {
                                            option { value: "{pkg.id}", "{pkg.name}" }
                                        }
                                    }
                                }
                            }
                        }
                        // Optional contact details
                        div { class: "grid grid-cols-1 md:grid-cols-3 gap-4",
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Company (optional)" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "Acme Inc.",
                                    value: "{new_company}",
                                    oninput: move |e| new_company.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Phone (optional)" }
                                input {
                                    r#type: "tel",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "+1 555 000 0000",
                                    value: "{new_phone}",
                                    oninput: move |e| new_phone.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Address (optional)" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                    placeholder: "123 Main St, City",
                                    value: "{new_address}",
                                    oninput: move |e| new_address.set(e.value()),
                                }
                            }
                        }
                        div { class: "flex justify-end",
                            button {
                                r#type: "submit",
                                class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50",
                                disabled: creating(),
                                if creating() { "Creating..." } else { "Create Client" }
                            }
                        }
                    }
                }
            }

            // Clients table
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*clients.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Username" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Email" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Created" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for user in list.iter() {
                                    ResellerClientRow { user: user.clone(), clients_resource: clients, action_error: action_error }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No clients yet. Click 'Add Client' to create one." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
        }
    }
}

#[component]
fn ResellerClientRow(
    user: panel::models::user::User,
    clients_resource: Resource<Result<Vec<panel::models::user::User>, ServerFnError>>,
    action_error: Signal<Option<String>>,
) -> Element {
    let user_id = user.id;
    let is_active = user.status == panel::models::user::AccountStatus::Active;
    let is_suspended = user.status == panel::models::user::AccountStatus::Suspended;
    let mut clients_resource = clients_resource;
    let mut action_error = action_error;
    let mut confirm_delete = use_signal(|| false);
    let mut loading = use_signal(|| false);
    let created = user.created_at.format("%Y-%m-%d").to_string();

    let toggle_status = move |_| {
        loading.set(true);
        action_error.set(None);
        let new_status = if is_active {
            panel::models::user::AccountStatus::Suspended
        } else {
            panel::models::user::AccountStatus::Active
        };
        spawn(async move {
            match server_update_user_status(user_id, new_status).await {
                Ok(_) => clients_resource.restart(),
                Err(e) => action_error.set(Some(e.to_string())),
            }
            loading.set(false);
        });
    };

    let on_delete = move |_| {
        loading.set(true);
        action_error.set(None);
        spawn(async move {
            match server_delete_user(user_id).await {
                Ok(_) => clients_resource.restart(),
                Err(e) => action_error.set(Some(e.to_string())),
            }
            loading.set(false);
            confirm_delete.set(false);
        });
    };

    rsx! {
        tr { class: "hover:bg-gray-50/50 transition-colors",
            td { class: "px-6 py-4 text-sm font-medium text-gray-900", "{user.username}" }
            td { class: "px-6 py-4 text-sm text-gray-500", "{user.email}" }
            td { class: "px-6 py-4 text-sm text-gray-500",
                if let Some(c) = &user.company {
                    "{c}"
                } else {
                    "—"
                }
            }
            td { class: "px-6 py-4", StatusBadge { status: user.status.to_string() } }
            td { class: "px-6 py-4 text-sm text-gray-500", "{created}" }
            td { class: "px-6 py-4",
                if confirm_delete() {
                    div { class: "flex items-center gap-2",
                        span { class: "text-xs text-red-600 font-medium", "Delete?" }
                        button {
                            class: "px-2 py-1 text-xs bg-red-600 hover:bg-red-700 text-white rounded disabled:opacity-50",
                            disabled: loading(),
                            onclick: on_delete,
                            "Yes"
                        }
                        button {
                            class: "px-2 py-1 text-xs bg-gray-200 hover:bg-gray-300 text-gray-700 rounded",
                            onclick: move |_| confirm_delete.set(false),
                            "No"
                        }
                    }
                } else {
                    div { class: "flex items-center gap-2",
                        button {
                            class: if is_active {
                                "px-3 py-1 text-xs bg-yellow-100 hover:bg-yellow-200 text-yellow-800 rounded-lg font-medium transition-colors disabled:opacity-50"
                            } else if is_suspended {
                                "px-3 py-1 text-xs bg-green-100 hover:bg-green-200 text-green-800 rounded-lg font-medium transition-colors disabled:opacity-50"
                            } else {
                                "px-3 py-1 text-xs bg-green-100 hover:bg-green-200 text-green-800 rounded-lg font-medium transition-colors disabled:opacity-50"
                            },
                            disabled: loading(),
                            onclick: toggle_status,
                            if is_active { "Suspend" } else { "Activate" }
                        }
                        button {
                            class: "px-3 py-1 text-xs bg-red-50 hover:bg-red-100 text-red-600 rounded-lg font-medium transition-colors disabled:opacity-50",
                            disabled: loading(),
                            onclick: move |_| confirm_delete.set(true),
                            "Delete"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ResellerPackages() -> Element {
    rsx! { PackagesPage {} }
}

#[component]
fn ResellerBranding() -> Element {
    let branding = use_resource(move || async move { server_get_branding(None).await });

    let mut panel_name = use_signal(String::new);
    let mut accent_color = use_signal(|| "#F43F5E".to_string());
    let mut custom_domain = use_signal(String::new);
    let mut custom_ns1 = use_signal(String::new);
    let mut custom_ns2 = use_signal(String::new);
    let mut footer_text = use_signal(String::new);
    let mut theme_preset = use_signal(|| "Default".to_string());
    let mut saving = use_signal(|| false);
    let mut save_error = use_signal(|| None::<String>);
    let mut save_success = use_signal(|| false);
    let mut initialized = use_signal(|| false);

    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "Branding" }
            match &*branding.read() {
                Some(Ok(existing)) => {
                    // Initialize form fields from loaded data (once)
                    if !initialized() {
                        if let Some(b) = existing {
                            panel_name.set(b.panel_name.clone());
                            accent_color.set(b.accent_color.clone());
                            custom_domain.set(b.custom_domain.clone().unwrap_or_default());
                            custom_ns1.set(b.custom_ns1.clone().unwrap_or_default());
                            custom_ns2.set(b.custom_ns2.clone().unwrap_or_default());
                            footer_text.set(b.footer_text.clone().unwrap_or_default());
                            theme_preset.set(b.theme_preset.clone());
                        }
                        initialized.set(true);
                    }
                    rsx! {
                        div { class: "space-y-6",
                            if let Some(ref _err) = save_error() {
                                div { class: "bg-red-50 border border-red-200 text-red-700 rounded-xl p-4 text-sm",
                                    "{_err}"
                                }
                            }
                            if save_success() {
                                div { class: "bg-green-50 border border-green-200 text-green-700 rounded-xl p-4 text-sm",
                                    "Branding saved successfully."
                                }
                            }
                            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                                h3 { class: "text-lg font-semibold text-gray-700 mb-4", "Panel Identity" }
                                div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Panel Name" }
                                        input {
                                            r#type: "text",
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            placeholder: "My Hosting",
                                            value: "{panel_name}",
                                            oninput: move |e| panel_name.set(e.value()),
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Theme" }
                                        select {
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                                            value: "{theme_preset}",
                                            onchange: move |e| theme_preset.set(e.value()),
                                            option { value: "Default", "Default" }
                                            option { value: "Dark", "Dark" }
                                            option { value: "Corporate", "Corporate" }
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Accent Color" }
                                        div { class: "flex gap-2 items-center",
                                            input {
                                                r#type: "color",
                                                class: "h-10 w-12 rounded border border-gray-300 p-0.5 cursor-pointer",
                                                value: "{accent_color}",
                                                oninput: move |e| accent_color.set(e.value()),
                                            }
                                            input {
                                                r#type: "text",
                                                class: "flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent font-mono text-sm",
                                                placeholder: "#F43F5E",
                                                value: "{accent_color}",
                                                oninput: move |e| accent_color.set(e.value()),
                                            }
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Footer Text" }
                                        input {
                                            r#type: "text",
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            placeholder: "© 2025 My Hosting. All rights reserved.",
                                            value: "{footer_text}",
                                            oninput: move |e| footer_text.set(e.value()),
                                        }
                                    }
                                }
                            }
                            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                                h3 { class: "text-lg font-semibold text-gray-700 mb-4", "White-Label Domain" }
                                div { class: "grid grid-cols-1 md:grid-cols-3 gap-4",
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Custom Domain" }
                                        input {
                                            r#type: "text",
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            placeholder: "panel.mybrand.com",
                                            value: "{custom_domain}",
                                            oninput: move |e| custom_domain.set(e.value()),
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Nameserver 1" }
                                        input {
                                            r#type: "text",
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            placeholder: "ns1.mybrand.com",
                                            value: "{custom_ns1}",
                                            oninput: move |e| custom_ns1.set(e.value()),
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Nameserver 2" }
                                        input {
                                            r#type: "text",
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            placeholder: "ns2.mybrand.com",
                                            value: "{custom_ns2}",
                                            oninput: move |e| custom_ns2.set(e.value()),
                                        }
                                    }
                                }
                            }
                            div { class: "flex justify-end",
                                button {
                                    class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-xl font-medium transition-colors disabled:opacity-50",
                                    disabled: saving(),
                                    onclick: move |_| {
                                        saving.set(true);
                                        save_error.set(None);
                                        save_success.set(false);
                                        let pn = panel_name();
                                        let ac = accent_color();
                                        let cd = custom_domain();
                                        let n1 = custom_ns1();
                                        let n2 = custom_ns2();
                                        let ft = footer_text();
                                        let tp = theme_preset();
                                        spawn(async move {
                                            let input = BrandingInput {
                                                panel_name: pn,
                                                logo_path: None,
                                                accent_color: ac,
                                                custom_domain: if cd.trim().is_empty() { None } else { Some(cd) },
                                                custom_ns1: if n1.trim().is_empty() { None } else { Some(n1) },
                                                custom_ns2: if n2.trim().is_empty() { None } else { Some(n2) },
                                                footer_text: if ft.trim().is_empty() { None } else { Some(ft) },
                                                theme_preset: Some(tp),
                                            };
                                            match server_save_branding(input).await {
                                                Ok(_) => save_success.set(true),
                                                Err(e) => save_error.set(Some(e.to_string())),
                                            }
                                            saving.set(false);
                                        });
                                    },
                                    if saving() { "Saving..." } else { "Save Branding" }
                                }
                            }
                        }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "bg-red-50 text-red-700 rounded-xl p-4", "Error loading branding: {e}" }
                },
                None => rsx! {
                    div { class: "text-gray-500 p-6", "Loading..." }
                },
            }
        }
    }
}

#[component]
fn ResellerSupportTickets() -> Element {
    let mut tickets = use_resource(move || async move { server_list_all_tickets().await });
    let mut selected_id = use_signal(|| None::<i64>);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Support Tickets" }
                    p { class: "text-gray-500 text-sm mt-1", "All client tickets for your accounts." }
                }
                button {
                    class: "p-2 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors",
                    title: "Refresh",
                    onclick: move |_| tickets.restart(),
                    Icon { name: "refresh-cw", class: "w-5 h-5".to_string() }
                }
            }
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*tickets.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Subject" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Priority" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Updated" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for ticket in list.iter() {
                                    tr {
                                        class: if selected_id() == Some(ticket.id) {
                                            "bg-blue-50/30 cursor-pointer transition-colors"
                                        } else {
                                            "hover:bg-gray-50/50 cursor-pointer transition-colors"
                                        },
                                        onclick: {
                                            let tid = ticket.id;
                                            move |_| {
                                                if selected_id() == Some(tid) {
                                                    selected_id.set(None);
                                                } else {
                                                    selected_id.set(Some(tid));
                                                }
                                            }
                                        },
                                        td { class: "px-6 py-4 text-sm font-medium text-gray-900", "{ticket.subject}" }
                                        td { class: "px-6 py-4 text-sm text-gray-500", "{ticket.priority}" }
                                        td { class: "px-6 py-4", StatusBadge { status: ticket.status.to_string() } }
                                        td { class: "px-6 py-4 text-sm text-gray-500",
                                            "{ticket.updated_at.format(\"%b %d, %Y\")}"
                                        }
                                    }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No support tickets." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
            if let Some(tid) = selected_id() {
                TicketDetail {
                    ticket_id: tid,
                    on_close: move |_| selected_id.set(None),
                    on_updated: move |_| tickets.restart(),
                }
            }
        }
    }
}

#[component]
fn ResellerSettings() -> Element {
    let mut user = use_resource(move || async move { server_get_current_user().await });

    let mut old_pw = use_signal(String::new);
    let mut new_pw = use_signal(String::new);
    let mut confirm_pw = use_signal(String::new);
    let mut pw_saving = use_signal(|| false);
    let mut pw_error = use_signal(|| None::<String>);
    let mut pw_success = use_signal(|| false);

    // 2FA setup
    let mut show_2fa_form = use_signal(|| false);
    let mut tfa_secret = use_signal(String::new);
    let mut tfa_qr_url = use_signal(String::new);
    let mut tfa_code = use_signal(String::new);
    let mut tfa_loading = use_signal(|| false);
    let mut tfa_error = use_signal(|| None::<String>);
    let mut tfa_success = use_signal(|| false);

    // Disable 2FA
    let mut show_disable_2fa = use_signal(|| false);
    let mut disable_2fa_pw = use_signal(String::new);
    let mut disable_2fa_saving = use_signal(|| false);
    let mut disable_2fa_error = use_signal(|| None::<String>);

    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "Settings" }
            div { class: "space-y-6",
                match &*user.read() {
                    Some(Ok(u)) => rsx! {
                        // Account Info card
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                            h3 { class: "text-lg font-semibold text-gray-700 mb-4", "Account Information" }
                            div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                                div {
                                    label { class: "block text-sm font-medium text-gray-500", "Username" }
                                    p { class: "text-gray-900 mt-0.5", "{u.username}" }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-500", "Email" }
                                    p { class: "text-gray-900 mt-0.5", "{u.email}" }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-500", "Two-Factor Auth" }
                                    p { class: "text-gray-900 mt-0.5",
                                        if u.totp_enabled { "Enabled ✅" } else { "Disabled" }
                                    }
                                }
                            }
                        }

                        // Security card: password + 2FA
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                            h3 { class: "text-lg font-semibold text-gray-700 mb-4", "Security" }

                            // Password change
                            div { class: "flex items-center justify-between py-2",
                                span { class: "text-sm text-gray-700", "Password" }
                            }
                            if let Some(ref err) = pw_error() {
                                div { class: "bg-red-50 border border-red-200 text-red-700 rounded-xl p-3 mb-4 text-sm",
                                    "{clean_err(err)}"
                                }
                            }
                            if pw_success() {
                                div { class: "bg-green-50 border border-green-200 text-green-700 rounded-xl p-3 mb-4 text-sm",
                                    "Password changed successfully."
                                }
                            }
                            div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-4",
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Current Password" }
                                    input {
                                        r#type: "password",
                                        class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                        value: "{old_pw}",
                                        oninput: move |e| old_pw.set(e.value()),
                                    }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "New Password" }
                                    input {
                                        r#type: "password",
                                        class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                        placeholder: "12+ characters",
                                        value: "{new_pw}",
                                        oninput: move |e| new_pw.set(e.value()),
                                    }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Confirm Password" }
                                    input {
                                        r#type: "password",
                                        class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                        value: "{confirm_pw}",
                                        oninput: move |e| confirm_pw.set(e.value()),
                                    }
                                }
                            }
                            button {
                                class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-xl font-medium transition-colors disabled:opacity-50 text-sm",
                                disabled: pw_saving(),
                                onclick: move |_| {
                                    let old = old_pw();
                                    let new = new_pw();
                                    let confirm = confirm_pw();
                                    if new != confirm {
                                        pw_error.set(Some("New passwords do not match".to_string()));
                                        return;
                                    }
                                    if new.len() < 12 {
                                        pw_error.set(Some("New password must be at least 12 characters".to_string()));
                                        return;
                                    }
                                    pw_saving.set(true);
                                    pw_error.set(None);
                                    pw_success.set(false);
                                    spawn(async move {
                                        match server_change_password(old, new).await {
                                            Ok(_) => {
                                                pw_success.set(true);
                                                old_pw.set(String::new());
                                                new_pw.set(String::new());
                                                confirm_pw.set(String::new());
                                            }
                                            Err(e) => pw_error.set(Some(e.to_string())),
                                        }
                                        pw_saving.set(false);
                                    });
                                },
                                if pw_saving() { "Saving..." } else { "Change Password" }
                            }

                            // 2FA section
                            div { class: "border-t border-gray-100 mt-6 pt-6",
                                div { class: "flex items-center justify-between",
                                    div {
                                        h4 { class: "text-sm font-semibold text-gray-700", "Two-Factor Authentication" }
                                        p { class: "text-xs text-gray-500 mt-0.5",
                                            if u.totp_enabled {
                                                "2FA is enabled. Your account is protected."
                                            } else {
                                                "Add an extra layer of security to your account."
                                            }
                                        }
                                    }
                                    if u.totp_enabled {
                                        button {
                                            class: "px-4 py-2 bg-amber-100 hover:bg-amber-200 text-amber-800 rounded-xl text-sm font-medium transition-colors",
                                            onclick: move |_| {
                                                show_disable_2fa.set(!show_disable_2fa());
                                                disable_2fa_error.set(None);
                                            },
                                            if show_disable_2fa() { "Cancel" } else { "Disable Two-Factor Auth" }
                                        }
                                    } else {
                                        button {
                                            class: "px-4 py-2 bg-blue-100 hover:bg-blue-200 text-blue-800 rounded-xl text-sm font-medium transition-colors disabled:opacity-50",
                                            disabled: tfa_loading(),
                                            onclick: move |_| {
                                                if !show_2fa_form() {
                                                    tfa_loading.set(true);
                                                    tfa_error.set(None);
                                                    spawn(async move {
                                                        match server_setup_2fa().await {
                                                            Ok(r) => {
                                                                tfa_secret.set(r.secret);
                                                                tfa_qr_url.set(r.qr_code_url);
                                                                show_2fa_form.set(true);
                                                            }
                                                            Err(e) => tfa_error.set(Some(e.to_string())),
                                                        }
                                                        tfa_loading.set(false);
                                                    });
                                                } else {
                                                    show_2fa_form.set(false);
                                                }
                                            },
                                            if tfa_loading() { "Loading…" } else if show_2fa_form() { "Cancel" } else { "Enable Two-Factor Auth" }
                                        }
                                    }
                                }

                                // 2FA setup form
                                if show_2fa_form() {
                                    div { class: "mt-4 space-y-4",
                                        if let Some(ref err) = tfa_error() {
                                            div { class: "bg-red-50 text-red-700 p-3 rounded-lg text-sm", "{clean_err(err)}" }
                                        }
                                        p { class: "text-sm text-gray-600",
                                            "Scan the QR code in your authenticator app (Google Authenticator, Authy, etc.), then enter the 6-digit code to confirm."
                                        }
                                        div { class: "bg-gray-50 rounded-lg p-4 font-mono text-xs text-gray-700 break-all",
                                            strong { "Secret: " }
                                            "{tfa_secret}"
                                        }
                                        div { class: "bg-gray-50 rounded-lg p-4 text-xs text-gray-500 break-all",
                                            strong { "OTP URL: " }
                                            code { "{tfa_qr_url}" }
                                        }
                                        div { class: "flex items-end gap-4",
                                            div {
                                                label { class: "block text-sm font-medium text-gray-700 mb-1", "Verification Code" }
                                                input {
                                                    r#type: "text",
                                                    inputmode: "numeric",
                                                    maxlength: "6",
                                                    class: "px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 w-40 font-mono text-center text-xl tracking-widest",
                                                    placeholder: "000000",
                                                    value: "{tfa_code}",
                                                    oninput: move |e| tfa_code.set(e.value()),
                                                }
                                            }
                                            button {
                                                class: "px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors text-sm disabled:opacity-50",
                                                disabled: tfa_loading() || tfa_code().len() < 6,
                                                onclick: move |_| {
                                                    let secret = tfa_secret();
                                                    let code = tfa_code();
                                                    tfa_loading.set(true);
                                                    tfa_error.set(None);
                                                    spawn(async move {
                                                        match server_confirm_2fa(secret, code).await {
                                                            Ok(()) => {
                                                                tfa_success.set(true);
                                                                show_2fa_form.set(false);
                                                                user.restart();
                                                            }
                                                            Err(e) => tfa_error.set(Some(e.to_string())),
                                                        }
                                                        tfa_loading.set(false);
                                                    });
                                                },
                                                if tfa_loading() { "Verifying…" } else { "Enable 2FA" }
                                            }
                                        }
                                    }
                                }

                                // 2FA success message
                                if tfa_success() {
                                    div { class: "mt-4 bg-green-50 text-green-700 p-3 rounded-lg text-sm",
                                        "Two-factor authentication has been enabled."
                                    }
                                }

                                // Disable 2FA form
                                if show_disable_2fa() {
                                    div { class: "mt-4 space-y-3",
                                        if let Some(ref err) = disable_2fa_error() {
                                            div { class: "bg-red-50 text-red-700 p-3 rounded-lg text-sm", "{clean_err(err)}" }
                                        }
                                        p { class: "text-sm text-gray-600", "Enter your password to disable two-factor authentication." }
                                        div { class: "flex items-end gap-4",
                                            input {
                                                r#type: "password",
                                                class: "px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 w-64",
                                                placeholder: "Your current password",
                                                value: "{disable_2fa_pw}",
                                                oninput: move |e| disable_2fa_pw.set(e.value()),
                                            }
                                            button {
                                                class: "px-4 py-2 bg-amber-500 hover:bg-amber-600 text-white rounded-lg transition-colors text-sm disabled:opacity-50",
                                                disabled: disable_2fa_saving(),
                                                onclick: move |_| {
                                                    let pw = disable_2fa_pw();
                                                    disable_2fa_saving.set(true);
                                                    disable_2fa_error.set(None);
                                                    spawn(async move {
                                                        match server_disable_2fa(pw).await {
                                                            Ok(()) => {
                                                                show_disable_2fa.set(false);
                                                                disable_2fa_pw.set(String::new());
                                                                user.restart();
                                                            }
                                                            Err(e) => disable_2fa_error.set(Some(e.to_string())),
                                                        }
                                                        disable_2fa_saving.set(false);
                                                    });
                                                },
                                                if disable_2fa_saving() { "Disabling…" } else { "Disable 2FA" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { div { class: "text-red-600", "Error: {e}" } },
                    None => rsx! { div { class: "text-gray-500", "Loading..." } },
                }
            }
        }
    }
}

#[component]
fn ClientDashboard() -> Element {
    let auth = use_context::<Signal<Option<AuthState>>>();
    let dashboard = use_resource(move || async move { server_get_client_dashboard().await });

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "mb-8",
                h2 { class: "text-2xl font-bold text-gray-900",
                    if let Some(ref user) = auth() {
                        "Welcome back, {user.username}"
                    } else {
                        "Dashboard"
                    }
                }
                p { class: "text-gray-500 mt-1 text-sm", "Manage your websites, databases, and hosting services." }
            }
            match &*dashboard.read() {
                Some(Ok(d)) => rsx! {
                    div { class: "grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5",
                        StatCard { label: "Websites", value: d.sites_count.to_string(), icon: "globe", color: "blue" }
                        StatCard { label: "Databases", value: d.databases_count.to_string(), icon: "database", color: "purple" }
                        StatCard { label: "Email Domains", value: d.email_domains_count.to_string(), icon: "mail", color: "emerald" }
                        StatCard { label: "Open Tickets", value: d.open_tickets.to_string(), icon: "message-square", color: "amber" }
                    }
                },
                Some(Err(e)) => rsx! { div { class: "text-red-600", "Error: {e}" } },
                None => rsx! {
                    div { class: "grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5",
                        for _ in 0..4 {
                            div { class: "bg-white rounded-2xl border border-gray-100 p-6 animate-pulse",
                                div { class: "h-3 bg-gray-200 rounded w-20 mb-4" }
                                div { class: "h-8 bg-gray-100 rounded w-12" }
                            }
                        }
                    }
                },
            }
        }
    }
}

#[component]
fn ClientSites() -> Element {
    let mut sites = use_resource(move || async move { server_list_sites().await });
    let mut new_domain = use_signal(String::new);
    let mut new_site_type = use_signal(|| "PHP".to_string());
    let mut create_error = use_signal(|| None::<String>);
    let mut creating = use_signal(|| false);

    let on_create = move |_: FormEvent| {
        creating.set(true);
        create_error.set(None);
        let domain = new_domain();
        let site_type = match new_site_type().as_str() {
            "Static" => panel::models::site::SiteType::Static,
            "ReverseProxy" => panel::models::site::SiteType::ReverseProxy,
            "NodeJS" => panel::models::site::SiteType::NodeJs,
            _ => panel::models::site::SiteType::Php,
        };
        spawn(async move {
            match server_create_site(domain, site_type).await {
                Ok(_) => {
                    new_domain.set(String::new());
                    new_site_type.set("PHP".to_string());
                    sites.restart();
                }
                Err(e) => create_error.set(Some(e.to_string())),
            }
            creating.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "My Websites" }

            // Create site form
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                h3 { class: "text-lg font-semibold text-gray-800 mb-4", "Add Website" }
                if let Some(err) = create_error() {
                    div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                }
                form { onsubmit: on_create, class: "flex gap-4 items-end flex-wrap",
                    div { class: "flex-1 min-w-[200px]",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Domain" }
                        input {
                            r#type: "text",
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                            placeholder: "example.com",
                            value: "{new_domain}",
                            oninput: move |e| new_domain.set(e.value()),
                            required: true,
                        }
                    }
                    div { class: "w-48",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Site Type" }
                        select {
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                            value: "{new_site_type}",
                            onchange: move |e| new_site_type.set(e.value()),
                            option { value: "PHP", "PHP" }
                            option { value: "Static", "Static" }
                            option { value: "NodeJS", "Node.js" }
                            option { value: "ReverseProxy", "Reverse Proxy" }
                        }
                    }
                    button {
                        r#type: "submit",
                        class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50",
                        disabled: creating(),
                        if creating() { "Adding..." } else { "Add Site" }
                    }
                }
            }

            // Sites list
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*sites.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Domain" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Type" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "SSL" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "HTTPS" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "HSTS" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Created" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for site in list.iter() {
                                    SiteRow { site: site.clone(), sites_resource: sites }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No websites yet. Add one above!" }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
        }
    }
}

#[component]
fn SiteRow(
    site: panel::models::site::Site,
    sites_resource: Resource<Result<Vec<panel::models::site::Site>, ServerFnError>>,
) -> Element {
    let site_id = site.id;
    let site_domain = site.domain.clone();
    let current_status = site.status;
    let ssl_on = site.ssl_enabled;
    let https_on = site.force_https;
    let hsts_on = site.hsts_enabled;
    let hsts_age = site.hsts_max_age;
    let hsts_subdoms = site.hsts_include_subdomains;
    let hsts_pre = site.hsts_preload;
    let is_php_site = matches!(
        site.site_type,
        panel::models::site::SiteType::Php | panel::models::site::SiteType::WordPress
    );
    let mut sites_resource = sites_resource;
    let mut confirm_delete = use_signal(|| false);
    let mut row_error = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    let mut show_logs = use_signal(|| false);
    let mut php_ver = use_signal(|| {
        site.php_version
            .clone()
            .unwrap_or_else(|| "8.3".to_string())
    });
    let available_php = use_resource(move || async move { server_list_php_versions().await });

    let on_toggle_status = move |_| {
        let new_status = match current_status {
            panel::models::site::SiteStatus::Active => panel::models::site::SiteStatus::Suspended,
            panel::models::site::SiteStatus::Suspended => panel::models::site::SiteStatus::Active,
            panel::models::site::SiteStatus::Inactive => panel::models::site::SiteStatus::Active,
        };
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_update_site_status(site_id, new_status).await {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let on_toggle_ssl = move |_| {
        let new_ssl = !ssl_on;
        let fhttps = if !new_ssl { false } else { https_on };
        // Disabling SSL also clears HSTS.
        let new_hsts = if !new_ssl { false } else { hsts_on };
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_update_site_ssl(
                site_id,
                new_ssl,
                fhttps,
                new_hsts,
                hsts_age,
                hsts_subdoms,
                hsts_pre,
            )
            .await
            {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let on_toggle_https = move |_| {
        let new_https = !https_on;
        // Disabling force-HTTPS also disables HSTS (requires HTTPS redirect to be active).
        let new_hsts = if !new_https { false } else { hsts_on };
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_update_site_ssl(
                site_id,
                ssl_on,
                new_https,
                new_hsts,
                hsts_age,
                hsts_subdoms,
                hsts_pre,
            )
            .await
            {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let on_toggle_hsts = move |_| {
        let new_hsts = !hsts_on;
        // Use 1-year max-age when enabling HSTS for the first time.
        let age = if hsts_age == 0 { 31536000 } else { hsts_age };
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_update_site_ssl(
                site_id,
                ssl_on,
                https_on,
                new_hsts,
                age,
                hsts_subdoms,
                hsts_pre,
            )
            .await
            {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let on_delete = move |_| {
        busy.set(true);
        row_error.set(None);
        spawn(async move {
            match server_delete_site(site_id).await {
                Ok(()) => sites_resource.restart(),
                Err(e) => row_error.set(Some(e.to_string())),
            }
            busy.set(false);
            confirm_delete.set(false);
        });
    };

    let on_change_php = move |e: dioxus::events::FormEvent| {
        let ver = e.value();
        row_error.set(None);
        spawn(async move {
            match server_update_site_php_version(site_id, ver.clone()).await {
                Ok(()) => {
                    php_ver.set(ver);
                    sites_resource.restart();
                }
                Err(e) => row_error.set(Some(e.to_string())),
            }
        });
    };

    let created = site.created_at.format("%Y-%m-%d").to_string();

    let status_btn_class = match current_status {
        panel::models::site::SiteStatus::Active => {
            "text-xs px-2 py-1 rounded bg-yellow-100 text-yellow-800 hover:bg-yellow-200 transition-colors disabled:opacity-50"
        }
        _ => {
            "text-xs px-2 py-1 rounded bg-green-100 text-green-800 hover:bg-green-200 transition-colors disabled:opacity-50"
        }
    };

    let status_btn_label = match current_status {
        panel::models::site::SiteStatus::Active => "Suspend",
        _ => "Activate",
    };

    rsx! {
        tr { class: "hover:bg-gray-50/50 transition-colors",
            td { class: "px-6 py-4",
                div { class: "text-sm font-medium text-gray-900", "{site_domain}" }
                if let Some(err) = row_error() {
                    div { class: "text-xs text-red-500 mt-1", "{err}" }
                }
            }
            td { class: "px-6 py-4 text-sm text-gray-500", "{site.site_type}" }
            td { class: "px-6 py-4", StatusBadge { status: site.status.to_string() } }
            td { class: "px-6 py-4 text-sm",
                button {
                    class: "text-sm cursor-pointer hover:opacity-70 disabled:opacity-50",
                    onclick: on_toggle_ssl,
                    disabled: busy(),
                    title: if ssl_on { "Click to disable SSL" } else { "Click to enable SSL" },
                    if ssl_on { "🔒" } else { "🔓" }
                }
            }
            td { class: "px-6 py-4 text-sm",
                if ssl_on {
                    button {
                        class: "text-xs px-2 py-1 rounded transition-colors disabled:opacity-50",
                        class: if https_on { "bg-green-100 text-green-800 hover:bg-green-200" } else { "bg-gray-100 text-gray-600 hover:bg-gray-200" },
                        onclick: on_toggle_https,
                        disabled: busy(),
                        if https_on { "Forced" } else { "Off" }
                    }
                } else {
                    span { class: "text-xs text-gray-400", "—" }
                }
            }
            td { class: "px-6 py-4 text-sm",
                if ssl_on && https_on {
                    button {
                        class: "text-xs px-2 py-1 rounded transition-colors disabled:opacity-50",
                        class: if hsts_on { "bg-purple-100 text-purple-800 hover:bg-purple-200" } else { "bg-gray-100 text-gray-600 hover:bg-gray-200" },
                        onclick: on_toggle_hsts,
                        disabled: busy(),
                        title: if hsts_on { "HSTS active — click to disable" } else { "Click to enable HSTS" },
                        if hsts_on { "On" } else { "Off" }
                    }
                } else {
                    span { class: "text-xs text-gray-400", "—" }
                }
            }
            td { class: "px-6 py-4 text-xs text-gray-500", "{created}" }
            td { class: "px-6 py-4",
                div { class: "flex items-center gap-2 flex-wrap",
                    button {
                        class: "{status_btn_class}",
                        onclick: on_toggle_status,
                        disabled: busy(),
                        "{status_btn_label}"
                    }
                    // PHP version picker — only for PHP/WordPress sites.
                    if is_php_site {
                        if let Some(Ok(versions)) = &*available_php.read() {
                            if !versions.is_empty() {
                                select {
                                    class: "text-xs px-1.5 py-1 border border-gray-300 rounded bg-white text-gray-700 focus:ring-1 focus:ring-blue-400",
                                    title: "PHP version",
                                    value: "{php_ver}",
                                    onchange: on_change_php,
                                    for ver in versions.iter() {
                                        option {
                                            value: "{ver}",
                                            selected: *ver == php_ver(),
                                            "PHP {ver}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                    button {
                        class: if show_logs() {
                            "text-xs px-2 py-1 rounded bg-indigo-200 text-indigo-800 hover:bg-indigo-300"
                        } else {
                            "text-xs px-2 py-1 rounded bg-gray-100 text-gray-700 hover:bg-gray-200"
                        },
                        onclick: move |_| show_logs.toggle(),
                        "Logs"
                    }
                    if confirm_delete() {
                        span { class: "text-xs text-red-600 font-medium", "Sure?" }
                        button {
                            class: "text-xs px-2 py-1 rounded bg-red-600 text-white hover:bg-red-700 disabled:opacity-50",
                            onclick: on_delete,
                            disabled: busy(),
                            "Yes"
                        }
                        button {
                            class: "text-xs px-2 py-1 rounded bg-gray-200 text-gray-700 hover:bg-gray-300",
                            onclick: move |_| confirm_delete.set(false),
                            "No"
                        }
                    } else {
                        button {
                            class: "text-xs px-2 py-1 rounded bg-red-100 text-red-700 hover:bg-red-200 disabled:opacity-50",
                            onclick: move |_| confirm_delete.set(true),
                            disabled: busy(),
                            "Delete"
                        }
                    }
                }
            }
        }
        if show_logs() {
            SiteLogViewer { site_id, col_span: 8 }
        }
    }
}

#[component]
fn ClientDatabases() -> Element {
    let mut databases = use_resource(move || async move { server_list_databases().await });
    let mut new_name = use_signal(String::new);
    let mut name_error = use_signal(|| None::<String>);
    let mut create_error = use_signal(|| None::<String>);
    let mut pma_error = use_signal(|| None::<String>);

    let _open_phpmyadmin_all = move |_: dioxus::events::MouseEvent| {
        pma_error.set(None);
        spawn(async move {
            match server_get_phpmyadmin_url(None).await {
                Ok(_url) => {
                    #[cfg(target_arch = "wasm32")]
                    {
                        let _ = web_sys::window()
                            .and_then(|w| w.open_with_url_and_target(&_url, "_blank").ok());
                    }
                }
                Err(e) => pma_error.set(Some(e.to_string())),
            }
        });
    };
    let open_phpmyadmin_all = move |_: dioxus::events::MouseEvent| {
        pma_error.set(None);
        spawn(async move {
            match server_get_phpmyadmin_url(None).await {
                Ok(_url) => {
                    #[cfg(target_arch = "wasm32")]
                    {
                        let _ = web_sys::window()
                            .and_then(|w| w.open_with_url_and_target(&_url, "_blank").ok());
                    }
                }
                Err(e) => pma_error.set(Some(e.to_string())),
            }
        });
    };
    let on_create = move |_: FormEvent| {
        create_error.set(None);
        name_error.set(None);
        let name = new_name().trim().to_string();

        // Client-side validation matching MariaDB / phpMyAdmin best practices
        if name.is_empty() {
            name_error.set(Some("Database name is required".to_string()));
            return;
        }
        if name.len() < 3 {
            name_error.set(Some(
                "Database name must be at least 3 characters".to_string(),
            ));
            return;
        }
        if name.len() > 64 {
            name_error.set(Some(
                "Database name must be at most 64 characters".to_string(),
            ));
            return;
        }
        if !name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
        {
            name_error.set(Some(
                "Database name must start with a letter (a–z, A–Z)".to_string(),
            ));
            return;
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            name_error.set(Some(
                "Only letters, digits (0–9), and underscores (_) are allowed".to_string(),
            ));
            return;
        }

        spawn(async move {
            match server_create_database(name, panel::models::database::DatabaseType::MariaDB).await
            {
                Ok(_) => {
                    new_name.set(String::new());
                    databases.restart();
                }
                Err(e) => create_error.set(Some(clean_err(&e.to_string()))),
            }
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Databases" }
                button {
                    class: "px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors flex items-center gap-2 text-sm",
                    onclick: open_phpmyadmin_all,
                    Icon { name: "database", class: "w-4 h-4".to_string() }
                    span { "Open phpMyAdmin" }
                }
            }

            if let Some(err) = pma_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                h3 { class: "text-lg font-semibold text-gray-800 mb-4", "Create Database" }
                if let Some(err) = create_error() {
                    div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                }
                form { onsubmit: on_create, class: "flex gap-4 items-end",
                    div { class: "flex-1",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Database Name" }
                        input {
                            r#type: "text",
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                            placeholder: "my_database",
                            value: "{new_name}",
                            oninput: move |e| {
                                new_name.set(e.value());
                                name_error.set(None);
                            },
                        }
                        if let Some(err) = name_error() {
                            p { class: "mt-1 text-xs text-red-600", "{err}" }
                        } else {
                            p { class: "mt-1 text-xs text-gray-400",
                                "3–64 chars · letters, digits, underscores · must start with a letter"
                            }
                        }
                    }
                    button {
                        r#type: "submit",
                        class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors",
                        "Create"
                    }
                }
            }
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*databases.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr { class: "hover:bg-gray-50/50 transition-colors",
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Name" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Type" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Users" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for db in list.iter() {
                                    DatabaseRow { db: db.clone(), databases_resource: databases }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No databases yet." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
        }
    }
}

/// Individual database row with expandable user management and delete actions.
#[component]
fn DatabaseRow(
    db: panel::models::database::Database,
    databases_resource: Resource<Result<Vec<panel::models::database::Database>, ServerFnError>>,
) -> Element {
    let db_id = db.id;
    let is_mariadb = db.database_type == panel::models::database::DatabaseType::MariaDB;
    let mut databases_resource = databases_resource;

    let mut users = use_resource(move || async move { server_list_db_users(db_id).await });
    let mut show_manage = use_signal(|| false);
    let mut deleting_db = use_signal(|| false);
    let mut db_error = use_signal(|| None::<String>);
    let mut new_username = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut add_error = use_signal(|| None::<String>);
    let mut adding = use_signal(|| false);
    // Delete confirmation modal state
    let mut show_delete_confirm = use_signal(|| false);
    let mut delete_confirm_input = use_signal(String::new);
    let mut downloading_dump = use_signal(|| false);
    let mut dump_error = use_signal(|| None::<String>);
    let db_name_display = db.name.clone();
    let db_name_for_download = db.name.clone();

    let open_phpmyadmin = move |_| {
        spawn(async move {
            match server_get_phpmyadmin_url(Some(db_id)).await {
                Ok(_url) => {
                    #[cfg(target_arch = "wasm32")]
                    {
                        let _ = web_sys::window()
                            .and_then(|w| w.open_with_url_and_target(&_url, "_blank").ok());
                    }
                }
                Err(_e) => {}
            }
        });
    };

    let delete_db = move |_| {
        deleting_db.set(true);
        db_error.set(None);
        show_delete_confirm.set(false);
        delete_confirm_input.set(String::new());
        spawn(async move {
            match server_delete_database(db_id).await {
                Ok(()) => databases_resource.restart(),
                Err(e) => {
                    db_error.set(Some(e.to_string()));
                    deleting_db.set(false);
                }
            }
        });
    };

    let download_db = move |_| {
        dump_error.set(None);
        downloading_dump.set(true);
        let _db_name_dl = db_name_for_download.clone();
        spawn(async move {
            match server_dump_database(db_id).await {
                Ok(_b64) => {
                    #[cfg(target_arch = "wasm32")]
                    {
                        let js = format!(
                            r#"(function(){{
                                var sql = atob('{}');
                                var blob = new Blob([sql], {{type:'application/octet-stream'}});
                                var url = URL.createObjectURL(blob);
                                var a = document.createElement('a');
                                a.href = url; a.download = '{}.sql';
                                document.body.appendChild(a); a.click();
                                setTimeout(function(){{ document.body.removeChild(a); URL.revokeObjectURL(url); }}, 150);
                            }})();"#,
                            _b64, _db_name_dl
                        );
                        let _ = js_sys::eval(&js);
                    }
                    downloading_dump.set(false);
                }
                Err(e) => {
                    dump_error.set(Some(e.to_string()));
                    downloading_dump.set(false);
                }
            }
        });
    };

    let add_user = move |_: FormEvent| {
        add_error.set(None);
        adding.set(true);
        let username = new_username();
        let password = new_password();
        spawn(async move {
            match server_create_db_user(db_id, username, password).await {
                Ok(_) => {
                    new_username.set(String::new());
                    new_password.set(String::new());
                    users.restart();
                }
                Err(e) => add_error.set(Some(e.to_string())),
            }
            adding.set(false);
        });
    };

    // Count of non-system (non-pma_) users
    let user_count = match &*users.read() {
        Some(Ok(list)) => list
            .iter()
            .filter(|u| !u.username.starts_with("pma_"))
            .count(),
        _ => 0,
    };
    let user_label = if user_count == 1 {
        "1 user"
    } else {
        &format!("{} users", user_count)
    };

    rsx! {
        tr { class: "hover:bg-gray-50/50 transition-colors",
            td { class: "px-6 py-4 text-sm font-medium text-gray-900", "{db.name}" }
            td { class: "px-6 py-4 text-sm text-gray-500", "{db.database_type}" }
            td { class: "px-6 py-4", StatusBadge { status: db.status.to_string() } }
            td { class: "px-6 py-4 text-sm text-gray-500", "{user_label}" }
            td { class: "px-6 py-4",
                div { class: "flex items-center gap-2 flex-wrap",
                    if is_mariadb {
                        button {
                            class: "px-3 py-1 bg-blue-500 hover:bg-blue-600 text-white text-xs rounded transition-colors",
                            onclick: open_phpmyadmin,
                            "phpMyAdmin"
                        }
                    }
                    button {
                        class: if show_manage() {
                            "px-3 py-1 bg-gray-200 text-gray-700 text-xs rounded transition-colors"
                        } else {
                            "px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 text-xs rounded transition-colors"
                        },
                        onclick: move |_| show_manage.set(!show_manage()),
                        if show_manage() { "Hide Users" } else { "Manage Users" }
                    }
                    button {
                        class: "px-3 py-1 bg-red-50 hover:bg-red-100 text-red-600 text-xs rounded transition-colors disabled:opacity-50",
                        disabled: deleting_db(),
                        onclick: move |_| {
                            delete_confirm_input.set(String::new());
                            dump_error.set(None);
                            show_delete_confirm.set(true);
                        },
                        if deleting_db() { "Deleting…" } else { "Delete" }
                    }
                }
                if let Some(err) = db_error() {
                    div { class: "mt-1 text-xs text-red-600", "{err}" }
                }
            }
        }
        // Expandable user management section
        if show_manage() {
            tr { class: "bg-gray-50/70 border-b border-gray-100",
                td { colspan: "5", class: "px-6 pb-5 pt-3",
                    div { class: "max-w-3xl space-y-4",
                        h4 { class: "text-sm font-semibold text-gray-700", "Database Users" }

                        // Users table
                        match &*users.read() {
                            Some(Ok(list)) => {
                                let visible: Vec<_> = list.iter()
                                    .filter(|u| !u.username.starts_with("pma_"))
                                    .collect();
                                if visible.is_empty() {
                                    rsx! {
                                        p { class: "text-sm text-gray-400 italic", "No additional users yet. Add one below." }
                                    }
                                } else {
                                    rsx! {
                                        div { class: "border border-gray-200 rounded-lg overflow-hidden",
                                            table { class: "w-full text-sm",
                                                thead { class: "bg-gray-100 border-b border-gray-200",
                                                    tr {
                                                        th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "Username" }
                                                        th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "Privileges" }
                                                        th { class: "px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase", "Actions" }
                                                    }
                                                }
                                                tbody { class: "divide-y divide-gray-100",
                                                    for user in visible {
                                                        DbUserRow {
                                                            user: user.clone(),
                                                            on_change: EventHandler::new(move |_| users.restart()),
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            Some(Err(e)) => rsx! {
                                p { class: "text-sm text-red-600", "Error loading users: {e}" }
                            },
                            None => rsx! {
                                p { class: "text-sm text-gray-400", "Loading…" }
                            },
                        }

                        // Add user form
                        div { class: "border border-gray-200 rounded-lg p-4 bg-white",
                            h5 { class: "text-sm font-semibold text-gray-700 mb-3", "Add Database User" }
                            if let Some(err) = add_error() {
                                div { class: "bg-red-50 text-red-700 p-2 rounded text-xs mb-3", "{err}" }
                            }
                            form { onsubmit: add_user, class: "flex flex-wrap gap-3 items-end",
                                div {
                                    label { class: "block text-xs font-medium text-gray-600 mb-1", "Username" }
                                    input {
                                        r#type: "text",
                                        class: "px-3 py-1.5 border border-gray-300 rounded text-sm focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                        placeholder: "app_user",
                                        value: "{new_username}",
                                        oninput: move |e| new_username.set(e.value()),
                                        required: true,
                                        maxlength: "32",
                                    }
                                }
                                div {
                                    label { class: "block text-xs font-medium text-gray-600 mb-1", "Password" }
                                    input {
                                        r#type: "password",
                                        class: "px-3 py-1.5 border border-gray-300 rounded text-sm focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                        placeholder: "Min 12 chars",
                                        value: "{new_password}",
                                        oninput: move |e| new_password.set(e.value()),
                                        required: true,
                                        minlength: "12",
                                    }
                                }
                                button {
                                    r#type: "submit",
                                    disabled: adding(),
                                    class: "px-4 py-1.5 bg-rose-500 hover:bg-rose-600 text-white text-sm font-medium rounded transition-colors disabled:opacity-50",
                                    if adding() { "Adding…" } else { "Add User" }
                                }
                            }
                            p { class: "text-xs text-gray-400 mt-2",
                                "Password: 12+ chars, uppercase, lowercase, digit and special char. Cannot contain: ' \" \\ ; | & $ ` ( ) {{ }}"
                            }
                        }
                    }
                }
            }
        }
        // Delete confirmation modal
        if show_delete_confirm() {
            div {
                class: "fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center",
                onclick: move |_| {
                    if !deleting_db() {
                        show_delete_confirm.set(false);
                        delete_confirm_input.set(String::new());
                        dump_error.set(None);
                    }
                },
                div {
                    class: "bg-white rounded-2xl shadow-xl p-6 max-w-md w-full mx-4",
                    onclick: move |e| e.stop_propagation(),
                    // Header
                    div { class: "flex items-center gap-3 mb-4",
                        div { class: "p-2 bg-red-100 rounded-xl shrink-0",
                            Icon { name: "alert-triangle", class: "w-6 h-6 text-red-600".to_string() }
                        }
                        div {
                            h3 { class: "text-lg font-semibold text-gray-900", "Delete Database" }
                            p { class: "text-sm text-gray-500 mt-0.5",
                                "\"" "{db_name_display}" "\""
                            }
                        }
                    }
                    p { class: "text-sm text-gray-600 mb-5",
                        "This will permanently delete the database and all its data. This action cannot be undone."
                    }
                    // Download section
                    div { class: "bg-amber-50 border border-amber-200 rounded-xl p-4 mb-5",
                        p { class: "text-sm font-medium text-amber-800 mb-3",
                            "💾 Download a backup before deleting (optional)"
                        }
                        if let Some(err) = dump_error() {
                            div { class: "text-xs text-red-600 mb-2", "{err}" }
                        }
                        div { class: "flex gap-2",
                            button {
                                class: "px-4 py-2 bg-amber-500 hover:bg-amber-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2",
                                disabled: downloading_dump(),
                                onclick: download_db,
                                if downloading_dump() {
                                    span { "Preparing…" }
                                } else {
                                    Icon { name: "download", class: "w-4 h-4".to_string() }
                                    span { "Download Database" }
                                }
                            }
                        }
                    }
                    // Confirm input
                    div { class: "mb-5",
                        label { class: "block text-sm font-medium text-gray-700 mb-1",
                            "Type "
                            span { class: "font-mono font-bold text-red-600", "DELETE" }
                            " to confirm"
                        }
                        input {
                            r#type: "text",
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent font-mono",
                            placeholder: "DELETE",
                            value: "{delete_confirm_input}",
                            oninput: move |e| delete_confirm_input.set(e.value()),
                            autocomplete: "off",
                            spellcheck: "false",
                        }
                    }
                    // Action buttons
                    div { class: "flex justify-end gap-3",
                        button {
                            class: "px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-xl hover:bg-gray-200 transition-colors",
                            disabled: deleting_db(),
                            onclick: move |_| {
                                show_delete_confirm.set(false);
                                delete_confirm_input.set(String::new());
                                dump_error.set(None);
                            },
                            "Cancel"
                        }
                        button {
                            class: "px-4 py-2 text-sm font-medium text-white bg-red-500 rounded-xl hover:bg-red-600 transition-colors shadow-sm disabled:opacity-40 disabled:cursor-not-allowed",
                            disabled: delete_confirm_input() != "DELETE" || deleting_db(),
                            onclick: delete_db,
                            if deleting_db() { "Deleting…" } else { "Delete Database" }
                        }
                    }
                }
            }
        }
    }
}

/// A single row in the DB user management table with inline change-password support.
#[component]
fn DbUserRow(user: panel::models::database::DatabaseUser, on_change: EventHandler<()>) -> Element {
    let user_id = user.id;
    let mut show_change_pw = use_signal(|| false);
    let mut new_pw = use_signal(String::new);
    let mut changing_pw = use_signal(|| false);
    let mut pw_error = use_signal(|| None::<String>);
    let mut deleting = use_signal(|| false);

    let delete_user = move |_| {
        deleting.set(true);
        spawn(async move {
            match server_delete_db_user(user_id).await {
                Ok(()) => on_change.call(()),
                Err(_) => deleting.set(false),
            }
        });
    };

    let change_pw = move |_: FormEvent| {
        changing_pw.set(true);
        pw_error.set(None);
        let pw = new_pw();
        spawn(async move {
            match server_change_db_user_password(user_id, pw).await {
                Ok(()) => {
                    new_pw.set(String::new());
                    show_change_pw.set(false);
                }
                Err(e) => pw_error.set(Some(e.to_string())),
            }
            changing_pw.set(false);
        });
    };

    rsx! {
        tr { class: "hover:bg-white transition-colors",
            td { class: "px-4 py-2 font-mono text-xs text-gray-800", "{user.username}" }
            td { class: "px-4 py-2 text-xs text-gray-500",
                if let Some(priv_str) = &user.privileges {
                    span { "{priv_str}" }
                } else {
                    span { class: "text-gray-300", "—" }
                }
            }
            td { class: "px-4 py-2",
                div { class: "flex items-center justify-end gap-2",
                    button {
                        class: if show_change_pw() {
                            "px-2 py-0.5 bg-amber-200 text-amber-800 text-xs rounded transition-colors"
                        } else {
                            "px-2 py-0.5 bg-amber-50 hover:bg-amber-100 text-amber-700 text-xs rounded transition-colors"
                        },
                        onclick: move |_| {
                            show_change_pw.set(!show_change_pw());
                            pw_error.set(None);
                        },
                        if show_change_pw() { "Cancel" } else { "Change PW" }
                    }
                    button {
                        class: "px-2 py-0.5 bg-red-50 hover:bg-red-100 text-red-600 text-xs rounded transition-colors disabled:opacity-50",
                        disabled: deleting(),
                        onclick: delete_user,
                        if deleting() { "…" } else { "Delete" }
                    }
                }
            }
        }
        if show_change_pw() {
            tr { class: "bg-amber-50/60",
                td { colspan: "3", class: "px-4 py-3",
                    if let Some(err) = pw_error() {
                        div { class: "text-xs text-red-600 mb-2", "{err}" }
                    }
                    form { onsubmit: change_pw, class: "flex flex-wrap gap-2 items-end",
                        div {
                            label { class: "block text-xs font-medium text-gray-600 mb-1", "New Password" }
                            input {
                                r#type: "password",
                                class: "px-3 py-1.5 border border-gray-300 rounded text-sm focus:ring-2 focus:ring-amber-400 focus:border-transparent w-64",
                                placeholder: "New password (12+ chars)",
                                value: "{new_pw}",
                                oninput: move |e| new_pw.set(e.value()),
                                required: true,
                                minlength: "12",
                            }
                        }
                        button {
                            r#type: "submit",
                            disabled: changing_pw(),
                            class: "px-3 py-1.5 bg-amber-500 hover:bg-amber-600 text-white text-xs font-medium rounded transition-colors disabled:opacity-50",
                            if changing_pw() { "Saving…" } else { "Save" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ClientDns() -> Element {
    let mut zones = use_resource(move || async move { server_list_dns_zones().await });

    let mut new_domain = use_signal(String::new);
    let mut create_error = use_signal(|| None::<String>);
    let mut creating = use_signal(|| false);

    let on_create_zone = move |_: FormEvent| {
        creating.set(true);
        create_error.set(None);
        let domain = new_domain();
        spawn(async move {
            match server_create_dns_zone(domain).await {
                Ok(_) => {
                    new_domain.set(String::new());
                    zones.restart();
                }
                Err(e) => create_error.set(Some(e.to_string())),
            }
            creating.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "DNS Management" }

            // Create zone form
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                h3 { class: "text-lg font-semibold text-gray-800 mb-4", "Add DNS Zone" }
                p { class: "text-sm text-gray-500 mb-4", "Zones are managed via Cloudflare. Adding a zone will create it in Cloudflare and assign nameservers." }
                if let Some(err) = create_error() {
                    div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                }
                form { onsubmit: on_create_zone, class: "flex gap-4 items-end",
                    div { class: "flex-1",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Domain" }
                        input {
                            r#type: "text",
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                            placeholder: "example.com",
                            value: "{new_domain}",
                            oninput: move |e| new_domain.set(e.value()),
                            required: true,
                        }
                    }
                    button {
                        r#type: "submit",
                        class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50",
                        disabled: creating(),
                        if creating() { "Creating..." } else { "Add Zone" }
                    }
                }
            }

            // Zones list
            match &*zones.read() {
                Some(Ok(list)) => rsx! {
                    if list.is_empty() {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 text-center",
                            p { class: "text-gray-500", "No DNS zones configured. Add one above!" }
                        }
                    }
                    for zone in list.iter() {
                        DnsZoneCard { zone: zone.clone(), zones_resource: zones }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                        p { class: "text-red-600", "Error: {e}" }
                    }
                },
                None => rsx! {
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                        p { class: "text-gray-500", "Loading..." }
                    }
                },
            }
        }
    }
}

#[component]
fn DnsZoneCard(
    zone: panel::models::dns::DnsZone,
    zones_resource: Resource<Result<Vec<panel::models::dns::DnsZone>, ServerFnError>>,
) -> Element {
    let zone_id = zone.id;
    let zone_domain = zone.domain.clone();
    let mut zones_resource = zones_resource;
    let mut expanded = use_signal(|| false);
    let mut deleting = use_signal(|| false);

    let records = use_resource(move || {
        let is_expanded = expanded();
        async move {
            if is_expanded {
                server_list_dns_records(zone_id).await.ok()
            } else {
                None
            }
        }
    });

    let on_delete_zone = move |_| {
        deleting.set(true);
        spawn(async move {
            match server_delete_dns_zone(zone_id).await {
                Ok(()) => zones_resource.restart(),
                Err(_) => deleting.set(false),
            }
        });
    };

    let sync_color = match zone.sync_status.as_deref() {
        Some("Synced") => "bg-green-100 text-green-700",
        Some("Pending") => "bg-yellow-100 text-yellow-700",
        Some("Error") => "bg-red-100 text-red-700",
        _ => "bg-gray-100 text-gray-700",
    };
    let sync_label = zone.sync_status.as_deref().unwrap_or("Unknown");

    rsx! {
        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 mb-4 overflow-hidden",
            // Zone header
            div { class: "p-6",
                div { class: "flex items-center justify-between",
                    div { class: "flex items-center gap-4",
                        div {
                            h3 { class: "text-lg font-semibold text-gray-900", "{zone_domain}" }
                            div { class: "flex items-center gap-3 mt-1",
                                span { class: "text-xs px-2 py-0.5 rounded-full font-medium {sync_color}", "{sync_label}" }
                                StatusBadge { status: zone.status.clone() }
                            }
                        }
                    }
                    div { class: "flex items-center gap-2",
                        {
                            let expand_cls = if expanded() { "bg-gray-200 text-gray-700" } else { "bg-gray-100 hover:bg-gray-200 text-gray-600" };
                            rsx! {
                                button {
                                    class: "px-4 py-2 text-sm font-medium rounded-lg transition-colors {expand_cls}",
                                    onclick: move |_| expanded.set(!expanded()),
                                    if expanded() { "Hide Records" } else { "Manage Records" }
                                }
                            }
                        }
                        button {
                            class: "px-4 py-2 text-sm font-medium rounded-lg bg-red-50 hover:bg-red-100 text-red-600 transition-colors disabled:opacity-50",
                            disabled: deleting(),
                            onclick: on_delete_zone,
                            if deleting() { "Deleting..." } else { "Delete Zone" }
                        }
                    }
                }

                // Nameserver info
                if zone.nameserver1.is_some() || zone.nameserver2.is_some() {
                    div { class: "mt-3 p-3 bg-blue-50 rounded-lg",
                        p { class: "text-xs font-medium text-blue-700 mb-1", "Assigned Nameservers" }
                        div { class: "flex gap-4",
                            if let Some(ref ns1) = zone.nameserver1 {
                                code { class: "text-sm text-blue-800 bg-blue-100 px-2 py-0.5 rounded", "{ns1}" }
                            }
                            if let Some(ref ns2) = zone.nameserver2 {
                                code { class: "text-sm text-blue-800 bg-blue-100 px-2 py-0.5 rounded", "{ns2}" }
                            }
                        }
                    }
                }
            }

            // Expanded records section
            if expanded() {
                DnsRecordPanel { zone_id: zone_id, records_resource: records }
            }
        }
    }
}

#[component]
fn DnsRecordPanel(
    zone_id: i64,
    records_resource: Resource<Option<Vec<panel::models::dns::DnsRecord>>>,
) -> Element {
    let mut records_resource = records_resource;
    let mut show_form = use_signal(|| false);
    let mut rec_name = use_signal(String::new);
    let mut rec_type = use_signal(|| "A".to_string());
    let mut rec_value = use_signal(String::new);
    let mut rec_priority = use_signal(|| "10".to_string());
    let mut rec_ttl = use_signal(|| "3600".to_string());
    let mut add_error = use_signal(|| None::<String>);
    let mut adding = use_signal(|| false);

    let on_add_record = move |_: FormEvent| {
        adding.set(true);
        add_error.set(None);
        let name = rec_name();
        let rtype_str = rec_type();
        let value = rec_value();
        let priority: i32 = rec_priority().parse().unwrap_or(10);
        let ttl: i32 = rec_ttl().parse().unwrap_or(3600);

        let record_type = match rtype_str.as_str() {
            "A" => panel::models::dns::RecordType::A,
            "AAAA" => panel::models::dns::RecordType::Aaaa,
            "CNAME" => panel::models::dns::RecordType::Cname,
            "MX" => panel::models::dns::RecordType::Mx,
            "TXT" => panel::models::dns::RecordType::Txt,
            "SRV" => panel::models::dns::RecordType::Srv,
            "CAA" => panel::models::dns::RecordType::Caa,
            "NS" => panel::models::dns::RecordType::Ns,
            _ => panel::models::dns::RecordType::A,
        };

        spawn(async move {
            match server_add_dns_record(zone_id, name, record_type, value, priority, ttl).await {
                Ok(_) => {
                    rec_name.set(String::new());
                    rec_value.set(String::new());
                    rec_priority.set("10".to_string());
                    rec_ttl.set("3600".to_string());
                    show_form.set(false);
                    records_resource.restart();
                }
                Err(e) => add_error.set(Some(e.to_string())),
            }
            adding.set(false);
        });
    };

    rsx! {
        div { class: "border-t border-gray-200",
            // Add record toggle + form
            div { class: "px-6 py-4 bg-gray-50/50",
                div { class: "flex items-center justify-between mb-3",
                    h4 { class: "text-sm font-semibold text-gray-700 uppercase tracking-wide", "DNS Records" }
                    button {
                        class: "px-3 py-1.5 text-sm font-medium rounded-lg bg-rose-500 hover:bg-rose-600 text-white transition-colors",
                        onclick: move |_| show_form.set(!show_form()),
                        if show_form() { "Cancel" } else { "+ Add Record" }
                    }
                }

                if show_form() {
                    div { class: "bg-white rounded-xl p-4 border border-gray-200 mb-4",
                        if let Some(err) = add_error() {
                            div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-3 text-sm", "{err}" }
                        }
                        form { onsubmit: on_add_record,
                            div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4",
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Type" }
                                    select {
                                        class: "w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                                        value: "{rec_type}",
                                        onchange: move |e| rec_type.set(e.value()),
                                        option { value: "A", "A" }
                                        option { value: "AAAA", "AAAA" }
                                        option { value: "CNAME", "CNAME" }
                                        option { value: "MX", "MX" }
                                        option { value: "TXT", "TXT" }
                                        option { value: "SRV", "SRV" }
                                        option { value: "CAA", "CAA" }
                                        option { value: "NS", "NS" }
                                    }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Name" }
                                    input {
                                        r#type: "text",
                                        class: "w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                        placeholder: "@ or subdomain",
                                        value: "{rec_name}",
                                        oninput: move |e| rec_name.set(e.value()),
                                        required: true,
                                    }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Value" }
                                    {
                                        let ph = match rec_type().as_str() { "A" => "192.168.1.1", "AAAA" => "2001:db8::1", "CNAME" => "target.example.com", "MX" => "mail.example.com", "TXT" => "v=spf1 ...", _ => "value" };
                                        rsx! {
                                            input {
                                                r#type: "text",
                                                class: "w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                                placeholder: "{ph}",
                                                value: "{rec_value}",
                                                oninput: move |e| rec_value.set(e.value()),
                                                required: true,
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-4",
                                if rec_type() == "MX" || rec_type() == "SRV" {
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Priority" }
                                        input {
                                            r#type: "number",
                                            class: "w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            value: "{rec_priority}",
                                            oninput: move |e| rec_priority.set(e.value()),
                                            min: "0",
                                            max: "65535",
                                        }
                                    }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "TTL (seconds)" }
                                    select {
                                        class: "w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                                        value: "{rec_ttl}",
                                        onchange: move |e| rec_ttl.set(e.value()),
                                        option { value: "1", "Auto" }
                                        option { value: "300", "5 min" }
                                        option { value: "1800", "30 min" }
                                        option { value: "3600", selected: true, "1 hour" }
                                        option { value: "43200", "12 hours" }
                                        option { value: "86400", "1 day" }
                                    }
                                }
                            }
                            button {
                                r#type: "submit",
                                class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50",
                                disabled: adding(),
                                if adding() { "Adding..." } else { "Add Record" }
                            }
                        }
                    }
                }
            }

            // Records table
            div { class: "px-6 pb-4",
                match &*records_resource.read() {
                    Some(Some(list)) => rsx! {
                        if list.is_empty() {
                            p { class: "py-4 text-gray-500 text-center text-sm", "No records yet. Add one above." }
                        } else {
                            div { class: "overflow-x-auto",
                                table { class: "w-full",
                                    thead {
                                        tr { class: "border-b border-gray-200",
                                            th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "Type" }
                                            th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "Name" }
                                            th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "Value" }
                                            th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "Priority" }
                                            th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "TTL" }
                                            th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                        }
                                    }
                                    tbody { class: "divide-y divide-gray-100",
                                        for record in list.iter() {
                                            DnsRecordRow {
                                                record: record.clone(),
                                                zone_id: zone_id,
                                                records_resource: records_resource,
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(None) => rsx! {
                        p { class: "py-4 text-gray-500 text-center text-sm", "Loading records..." }
                    },
                    None => rsx! {
                        p { class: "py-4 text-gray-500 text-center text-sm", "Loading records..." }
                    },
                }
            }
        }
    }
}

#[component]
fn DnsRecordRow(
    record: panel::models::dns::DnsRecord,
    zone_id: i64,
    records_resource: Resource<Option<Vec<panel::models::dns::DnsRecord>>>,
) -> Element {
    let record_id = record.id;
    let mut records_resource = records_resource;
    let mut deleting = use_signal(|| false);

    let on_delete = move |_| {
        deleting.set(true);
        spawn(async move {
            match server_delete_dns_record(zone_id, record_id).await {
                Ok(()) => records_resource.restart(),
                Err(_) => deleting.set(false),
            }
        });
    };

    let ttl_display = match record.ttl {
        1 => "Auto".to_string(),
        t if t < 60 => format!("{t}s"),
        t if t < 3600 => format!("{}m", t / 60),
        t if t < 86400 => format!("{}h", t / 3600),
        t => format!("{}d", t / 86400),
    };

    let type_color = match record.r#type {
        panel::models::dns::RecordType::A => "bg-blue-100 text-blue-700",
        panel::models::dns::RecordType::Aaaa => "bg-indigo-100 text-indigo-700",
        panel::models::dns::RecordType::Cname => "bg-purple-100 text-purple-700",
        panel::models::dns::RecordType::Mx => "bg-amber-100 text-amber-700",
        panel::models::dns::RecordType::Txt => "bg-green-100 text-green-700",
        panel::models::dns::RecordType::Srv => "bg-pink-100 text-pink-700",
        panel::models::dns::RecordType::Caa => "bg-teal-100 text-teal-700",
        panel::models::dns::RecordType::Ns => "bg-gray-100 text-gray-700",
    };

    rsx! {
        tr { class: "hover:bg-gray-50/50 transition-colors",
            td { class: "px-4 py-2.5",
                span { class: "text-xs font-mono font-semibold px-2 py-0.5 rounded {type_color}", "{record.r#type}" }
            }
            td { class: "px-4 py-2.5 text-sm text-gray-900 font-medium", "{record.name}" }
            td { class: "px-4 py-2.5 text-sm text-gray-600 font-mono max-w-xs truncate", "{record.value}" }
            td { class: "px-4 py-2.5 text-sm text-gray-500",
                match record.r#type {
                    panel::models::dns::RecordType::Mx | panel::models::dns::RecordType::Srv => rsx! { "{record.priority}" },
                    _ => rsx! { span { class: "text-gray-300", "—" } },
                }
            }
            td { class: "px-4 py-2.5 text-sm text-gray-500", "{ttl_display}" }
            td { class: "px-4 py-2.5",
                button {
                    class: "text-red-600 hover:text-red-800 text-sm font-medium disabled:opacity-50",
                    disabled: deleting(),
                    onclick: on_delete,
                    if deleting() { "..." } else { "Delete" }
                }
            }
        }
    }
}

#[component]
fn ClientEmail() -> Element {
    let domains = use_resource(move || async move { server_list_email_domains().await });
    // Which domain_id is expanded to show its mailboxes.
    let mut expanded = use_signal(|| None::<i64>);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Email" }
            }
            match &*domains.read() {
                Some(Ok(list)) if !list.is_empty() => rsx! {
                    div { class: "space-y-4",
                        for domain in list.iter() {
                            {
                                let dom_id = domain.id;
                                let is_open = expanded() == Some(dom_id);
                                let chevron = if is_open { "chevron-up" } else { "chevron-down" };
                                let domain_name = domain.domain.clone();
                                let domain_status = domain.status.clone();
                                let no_limits = domain.send_limit_per_hour == 0 && domain.send_limit_per_day == 0;
                                rsx! {
                                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                                        // Domain header row
                                        div { class: "flex items-center justify-between px-6 py-4 cursor-pointer hover:bg-gray-50/60 transition-colors",
                                            onclick: move |_| {
                                                if expanded() == Some(dom_id) {
                                                    expanded.set(None);
                                                } else {
                                                    expanded.set(Some(dom_id));
                                                }
                                            },
                                            div { class: "flex items-center gap-3",
                                                div { class: "p-2 bg-rose-50 rounded-lg",
                                                    Icon { name: "mail", class: "w-4 h-4 text-rose-500".to_string() }
                                                }
                                                div {
                                                    p { class: "font-semibold text-gray-900 text-sm", "{domain_name}" }
                                                    p { class: "text-xs text-gray-400 mt-0.5",
                                                        if no_limits { "No send limits" } else { "Send limits active" }
                                                    }
                                                }
                                            }
                                            div { class: "flex items-center gap-3",
                                                StatusBadge { status: domain_status }
                                                Icon { name: chevron, class: "w-4 h-4 text-gray-400".to_string() }
                                            }
                                        }
                                        // Expanded mailbox list
                                        if is_open {
                                            MailboxList { domain_id: dom_id, domain_name: domain_name }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                Some(Ok(_)) => rsx! {
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-12 text-center",
                        div { class: "mx-auto w-16 h-16 rounded-2xl bg-rose-50 flex items-center justify-center mb-5",
                            Icon { name: "mail", class: "w-8 h-8 text-rose-500".to_string() }
                        }
                        h3 { class: "text-lg font-semibold text-gray-800 mb-2", "No Email Domains" }
                        p { class: "text-gray-500", "Contact your administrator to set up email hosting for your account." }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
            }
        }
    }
}

/// Expandable mailbox list (used inside ClientEmail).
/// Shows each mailbox with per-mailbox stats and a backup download button.
#[component]
fn MailboxList(domain_id: i64, domain_name: String) -> Element {
    let mailboxes = use_resource(move || async move { server_list_mailboxes(domain_id).await });
    // Which mailbox_id has its stats expanded.
    let mut stats_open = use_signal(|| None::<i64>);
    // Map mailbox_id → MailboxStats (loaded on demand).
    let mut stats_cache: Signal<
        std::collections::HashMap<i64, panel::models::email::MailboxStats>,
    > = use_signal(std::collections::HashMap::new);
    // Map mailbox_id → loading state for stats.
    let mut stats_loading = use_signal(|| None::<i64>);
    // Backup state per mailbox.
    let mut backup_loading = use_signal(|| None::<i64>);
    let mut backup_links: Signal<
        std::collections::HashMap<i64, panel::models::email::MailboxBackupToken>,
    > = use_signal(std::collections::HashMap::new);
    let mut backup_error = use_signal(|| None::<String>);

    rsx! {
        div { class: "border-t border-gray-100",
            match &*mailboxes.read() {
                Some(Ok(mboxes)) if !mboxes.is_empty() => rsx! {
                    div { class: "divide-y divide-gray-50",
                        for mb in mboxes.iter() {
                            {
                                let mb = mb.clone();
                                let mb_id = mb.id;
                                let address = format!("{}@{}", mb.local_part, domain_name);
                                let has_stats = stats_open() == Some(mb_id);
                                let is_stats_loading = stats_loading() == Some(mb_id);
                                let is_backup_loading = backup_loading() == Some(mb_id);
                                rsx! {
                                    div { class: "px-6 py-4",
                                        // Mailbox row header
                                        div { class: "flex items-center justify-between",
                                            div { class: "flex items-center gap-3 min-w-0",
                                                div { class: "p-1.5 bg-gray-100 rounded-lg shrink-0",
                                                    Icon { name: "inbox", class: "w-3.5 h-3.5 text-gray-500".to_string() }
                                                }
                                                div { class: "min-w-0",
                                                    p { class: "text-sm font-medium text-gray-800 truncate", "{address}" }
                                                    p { class: "text-xs text-gray-400",
                                                        "Quota: {mb.quota_mb} MB"
                                                    }
                                                }
                                            }
                                            div { class: "flex items-center gap-2 shrink-0 ml-4",
                                                StatusBadge { status: mb.status.clone() }
                                                // Stats button
                                                button {
                                                    class: "flex items-center gap-1.5 px-3 py-1.5 bg-blue-50 hover:bg-blue-100 text-blue-700 text-xs font-medium rounded-lg transition-colors disabled:opacity-50",
                                                    disabled: is_stats_loading,
                                                    onclick: move |_| {
                                                        if has_stats {
                                                            stats_open.set(None);
                                                            return;
                                                        }
                                                        // If already cached, just toggle open
                                                        if stats_cache.read().contains_key(&mb_id) {
                                                            stats_open.set(Some(mb_id));
                                                            return;
                                                        }
                                                        stats_loading.set(Some(mb_id));
                                                        let did = domain_id;
                                                        spawn(async move {
                                                            match server_get_mailbox_stats(did, mb_id).await {
                                                                Ok(s) => {
                                                                    stats_cache.write().insert(mb_id, s);
                                                                    stats_open.set(Some(mb_id));
                                                                }
                                                                Err(_) => {}
                                                            }
                                                            stats_loading.set(None);
                                                        });
                                                    },
                                                    Icon { name: "bar-chart-2", class: "w-3 h-3".to_string() }
                                                    if is_stats_loading {
                                                        "Loading…"
                                                    } else if has_stats {
                                                        "Hide Stats"
                                                    } else {
                                                        "Stats"
                                                    }
                                                }
                                                // Backup button
                                                button {
                                                    class: "flex items-center gap-1.5 px-3 py-1.5 bg-emerald-50 hover:bg-emerald-100 text-emerald-700 text-xs font-medium rounded-lg transition-colors disabled:opacity-50",
                                                    disabled: is_backup_loading,
                                                    onclick: move |_| {
                                                        backup_error.set(None);
                                                        backup_loading.set(Some(mb_id));
                                                        let did = domain_id;
                                                        spawn(async move {
                                                            match server_create_mailbox_backup(did, mb_id).await {
                                                                Ok(token) => {
                                                                    backup_links.write().insert(mb_id, token);
                                                                }
                                                                Err(e) => {
                                                                    backup_error.set(Some(e.to_string()));
                                                                }
                                                            }
                                                            backup_loading.set(None);
                                                        });
                                                    },
                                                    Icon { name: "download", class: "w-3 h-3".to_string() }
                                                    if is_backup_loading { "Creating…" } else { "Backup" }
                                                }
                                            }
                                        }

                                        // Stats panel (shown when toggled)
                                        if has_stats {
                                            if let Some(st) = stats_cache.read().get(&mb_id) {
                                                div { class: "mt-3 p-4 bg-blue-50/60 rounded-xl border border-blue-100",
                                                    p { class: "text-xs font-semibold text-blue-800 mb-3 uppercase tracking-wide", "Mailbox Statistics" }
                                                    div { class: "grid grid-cols-2 sm:grid-cols-4 gap-3",
                                                        div { class: "bg-white rounded-lg p-3 text-center shadow-sm",
                                                            p { class: "text-lg font-bold text-gray-800", "{st.messages_total}" }
                                                            p { class: "text-xs text-gray-500 mt-0.5", "Total Messages" }
                                                        }
                                                        div { class: "bg-white rounded-lg p-3 text-center shadow-sm",
                                                            p { class: "text-lg font-bold text-rose-600", "{st.messages_new}" }
                                                            p { class: "text-xs text-gray-500 mt-0.5", "Unread" }
                                                        }
                                                        div { class: "bg-white rounded-lg p-3 text-center shadow-sm",
                                                            p { class: "text-lg font-bold text-gray-800",
                                                                {
                                                                    let kb = st.disk_usage_kb;
                                                                    if kb >= 1024 * 1024 {
                                                                        format!("{:.1} GB", kb as f64 / 1024.0 / 1024.0)
                                                                    } else if kb >= 1024 {
                                                                        format!("{:.1} MB", kb as f64 / 1024.0)
                                                                    } else {
                                                                        format!("{kb} KB")
                                                                    }
                                                                }
                                                            }
                                                            p { class: "text-xs text-gray-500 mt-0.5", "Disk Usage" }
                                                        }
                                                        div { class: "bg-white rounded-lg p-3 text-center shadow-sm",
                                                            p { class: "text-lg font-bold text-gray-800",
                                                                "{st.quota_used_pct:.1}%"
                                                            }
                                                            p { class: "text-xs text-gray-500 mt-0.5", "Quota Used" }
                                                        }
                                                    }
                                                    // Quota progress bar
                                                    div { class: "mt-3",
                                                        div { class: "flex justify-between text-xs text-blue-700 mb-1",
                                                            span { "Quota usage" }
                                                            span {
                                                                {
                                                                    let used_mb = st.disk_usage_kb as f64 / 1024.0;
                                                                    format!("{used_mb:.1} MB / {} MB", st.quota_mb)
                                                                }
                                                            }
                                                        }
                                                        div { class: "w-full bg-blue-100 rounded-full h-2",
                                                            div {
                                                                class: "h-2 rounded-full transition-all",
                                                                class: if st.quota_used_pct > 90.0 { "bg-red-500" } else if st.quota_used_pct > 70.0 { "bg-yellow-500" } else { "bg-blue-500" },
                                                                style: format!("width: {:.1}%", st.quota_used_pct.min(100.0)),
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Backup download link (shown after backup is created)
                                        if let Some(bk) = backup_links.read().get(&mb_id) {
                                            div { class: "mt-3 p-3 bg-emerald-50 border border-emerald-100 rounded-xl flex items-center justify-between gap-3",
                                                div { class: "min-w-0",
                                                    p { class: "text-xs font-medium text-emerald-800", "Backup ready" }
                                                    p { class: "text-xs text-emerald-600 truncate", "{bk.filename}" }
                                                    p { class: "text-xs text-emerald-500",
                                                        {
                                                            let sz = bk.size_bytes;
                                                            if sz >= 1024 * 1024 {
                                                                format!("{:.1} MB", sz as f64 / 1024.0 / 1024.0)
                                                            } else {
                                                                format!("{:.0} KB", sz as f64 / 1024.0)
                                                            }
                                                        }
                                                        " · Link expires in 5 minutes"
                                                    }
                                                }
                                                a {
                                                    href: "{bk.download_url}",
                                                    class: "shrink-0 flex items-center gap-1.5 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white text-xs font-medium rounded-lg transition-colors",
                                                    Icon { name: "download", class: "w-3.5 h-3.5".to_string() }
                                                    "Download"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Backup error
                    if let Some(err) = backup_error() {
                        div { class: "px-6 pb-4",
                            div { class: "bg-red-50 text-red-700 p-3 rounded-lg text-xs", "{err}" }
                        }
                    }
                },
                Some(Ok(_)) => rsx! {
                    div { class: "px-6 py-4 text-sm text-gray-400 text-center",
                        "No mailboxes configured for this domain."
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "px-6 py-4 text-sm text-red-600", "Error loading mailboxes: {e}" }
                },
                None => rsx! {
                    div { class: "px-6 py-4 text-sm text-gray-400", "Loading mailboxes…" }
                },
            }
        }
    }
}

#[component]
fn ClientFileManager() -> Element {
    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "File Manager" }
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-12 text-center",
                div { class: "mx-auto w-16 h-16 rounded-2xl bg-rose-50 flex items-center justify-center mb-5",
                    Icon { name: "folder", class: "w-8 h-8 text-rose-500".to_string() }
                }
                h3 { class: "text-lg font-semibold text-gray-800 mb-2", "Web-Based File Manager" }
                p { class: "text-gray-500 mb-6 max-w-md mx-auto", "Manage your website files directly from the browser." }
                p { class: "text-sm text-gray-400", "Alternatively, use SFTP or SSH for file access." }
            }
        }
    }
}

// ─── Helper: format bytes ────────────────────────────────────────────────────
fn fmt_bytes_backup(bytes: i64) -> String {
    if bytes < 1_024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}

// ─── ClientBackups ────────────────────────────────────────────────────────────
#[component]
fn ClientBackups() -> Element {
    // ── Data sources
    let mut schedules_res =
        use_resource(move || async move { server_list_backup_schedules().await });
    let mut stats_res = use_resource(move || async move { server_get_backup_stats().await });
    let sites_res = use_resource(move || async move { server_list_sites().await });
    // Mailboxes fetched as email domains with accounts
    let email_res =
        use_resource(move || async move { server_list_email_domains_with_accounts().await });

    // ── View state
    let mut active_tab = use_signal(|| "schedules"); // "schedules" | "runs" | "create"
    let mut form_error = use_signal(|| None::<String>);
    let mut form_success = use_signal(|| None::<String>);
    let mut submitting = use_signal(|| false);
    let mut triggering = use_signal(|| None::<i64>); // schedule id being triggered
    let mut deleting = use_signal(|| None::<i64>);

    // ── Selected run history
    let mut selected_schedule_id = use_signal(|| None::<i64>);
    let runs_res = use_resource(move || {
        let sid = selected_schedule_id();
        async move {
            match sid {
                Some(id) => server_list_backup_runs(id).await.ok(),
                None => None,
            }
        }
    });
    let mut recent_runs_res =
        use_resource(move || async move { server_list_recent_backup_runs().await });

    // ── Create-form state
    let mut form_target = use_signal(|| "site"); // "site" | "mail"
    let mut form_site_id = use_signal(|| 0i64);
    let mut form_mailbox_id = use_signal(|| 0i64);
    let mut form_name = use_signal(String::new);
    let mut form_schedule = use_signal(|| "@daily".to_string());
    let mut form_storage = use_signal(|| "local".to_string());
    let mut form_destination = use_signal(|| "/var/backups/panel".to_string());
    let mut form_retention = use_signal(|| 7i32);
    let mut form_compress = use_signal(|| true);

    rsx! {
        div { class: "p-6 lg:p-8",
            // ── Page header
            div { class: "flex items-center justify-between mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Backups" }
                    p { class: "text-gray-500 text-sm mt-1",
                        "Per-domain and per-mailbox scheduled backups with history and stats."
                    }
                }
                button {
                    class: "px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2",
                    onclick: move |_| { active_tab.set("create"); form_error.set(None); form_success.set(None); },
                    Icon { name: "plus", class: "w-4 h-4".to_string() }
                    "New Schedule"
                }
            }

            // ── Stats cards
            match &*stats_res.read() {
                Some(Ok(st)) => rsx! {
                    div { class: "grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6",
                        BackupStatCard { label: "Schedules", value: st.total_schedules.to_string(), color: "blue" }
                        BackupStatCard { label: "Active", value: st.enabled_schedules.to_string(), color: "green" }
                        BackupStatCard { label: "Total Runs", value: st.total_runs.to_string(), color: "gray" }
                        BackupStatCard { label: "Successful", value: st.successful_runs.to_string(), color: "green" }
                        BackupStatCard { label: "Failed", value: st.failed_runs.to_string(), color: "red" }
                        BackupStatCard { label: "Total Size", value: fmt_bytes_backup(st.total_size_bytes), color: "purple" }
                    }
                },
                _ => rsx! { div { class: "mb-6" } },
            }

            // ── Tab bar
            div { class: "flex gap-1 bg-gray-100 rounded-xl p-1 w-fit mb-6",
                for (label, id) in [("Schedules", "schedules"), ("Recent Runs", "runs"), ("New Schedule", "create")] {
                    button {
                        class: if active_tab() == id {
                            "px-4 py-2 rounded-lg text-sm font-medium bg-white text-gray-900 shadow-sm"
                        } else {
                            "px-4 py-2 rounded-lg text-sm font-medium text-gray-500 hover:text-gray-700"
                        },
                        onclick: move |_| { active_tab.set(id); },
                        "{label}"
                    }
                }
            }

            // ─────────────────────────────────────────────────────────────
            // SCHEDULES TAB
            // ─────────────────────────────────────────────────────────────
            if active_tab() == "schedules" {
                match &*schedules_res.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-12 text-center",
                            div { class: "mx-auto w-16 h-16 rounded-2xl bg-amber-50 flex items-center justify-center mb-5",
                                Icon { name: "archive", class: "w-8 h-8 text-amber-500".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-800 mb-2", "No backup schedules yet" }
                            p { class: "text-gray-500 mb-6 max-w-sm mx-auto",
                                "Create a schedule to automatically back up a website or mailbox."
                            }
                            button {
                                class: "px-6 py-2.5 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg text-sm transition-colors",
                                onclick: move |_| active_tab.set("create"),
                                "Create First Schedule"
                            }
                        }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Name" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Target" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Schedule" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Destination" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Last Run" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Status" }
                                        th { class: "px-4 py-3 text-right text-xs font-semibold text-gray-500 uppercase", "Actions" }
                                    }
                                }
                                tbody {
                                    for item in list.iter() {
                                        BackupScheduleRow {
                                            item: item.clone(),
                                            is_triggering: triggering() == Some(item.schedule.id),
                                            is_deleting: deleting() == Some(item.schedule.id),
                                            on_trigger: {
                                                let sid = item.schedule.id;
                                                move |_| {
                                                    triggering.set(Some(sid));
                                                    spawn(async move {
                                                        let _ = server_trigger_backup(sid).await;
                                                        triggering.set(None);
                                                        schedules_res.restart();
                                                        stats_res.restart();
                                                        recent_runs_res.restart();
                                                    });
                                                }
                                            },
                                            on_toggle: {
                                                let sid = item.schedule.id;
                                                let cur = item.schedule.enabled;
                                                move |_| {
                                                    spawn(async move {
                                                        let _ = server_toggle_backup_schedule(sid, !cur).await;
                                                        schedules_res.restart();
                                                        stats_res.restart();
                                                    });
                                                }
                                            },
                                            on_view_runs: {
                                                let sid = item.schedule.id;
                                                move |_| {
                                                    selected_schedule_id.set(Some(sid));
                                                    active_tab.set("runs");
                                                }
                                            },
                                            on_delete: {
                                                let sid = item.schedule.id;
                                                move |_| {
                                                    deleting.set(Some(sid));
                                                    spawn(async move {
                                                        let _ = server_delete_backup_schedule(sid).await;
                                                        deleting.set(None);
                                                        schedules_res.restart();
                                                        stats_res.restart();
                                                    });
                                                }
                                            },
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "bg-red-50 rounded-2xl border border-red-200 p-6 text-red-700 text-sm", "Error loading schedules: {e}" }
                    },
                    None => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center text-gray-400 animate-pulse text-sm",
                            "Loading schedules…"
                        }
                    },
                }
            }

            // ─────────────────────────────────────────────────────────────
            // RECENT RUNS TAB
            // ─────────────────────────────────────────────────────────────
            if active_tab() == "runs" {
                div { class: "mb-4 flex items-center justify-between",
                    h3 { class: "text-base font-semibold text-gray-800",
                        if selected_schedule_id().is_some() {
                            "Run History for Selected Schedule"
                        } else {
                            "Recent Runs (All Schedules)"
                        }
                    }
                    if selected_schedule_id().is_some() {
                        button {
                            class: "text-xs text-rose-500 hover:text-rose-700 underline",
                            onclick: move |_| selected_schedule_id.set(None),
                            "Show all"
                        }
                    }
                }

                {
                    let render_runs = |runs: &Vec<panel::models::backup::BackupRun>| {
                        rsx! {
                            if runs.is_empty() {
                                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center text-gray-400 text-sm",
                                    "No backup runs recorded yet."
                                }
                            } else {
                                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                                    table { class: "w-full text-sm",
                                        thead { class: "bg-gray-50 border-b border-gray-200",
                                            tr {
                                                th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Started" }
                                                th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Finished" }
                                                th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Status" }
                                                th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Size" }
                                                th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Archive" }
                                            }
                                        }
                                        tbody {
                                            for run in runs.iter() {
                                                BackupRunRow { run: run.clone() }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    };

                    if selected_schedule_id().is_some() {
                        match &*runs_res.read() {
                            Some(Some(runs)) => render_runs(runs),
                            Some(None) => rsx! {
                                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center text-gray-400 text-sm",
                                    "No runs found for this schedule."
                                }
                            },
                            None => rsx! {
                                div { class: "bg-white p-8 text-center text-gray-400 animate-pulse text-sm rounded-2xl border border-gray-100",
                                    "Loading…"
                                }
                            },
                        }
                    } else {
                        match &*recent_runs_res.read() {
                            Some(Ok(runs)) => render_runs(runs),
                            Some(Err(e)) => rsx! {
                                div { class: "bg-red-50 rounded-2xl border border-red-200 p-6 text-red-700 text-sm", "Error: {e}" }
                            },
                            None => rsx! {
                                div { class: "bg-white p-8 text-center text-gray-400 animate-pulse text-sm rounded-2xl border border-gray-100",
                                    "Loading…"
                                }
                            },
                        }
                    }
                }
            }

            // ─────────────────────────────────────────────────────────────
            // CREATE SCHEDULE TAB
            // ─────────────────────────────────────────────────────────────
            if active_tab() == "create" {
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 max-w-2xl",
                    h3 { class: "text-base font-semibold text-gray-800 mb-5", "New Backup Schedule" }

                    if let Some(ref err) = form_error() {
                        div { class: "mb-4 p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm", "{err}" }
                    }
                    if let Some(ref ok) = form_success() {
                        div { class: "mb-4 p-3 bg-green-50 border border-green-200 text-green-700 rounded-lg text-sm", "{ok}" }
                    }

                    form {
                        onsubmit: move |ev: FormEvent| {
                            ev.prevent_default();
                            form_error.set(None);
                            form_success.set(None);
                            submitting.set(true);

                            let target = form_target();
                            let (site_id, mailbox_id) = if target == "site" {
                                let sid = form_site_id();
                                if sid == 0 {
                                    form_error.set(Some("Please select a website.".to_string()));
                                    submitting.set(false);
                                    return;
                                }
                                (Some(sid), None)
                            } else {
                                let mid = form_mailbox_id();
                                if mid == 0 {
                                    form_error.set(Some("Please select a mailbox.".to_string()));
                                    submitting.set(false);
                                    return;
                                }
                                (None, Some(mid))
                            };

                            let req = panel::models::backup::CreateBackupScheduleRequest {
                                site_id,
                                mailbox_id,
                                name: form_name(),
                                schedule: form_schedule(),
                                storage_type: form_storage(),
                                destination: form_destination(),
                                retention_count: form_retention(),
                                compress: form_compress(),
                            };

                            spawn(async move {
                                match server_create_backup_schedule(req).await {
                                    Ok(_) => {
                                        form_success.set(Some("Backup schedule created successfully!".to_string()));
                                        form_name.set(String::new());
                                        form_site_id.set(0);
                                        form_mailbox_id.set(0);
                                        schedules_res.restart();
                                        stats_res.restart();
                                    }
                                    Err(e) => form_error.set(Some(e.to_string())),
                                }
                                submitting.set(false);
                            });
                        },

                        // Target type
                        div { class: "mb-4",
                            label { class: "block text-xs font-semibold text-gray-600 mb-2 uppercase tracking-wide", "Backup Target" }
                            div { class: "flex gap-3",
                                for (val, lbl) in [("site", "Website / Domain"), ("mail", "Mailbox")] {
                                    label { class: "flex items-center gap-2 cursor-pointer",
                                        input {
                                            r#type: "radio",
                                            name: "target_type",
                                            value: "{val}",
                                            checked: form_target() == val,
                                            onchange: move |_| form_target.set(val),
                                        }
                                        span { class: "text-sm text-gray-700", "{lbl}" }
                                    }
                                }
                            }
                        }

                        // Site / mailbox selector
                        div { class: "mb-4",
                            if form_target() == "site" {
                                label { class: "block text-xs font-medium text-gray-600 mb-1", "Website" }
                                match &*sites_res.read() {
                                    Some(Ok(sites)) if !sites.is_empty() => rsx! {
                                        select {
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm bg-white",
                                            value: "{form_site_id}",
                                            onchange: move |e| form_site_id.set(e.value().parse().unwrap_or(0)),
                                            option { value: "0", disabled: true, "-- Select website --" }
                                            for s in sites.iter() {
                                                option { value: "{s.id}", "{s.domain}" }
                                            }
                                        }
                                    },
                                    Some(Ok(_)) => rsx! { p { class: "text-sm text-gray-500", "No websites found." } },
                                    _ => rsx! { p { class: "text-sm text-gray-400 animate-pulse", "Loading…" } },
                                }
                            } else {
                                label { class: "block text-xs font-medium text-gray-600 mb-1", "Mailbox" }
                                match &*email_res.read() {
                                    Some(Ok(domains)) if !domains.is_empty() => rsx! {
                                        select {
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm bg-white",
                                            onchange: move |e| form_mailbox_id.set(e.value().parse().unwrap_or(0)),
                                            option { value: "0", disabled: true, "-- Select mailbox --" }
                                            for d in domains.iter() {
                                                for mb in d.mailboxes.iter() {
                                                    option { value: "{mb.id}", "{mb.local_part}@{d.domain.domain}" }
                                                }
                                            }
                                        }
                                    },
                                    Some(Ok(_)) => rsx! { p { class: "text-sm text-gray-500", "No mailboxes found." } },
                                    _ => rsx! { p { class: "text-sm text-gray-400 animate-pulse", "Loading…" } },
                                }
                            }
                        }

                        // Name + schedule
                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-4",
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1", "Schedule Name" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm",
                                    placeholder: "e.g. Daily site backup",
                                    value: "{form_name}",
                                    oninput: move |e| form_name.set(e.value()),
                                    required: true,
                                }
                            }
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1",
                                    "Schedule"
                                    span { class: "text-gray-400 font-normal ml-1", "(cron or @alias)" }
                                }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm font-mono",
                                    placeholder: "@daily",
                                    value: "{form_schedule}",
                                    oninput: move |e| form_schedule.set(e.value()),
                                    required: true,
                                }
                                p { class: "text-xs text-gray-400 mt-1",
                                    code { class: "bg-gray-100 px-1 rounded", "@daily" }
                                    "  "
                                    code { class: "bg-gray-100 px-1 rounded", "@weekly" }
                                    "  "
                                    code { class: "bg-gray-100 px-1 rounded", "0 2 * * *" }
                                }
                            }
                        }

                        // Destination + storage
                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-4",
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1", "Destination Path" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm font-mono",
                                    placeholder: "/var/backups/panel",
                                    value: "{form_destination}",
                                    oninput: move |e| form_destination.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1", "Storage Type" }
                                select {
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm bg-white",
                                    value: "{form_storage}",
                                    onchange: move |e| form_storage.set(e.value()),
                                    option { value: "local", "Local Disk" }
                                    option { value: "s3", "S3 / Compatible" }
                                    option { value: "sftp", "SFTP" }
                                }
                            }
                        }

                        // Retention + compress
                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-6",
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1",
                                    "Retention (snapshots to keep)"
                                    span { class: "text-gray-400 font-normal ml-1", "(0 = unlimited)" }
                                }
                                input {
                                    r#type: "number",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm",
                                    min: "0", max: "365",
                                    value: "{form_retention}",
                                    oninput: move |e| form_retention.set(e.value().parse().unwrap_or(7)),
                                }
                            }
                            div { class: "flex items-center gap-3 mt-5",
                                input {
                                    r#type: "checkbox",
                                    id: "compress_flag",
                                    class: "rounded border-gray-300 text-rose-500 focus:ring-rose-500",
                                    checked: form_compress(),
                                    onchange: move |e| form_compress.set(e.checked()),
                                }
                                label { r#for: "compress_flag",
                                    class: "text-sm text-gray-700 cursor-pointer",
                                    "Compress with gzip (.tar.gz)"
                                }
                            }
                        }

                        div { class: "flex gap-3",
                            button {
                                r#type: "submit",
                                class: if submitting() {
                                    "px-6 py-2.5 bg-rose-300 text-white rounded-lg text-sm font-medium cursor-not-allowed"
                                } else {
                                    "px-6 py-2.5 bg-rose-500 hover:bg-rose-600 text-white rounded-lg text-sm font-medium transition-colors"
                                },
                                disabled: submitting(),
                                if submitting() { "Creating…" } else { "Create Schedule" }
                            }
                            button {
                                r#type: "button",
                                class: "px-6 py-2.5 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm font-medium transition-colors",
                                onclick: move |_| { active_tab.set("schedules"); form_error.set(None); form_success.set(None); },
                                "Cancel"
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── BackupStatCard ────────────────────────────────────────────────────────────
#[component]
fn BackupStatCard(label: &'static str, value: String, color: &'static str) -> Element {
    let (_bg, text) = match color {
        "blue" => ("bg-blue-50", "text-blue-600"),
        "green" => ("bg-green-50", "text-green-600"),
        "red" => ("bg-red-50", "text-red-600"),
        "purple" => ("bg-purple-50", "text-purple-600"),
        _ => ("bg-gray-50", "text-gray-600"),
    };
    rsx! {
        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-4",
            p { class: "text-xs text-gray-500 font-medium uppercase tracking-wide mb-1", "{label}" }
            p { class: "text-xl font-bold {text}", "{value}" }
        }
    }
}

// ── BackupScheduleRow ─────────────────────────────────────────────────────────
#[component]
fn BackupScheduleRow(
    item: panel::models::backup::BackupScheduleWithLatest,
    is_triggering: bool,
    is_deleting: bool,
    on_trigger: EventHandler<MouseEvent>,
    on_toggle: EventHandler<MouseEvent>,
    on_view_runs: EventHandler<MouseEvent>,
    on_delete: EventHandler<MouseEvent>,
) -> Element {
    let sched = &item.schedule;
    let target_label = if let Some(ref domain) = item.site_domain {
        domain.clone()
    } else if sched.site_id.is_some() {
        format!("Site #{}", sched.site_id.unwrap())
    } else {
        format!("Mailbox #{}", sched.mailbox_id.unwrap_or(0))
    };
    let (status_bg, status_text) = if sched.enabled {
        ("bg-green-100 text-green-700", "Active")
    } else {
        ("bg-gray-100 text-gray-500", "Disabled")
    };
    let last_run_str = match &item.latest_run {
        Some(r) => match r.status.as_str() {
            "success" => format!("✓ {}", r.started_at.format("%b %d %H:%M")),
            "failed" => format!("✗ {}", r.started_at.format("%b %d %H:%M")),
            _ => format!("… {}", r.started_at.format("%b %d %H:%M")),
        },
        None => "Never".to_string(),
    };
    let last_run_color = match item.latest_run.as_ref().map(|r| r.status.as_str()) {
        Some("success") => "text-green-600",
        Some("failed") => "text-red-600",
        _ => "text-gray-400",
    };

    rsx! {
        tr { class: "border-b border-gray-100 hover:bg-gray-50/40 transition-colors",
            td { class: "px-4 py-3 font-medium text-gray-900", "{sched.name}" }
            td { class: "px-4 py-3 text-gray-500 text-xs font-mono", "{target_label}" }
            td { class: "px-4 py-3 text-gray-500 text-xs font-mono", "{sched.schedule}" }
            td { class: "px-4 py-3 text-gray-400 text-xs max-w-[140px] truncate", "{sched.destination}" }
            td { class: "px-4 py-3 text-xs {last_run_color}", "{last_run_str}" }
            td { class: "px-4 py-3",
                span { class: "px-2 py-0.5 rounded-full text-xs font-semibold {status_bg} {status_text}",
                    "{status_text}"
                }
            }
            td { class: "px-4 py-3",
                div { class: "flex items-center justify-end gap-1",
                    button {
                        class: "p-1.5 rounded-lg text-gray-400 hover:text-blue-600 hover:bg-blue-50 transition-colors text-xs font-medium",
                        title: "Run Now",
                        disabled: is_triggering,
                        onclick: move |e| on_trigger.call(e),
                        if is_triggering {
                            "…"
                        } else {
                            Icon { name: "play", class: "w-3.5 h-3.5".to_string() }
                        }
                    }
                    button {
                        class: "p-1.5 rounded-lg text-gray-400 hover:text-amber-600 hover:bg-amber-50 transition-colors",
                        title: if sched.enabled { "Disable" } else { "Enable" },
                        onclick: move |e| on_toggle.call(e),
                        if sched.enabled {
                            Icon { name: "pause", class: "w-3.5 h-3.5".to_string() }
                        } else {
                            Icon { name: "play-circle", class: "w-3.5 h-3.5".to_string() }
                        }
                    }
                    button {
                        class: "p-1.5 rounded-lg text-gray-400 hover:text-purple-600 hover:bg-purple-50 transition-colors",
                        title: "View Run History",
                        onclick: move |e| on_view_runs.call(e),
                        Icon { name: "list", class: "w-3.5 h-3.5".to_string() }
                    }
                    button {
                        class: "p-1.5 rounded-lg text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors",
                        title: "Delete Schedule",
                        disabled: is_deleting,
                        onclick: move |e| on_delete.call(e),
                        if is_deleting {
                            "…"
                        } else {
                            Icon { name: "trash-2", class: "w-3.5 h-3.5".to_string() }
                        }
                    }
                }
            }
        }
    }
}

// ── BackupRunRow ──────────────────────────────────────────────────────────────
#[component]
fn BackupRunRow(run: panel::models::backup::BackupRun) -> Element {
    let (status_cls, status_label) = match run.status.as_str() {
        "success" => ("bg-green-100 text-green-700", "Success"),
        "failed" => ("bg-red-100 text-red-700", "Failed"),
        _ => ("bg-yellow-100 text-yellow-700", "Running"),
    };
    let duration = match run.finished_at {
        Some(fin) => {
            let secs = (fin - run.started_at).num_seconds();
            if secs < 60 {
                format!("{}s", secs)
            } else {
                format!("{}m {}s", secs / 60, secs % 60)
            }
        }
        None => "—".to_string(),
    };
    let size_str = run
        .size_bytes
        .map(fmt_bytes_backup)
        .unwrap_or_else(|| "—".to_string());
    let archive = run.archive_path.as_deref().unwrap_or("—");
    let error = run.error_message.as_deref().unwrap_or("");
    let started_at_str = run.started_at.format("%b %d %H:%M:%S").to_string();

    rsx! {
        tr { class: "border-b border-gray-100 hover:bg-gray-50/40 transition-colors",
            td { class: "px-4 py-3 text-xs text-gray-700 font-mono",
                "{started_at_str}"
            }
            td { class: "px-4 py-3 text-xs text-gray-500",
                "{duration}"
            }
            td { class: "px-4 py-3",
                span { class: "px-2 py-0.5 rounded-full text-xs font-semibold {status_cls}", "{status_label}" }
                if !error.is_empty() {
                    p { class: "text-xs text-red-500 mt-0.5 max-w-xs truncate", title: "{error}", "{error}" }
                }
            }
            td { class: "px-4 py-3 text-xs text-gray-500 font-mono", "{size_str}" }
            td { class: "px-4 py-3 text-xs text-gray-400 font-mono max-w-[200px] truncate", title: "{archive}", "{archive}" }
        }
    }
}

#[component]
fn ClientUsage() -> Element {
    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "Resource Usage" }
            div { class: "grid grid-cols-1 md:grid-cols-2 gap-5",
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                    div { class: "flex items-center gap-3 mb-4",
                        div { class: "p-2 bg-rose-50 rounded-lg",
                            Icon { name: "hard-drive", class: "w-5 h-5 text-rose-500".to_string() }
                        }
                        h3 { class: "text-base font-semibold text-gray-800", "Disk Usage" }
                    }
                    div { class: "w-full bg-gray-100 rounded-full h-3 mb-2",
                        div { class: "bg-rose-500 h-3 rounded-full transition-all duration-500", style: "width: 35%" }
                    }
                    p { class: "text-sm text-gray-500", "Usage data loaded from your quota" }
                }
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                    div { class: "flex items-center gap-3 mb-4",
                        div { class: "p-2 bg-blue-50 rounded-lg",
                            Icon { name: "trending-up", class: "w-5 h-5 text-blue-500".to_string() }
                        }
                        h3 { class: "text-base font-semibold text-gray-800", "Bandwidth" }
                    }
                    div { class: "w-full bg-gray-100 rounded-full h-3 mb-2",
                        div { class: "bg-blue-500 h-3 rounded-full transition-all duration-500", style: "width: 12%" }
                    }
                    p { class: "text-sm text-gray-500", "Monthly bandwidth usage" }
                }
            }
        }
    }
}

/// Format a byte count as a human-readable string (KB / MB / GB).
fn fmt_bytes(bytes: i64) -> String {
    if bytes < 1_024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}

/// Format a UTC DateTime for display in RSX templates.
fn fmt_dt(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M").to_string()
}

/// Format transfer speed.
fn fmt_secs(secs: f64) -> String {
    format!("{:.1}s", secs)
}

#[component]
fn ClientFtp() -> Element {
    let stats = use_resource(move || async move { server_get_ftp_stats().await });

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "FTP Usage Statistics" }
                p { class: "text-gray-500 text-sm mt-1",
                    "Transfer activity across all your FTP accounts."
                }
            }

            match &*stats.read() {
                None => rsx! {
                    div { class: "py-12 text-center text-gray-400", "Loading FTP statistics…" }
                },
                Some(Err(e)) => rsx! {
                    div { class: "bg-red-50 text-red-600 rounded-xl p-6", "Error: {e}" }
                },
                Some(Ok(s)) => rsx! {
                    // ── Summary cards ──
                    div { class: "grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6",
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5",
                            div { class: "flex items-center gap-3 mb-3",
                                div { class: "p-2 bg-indigo-50 rounded-lg",
                                    Icon { name: "users", class: "w-5 h-5 text-indigo-500".to_string() }
                                }
                                span { class: "text-sm font-medium text-gray-500", "Accounts" }
                            }
                            p { class: "text-2xl font-bold text-gray-900", "{s.active_accounts}" }
                            p { class: "text-xs text-gray-400 mt-1", "active of {s.total_accounts} total" }
                        }
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5",
                            div { class: "flex items-center gap-3 mb-3",
                                div { class: "p-2 bg-green-50 rounded-lg",
                                    Icon { name: "upload", class: "w-5 h-5 text-green-500".to_string() }
                                }
                                span { class: "text-sm font-medium text-gray-500", "Uploads" }
                            }
                            p { class: "text-2xl font-bold text-gray-900", "{s.total_uploads}" }
                            p { class: "text-xs text-gray-400 mt-1", "{fmt_bytes(s.bytes_uploaded)} transferred" }
                        }
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5",
                            div { class: "flex items-center gap-3 mb-3",
                                div { class: "p-2 bg-blue-50 rounded-lg",
                                    Icon { name: "download", class: "w-5 h-5 text-blue-500".to_string() }
                                }
                                span { class: "text-sm font-medium text-gray-500", "Downloads" }
                            }
                            p { class: "text-2xl font-bold text-gray-900", "{s.total_downloads}" }
                            p { class: "text-xs text-gray-400 mt-1", "{fmt_bytes(s.bytes_downloaded)} transferred" }
                        }
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5",
                            div { class: "flex items-center gap-3 mb-3",
                                div { class: "p-2 bg-rose-50 rounded-lg",
                                    Icon { name: "hard-drive", class: "w-5 h-5 text-rose-500".to_string() }
                                }
                                span { class: "text-sm font-medium text-gray-500", "Total Transferred" }
                            }
                            p { class: "text-2xl font-bold text-gray-900",
                                "{fmt_bytes(s.bytes_uploaded + s.bytes_downloaded)}"
                            }
                            p { class: "text-xs text-gray-400 mt-1", "all directions" }
                        }
                    }

                    // ── Per-account breakdown ──
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden mb-6",
                        div { class: "px-6 py-4 border-b border-gray-100",
                            h3 { class: "font-semibold text-gray-900", "Per-Account Breakdown" }
                        }
                        if s.per_account.is_empty() {
                            div { class: "py-10 text-center text-gray-400 text-sm",
                                "No FTP accounts found. Create one from the Sites section."
                            }
                        } else {
                            div { class: "overflow-x-auto",
                                table { class: "w-full text-sm",
                                    thead { class: "bg-gray-50 border-b border-gray-200/60",
                                        tr {
                                            th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Username" }
                                            th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Uploads" }
                                            th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Up Bytes" }
                                            th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Downloads" }
                                            th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Down Bytes" }
                                            th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Last Active" }
                                        }
                                    }
                                    tbody { class: "divide-y divide-gray-100",
                                        for acct in s.per_account.iter() {
                                            tr { class: "hover:bg-gray-50/50",
                                                td { class: "px-5 py-3 font-medium text-gray-900", "{acct.username}" }
                                                td { class: "px-5 py-3 text-right text-green-600", "{acct.total_uploads}" }
                                                td { class: "px-5 py-3 text-right text-gray-600", "{fmt_bytes(acct.bytes_uploaded)}" }
                                                td { class: "px-5 py-3 text-right text-blue-600", "{acct.total_downloads}" }
                                                td { class: "px-5 py-3 text-right text-gray-600", "{fmt_bytes(acct.bytes_downloaded)}" }
                                                td { class: "px-5 py-3 text-gray-400 text-xs",
                                                    if let Some(ts) = &acct.last_active {
                                                        "{fmt_dt(ts)}"
                                                    } else {
                                                        "—"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ── Recent transfers ──
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                        div { class: "px-6 py-4 border-b border-gray-100",
                            h3 { class: "font-semibold text-gray-900", "Recent Transfers" }
                        }
                        if s.recent_transfers.is_empty() {
                            div { class: "py-10 text-center text-gray-400 text-sm",
                                "No transfer records yet."
                            }
                        } else {
                            div { class: "overflow-x-auto",
                                table { class: "w-full text-sm",
                                    thead { class: "bg-gray-50 border-b border-gray-200/60",
                                        tr {
                                            th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Time" }
                                            th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "User" }
                                            th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Direction" }
                                            th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "File" }
                                            th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Size" }
                                            th { class: "px-5 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Secs" }
                                            th { class: "px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Client IP" }
                                        }
                                    }
                                    tbody { class: "divide-y divide-gray-100",
                                        for xfer in s.recent_transfers.iter() {
                                            tr { class: "hover:bg-gray-50/50",
                                                td { class: "px-5 py-3 text-gray-400 text-xs whitespace-nowrap",
                                                    "{fmt_dt(&xfer.completed_at)}"
                                                }
                                                td { class: "px-5 py-3 text-gray-700", "{xfer.username}" }
                                                td { class: "px-5 py-3",
                                                    if xfer.direction == "Upload" {
                                                        span { class: "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-green-50 text-green-700",
                                                            Icon { name: "upload", class: "w-3 h-3".to_string() }
                                                            "Upload"
                                                        }
                                                    } else {
                                                        span { class: "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-blue-50 text-blue-700",
                                                            Icon { name: "download", class: "w-3 h-3".to_string() }
                                                            "Download"
                                                        }
                                                    }
                                                }
                                                td { class: "px-5 py-3 text-gray-600 max-w-xs truncate",
                                                    title: "{xfer.filename}",
                                                    "{xfer.filename}"
                                                }
                                                td { class: "px-5 py-3 text-right text-gray-600", "{fmt_bytes(xfer.bytes_transferred)}" }
                                                td { class: "px-5 py-3 text-right text-gray-400 text-xs",
                                                    "{fmt_secs(xfer.transfer_time_secs)}"
                                                }
                                                td { class: "px-5 py-3 text-gray-400 text-xs",
                                                    "{xfer.remote_host.as_deref().unwrap_or(\"—\")}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}

// ──── Admin Support Tickets ───────────────────────────────────────────────────

#[component]
fn AdminSupportTickets() -> Element {
    let mut tickets = use_resource(move || async move { server_list_all_tickets().await });
    let mut selected_id = use_signal(|| None::<i64>);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Support Tickets" }
                    p { class: "text-gray-500 text-sm mt-1", "All client and reseller tickets." }
                }
                button {
                    class: "p-2 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors",
                    title: "Refresh",
                    onclick: move |_| tickets.restart(),
                    Icon { name: "refresh-cw", class: "w-5 h-5".to_string() }
                }
            }
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*tickets.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr {
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Subject" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Priority" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Updated" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for ticket in list.iter() {
                                    tr {
                                        class: if selected_id() == Some(ticket.id) {
                                            "bg-rose-50/30 cursor-pointer transition-colors"
                                        } else {
                                            "hover:bg-gray-50/50 cursor-pointer transition-colors"
                                        },
                                        onclick: {
                                            let tid = ticket.id;
                                            move |_| {
                                                if selected_id() == Some(tid) {
                                                    selected_id.set(None);
                                                } else {
                                                    selected_id.set(Some(tid));
                                                }
                                            }
                                        },
                                        td { class: "px-6 py-4 text-sm font-medium text-gray-900", "{ticket.subject}" }
                                        td { class: "px-6 py-4 text-sm text-gray-500", "{ticket.priority}" }
                                        td { class: "px-6 py-4", StatusBadge { status: ticket.status.to_string() } }
                                        td { class: "px-6 py-4 text-sm text-gray-500",
                                            "{ticket.updated_at.format(\"%b %d, %Y\")}"
                                        }
                                    }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No support tickets." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
            if let Some(tid) = selected_id() {
                TicketDetail {
                    ticket_id: tid,
                    on_close: move |_| selected_id.set(None),
                    on_updated: move |_| tickets.restart(),
                }
            }
        }
    }
}

/// Sub-component: expands inline below the ticket list to show message thread + reply form.
#[component]
fn TicketDetail(
    ticket_id: i64,
    on_close: EventHandler<()>,
    on_updated: EventHandler<()>,
) -> Element {
    let auth = use_context::<Signal<Option<AuthState>>>();
    let mut data = use_resource(move || async move { server_get_ticket(ticket_id).await });
    let mut reply_body = use_signal(String::new);
    let mut reply_sending = use_signal(|| false);
    let mut reply_error = use_signal(|| None::<String>);

    rsx! {
        div { class: "mt-6 bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
            div { class: "px-6 py-4 bg-gray-50 border-b border-gray-200/60 flex items-center justify-between",
                match &*data.read() {
                    Some(Ok((ticket, _))) => rsx! { h3 { class: "text-lg font-semibold text-gray-900", "{ticket.subject}" } },
                    _ => rsx! { h3 { class: "text-lg font-semibold text-gray-500", "Ticket Detail" } },
                }
                button {
                    class: "text-gray-400 hover:text-gray-600 text-xl font-medium px-2",
                    onclick: move |_| on_close.call(()),
                    "✕"
                }
            }
            match &*data.read() {
                Some(Ok((ticket, messages))) => {
                    let is_open = ticket.status.to_string() != "Closed";
                    let current_uid = auth().map(|a| a.user_id).unwrap_or(0);
                    rsx! {
                        div { class: "p-6",
                            div { class: "flex flex-wrap gap-4 text-sm text-gray-500 mb-5",
                                span { "Status: " span { class: "font-medium text-gray-900", "{ticket.status}" } }
                                span { "Priority: " span { class: "font-medium text-gray-900", "{ticket.priority}" } }
                                span { "Department: " span { class: "font-medium text-gray-900", "{ticket.department}" } }
                            }
                            div { class: "space-y-3 mb-5 max-h-80 overflow-y-auto",
                                for msg in messages.iter() {
                                    {
                                        let is_mine = msg.sender_id == current_uid;
                                        rsx! {
                                            div { class: if is_mine { "flex justify-end" } else { "flex" },
                                                div {
                                                    class: if is_mine {
                                                        "max-w-[75%] bg-rose-50 border border-rose-200 rounded-xl px-4 py-3"
                                                    } else {
                                                        "max-w-[75%] bg-gray-100 border border-gray-200 rounded-xl px-4 py-3"
                                                    },
                                                    p { class: "text-sm text-gray-900 whitespace-pre-wrap", "{msg.body}" }
                                                    p { class: "text-xs text-gray-400 mt-1",
                                                        {msg.created_at.format("%b %d, %Y %H:%M").to_string()}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if messages.is_empty() {
                                    p { class: "text-sm text-gray-400 text-center py-4", "No messages yet." }
                                }
                            }
                            if is_open {
                                div { class: "border-t border-gray-100 pt-4",
                                    if let Some(ref err) = reply_error() {
                                        div { class: "bg-red-50 border border-red-200 text-red-700 rounded-lg p-3 mb-3 text-sm", "{err}" }
                                    }
                                    textarea {
                                        class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm resize-none",
                                        rows: "3",
                                        placeholder: "Type your reply...",
                                        value: "{reply_body}",
                                        oninput: move |e| reply_body.set(e.value()),
                                    }
                                    div { class: "flex gap-2 mt-2",
                                        button {
                                            class: "px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50",
                                            disabled: reply_sending() || reply_body().trim().is_empty(),
                                            onclick: move |_| {
                                                let rb = reply_body();
                                                if rb.trim().is_empty() { return; }
                                                reply_sending.set(true);
                                                reply_error.set(None);
                                                spawn(async move {
                                                    match server_reply_to_ticket(ticket_id, rb, false).await {
                                                        Ok(_) => {
                                                            reply_body.set(String::new());
                                                            data.restart();
                                                            on_updated.call(());
                                                        }
                                                        Err(e) => reply_error.set(Some(clean_err(&e.to_string()))),
                                                    }
                                                    reply_sending.set(false);
                                                });
                                            },
                                            if reply_sending() { "Sending..." } else { "Send Reply" }
                                        }
                                        button {
                                            class: "px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm font-medium transition-colors",
                                            onclick: move |_| {
                                                reply_error.set(None);
                                                spawn(async move {
                                                    match server_close_ticket(ticket_id).await {
                                                        Ok(_) => { data.restart(); on_updated.call(()); }
                                                        Err(e) => reply_error.set(Some(clean_err(&e.to_string()))),
                                                    }
                                                });
                                            },
                                            "Close Ticket"
                                        }
                                    }
                                }
                            } else {
                                div { class: "border-t border-gray-100 pt-4",
                                    p { class: "text-sm text-gray-500 italic", "This ticket is closed." }
                                }
                            }
                        }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                None => rsx! { p { class: "p-6 text-gray-500 text-center", "Loading ticket details..." } },
            }
        }
    }
}

#[component]
fn ClientSupportTickets() -> Element {
    let mut tickets = use_resource(move || async move { server_list_tickets().await });
    let mut show_form = use_signal(|| false);
    let mut subject = use_signal(String::new);
    let mut body = use_signal(String::new);
    let mut priority = use_signal(|| "Low".to_string());
    let mut department = use_signal(|| "General".to_string());
    let mut submitting = use_signal(|| false);
    let mut submit_error = use_signal(|| None::<String>);
    let mut selected_id = use_signal(|| None::<i64>);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Support Tickets" }
                button {
                    class: "flex items-center gap-2 px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-xl font-medium transition-colors text-sm",
                    onclick: move |_| {
                        show_form.set(!show_form());
                        submit_error.set(None);
                    },
                    Icon { name: "plus", class: "w-4 h-4".to_string() }
                    if show_form() { "Cancel" } else { "New Ticket" }
                }
            }
            if show_form() {
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 mb-6",
                    h3 { class: "text-lg font-semibold text-gray-700 mb-4", "Open New Ticket" }
                    if let Some(ref err) = submit_error() {
                        div { class: "bg-red-50 border border-red-200 text-red-700 rounded-xl p-3 mb-4 text-sm", "{err}" }
                    }
                    div { class: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-4",
                        div {
                            label { class: "block text-sm font-medium text-gray-700 mb-1", "Subject" }
                            input {
                                r#type: "text",
                                class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                placeholder: "Brief description of your issue",
                                value: "{subject}",
                                oninput: move |e| subject.set(e.value()),
                            }
                        }
                        div {
                            label { class: "block text-sm font-medium text-gray-700 mb-1", "Priority" }
                            select {
                                class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                                value: "{priority}",
                                onchange: move |e| priority.set(e.value()),
                                option { value: "Low", "Low" }
                                option { value: "Medium", "Medium" }
                                option { value: "High", "High" }
                                option { value: "Critical", "Critical" }
                            }
                        }
                        div {
                            label { class: "block text-sm font-medium text-gray-700 mb-1", "Department" }
                            select {
                                class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent bg-white",
                                value: "{department}",
                                onchange: move |e| department.set(e.value()),
                                option { value: "General", "General" }
                                option { value: "Technical", "Technical Support" }
                                option { value: "Billing", "Billing" }
                                option { value: "Sales", "Sales" }
                            }
                        }
                    }
                    div { class: "mb-4",
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Message" }
                        textarea {
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                            rows: "4",
                            placeholder: "Describe your issue in detail...",
                            value: "{body}",
                            oninput: move |e| body.set(e.value()),
                        }
                    }
                    button {
                        class: "px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-xl font-medium transition-colors text-sm disabled:opacity-50",
                        disabled: submitting(),
                        onclick: move |_| {
                            let s = subject();
                            let b = body();
                            let p = priority();
                            let d = department();
                            if s.trim().is_empty() {
                                submit_error.set(Some("Subject is required".to_string()));
                                return;
                            }
                            if b.trim().is_empty() {
                                submit_error.set(Some("Message is required".to_string()));
                                return;
                            }
                            submitting.set(true);
                            submit_error.set(None);
                            spawn(async move {
                                use panel::models::ticket::TicketPriority;
                                let prio = match p.as_str() {
                                    "Medium" => TicketPriority::Medium,
                                    "High" => TicketPriority::High,
                                    "Critical" => TicketPriority::Critical,
                                    _ => TicketPriority::Low,
                                };
                                match server_create_ticket(s, b, prio, d).await {
                                    Ok(_) => {
                                        show_form.set(false);
                                        subject.set(String::new());
                                        body.set(String::new());
                                        priority.set("Low".to_string());
                                        tickets.restart();
                                    }
                                    Err(e) => submit_error.set(Some(e.to_string())),
                                }
                                submitting.set(false);
                            });
                        },
                        if submitting() { "Submitting..." } else { "Submit Ticket" }
                    }
                }
            }
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*tickets.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200/60",
                                tr { class: "hover:bg-gray-50/50 transition-colors",
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Subject" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Priority" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Status" }
                                    th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Updated" }
                                }
                            }
                            tbody { class: "divide-y divide-gray-100",
                                for ticket in list.iter() {
                                    tr {
                                        class: if selected_id() == Some(ticket.id) { "bg-rose-50/30 cursor-pointer transition-colors" } else { "hover:bg-gray-50/50 cursor-pointer transition-colors" },
                                        onclick: {
                                            let tid = ticket.id;
                                            move |_| {
                                                if selected_id() == Some(tid) { selected_id.set(None); } else { selected_id.set(Some(tid)); }
                                            }
                                        },
                                        td { class: "px-6 py-4 text-sm font-medium text-gray-900", "{ticket.subject}" }
                                        td { class: "px-6 py-4 text-sm text-gray-500", "{ticket.priority}" }
                                        td { class: "px-6 py-4", StatusBadge { status: ticket.status.to_string() } }
                                        td { class: "px-6 py-4 text-sm text-gray-500", "{ticket.updated_at.format(\"%b %d, %Y\")}" }
                                    }
                                }
                            }
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No support tickets. Click 'New Ticket' to open one." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-gray-500", "Loading..." } },
                }
            }
            if let Some(tid) = selected_id() {
                TicketDetail {
                    ticket_id: tid,
                    on_close: move |_| selected_id.set(None),
                    on_updated: move |_| tickets.restart(),
                }
            }
        }
    }
}

// ──── Web Statistics Page ─────────────────────────────────────────────────────

#[component]
fn ClientWebStats() -> Element {
    let sites = use_resource(move || async move { server_list_sites().await });
    let stats = use_resource(move || async move { server_list_stats().await });
    let tools = use_resource(move || async move { server_check_stats_tools().await });

    let mut run_error = use_signal(|| None::<String>);
    let mut run_busy = use_signal(|| false);
    let mut toggle_busy = use_signal(|| false);

    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-2", "Web Statistics" }
            p { class: "text-sm text-gray-500 mb-6",
                "Analyze your visitors with Webalizer, GoAccess, or AWStats. Reports are built from the OpenLiteSpeed access log for each domain."
            }

            // Tool availability banner
            match &*tools.read() {
                Some(Ok(avail)) => rsx! {
                    div { class: "grid grid-cols-3 gap-4 mb-6",
                        StatsToolCard {
                            name: "Webalizer",
                            icon: "bar-chart-2",
                            installed: avail.webalizer,
                            color: "rose",
                        }
                        StatsToolCard {
                            name: "GoAccess",
                            icon: "activity",
                            installed: avail.goaccess,
                            color: "emerald",
                        }
                        StatsToolCard {
                            name: "AWStats",
                            icon: "pie-chart",
                            installed: avail.awstats,
                            color: "blue",
                        }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "bg-yellow-50 border border-yellow-200 text-yellow-800 rounded-lg p-3 mb-4 text-sm",
                        "Could not detect installed tools: {e}"
                    }
                },
                None => rsx! {
                    div { class: "text-sm text-gray-400 mb-4", "Checking installed tools…" }
                },
            }

            if let Some(err) = run_error() {
                div { class: "bg-red-50 border border-red-200 text-red-700 rounded-lg p-3 mb-4 text-sm",
                    "{err}"
                }
            }

            // Stats table per site/tool
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                div { class: "px-6 py-4 border-b border-gray-100",
                    h3 { class: "text-base font-semibold text-gray-800", "Domain Statistics" }
                }
                match (&*sites.read(), &*stats.read()) {
                    (Some(Ok(site_list)), Some(Ok(cfg_list))) => rsx! {
                        if site_list.is_empty() {
                            div { class: "p-12 text-center text-gray-400",
                                Icon { name: "globe", class: "w-10 h-10 mx-auto mb-3 opacity-30".to_string() }
                                p { "No websites found. Add a site first." }
                            }
                        } else {
                            table { class: "w-full",
                                thead { class: "bg-gray-50 border-b border-gray-200/60",
                                    tr {
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Domain" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Tool" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Last Run" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Status" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider", "Actions" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-100",
                                    for site in site_list.iter() {
                                        for tool in [
                                            panel::models::stats::StatsTool::Webalizer,
                                            panel::models::stats::StatsTool::GoAccess,
                                            panel::models::stats::StatsTool::AwStats,
                                        ] {
                                            {
                                                let cfg = cfg_list.iter().find(|c| {
                                                    c.site_id == site.id && c.tool == tool
                                                });
                                                let site_id = site.id;
                                                let domain = site.domain.clone();
                                                let tool_label = match tool {
                                                    panel::models::stats::StatsTool::Webalizer => "Webalizer",
                                                    panel::models::stats::StatsTool::GoAccess => "GoAccess",
                                                    panel::models::stats::StatsTool::AwStats => "AWStats",
                                                };
                                                let enabled = cfg.map(|c| c.enabled).unwrap_or(true);
                                                let last_run = cfg
                                                    .and_then(|c| c.last_run_at)
                                                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                                                    .unwrap_or_else(|| "Never".to_string());
                                                let last_status = cfg.and_then(|c| c.last_status);
                                                let last_error = cfg.and_then(|c| c.last_error.clone());

                                                rsx! {
                                                    tr { class: "hover:bg-gray-50/50 transition-colors",
                                                        td { class: "px-6 py-3 text-sm font-medium text-gray-900", "{domain}" }
                                                        td { class: "px-6 py-3 text-sm text-gray-600", "{tool_label}" }
                                                        td { class: "px-6 py-3 text-xs text-gray-500", "{last_run}" }
                                                        td { class: "px-6 py-3",
                                                            match last_status {
                                                                Some(panel::models::stats::StatsRunStatus::Success) => rsx! {
                                                                    span { class: "inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700",
                                                                        "✓ Success"
                                                                    }
                                                                },
                                                                Some(panel::models::stats::StatsRunStatus::Failed) => rsx! {
                                                                    div {
                                                                        span { class: "inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700",
                                                                            "✗ Failed"
                                                                        }
                                                                        if let Some(err) = last_error {
                                                                            p { class: "text-xs text-red-400 mt-0.5 max-w-xs truncate", title: "{err}", "{err}" }
                                                                        }
                                                                    }
                                                                },
                                                                Some(panel::models::stats::StatsRunStatus::Running) => rsx! {
                                                                    span { class: "inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-yellow-100 text-yellow-700",
                                                                        "⟳ Running"
                                                                    }
                                                                },
                                                                None => rsx! {
                                                                    span { class: "text-xs text-gray-400", "—" }
                                                                },
                                                            }
                                                        }
                                                        td { class: "px-6 py-3",
                                                            div { class: "flex items-center gap-2",
                                                                // Enable/Disable toggle
                                                                button {
                                                                    class: if enabled {
                                                                        "text-xs px-2 py-1 rounded bg-green-100 text-green-700 hover:bg-green-200 disabled:opacity-50"
                                                                    } else {
                                                                        "text-xs px-2 py-1 rounded bg-gray-100 text-gray-600 hover:bg-gray-200 disabled:opacity-50"
                                                                    },
                                                                    disabled: toggle_busy(),
                                                                    onclick: {
                                                                        let mut stats = stats;
                                                                        move |_| {
                                                                            toggle_busy.set(true);
                                                                            run_error.set(None);
                                                                            spawn(async move {
                                                                                match server_toggle_stats(site_id, tool, !enabled).await {
                                                                                    Ok(()) => stats.restart(),
                                                                                    Err(e) => run_error.set(Some(e.to_string())),
                                                                                }
                                                                                toggle_busy.set(false);
                                                                            });
                                                                        }
                                                                    },
                                                                    if enabled { "Enabled" } else { "Disabled" }
                                                                }
                                                                // Run now
                                                                button {
                                                                    class: "text-xs px-2 py-1 rounded bg-indigo-100 text-indigo-700 hover:bg-indigo-200 disabled:opacity-50",
                                                                    disabled: run_busy() || !enabled,
                                                                    onclick: {
                                                                        let mut stats = stats;
                                                                        move |_| {
                                                                            run_busy.set(true);
                                                                            run_error.set(None);
                                                                            spawn(async move {
                                                                                match server_run_stats(site_id, tool).await {
                                                                                    Ok(()) => stats.restart(),
                                                                                    Err(e) => run_error.set(Some(e.to_string())),
                                                                                }
                                                                                run_busy.set(false);
                                                                            });
                                                                        }
                                                                    },
                                                                    if run_busy() { "Running…" } else { "Run Now" }
                                                                }
                                                                // View report link
                                                                if matches!(last_status, Some(panel::models::stats::StatsRunStatus::Success)) {
                                                                    a {
                                                                        class: "text-xs px-2 py-1 rounded bg-rose-100 text-rose-700 hover:bg-rose-200",
                                                                        href: "#",
                                                                        onclick: {
                                                                            let _domain = domain.clone();
                                                                            move |e: MouseEvent| {
                                                                                e.prevent_default();
                                                                                let _tool_path = match tool {
                                                                                    panel::models::stats::StatsTool::Webalizer => "webalizer",
                                                                                    panel::models::stats::StatsTool::GoAccess => "goaccess",
                                                                                    panel::models::stats::StatsTool::AwStats => "awstats",
                                                                                };
                                                                                let _entry = match tool {
                                                                                    panel::models::stats::StatsTool::GoAccess => "report.html",
                                                                                    _ => "index.html",
                                                                                };
                                                                                #[cfg(target_arch = "wasm32")]
                                                                                {
                                                                                    let url = format!("https://{}/stats/{}/{}", _domain, _tool_path, _entry);
                                                                                    let _ = web_sys::window()
                                                                                        .and_then(|w| w.open_with_url_and_target(&url, "_blank").ok());
                                                                                }
                                                                            }
                                                                        },
                                                                        "View Report"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    (Some(Err(e)), _) | (_, Some(Err(e))) => rsx! {
                        p { class: "p-6 text-red-600", "Error: {e}" }
                    },
                    _ => rsx! {
                        p { class: "p-6 text-gray-500", "Loading…" }
                    },
                }
            }
        }
    }
}

#[derive(PartialEq, Clone, Props)]
struct StatsToolCardProps {
    name: &'static str,
    icon: &'static str,
    installed: bool,
    color: &'static str,
}

#[component]
fn StatsToolCard(props: StatsToolCardProps) -> Element {
    let (bg, text, dot) = if props.installed {
        ("bg-green-50", "text-green-700", "bg-green-500")
    } else {
        ("bg-gray-50", "text-gray-500", "bg-gray-300")
    };

    rsx! {
        div { class: "bg-white rounded-xl border border-gray-100 p-4 flex items-center gap-3 shadow-sm",
            div { class: "p-2.5 rounded-lg {bg}",
                Icon { name: props.icon, class: format!("w-5 h-5 {text}") }
            }
            div { class: "flex-1 min-w-0",
                p { class: "text-sm font-semibold text-gray-800", "{props.name}" }
                div { class: "flex items-center gap-1.5 mt-0.5",
                    div { class: "w-2 h-2 rounded-full {dot}" }
                    p { class: "text-xs {text}",
                        if props.installed { "Installed" } else { "Not installed" }
                    }
                }
            }
        }
    }
}

/// Strip the verbose Dioxus server function error prefix for clean user display.
fn clean_err(e: &str) -> String {
    e.strip_prefix("error running server function: ")
        .unwrap_or(e)
        .trim_end_matches(" (details: None)")
        .to_string()
}

#[component]
fn ClientSettings() -> Element {
    let mut user = use_resource(move || async move { server_get_current_user().await });
    let mut edit_company = use_signal(String::new);
    let mut edit_address = use_signal(String::new);
    let mut edit_phone = use_signal(String::new);
    let mut details_editing = use_signal(|| false);
    let mut details_saving = use_signal(|| false);
    let mut details_error = use_signal(|| None::<String>);
    let mut details_success = use_signal(|| false);

    // Change password
    let mut show_pw_form = use_signal(|| false);
    let mut pw_current = use_signal(String::new);
    let mut pw_new = use_signal(String::new);
    let mut pw_confirm = use_signal(String::new);
    let mut pw_saving = use_signal(|| false);
    let mut pw_error = use_signal(|| None::<String>);
    let mut pw_success = use_signal(|| false);

    // 2FA setup
    let mut show_2fa_form = use_signal(|| false);
    let mut tfa_secret = use_signal(String::new);
    let mut tfa_qr_url = use_signal(String::new);
    let mut tfa_code = use_signal(String::new);
    let mut tfa_loading = use_signal(|| false);
    let mut tfa_error = use_signal(|| None::<String>);
    let mut tfa_success = use_signal(|| false);

    // Disable 2FA
    let mut show_disable_2fa = use_signal(|| false);
    let mut disable_2fa_pw = use_signal(String::new);
    let mut disable_2fa_saving = use_signal(|| false);
    let mut disable_2fa_error = use_signal(|| None::<String>);

    rsx! {
        div { class: "p-6 lg:p-8",
            h2 { class: "text-2xl font-bold text-gray-900 mb-6", "Account Settings" }
            match &*user.read() {
                Some(Ok(u)) => rsx! {
                    div { class: "space-y-6",
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                            h3 { class: "text-lg font-semibold text-gray-700 mb-4", "Profile Information" }
                            div { class: "grid grid-cols-2 gap-4",
                                div {
                                    label { class: "block text-sm font-medium text-gray-500", "Username" }
                                    p { class: "text-gray-900", "{u.username}" }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-500", "Email" }
                                    p { class: "text-gray-900", "{u.email}" }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-500", "Role" }
                                    p { class: "text-gray-900", "{u.role:?}" }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-500", "Two-Factor Auth" }
                                    p { class: "text-gray-900",
                                        if u.totp_enabled { "Enabled ✅" } else { "Disabled" }
                                    }
                                }
                            }
                        }
                        // Contact details card
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                            div { class: "flex items-center justify-between mb-4",
                                h3 { class: "text-lg font-semibold text-gray-700", "Contact Details" }
                                if !details_editing() {
                                    button {
                                        class: "px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition-colors",
                                        onclick: {
                                            let company = u.company.clone().unwrap_or_default();
                                            let address = u.address.clone().unwrap_or_default();
                                            let phone = u.phone.clone().unwrap_or_default();
                                            move |_| {
                                                edit_company.set(company.clone());
                                                edit_address.set(address.clone());
                                                edit_phone.set(phone.clone());
                                                details_editing.set(true);
                                                details_success.set(false);
                                                details_error.set(None);
                                            }
                                        },
                                        "Edit"
                                    }
                                }
                            }
                            if details_editing() {
                                if let Some(err) = details_error() {
                                    div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-3 text-sm", "{err}" }
                                }
                                div { class: "grid grid-cols-1 md:grid-cols-3 gap-4",
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Company" }
                                        input {
                                            r#type: "text",
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            placeholder: "Acme Inc.",
                                            value: "{edit_company}",
                                            oninput: move |e| edit_company.set(e.value()),
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Phone" }
                                        input {
                                            r#type: "tel",
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            placeholder: "+1 555 000 0000",
                                            value: "{edit_phone}",
                                            oninput: move |e| edit_phone.set(e.value()),
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Address" }
                                        input {
                                            r#type: "text",
                                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                            placeholder: "123 Main St, City",
                                            value: "{edit_address}",
                                            oninput: move |e| edit_address.set(e.value()),
                                        }
                                    }
                                }
                                div { class: "flex gap-2 mt-4",
                                    button {
                                        class: "px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-lg transition-colors text-sm disabled:opacity-50",
                                        disabled: details_saving(),
                                        onclick: move |_| {
                                            details_saving.set(true);
                                            details_error.set(None);
                                            let company = edit_company();
                                            let address = edit_address();
                                            let phone = edit_phone();
                                            spawn(async move {
                                                let c = if company.trim().is_empty() { None } else { Some(company) };
                                                let a = if address.trim().is_empty() { None } else { Some(address) };
                                                let p = if phone.trim().is_empty() { None } else { Some(phone) };
                                                // Use 0 – server will resolve current user from JWT.
                                                match server_update_user_details(0, c, a, p).await {
                                                    Ok(_) => {
                                                        details_editing.set(false);
                                                        details_success.set(true);
                                                        user.restart();
                                                    }
                                                    Err(e) => details_error.set(Some(e.to_string())),
                                                }
                                                details_saving.set(false);
                                            });
                                        },
                                        if details_saving() { "Saving..." } else { "Save" }
                                    }
                                    button {
                                        class: "px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition-colors text-sm",
                                        onclick: move |_| {
                                            details_editing.set(false);
                                            details_error.set(None);
                                        },
                                        "Cancel"
                                    }
                                }
                            } else {
                                if details_success() {
                                    div { class: "bg-green-50 text-green-700 p-3 rounded-lg mb-3 text-sm", "Contact details updated." }
                                }
                                div { class: "grid grid-cols-1 md:grid-cols-3 gap-4",
                                    div {
                                        label { class: "block text-sm font-medium text-gray-500", "Company" }
                                        p { class: "text-gray-900 mt-0.5",
                                            if let Some(c) = &u.company { "{c}" } else { "—" }
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-500", "Phone" }
                                        p { class: "text-gray-900 mt-0.5",
                                            if let Some(p) = &u.phone { "{p}" } else { "—" }
                                        }
                                    }
                                    div {
                                        label { class: "block text-sm font-medium text-gray-500", "Address" }
                                        p { class: "text-gray-900 mt-0.5",
                                            if let Some(a) = &u.address { "{a}" } else { "—" }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                            h3 { class: "text-lg font-semibold text-gray-700 mb-4", "Security" }
                            div { class: "flex gap-4 mb-4",
                                button {
                                    class: "px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-lg transition-colors text-sm",
                                    onclick: move |_| {
                                        show_pw_form.set(!show_pw_form());
                                        pw_error.set(None);
                                        pw_success.set(false);
                                        pw_current.set(String::new());
                                        pw_new.set(String::new());
                                        pw_confirm.set(String::new());
                                    },
                                    if show_pw_form() { "Cancel" } else { "Change Password" }
                                }
                                if u.totp_enabled {
                                    button {
                                        class: "px-4 py-2 bg-amber-500 hover:bg-amber-600 text-white rounded-lg transition-colors text-sm",
                                        onclick: move |_| {
                                            show_disable_2fa.set(!show_disable_2fa());
                                            disable_2fa_error.set(None);
                                            disable_2fa_pw.set(String::new());
                                        },
                                        if show_disable_2fa() { "Cancel" } else { "Disable Two-Factor Auth" }
                                    }
                                } else {
                                    button {
                                        class: "px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors text-sm",
                                        onclick: move |_| {
                                            if !show_2fa_form() {
                                                tfa_loading.set(true);
                                                tfa_error.set(None);
                                                tfa_success.set(false);
                                                tfa_code.set(String::new());
                                                spawn(async move {
                                                    match server_setup_2fa().await {
                                                        Ok(r) => {
                                                            tfa_secret.set(r.secret);
                                                            tfa_qr_url.set(r.qr_code_url);
                                                            show_2fa_form.set(true);
                                                        }
                                                        Err(e) => tfa_error.set(Some(e.to_string())),
                                                    }
                                                    tfa_loading.set(false);
                                                });
                                            } else {
                                                show_2fa_form.set(false);
                                            }
                                        },
                                        if tfa_loading() { "Loading…" } else if show_2fa_form() { "Cancel" } else { "Enable Two-Factor Auth" }
                                    }
                                }
                            }

                            // Change password success (shown after form closes)
                            if pw_success() && !show_pw_form() {
                                div { class: "bg-green-50 text-green-700 p-3 rounded-lg text-sm", "Password changed successfully." }
                            }

                            // Change password form
                            if show_pw_form() {
                                div { class: "border-t border-gray-100 pt-4 space-y-3",
                                    if let Some(err) = pw_error() {
                                        div { class: "bg-red-50 text-red-700 p-3 rounded-lg text-sm", "{clean_err(&err)}" }
                                    }
                                    div { class: "grid grid-cols-1 md:grid-cols-3 gap-4",
                                        div {
                                            label { class: "block text-sm font-medium text-gray-700 mb-1", "Current Password" }
                                            input {
                                                r#type: "password",
                                                class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                                placeholder: "Current password",
                                                value: "{pw_current}",
                                                oninput: move |e| pw_current.set(e.value()),
                                            }
                                        }
                                        div {
                                            label { class: "block text-sm font-medium text-gray-700 mb-1", "New Password" }
                                            input {
                                                r#type: "password",
                                                class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                                placeholder: "New password (12+ chars)",
                                                value: "{pw_new}",
                                                oninput: move |e| pw_new.set(e.value()),
                                            }
                                        }
                                        div {
                                            label { class: "block text-sm font-medium text-gray-700 mb-1", "Confirm New Password" }
                                            input {
                                                r#type: "password",
                                                class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 focus:border-transparent",
                                                placeholder: "Confirm new password",
                                                value: "{pw_confirm}",
                                                oninput: move |e| pw_confirm.set(e.value()),
                                            }
                                        }
                                    }
                                    button {
                                        class: "px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-lg transition-colors text-sm disabled:opacity-50",
                                        disabled: pw_saving(),
                                        onclick: move |_| {
                                            let cur = pw_current();
                                            let new = pw_new();
                                            let conf = pw_confirm();
                                            if new != conf {
                                                pw_error.set(Some("Passwords do not match".to_string()));
                                                return;
                                            }
                                            if new.len() < 12 {
                                                pw_error.set(Some("New password must be at least 12 characters".to_string()));
                                                return;
                                            }
                                            pw_error.set(None);
                                            pw_saving.set(true);
                                            spawn(async move {
                                                match server_change_password(cur, new).await {
                                                    Ok(()) => {
                                                        pw_success.set(true);
                                                        pw_current.set(String::new());
                                                        pw_new.set(String::new());
                                                        pw_confirm.set(String::new());
                                                        show_pw_form.set(false);
                                                    }
                                                    Err(e) => pw_error.set(Some(e.to_string())),
                                                }
                                                pw_saving.set(false);
                                            });
                                        },
                                        if pw_saving() { "Saving…" } else { "Save Password" }
                                    }
                                }
                            }

                            // 2FA setup form
                            if show_2fa_form() {
                                div { class: "border-t border-gray-100 pt-4 space-y-4",
                                    if let Some(err) = tfa_error() {
                                        div { class: "bg-red-50 text-red-700 p-3 rounded-lg text-sm", "{clean_err(&err)}" }
                                    }
                                    p { class: "text-sm text-gray-600",
                                        "Scan the QR code below with your authenticator app (Google Authenticator, Authy, etc.), then enter the 6-digit code to confirm."
                                    }
                                    // Show OTP URI as a link for manual entry
                                    div { class: "bg-gray-50 rounded-lg p-4 font-mono text-xs text-gray-700 break-all",
                                        strong { "Secret: " }
                                        "{tfa_secret}"
                                    }
                                    div { class: "bg-gray-50 rounded-lg p-4 text-xs text-gray-500 break-all",
                                        strong { "OTP URL: " }
                                        code { "{tfa_qr_url}" }
                                    }
                                    div { class: "flex items-end gap-4",
                                        div {
                                            label { class: "block text-sm font-medium text-gray-700 mb-1", "Verification Code" }
                                            input {
                                                r#type: "text",
                                                inputmode: "numeric",
                                                pattern: "[0-9]*",
                                                maxlength: "6",
                                                class: "px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent w-40 font-mono text-center text-xl tracking-widest",
                                                placeholder: "000000",
                                                value: "{tfa_code}",
                                                oninput: move |e| tfa_code.set(e.value()),
                                            }
                                        }
                                        button {
                                            class: "px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors text-sm disabled:opacity-50",
                                            disabled: tfa_loading() || tfa_code().len() < 6,
                                            onclick: move |_| {
                                                let secret = tfa_secret();
                                                let code = tfa_code();
                                                tfa_loading.set(true);
                                                tfa_error.set(None);
                                                spawn(async move {
                                                    match server_confirm_2fa(secret, code).await {
                                                        Ok(()) => {
                                                            tfa_success.set(true);
                                                            show_2fa_form.set(false);
                                                            user.restart();
                                                        }
                                                        Err(e) => tfa_error.set(Some(e.to_string())),
                                                    }
                                                    tfa_loading.set(false);
                                                });
                                            },
                                            if tfa_loading() { "Verifying…" } else { "Enable 2FA" }
                                        }
                                    }
                                }
                            }

                            // 2FA success message
                            if tfa_success() {
                                div { class: "border-t border-gray-100 pt-4",
                                    div { class: "bg-green-50 text-green-700 p-3 rounded-lg text-sm", "Two-factor authentication has been enabled." }
                                }
                            }

                            // Disable 2FA form
                            if show_disable_2fa() {
                                div { class: "border-t border-gray-100 pt-4 space-y-3",
                                    if let Some(err) = disable_2fa_error() {
                                        div { class: "bg-red-50 text-red-700 p-3 rounded-lg text-sm", "{clean_err(&err)}" }
                                    }
                                    p { class: "text-sm text-gray-600", "Enter your password to disable two-factor authentication." }
                                    div { class: "flex items-end gap-4",
                                        div {
                                            label { class: "block text-sm font-medium text-gray-700 mb-1", "Password" }
                                            input {
                                                r#type: "password",
                                                class: "px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-transparent w-64",
                                                placeholder: "Your current password",
                                                value: "{disable_2fa_pw}",
                                                oninput: move |e| disable_2fa_pw.set(e.value()),
                                            }
                                        }
                                        button {
                                            class: "px-4 py-2 bg-amber-500 hover:bg-amber-600 text-white rounded-lg transition-colors text-sm disabled:opacity-50",
                                            disabled: disable_2fa_saving(),
                                            onclick: move |_| {
                                                let pw = disable_2fa_pw();
                                                disable_2fa_saving.set(true);
                                                disable_2fa_error.set(None);
                                                spawn(async move {
                                                    match server_disable_2fa(pw).await {
                                                        Ok(()) => {
                                                            show_disable_2fa.set(false);
                                                            disable_2fa_pw.set(String::new());
                                                            user.restart();
                                                        }
                                                        Err(e) => disable_2fa_error.set(Some(e.to_string())),
                                                    }
                                                    disable_2fa_saving.set(false);
                                                });
                                            },
                                            if disable_2fa_saving() { "Disabling…" } else { "Disable 2FA" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                Some(Err(e)) => rsx! { div { class: "text-red-600", "Error: {e}" } },
                None => rsx! { div { class: "text-gray-500", "Loading..." } },
            }
        }
    }
}

#[component]
fn ClientGit() -> Element {
    let sites = use_resource(move || async move { server_list_sites().await });
    let mut selected_site_id = use_signal(|| 0i64);

    let mut repo_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(None);
            }
            server_get_site_git_repo(sid).await
        }
    });
    let mut status_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(String::new());
            }
            server_git_status(sid).await
        }
    });
    let mut branches_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(vec![]);
            }
            server_git_branches(sid).await
        }
    });
    let mut log_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(vec![]);
            }
            server_git_log(sid, 50).await
        }
    });

    let mut attach_url = use_signal(String::new);
    let mut attach_branch = use_signal(|| "main".to_string());
    let mut attach_error = use_signal(|| None::<String>);
    let mut attaching = use_signal(|| false);

    let mut active_tab = use_signal(|| "status".to_string());
    let mut commit_msg = use_signal(String::new);
    let mut action_output = use_signal(|| None::<String>);
    let mut action_error = use_signal(|| None::<String>);
    let mut action_loading = use_signal(|| false);
    let mut new_deploy_key = use_signal(|| None::<String>);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Git Integration" }
                p { class: "text-gray-500 text-sm mt-1", "Attach and manage Git repositories for your websites." }
            }

            // ── Site selector ──
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6",
                label { class: "block text-sm font-medium text-gray-700 mb-2", "Select Website" }
                match &*sites.read() {
                    Some(Ok(site_list)) => rsx! {
                        select {
                            class: "w-full max-w-sm px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 bg-white text-sm",
                            value: "{selected_site_id}",
                            onchange: move |e| {
                                let val: i64 = e.value().parse().unwrap_or(0);
                                selected_site_id.set(val);
                                action_output.set(None);
                                action_error.set(None);
                                new_deploy_key.set(None);
                                active_tab.set("status".to_string());
                            },
                            option { value: "0", disabled: true, "-- Choose a website --" }
                            for s in site_list.iter() {
                                option { value: "{s.id}", "{s.domain}" }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "text-red-600 text-sm", "Error loading sites: {e}" } },
                    None => rsx! { p { class: "text-gray-500 text-sm", "Loading sites..." } },
                }
            }

            // ── Git panel (only when a site is chosen) ──
            if selected_site_id() != 0 {
                match &*repo_resource.read() {
                    // ── No repo attached ──────────────────────────────────────────────
                    Some(Ok(None)) => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-10",
                            div { class: "text-center mb-8",
                                div { class: "mx-auto w-14 h-14 rounded-2xl bg-rose-50 flex items-center justify-center mb-4",
                                    Icon { name: "git-branch", class: "w-7 h-7 text-rose-500".to_string() }
                                }
                                h3 { class: "text-lg font-semibold text-gray-800 mb-1", "No Repository Attached" }
                                p { class: "text-gray-500 text-sm", "Attach a Git repository to deploy and manage your site's code." }
                            }
                            if let Some(ref err) = attach_error() {
                                div { class: "max-w-lg mx-auto bg-red-50 border border-red-200 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                            }
                            form {
                                onsubmit: move |ev: FormEvent| {
                                    ev.prevent_default();
                                    attaching.set(true);
                                    attach_error.set(None);
                                    let sid = selected_site_id();
                                    let url = attach_url();
                                    let br = attach_branch();
                                    spawn(async move {
                                        match server_attach_git_repo(sid, url, br).await {
                                            Ok(()) => repo_resource.restart(),
                                            Err(e) => attach_error.set(Some(e.to_string())),
                                        }
                                        attaching.set(false);
                                    });
                                },
                                class: "max-w-lg mx-auto space-y-4",
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Repository URL" }
                                    input {
                                        r#type: "text",
                                        class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm",
                                        placeholder: "https://github.com/user/repo.git  or  git@github.com:user/repo.git",
                                        value: "{attach_url}",
                                        oninput: move |e| attach_url.set(e.value()),
                                        required: true,
                                    }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Branch" }
                                    input {
                                        r#type: "text",
                                        class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm",
                                        placeholder: "main",
                                        value: "{attach_branch}",
                                        oninput: move |e| attach_branch.set(e.value()),
                                        required: true,
                                    }
                                }
                                div { class: "flex justify-center pt-2",
                                    button {
                                        r#type: "submit",
                                        class: "px-8 py-2.5 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50 text-sm",
                                        disabled: attaching(),
                                        if attaching() { "Attaching..." } else { "Attach Repository" }
                                    }
                                }
                            }
                        }
                    },

                    // ── Repo attached ─────────────────────────────────────────────────
                    Some(Ok(Some(repo))) => {
                        let repo = repo.clone();
                        rsx! {
                            // Repo info card
                            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-5",
                                div { class: "flex items-start justify-between gap-4 flex-wrap",
                                    div { class: "flex items-center gap-3",
                                        div { class: "w-10 h-10 rounded-xl bg-emerald-50 flex items-center justify-center shrink-0",
                                            Icon { name: "git-branch", class: "w-5 h-5 text-emerald-600".to_string() }
                                        }
                                        div {
                                            p { class: "font-semibold text-gray-900 text-sm break-all", "{repo.repo_url}" }
                                            p { class: "text-xs text-gray-500 mt-0.5",
                                                span { class: "font-medium text-gray-700", "Branch: " }
                                                "{repo.branch}"
                                                if let Some(ref hash) = repo.last_commit_hash {
                                                    span { class: "ml-3",
                                                        span { class: "font-medium text-gray-700", "Last: " }
                                                        span { class: "font-mono text-xs", "{&hash[..7.min(hash.len())]}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "flex gap-2 flex-wrap",
                                        button {
                                            class: "flex items-center gap-1.5 px-3 py-1.5 text-xs border border-gray-200 text-gray-600 hover:bg-gray-50 rounded-lg transition-colors",
                                            onclick: move |_| {
                                                let sid = selected_site_id();
                                                action_error.set(None);
                                                spawn(async move {
                                                    match server_git_generate_deploy_key(sid).await {
                                                        Ok(pub_key) => new_deploy_key.set(Some(pub_key)),
                                                        Err(e) => action_error.set(Some(e.to_string())),
                                                    }
                                                });
                                            },
                                            Icon { name: "key", class: "w-3.5 h-3.5".to_string() }
                                            "(Re)generate Deploy Key"
                                        }
                                        button {
                                            class: "flex items-center gap-1.5 px-3 py-1.5 text-xs border border-red-200 text-red-600 hover:bg-red-50 rounded-lg transition-colors",
                                            onclick: move |_| {
                                                let sid = selected_site_id();
                                                action_loading.set(true);
                                                action_error.set(None);
                                                action_output.set(None);
                                                new_deploy_key.set(None);
                                                spawn(async move {
                                                    match server_detach_git_repo(sid).await {
                                                        Ok(()) => {
                                                            repo_resource.restart();
                                                            status_resource.restart();
                                                            branches_resource.restart();
                                                            log_resource.restart();
                                                        }
                                                        Err(e) => action_error.set(Some(e.to_string())),
                                                    }
                                                    action_loading.set(false);
                                                });
                                            },
                                            Icon { name: "trash-2", class: "w-3.5 h-3.5".to_string() }
                                            "Detach"
                                        }
                                    }
                                }
                                // New deploy key freshly generated
                                if let Some(ref pub_key) = new_deploy_key() {
                                    div { class: "mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg",
                                        p { class: "text-xs font-semibold text-blue-800 mb-1.5",
                                            "Add this deploy key to your repository (GitHub → Settings → Deploy Keys → Add deploy key):"
                                        }
                                        pre { class: "text-xs text-blue-900 font-mono break-all whitespace-pre-wrap select-all", "{pub_key}" }
                                    }
                                // Existing deploy key stored on record
                                } else if let Some(ref pub_key) = repo.deploy_key_pub {
                                    div { class: "mt-4 p-3 bg-gray-50 border border-gray-200 rounded-lg",
                                        p { class: "text-xs font-semibold text-gray-700 mb-1", "Current deploy key (public):" }
                                        pre { class: "text-xs text-gray-700 font-mono break-all whitespace-pre-wrap select-all", "{pub_key}" }
                                    }
                                }
                            }

                            // Action bar
                            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-5",
                                div { class: "flex items-start gap-3 flex-wrap",
                                    button {
                                        class: "flex items-center gap-1.5 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50",
                                        disabled: action_loading(),
                                        onclick: move |_| {
                                            let sid = selected_site_id();
                                            action_loading.set(true);
                                            action_error.set(None);
                                            action_output.set(None);
                                            spawn(async move {
                                                match server_git_pull(sid).await {
                                                    Ok(out) => {
                                                        action_output.set(Some(out));
                                                        status_resource.restart();
                                                        log_resource.restart();
                                                        repo_resource.restart();
                                                    }
                                                    Err(e) => action_error.set(Some(e.to_string())),
                                                }
                                                action_loading.set(false);
                                            });
                                        },
                                        Icon { name: "download", class: "w-4 h-4".to_string() }
                                        "Pull"
                                    }
                                    button {
                                        class: "flex items-center gap-1.5 px-4 py-2 bg-purple-500 hover:bg-purple-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50",
                                        disabled: action_loading(),
                                        onclick: move |_| {
                                            let sid = selected_site_id();
                                            action_loading.set(true);
                                            action_error.set(None);
                                            action_output.set(None);
                                            spawn(async move {
                                                match server_git_push(sid).await {
                                                    Ok(out) => {
                                                        action_output.set(Some(out));
                                                        log_resource.restart();
                                                    }
                                                    Err(e) => action_error.set(Some(e.to_string())),
                                                }
                                                action_loading.set(false);
                                            });
                                        },
                                        Icon { name: "upload", class: "w-4 h-4".to_string() }
                                        "Push"
                                    }
                                    div { class: "flex flex-1 gap-2 items-center min-w-[260px]",
                                        input {
                                            r#type: "text",
                                            class: "flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-rose-500",
                                            placeholder: "Commit message…",
                                            value: "{commit_msg}",
                                            oninput: move |e| commit_msg.set(e.value()),
                                        }
                                        button {
                                            class: "flex items-center gap-1.5 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 whitespace-nowrap",
                                            disabled: action_loading() || commit_msg().trim().is_empty(),
                                            onclick: move |_| {
                                                let sid = selected_site_id();
                                                let msg = commit_msg();
                                                action_loading.set(true);
                                                action_error.set(None);
                                                action_output.set(None);
                                                spawn(async move {
                                                    match server_git_commit_and_push(sid, msg).await {
                                                        Ok(out) => {
                                                            action_output.set(Some(out));
                                                            commit_msg.set(String::new());
                                                            status_resource.restart();
                                                            log_resource.restart();
                                                            repo_resource.restart();
                                                        }
                                                        Err(e) => action_error.set(Some(e.to_string())),
                                                    }
                                                    action_loading.set(false);
                                                });
                                            },
                                            Icon { name: "git-commit", class: "w-4 h-4".to_string() }
                                            "Commit & Push"
                                        }
                                    }
                                }
                                if let Some(ref out) = action_output() {
                                    div { class: "mt-3 p-3 bg-gray-950 rounded-lg",
                                        pre { class: "text-xs text-green-400 font-mono overflow-auto max-h-48 whitespace-pre-wrap", "{out}" }
                                    }
                                }
                                if let Some(ref err) = action_error() {
                                    div { class: "mt-3 p-3 bg-red-50 border border-red-200 rounded-lg",
                                        pre { class: "text-xs text-red-700 font-mono overflow-auto max-h-32 whitespace-pre-wrap", "{err}" }
                                    }
                                }
                            }

                            // Tabs
                            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                                div { class: "flex border-b border-gray-200",
                                    button {
                                        class: "flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 transition-colors",
                                        class: if active_tab() == "status" { "border-rose-500 text-rose-600" } else { "border-transparent text-gray-500 hover:text-gray-700" },
                                        onclick: move |_| active_tab.set("status".to_string()),
                                        Icon { name: "list", class: "w-4 h-4".to_string() }
                                        "Working Tree"
                                    }
                                    button {
                                        class: "flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 transition-colors",
                                        class: if active_tab() == "branches" { "border-rose-500 text-rose-600" } else { "border-transparent text-gray-500 hover:text-gray-700" },
                                        onclick: move |_| active_tab.set("branches".to_string()),
                                        Icon { name: "git-branch", class: "w-4 h-4".to_string() }
                                        "Branches"
                                    }
                                    button {
                                        class: "flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 transition-colors",
                                        class: if active_tab() == "history" { "border-rose-500 text-rose-600" } else { "border-transparent text-gray-500 hover:text-gray-700" },
                                        onclick: move |_| active_tab.set("history".to_string()),
                                        Icon { name: "clock", class: "w-4 h-4".to_string() }
                                        "Commit History"
                                    }
                                }

                                if active_tab() == "status" {
                                    div { class: "p-5",
                                        div { class: "flex items-center justify-between mb-3",
                                            p { class: "text-sm font-medium text-gray-700", "Uncommitted changes (git status)" }
                                            button {
                                                class: "text-xs text-rose-500 hover:text-rose-600 font-medium",
                                                onclick: move |_| status_resource.restart(),
                                                "↻ Refresh"
                                            }
                                        }
                                        match &*status_resource.read() {
                                            Some(Ok(s)) => rsx! {
                                                if s.trim().is_empty() {
                                                    div { class: "flex items-center gap-2 p-4 bg-green-50 border border-green-200 rounded-lg text-sm text-green-700",
                                                        Icon { name: "check-circle", class: "w-4 h-4 shrink-0".to_string() }
                                                        "Working tree is clean — nothing to commit."
                                                    }
                                                } else {
                                                    pre { class: "bg-gray-50 border border-gray-200 rounded-lg p-4 text-xs font-mono text-gray-800 overflow-auto max-h-64 whitespace-pre-wrap", "{s}" }
                                                }
                                            },
                                            Some(Err(e)) => rsx! { p { class: "text-red-600 text-sm", "Error: {e}" } },
                                            None => rsx! { p { class: "text-gray-500 text-sm", "Loading…" } },
                                        }
                                    }
                                } else if active_tab() == "branches" {
                                    div { class: "p-5",
                                        div { class: "flex items-center justify-between mb-3",
                                            p { class: "text-sm font-medium text-gray-700", "Local and remote-tracking branches" }
                                            button {
                                                class: "text-xs text-rose-500 hover:text-rose-600 font-medium",
                                                onclick: move |_| branches_resource.restart(),
                                                "↻ Refresh"
                                            }
                                        }
                                        match &*branches_resource.read() {
                                            Some(Ok(branch_list)) => rsx! {
                                                if branch_list.is_empty() {
                                                    p { class: "text-gray-500 text-sm", "No branches found. Pull from remote first." }
                                                } else {
                                                    div { class: "space-y-2",
                                                        for branch in branch_list.iter() {
                                                            GitBranchRow {
                                                                branch: branch.clone(),
                                                                site_id: selected_site_id(),
                                                                branches_resource,
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            Some(Err(e)) => rsx! { p { class: "text-red-600 text-sm", "Error: {e}" } },
                                            None => rsx! { p { class: "text-gray-500 text-sm", "Loading…" } },
                                        }
                                    }
                                } else {
                                    div { class: "p-5",
                                        div { class: "flex items-center justify-between mb-3",
                                            p { class: "text-sm font-medium text-gray-700", "Recent commits (last 50)" }
                                            button {
                                                class: "text-xs text-rose-500 hover:text-rose-600 font-medium",
                                                onclick: move |_| log_resource.restart(),
                                                "↻ Refresh"
                                            }
                                        }
                                        match &*log_resource.read() {
                                            Some(Ok(commits)) => rsx! {
                                                if commits.is_empty() {
                                                    p { class: "text-gray-500 text-sm",
                                                        "No commits yet. Pull from remote or create your first commit above."
                                                    }
                                                } else {
                                                    div { class: "divide-y divide-gray-100",
                                                        for commit in commits.iter() {
                                                            div { class: "flex items-start gap-3 py-3 hover:bg-gray-50/50 rounded-lg px-2 transition-colors",
                                                                div { class: "w-6 h-6 rounded-full bg-gray-100 flex items-center justify-center shrink-0 mt-0.5",
                                                                    Icon { name: "git-commit", class: "w-3.5 h-3.5 text-gray-400".to_string() }
                                                                }
                                                                div { class: "flex-1 min-w-0",
                                                                    div { class: "flex items-baseline gap-2 flex-wrap",
                                                                        span { class: "font-mono text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded",
                                                                            "{commit.hash_short}"
                                                                        }
                                                                        span { class: "text-sm text-gray-900 font-medium", "{commit.message}" }
                                                                    }
                                                                    div { class: "flex items-center gap-2 mt-0.5",
                                                                        span { class: "text-xs text-gray-500", "{commit.author_name}" }
                                                                        span { class: "text-gray-300", "·" }
                                                                        span { class: "text-xs text-gray-400", "{commit.date}" }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            Some(Err(e)) => rsx! { p { class: "text-red-600 text-sm", "Error: {e}" } },
                                            None => rsx! { p { class: "text-gray-500 text-sm", "Loading…" } },
                                        }
                                    }
                                }
                            }
                        }
                    },

                    Some(Err(e)) => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center",
                            p { class: "text-red-600 text-sm", "Error: {e}" }
                        }
                    },
                    None => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center",
                            div { class: "animate-pulse text-gray-400 text-sm", "Loading repository info…" }
                        }
                    },
                }
            }
        }
    }
}

/// A single row in the Branches tab.
#[component]
fn GitBranchRow(
    branch: panel::models::git::GitBranch,
    site_id: i64,
    branches_resource: Resource<Result<Vec<panel::models::git::GitBranch>, ServerFnError>>,
) -> Element {
    let mut switching = use_signal(|| false);
    let mut switch_error = use_signal(|| None::<String>);
    let mut branches_resource = branches_resource;
    let branch_name = branch.name.clone();
    let is_current = branch.is_current;
    rsx! {
        div {
            class: "flex items-center justify-between p-3 rounded-lg border",
            class: if is_current { "border-emerald-200 bg-emerald-50" } else { "border-gray-200 bg-white" },
            div { class: "flex items-center gap-2",
                Icon { name: "git-branch", class: "w-4 h-4 text-gray-400".to_string() }
                span { class: "text-sm font-medium text-gray-800", "{branch.name}" }
                if is_current {
                    span { class: "px-1.5 py-0.5 text-xs bg-emerald-500 text-white rounded-full", "current" }
                }
            }
            div { class: "flex items-center gap-2",
                if let Some(ref err) = switch_error() {
                    span { class: "text-xs text-red-600", "{err}" }
                }
                if !is_current {
                    button {
                        class: "flex items-center gap-1.5 px-3 py-1.5 text-xs border border-gray-200 text-gray-600 hover:bg-gray-50 rounded-lg transition-colors disabled:opacity-50",
                        disabled: switching(),
                        onclick: move |_| {
                            switching.set(true);
                            switch_error.set(None);
                            let name = branch_name.clone();
                            spawn(async move {
                                match server_git_checkout(site_id, name).await {
                                    Ok(()) => branches_resource.restart(),
                                    Err(e) => switch_error.set(Some(e.to_string())),
                                }
                                switching.set(false);
                            });
                        },
                        Icon { name: "check", class: "w-3.5 h-3.5".to_string() }
                        if switching() { "Switching…" } else { "Switch" }
                    }
                }
            }
        }
    }
}

// ──── Cron Job Manager ──────────────────────────────────────────────────────

#[component]
fn ClientCron() -> Element {
    let sites = use_resource(move || async move { server_list_sites().await });
    let mut selected_site_id = use_signal(|| 0i64);

    let mut jobs_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(vec![]);
            }
            server_list_cron_jobs(sid).await
        }
    });

    // Form state
    let mut schedule = use_signal(|| "0 * * * *".to_string());
    let mut command = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut form_error = use_signal(|| None::<String>);
    let mut submitting = use_signal(|| false);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Cron Jobs" }
                p { class: "text-gray-500 text-sm mt-1",
                    "Schedule recurring commands for each website. Changes are written directly to the site owner's crontab."
                }
            }

            // ── Site selector ──────────────────────────────────────────────
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6",
                label { class: "block text-sm font-medium text-gray-700 mb-2", "Select Website" }
                match &*sites.read() {
                    Some(Ok(site_list)) if !site_list.is_empty() => rsx! {
                        select {
                            class: "w-full max-w-sm px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 bg-white text-sm",
                            value: "{selected_site_id}",
                            onchange: move |e| {
                                let val: i64 = e.value().parse().unwrap_or(0);
                                selected_site_id.set(val);
                                form_error.set(None);
                            },
                            option { value: "0", disabled: true, "-- Choose a website --" }
                            for s in site_list.iter() {
                                option { value: "{s.id}", "{s.domain}" }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        p { class: "text-gray-500 text-sm", "No websites found. Create one first." }
                    },
                    Some(Err(e)) => rsx! {
                        p { class: "text-red-600 text-sm", "Error loading sites: {e}" }
                    },
                    None => rsx! {
                        p { class: "text-gray-400 text-sm animate-pulse", "Loading websites…" }
                    },
                }
            }

            if selected_site_id() != 0 {
                // ── Add cron job form ──────────────────────────────────────
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6",
                    h3 { class: "text-sm font-semibold text-gray-700 mb-4", "Add New Cron Job" }

                    if let Some(ref err) = form_error() {
                        div { class: "mb-4 p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm", "{err}" }
                    }

                    form {
                        onsubmit: move |ev: FormEvent| {
                            ev.prevent_default();
                            submitting.set(true);
                            form_error.set(None);
                            let sid = selected_site_id();
                            let sched = schedule();
                            let cmd = command();
                            let desc = description();
                            spawn(async move {
                                match server_create_cron_job(sid, sched, cmd, desc).await {
                                    Ok(_) => {
                                        command.set(String::new());
                                        description.set(String::new());
                                        jobs_resource.restart();
                                    }
                                    Err(e) => form_error.set(Some(e.to_string())),
                                }
                                submitting.set(false);
                            });
                        },
                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-4",
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1",
                                    "Schedule"
                                    span { class: "text-gray-400 font-normal ml-1", "(cron expression or @alias)" }
                                }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm font-mono",
                                    placeholder: "*/5 * * * *",
                                    value: "{schedule}",
                                    oninput: move |e| schedule.set(e.value()),
                                    required: true,
                                }
                                p { class: "text-xs text-gray-400 mt-1",
                                    "Examples: "
                                    code { class: "bg-gray-100 px-1 rounded", "0 * * * *" }
                                    " (hourly)  "
                                    code { class: "bg-gray-100 px-1 rounded", "@daily" }
                                    "  "
                                    code { class: "bg-gray-100 px-1 rounded", "*/15 * * * *" }
                                    " (every 15 min)"
                                }
                            }
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1", "Command" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm font-mono",
                                    placeholder: "/usr/bin/php /home/user/site.com/artisan schedule:run",
                                    value: "{command}",
                                    oninput: move |e| command.set(e.value()),
                                    required: true,
                                }
                            }
                        }
                        div { class: "mb-4",
                            label { class: "block text-xs font-medium text-gray-600 mb-1",
                                "Description "
                                span { class: "text-gray-400 font-normal", "(optional)" }
                            }
                            input {
                                r#type: "text",
                                class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm",
                                placeholder: "Laravel scheduler, backup script, etc.",
                                value: "{description}",
                                oninput: move |e| description.set(e.value()),
                                maxlength: "255",
                            }
                        }
                        div { class: "flex justify-end",
                            button {
                                r#type: "submit",
                                class: "flex items-center gap-2 px-5 py-2.5 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50 text-sm",
                                disabled: submitting(),
                                Icon { name: "plus", class: "w-4 h-4".to_string() }
                                if submitting() { "Adding…" } else { "Add Cron Job" }
                            }
                        }
                    }
                }

                // ── Cron job list ──────────────────────────────────────────
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                    div { class: "px-5 py-4 border-b border-gray-100 flex items-center justify-between",
                        h3 { class: "text-sm font-semibold text-gray-700", "Scheduled Jobs" }
                        button {
                            class: "flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-500 hover:bg-gray-50 border border-gray-200 rounded-lg transition-colors",
                            onclick: move |_| jobs_resource.restart(),
                            Icon { name: "refresh-cw", class: "w-3.5 h-3.5".to_string() }
                            "Refresh"
                        }
                    }
                    match &*jobs_resource.read() {
                        Some(Ok(jobs)) if jobs.is_empty() => rsx! {
                            div { class: "p-10 text-center",
                                div { class: "mx-auto w-12 h-12 rounded-xl bg-gray-50 flex items-center justify-center mb-3",
                                    Icon { name: "clock", class: "w-6 h-6 text-gray-300".to_string() }
                                }
                                p { class: "text-gray-400 text-sm", "No cron jobs yet. Add your first one above." }
                            }
                        },
                        Some(Ok(jobs)) => {
                            let jobs = jobs.clone();
                            rsx! {
                                div { class: "divide-y divide-gray-50",
                                    for job in jobs.iter() {
                                        CronJobRow {
                                            job: job.clone(),
                                            jobs_resource,
                                        }
                                    }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "p-6 text-center text-red-600 text-sm", "Error: {e}" }
                        },
                        None => rsx! {
                            div { class: "p-6 text-center text-gray-400 text-sm animate-pulse", "Loading…" }
                        },
                    }
                }
            }
        }
    }
}

/// A single cron job row with toggle and delete actions.
#[component]
fn CronJobRow(
    job: panel::models::cron::CronJob,
    jobs_resource: Resource<Result<Vec<panel::models::cron::CronJob>, ServerFnError>>,
) -> Element {
    let mut jobs_resource = jobs_resource;
    let mut toggling = use_signal(|| false);
    let mut deleting = use_signal(|| false);
    let mut row_error = use_signal(|| None::<String>);
    let job_id = job.id;
    let enabled = job.enabled;
    let last_run_str = job
        .last_run
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string());

    rsx! {
        div { class: "flex items-start gap-3 px-5 py-4 hover:bg-gray-50/50 transition-colors",
            // Enable/disable toggle
            button {
                class: "mt-0.5 shrink-0 disabled:opacity-50",
                title: if enabled { "Disable job" } else { "Enable job" },
                disabled: toggling() || deleting(),
                onclick: move |_| {
                    toggling.set(true);
                    row_error.set(None);
                    spawn(async move {
                        match server_toggle_cron_job(job_id, !enabled).await {
                            Ok(()) => jobs_resource.restart(),
                            Err(e) => row_error.set(Some(e.to_string())),
                        }
                        toggling.set(false);
                    });
                },
                if enabled {
                    div { class: "w-9 h-5 bg-emerald-500 rounded-full relative transition-colors",
                        div { class: "absolute right-0.5 top-0.5 w-4 h-4 bg-white rounded-full shadow-sm" }
                    }
                } else {
                    div { class: "w-9 h-5 bg-gray-300 rounded-full relative transition-colors",
                        div { class: "absolute left-0.5 top-0.5 w-4 h-4 bg-white rounded-full shadow-sm" }
                    }
                }
            }

            // Job details
            div { class: "flex-1 min-w-0",
                div { class: "flex items-center gap-2 flex-wrap",
                    code { class: "text-xs font-mono bg-gray-100 text-gray-700 px-2 py-0.5 rounded", "{job.schedule}" }
                    code { class: "text-xs font-mono text-gray-600 truncate max-w-xs", "{job.command}" }
                }
                if !job.description.is_empty() {
                    p { class: "text-xs text-gray-400 mt-0.5", "{job.description}" }
                }
                div { class: "flex items-center gap-3 mt-1",
                    if !enabled {
                        span { class: "text-xs text-gray-400 italic", "Disabled" }
                    }
                    if let Some(ref last_run_str) = last_run_str {
                        span { class: "text-xs text-gray-400",
                            "Last run: {last_run_str}"
                        }
                    }
                    if let Some(ref err) = row_error() {
                        span { class: "text-xs text-red-600", "{err}" }
                    }
                }
            }

            // Delete button
            button {
                class: "shrink-0 p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-40",
                title: "Delete cron job",
                disabled: deleting() || toggling(),
                onclick: move |_| {
                    deleting.set(true);
                    row_error.set(None);
                    spawn(async move {
                        match server_delete_cron_job(job_id).await {
                            Ok(()) => jobs_resource.restart(),
                            Err(e) => {
                                row_error.set(Some(e.to_string()));
                                deleting.set(false);
                            }
                        }
                    });
                },
                if deleting() {
                    Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                } else {
                    Icon { name: "trash-2", class: "w-4 h-4".to_string() }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Anti-Spam Configuration
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminAntiSpam() -> Element {
    let settings_res = use_resource(move || async move { server_get_spam_filter_settings().await });
    let status_res =
        use_resource(move || async move { server_get_antispam_service_status().await });

    let mut engine = use_signal(|| "none".to_string());
    let mut spam_threshold = use_signal(|| "5.0".to_string());
    let mut add_header = use_signal(|| true);
    let mut quarantine = use_signal(|| false);
    let mut quarantine_mailbox = use_signal(|| String::new());
    let mut reject_score = use_signal(|| "15.0".to_string());
    let mut clamav = use_signal(|| false);
    let mut mailscanner = use_signal(|| false);
    let mut saving = use_signal(|| false);
    let mut save_error = use_signal(|| None::<String>);
    let mut save_ok = use_signal(|| false);

    // Populate form when settings load
    use_effect(move || {
        if let Some(Ok(ref s)) = *settings_res.read() {
            engine.set(s.engine.clone());
            spam_threshold.set(format!("{:.1}", s.spam_threshold));
            add_header.set(s.add_header_enabled);
            quarantine.set(s.quarantine_enabled);
            quarantine_mailbox.set(s.quarantine_mailbox.clone().unwrap_or_default());
            reject_score.set(format!("{:.1}", s.reject_score));
            clamav.set(s.clamav_enabled);
            mailscanner.set(s.mailscanner_enabled);
        }
    });

    let save = {
        let mut settings_res = settings_res.clone();
        move |_| {
            let eng = engine();
            let thresh: f64 = spam_threshold().parse().unwrap_or(5.0);
            let reject: f64 = reject_score().parse().unwrap_or(15.0);
            let qmb = quarantine_mailbox();
            let qmb_opt = if quarantine() && !qmb.is_empty() {
                Some(qmb)
            } else {
                None
            };
            save_error.set(None);
            save_ok.set(false);
            saving.set(true);
            spawn(async move {
                match server_save_spam_filter_settings(
                    eng,
                    thresh,
                    add_header(),
                    quarantine(),
                    qmb_opt,
                    reject,
                    clamav(),
                    mailscanner(),
                )
                .await
                {
                    Ok(()) => {
                        save_ok.set(true);
                        settings_res.restart();
                    }
                    Err(e) => save_error.set(Some(e.to_string())),
                }
                saving.set(false);
            });
        }
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-4xl",
            div { class: "mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Anti-Spam & Email Security" }
                p { class: "text-sm text-gray-500 mt-1",
                    "Configure SpamAssassin, Rspamd, ClamAV virus scanning, and MailScanner. "
                    "Changes are applied immediately to Postfix."
                }
            }

            // Service status badges
            div { class: "mb-6",
                h3 { class: "text-sm font-semibold text-gray-700 mb-3 uppercase tracking-wide", "Component Status" }
                div { class: "grid grid-cols-2 md:grid-cols-4 gap-3",
                    match &*status_res.read() {
                        Some(Ok(list)) => rsx! {
                            for (name, installed, running) in list.iter() {
                                {
                                    let badge_class = if *running {
                                        "bg-green-50 border-green-200 text-green-700"
                                    } else if *installed {
                                        "bg-yellow-50 border-yellow-200 text-yellow-700"
                                    } else {
                                        "bg-gray-50 border-gray-200 text-gray-500"
                                    };
                                    let status_text = if *running { "Running" } else if *installed { "Stopped" } else { "Not installed" };
                                    rsx! {
                                        div { class: "border rounded-xl p-3 {badge_class}",
                                            p { class: "font-semibold text-sm", "{name}" }
                                            p { class: "text-xs mt-0.5", "{status_text}" }
                                        }
                                    }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! { p { class: "text-sm text-red-500", "{e}" } },
                        None => rsx! { p { class: "text-sm text-gray-400", "Loading..." } },
                    }
                }
            }

            if save_ok() {
                div { class: "bg-green-50 text-green-700 p-3 rounded-lg mb-4 text-sm",
                    "Settings saved and applied to Postfix."
                }
            }
            if let Some(err) = save_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 space-y-6",

                // Engine selection
                div {
                    h3 { class: "text-sm font-semibold text-gray-700 mb-3", "Spam Filter Engine" }
                    div { class: "grid grid-cols-3 gap-3",
                        for (val, label, desc) in [
                            ("none", "Disabled", "No spam filtering"),
                            ("spamassassin", "SpamAssassin", "Rule-based scoring"),
                            ("rspamd", "Rspamd", "ML-based + Redis cache"),
                        ] {
                            {
                                let is_sel = engine() == val;
                                let card_class = if is_sel {
                                    "border-2 border-rose-500 bg-rose-50"
                                } else {
                                    "border border-gray-200 hover:border-gray-300 bg-white"
                                };
                                rsx! {
                                    button {
                                        class: "rounded-xl p-3 text-left transition-colors {card_class}",
                                        onclick: {
                                            let val = val.to_string();
                                            move |_| engine.set(val.clone())
                                        },
                                        p { class: "font-semibold text-sm text-gray-900", "{label}" }
                                        p { class: "text-xs text-gray-500 mt-0.5", "{desc}" }
                                    }
                                }
                            }
                        }
                    }
                }

                // Threshold settings
                div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                    div {
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Spam Score Threshold" }
                        input {
                            r#type: "number",
                            step: "0.5",
                            min: "1",
                            max: "20",
                            class: "w-full border border-gray-300 rounded-lg px-3 py-2 text-sm",
                            value: "{spam_threshold}",
                            oninput: move |e| spam_threshold.set(e.value()),
                        }
                        p { class: "text-xs text-gray-400 mt-1", "Messages scoring above this are tagged as spam (default: 5.0)" }
                    }
                    div {
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Reject Score (0 = disabled)" }
                        input {
                            r#type: "number",
                            step: "0.5",
                            min: "0",
                            max: "100",
                            class: "w-full border border-gray-300 rounded-lg px-3 py-2 text-sm",
                            value: "{reject_score}",
                            oninput: move |e| reject_score.set(e.value()),
                        }
                        p { class: "text-xs text-gray-400 mt-1", "Messages scoring above this are rejected outright (0 = tag only)" }
                    }
                }

                // Toggle options
                div { class: "space-y-3",
                    h3 { class: "text-sm font-semibold text-gray-700", "Options" }
                    label { class: "flex items-center gap-3 cursor-pointer",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 accent-rose-500",
                            checked: "{add_header}",
                            onchange: move |e| add_header.set(e.checked()),
                        }
                        span { class: "text-sm text-gray-700", "Add X-Spam-Status / X-Spam-Score headers" }
                    }
                    label { class: "flex items-center gap-3 cursor-pointer",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 accent-rose-500",
                            checked: "{quarantine}",
                            onchange: move |e| quarantine.set(e.checked()),
                        }
                        span { class: "text-sm text-gray-700", "Quarantine spam instead of delivering" }
                    }
                    if quarantine() {
                        div { class: "ml-7",
                            input {
                                r#type: "email",
                                placeholder: "quarantine@yourdomain.com",
                                class: "border border-gray-300 rounded-lg px-3 py-2 text-sm w-72",
                                value: "{quarantine_mailbox}",
                                oninput: move |e| quarantine_mailbox.set(e.value()),
                            }
                        }
                    }
                    label { class: "flex items-center gap-3 cursor-pointer",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 accent-rose-500",
                            checked: "{clamav}",
                            onchange: move |e| clamav.set(e.checked()),
                        }
                        span { class: "text-sm text-gray-700", "Enable ClamAV virus scanning (requires Rspamd)" }
                    }
                    label { class: "flex items-center gap-3 cursor-pointer",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 accent-rose-500",
                            checked: "{mailscanner}",
                            onchange: move |e| mailscanner.set(e.checked()),
                        }
                        span { class: "text-sm text-gray-700", "Enable MailScanner (alternative in-transit scanner)" }
                    }
                }

                div { class: "pt-2",
                    button {
                        class: "px-5 py-2.5 bg-rose-500 hover:bg-rose-600 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50",
                        disabled: saving(),
                        onclick: save,
                        if saving() { "Applying..." } else { "Save & Apply" }
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Mail Queue Manager
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminMailQueue() -> Element {
    let mut queue = use_resource(move || async move { server_list_mail_queue().await });
    let mut action_error = use_signal(|| None::<String>);
    let mut action_ok = use_signal(|| None::<String>);

    let flush = {
        let mut queue = queue.clone();
        move |_| {
            action_error.set(None);
            action_ok.set(None);
            spawn(async move {
                match server_flush_mail_queue().await {
                    Ok(()) => {
                        action_ok.set(Some(
                            "Queue flushed — deferred messages will be retried.".to_string(),
                        ));
                        queue.restart();
                    }
                    Err(e) => action_error.set(Some(e.to_string())),
                }
            });
        }
    };

    let delete_all = {
        let mut queue = queue.clone();
        move |_| {
            action_error.set(None);
            action_ok.set(None);
            spawn(async move {
                match server_delete_all_deferred().await {
                    Ok(()) => {
                        action_ok.set(Some("All deferred messages deleted.".to_string()));
                        queue.restart();
                    }
                    Err(e) => action_error.set(Some(e.to_string())),
                }
            });
        }
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Mail Queue Manager" }
                    p { class: "text-sm text-gray-500 mt-1",
                        "View, flush, hold, and delete messages from the Postfix mail queue."
                    }
                }
                div { class: "flex gap-2",
                    button {
                        class: "px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-xl transition-colors",
                        onclick: flush,
                        "Flush Deferred"
                    }
                    button {
                        class: "px-4 py-2 bg-red-500 hover:bg-red-600 text-white text-sm font-medium rounded-xl transition-colors",
                        onclick: delete_all,
                        "Delete All Deferred"
                    }
                    button {
                        class: "px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm font-medium rounded-xl transition-colors",
                        onclick: move |_| queue.restart(),
                        "Refresh"
                    }
                }
            }

            if let Some(ok) = action_ok() {
                div { class: "bg-green-50 text-green-700 p-3 rounded-lg mb-4 text-sm", "{ok}" }
            }
            if let Some(err) = action_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*queue.read() {
                    Some(Ok(entries)) if !entries.is_empty() => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200/60",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Queue ID" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Type" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Size" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Arrived" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Sender" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Recipient" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Reason" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-100",
                                    for entry in entries.iter() {
                                        {
                                            let qid = entry.queue_id.clone();
                                            let queue_type_class = match entry.queue_type.as_str() {
                                                "active" => "bg-green-100 text-green-700",
                                                "hold" => "bg-yellow-100 text-yellow-700",
                                                _ => "bg-gray-100 text-gray-600",
                                            };
                                            let queue2 = queue.clone();
                                            rsx! {
                                                tr { class: "hover:bg-gray-50/50",
                                                    td { class: "px-4 py-3 font-mono text-xs text-gray-700", "{entry.queue_id}" }
                                                    td { class: "px-4 py-3",
                                                        span { class: "px-2 py-0.5 rounded-full text-xs font-medium {queue_type_class}",
                                                            "{entry.queue_type}"
                                                        }
                                                    }
                                                    td { class: "px-4 py-3 text-gray-500", "{entry.size}B" }
                                                    td { class: "px-4 py-3 text-gray-500 text-xs", "{entry.arrival_time}" }
                                                    td { class: "px-4 py-3 text-gray-700 text-xs max-w-32 truncate", "{entry.sender}" }
                                                    td { class: "px-4 py-3 text-gray-700 text-xs max-w-32 truncate", "{entry.recipient}" }
                                                    td { class: "px-4 py-3 text-gray-400 text-xs max-w-40 truncate", "{entry.reason}" }
                                                    td { class: "px-4 py-3",
                                                        div { class: "flex gap-1",
                                                            button {
                                                                class: "px-2 py-1 bg-red-100 hover:bg-red-200 text-red-700 text-xs rounded transition-colors",
                                                                title: "Delete message",
                                                                onclick: move |_| {
                                                                    let id = qid.clone();
                                                                    let mut queue2 = queue2.clone();
                                                                    spawn(async move {
                                                                        server_delete_queued_message(id).await.ok();
                                                                        queue2.restart();
                                                                    });
                                                                },
                                                                "Delete"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        div { class: "py-16 text-center",
                            Icon { name: "inbox", class: "w-10 h-10 text-gray-300 mx-auto mb-3".to_string() }
                            p { class: "text-gray-400", "Mail queue is empty." }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "p-6 text-red-500 text-sm", "{e}" }
                    },
                    None => rsx! {
                        div { class: "p-6 text-gray-400 text-sm", "Loading queue..." }
                    },
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Email Statistics & Logs Viewer
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminEmailStats() -> Element {
    let mut days = use_signal(|| 7i64);
    let mut stats = use_resource(move || async move { server_get_email_stats(days()).await });
    let logs = use_resource(move || async move { server_get_mail_logs(100, None).await });
    let mut search = use_signal(|| String::new());
    let mut search_res: Resource<Result<Vec<panel::models::email::EmailLogEntry>, ServerFnError>> =
        use_resource(move || async move {
            let s = search();
            if s.is_empty() {
                return Ok(vec![]);
            }
            server_get_mail_logs(100, Some(s)).await
        });
    let mut ingest_msg = use_signal(|| None::<String>);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Email Statistics & Logs" }
                    p { class: "text-sm text-gray-500 mt-1",
                        "Aggregated delivery statistics and recent mail log entries."
                    }
                }
                div { class: "flex gap-2 items-center",
                    label { class: "text-sm text-gray-600", "Last" }
                    select {
                        class: "border border-gray-300 rounded-lg px-3 py-2 text-sm",
                        value: "{days}",
                        onchange: move |e| {
                            let v = e.value().parse().unwrap_or(7);
                            days.set(v);
                            stats.restart();
                        },
                        option { value: "1", "1 day" }
                        option { value: "7", selected: true, "7 days" }
                        option { value: "30", "30 days" }
                        option { value: "90", "90 days" }
                    }
                    button {
                        class: "px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm rounded-xl",
                        onclick: move |_| {
                            spawn(async move {
                                match server_ingest_mail_stats().await {
                                    Ok(msg) => ingest_msg.set(Some(msg)),
                                    Err(e) => ingest_msg.set(Some(e.to_string())),
                                }
                                stats.restart();
                            });
                        },
                        "Ingest Today's Stats"
                    }
                }
            }

            if let Some(msg) = ingest_msg() {
                div { class: "bg-blue-50 text-blue-700 p-3 rounded-lg mb-4 text-sm", "{msg}" }
            }

            // Stats table
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden mb-6",
                div { class: "px-6 py-4 border-b border-gray-100",
                    h3 { class: "font-semibold text-gray-900", "Delivery Statistics" }
                }
                match &*stats.read() {
                    Some(Ok(rows)) if !rows.is_empty() => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200/60",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Date" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Domain" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Sent" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Received" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Rejected" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Spam" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Bounced" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-100",
                                    for row in rows.iter() {
                                        tr { class: "hover:bg-gray-50/50",
                                            td { class: "px-4 py-3 text-gray-700", "{row.stat_date}" }
                                            td { class: "px-4 py-3 text-gray-500", "{row.domain.as_deref().unwrap_or(\"—\")}" }
                                            td { class: "px-4 py-3 text-right text-green-600 font-medium", "{row.sent_count}" }
                                            td { class: "px-4 py-3 text-right text-blue-600 font-medium", "{row.received_count}" }
                                            td { class: "px-4 py-3 text-right text-red-500 font-medium", "{row.rejected_count}" }
                                            td { class: "px-4 py-3 text-right text-yellow-600 font-medium", "{row.spam_count}" }
                                            td { class: "px-4 py-3 text-right text-orange-500 font-medium", "{row.bounced_count}" }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        div { class: "py-10 text-center text-gray-400 text-sm",
                            "No statistics recorded yet. Click \"Ingest Today's Stats\" to parse the mail log."
                        }
                    },
                    Some(Err(e)) => rsx! { div { class: "p-6 text-red-500 text-sm", "{e}" } },
                    None => rsx! { div { class: "p-6 text-gray-400 text-sm", "Loading..." } },
                }
            }

            // Log viewer
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                div { class: "px-6 py-4 border-b border-gray-100 flex items-center gap-4",
                    h3 { class: "font-semibold text-gray-900 shrink-0", "Mail Log" }
                    input {
                        r#type: "text",
                        placeholder: "Filter logs (queue-id, domain, address…)",
                        class: "flex-1 border border-gray-300 rounded-lg px-3 py-1.5 text-sm",
                        value: "{search}",
                        oninput: move |e| {
                            search.set(e.value());
                            search_res.restart();
                        },
                    }
                }
                {
                    let display_logs = if search().is_empty() {
                        &*logs.read()
                    } else {
                        &*search_res.read()
                    };
                    match display_logs {
                        Some(Ok(entries)) if !entries.is_empty() => rsx! {
                            div { class: "overflow-x-auto max-h-96 overflow-y-auto",
                                table { class: "w-full text-xs font-mono",
                                    thead { class: "bg-gray-50 border-b border-gray-200/60 sticky top-0",
                                        tr {
                                            th { class: "px-4 py-2 text-left text-gray-500", "Time" }
                                            th { class: "px-4 py-2 text-left text-gray-500", "Process" }
                                            th { class: "px-4 py-2 text-left text-gray-500", "Queue ID" }
                                            th { class: "px-4 py-2 text-left text-gray-500", "Message" }
                                        }
                                    }
                                    tbody { class: "divide-y divide-gray-100",
                                        for entry in entries.iter() {
                                            tr { class: "hover:bg-gray-50/30",
                                                td { class: "px-4 py-1.5 text-gray-400 whitespace-nowrap", "{entry.timestamp}" }
                                                td { class: "px-4 py-1.5 text-blue-600 whitespace-nowrap", "{entry.process}" }
                                                td { class: "px-4 py-1.5 text-gray-500", "{entry.queue_id}" }
                                                td { class: "px-4 py-1.5 text-gray-700", "{entry.message}" }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Some(Ok(_)) => rsx! {
                            div { class: "py-8 text-center text-gray-400 text-sm", "No log entries found." }
                        },
                        Some(Err(e)) => rsx! { div { class: "p-4 text-red-500 text-sm", "{e}" } },
                        None => rsx! { div { class: "p-4 text-gray-400 text-sm", "Loading..." } },
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Email Debugger
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminEmailDebug() -> Element {
    let mut target_domain = use_signal(|| String::new());
    let mut result: Signal<Option<panel::models::email::EmailDebugResult>> = use_signal(|| None);
    let mut running = use_signal(|| false);
    let mut debug_error = use_signal(|| None::<String>);

    let mut do_debug = move || {
        let domain = target_domain().trim().to_string();
        if domain.is_empty() {
            return;
        }
        result.set(None);
        debug_error.set(None);
        running.set(true);
        spawn(async move {
            match server_debug_email(domain).await {
                Ok(r) => result.set(Some(r)),
                Err(e) => debug_error.set(Some(e.to_string())),
            }
            running.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-3xl",
            div { class: "mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Email Debugger" }
                p { class: "text-sm text-gray-500 mt-1",
                    "Check MX, SPF, DKIM, and DMARC records for a domain. "
                    "Also probes the primary MX host for SMTP reachability."
                }
            }

            div { class: "flex gap-3 mb-6",
                input {
                    r#type: "text",
                    placeholder: "example.com",
                    class: "flex-1 border border-gray-300 rounded-xl px-4 py-2.5 text-sm",
                    value: "{target_domain}",
                    oninput: move |e| target_domain.set(e.value()),
                    onkeydown: move |e| {
                        if e.key() == Key::Enter {
                            do_debug();
                        }
                    },
                }
                button {
                    class: "px-5 py-2.5 bg-rose-500 hover:bg-rose-600 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50",
                    disabled: running() || target_domain().is_empty(),
                    onclick: move |_| do_debug(),
                    if running() {
                        div { class: "flex items-center gap-2",
                            Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                            "Running…"
                        }
                    } else {
                        "Run Diagnostics"
                    }
                }
            }

            if let Some(err) = debug_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-xl mb-4 text-sm", "{err}" }
            }

            if let Some(res) = result() {
                div { class: "space-y-4",
                    // Overview
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                        h3 { class: "font-semibold text-gray-900 mb-4 flex items-center gap-2",
                            Icon { name: "search", class: "w-4 h-4 text-gray-400".to_string() }
                            "Results for {res.target}"
                        }
                        div { class: "grid grid-cols-2 gap-4",
                            // MX reachable
                            div { class: "flex items-center gap-2",
                                div { class: if res.mx_reachable { "w-2 h-2 rounded-full bg-green-500" } else { "w-2 h-2 rounded-full bg-red-400" } }
                                span { class: "text-sm text-gray-700", "MX Reachable" }
                            }
                            // SPF
                            div { class: "flex items-center gap-2",
                                div { class: if res.spf_record.is_some() { "w-2 h-2 rounded-full bg-green-500" } else { "w-2 h-2 rounded-full bg-yellow-400" } }
                                span { class: "text-sm text-gray-700", "SPF Record" }
                            }
                            // DKIM
                            div { class: "flex items-center gap-2",
                                div { class: if res.dkim_record.is_some() { "w-2 h-2 rounded-full bg-green-500" } else { "w-2 h-2 rounded-full bg-yellow-400" } }
                                span { class: "text-sm text-gray-700", "DKIM Record" }
                            }
                            // DMARC
                            div { class: "flex items-center gap-2",
                                div { class: if res.dmarc_record.is_some() { "w-2 h-2 rounded-full bg-green-500" } else { "w-2 h-2 rounded-full bg-yellow-400" } }
                                span { class: "text-sm text-gray-700", "DMARC Record" }
                            }
                        }
                    }

                    // MX Records
                    if !res.mx_records.is_empty() {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5",
                            h4 { class: "font-medium text-gray-800 mb-3 text-sm uppercase tracking-wide", "MX Records" }
                            div { class: "space-y-1",
                                for mx in res.mx_records.iter() {
                                    p { class: "font-mono text-sm text-gray-700 bg-gray-50 rounded px-3 py-1.5", "{mx}" }
                                }
                            }
                            if let Some(banner) = &res.smtp_banner {
                                p { class: "text-xs text-gray-500 mt-2 font-mono", "SMTP: {banner}" }
                            }
                        }
                    }

                    // DNS records
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 space-y-4",
                        h4 { class: "font-medium text-gray-800 text-sm uppercase tracking-wide", "DNS Records" }
                        for (label, val) in [
                            ("SPF", res.spf_record.as_deref()),
                            ("DKIM (default)", res.dkim_record.as_deref()),
                            ("DMARC", res.dmarc_record.as_deref()),
                        ] {
                            div {
                                p { class: "text-xs font-semibold text-gray-500 mb-1", "{label}" }
                                if let Some(v) = val {
                                    p { class: "font-mono text-xs text-gray-700 bg-gray-50 rounded px-3 py-2 break-all", "{v}" }
                                } else {
                                    p { class: "text-xs text-red-400 italic", "Not found" }
                                }
                            }
                        }
                    }

                    // Notes / recommendations
                    if !res.notes.is_empty() {
                        div { class: "bg-amber-50 border border-amber-200 rounded-2xl p-5",
                            h4 { class: "font-medium text-amber-800 mb-3 text-sm flex items-center gap-2",
                                Icon { name: "alert-triangle", class: "w-4 h-4".to_string() }
                                "Recommendations"
                            }
                            ul { class: "space-y-2",
                                for note in res.notes.iter() {
                                    li { class: "text-sm text-amber-700 flex items-start gap-2",
                                        span { class: "mt-1 shrink-0", "•" }
                                        "{note}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn PageNotFound(route: Vec<String>) -> Element {
    let not_found_path = route.join("/");
    rsx! {
        div { class: "flex items-center justify-center h-screen",
            div { class: "text-center",
                h1 { class: "text-4xl font-bold text-gray-900 mb-2", "404" }
                p { class: "text-gray-600 mb-4", "Page not found: /{not_found_path}" }
                Link {
                    to: Route::Login {},
                    class: "text-rose-500 hover:text-rose-600",
                    "← Back to login"
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Firewall (UFW)
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminFirewall() -> Element {
    let mut status_res = use_resource(move || async move { server_ufw_get_status().await });
    let mut rules_res = use_resource(move || async move { server_ufw_get_numbered_rules().await });

    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut ok_msg = use_signal(|| None::<String>);

    // quick-add form
    let mut add_action = use_signal(|| "allow".to_string());
    let mut add_port = use_signal(|| String::new());
    let mut add_from = use_signal(|| String::new());
    let mut add_proto = use_signal(|| "tcp".to_string());
    let mut add_comment = use_signal(|| String::new());

    // ip-block form
    let mut block_ip = use_signal(|| String::new());

    // import textarea
    let mut import_text = use_signal(|| String::new());
    let mut show_import = use_signal(|| false);

    let mut refresh = move || {
        status_res.restart();
        rules_res.restart();
    };

    let do_enable = {
        move |_| {
            error.set(None);
            ok_msg.set(None);
            busy.set(true);
            spawn(async move {
                match server_ufw_enable().await {
                    Ok(()) => {
                        ok_msg.set(Some("UFW enabled.".to_string()));
                        refresh();
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
                busy.set(false);
            });
        }
    };

    let do_disable = move |_| {
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_disable().await {
                Ok(()) => {
                    ok_msg.set(Some("UFW disabled.".to_string()));
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let do_reload = move |_| {
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_reload().await {
                Ok(()) => {
                    ok_msg.set(Some("UFW reloaded.".to_string()));
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let do_add_rule = move |_| {
        let port = add_port();
        let from = if add_from().is_empty() {
            None
        } else {
            Some(add_from())
        };
        let comment = if add_comment().is_empty() {
            None
        } else {
            Some(add_comment())
        };
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_add_rule(
                add_action(),
                "in".to_string(),
                Some(add_proto()),
                from,
                if port.is_empty() { None } else { Some(port) },
                comment,
            )
            .await
            {
                Ok(()) => {
                    ok_msg.set(Some("Rule added.".to_string()));
                    add_port.set(String::new());
                    add_from.set(String::new());
                    add_comment.set(String::new());
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let do_block_ip = move |_| {
        let ip = block_ip();
        if ip.is_empty() {
            return;
        }
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_block_ip(ip.clone()).await {
                Ok(()) => {
                    ok_msg.set(Some(format!("Blocked {ip}.")));
                    block_ip.set(String::new());
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let do_import = move |_| {
        let content = import_text();
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_import_rules(content).await {
                Ok(()) => {
                    ok_msg.set(Some("Rules imported.".to_string()));
                    show_import.set(false);
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-5xl space-y-6",
            // Header
            div { class: "flex items-center justify-between",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Firewall (UFW)" }
                    p { class: "text-sm text-gray-500 mt-1", "Manage UFW rules, default policies, and IP blocks." }
                }
                div { class: "flex gap-2",
                    button {
                        class: "px-3 py-2 text-sm font-medium rounded-lg bg-white border border-gray-200 hover:bg-gray-50 transition-colors",
                        onclick: do_reload,
                        disabled: busy(),
                        "Reload"
                    }
                    button {
                        class: "px-3 py-2 text-sm font-medium rounded-lg bg-green-600 text-white hover:bg-green-700 transition-colors",
                        onclick: do_enable,
                        disabled: busy(),
                        "Enable UFW"
                    }
                    button {
                        class: "px-3 py-2 text-sm font-medium rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors",
                        onclick: do_disable,
                        disabled: busy(),
                        "Disable UFW"
                    }
                }
            }

            // Feedback
            if let Some(msg) = ok_msg() {
                div { class: "bg-green-50 text-green-700 px-4 py-3 rounded-lg text-sm", "{msg}" }
            }
            if let Some(err) = error() {
                div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }

            // Status card
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                h3 { class: "text-sm font-semibold text-gray-700 mb-3", "Status" }
                match &*status_res.read() {
                    Some(Ok(s)) => rsx! {
                        div { class: "flex flex-wrap gap-4 text-sm",
                            div {
                                span { class: "text-gray-400", "State: " }
                                span { class: if s.active { "text-green-600 font-semibold" } else { "text-red-600 font-semibold" },
                                    if s.active { "ACTIVE" } else { "INACTIVE" }
                                }
                            }
                            div {
                                span { class: "text-gray-400", "Default incoming: " }
                                span { class: "font-medium", "{s.default_incoming}" }
                            }
                            div {
                                span { class: "text-gray-400", "Default outgoing: " }
                                span { class: "font-medium", "{s.default_outgoing}" }
                            }
                            div {
                                span { class: "text-gray-400", "Logging: " }
                                span { class: "font-medium", "{s.logging}" }
                            }
                        }
                    },
                    Some(Err(e)) => {
                        let msg = e.to_string();
                        if msg.contains("not installed") {
                            rsx! {
                                div { class: "flex items-center gap-2 text-sm text-amber-700 bg-amber-50 rounded-lg p-3",
                                    Icon { name: "alert-triangle", class: "w-4 h-4 shrink-0".to_string() }
                                    span { "UFW is not installed. Install it with: "
                                        code { class: "font-mono bg-amber-100 px-1 rounded", "apt install ufw" }
                                    }
                                }
                            }
                        } else {
                            rsx! { p { class: "text-sm text-red-500", "{msg}" } }
                        }
                    },
                    None => rsx! { p { class: "text-sm text-gray-400", "Loading..." } },
                }
            }

            // Quick-add rule + IP block side-by-side
            div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                // Add rule
                div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                    h3 { class: "text-sm font-semibold text-gray-700 mb-3", "Add Rule" }
                    div { class: "space-y-3",
                        div { class: "grid grid-cols-2 gap-2",
                            select {
                                class: "border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                value: add_action(),
                                oninput: move |e| add_action.set(e.value()),
                                option { value: "allow", "Allow" }
                                option { value: "deny", "Deny" }
                                option { value: "reject", "Reject" }
                                option { value: "limit", "Limit" }
                            }
                            select {
                                class: "border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                value: add_proto(),
                                oninput: move |e| add_proto.set(e.value()),
                                option { value: "tcp", "TCP" }
                                option { value: "udp", "UDP" }
                                option { value: "any", "Any" }
                            }
                        }
                        input {
                            class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                            placeholder: "Port (e.g. 80, 443, 8080:8090)",
                            value: add_port(),
                            oninput: move |e| add_port.set(e.value()),
                        }
                        input {
                            class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                            placeholder: "From IP/CIDR (leave blank for any)",
                            value: add_from(),
                            oninput: move |e| add_from.set(e.value()),
                        }
                        input {
                            class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                            placeholder: "Comment (optional)",
                            value: add_comment(),
                            oninput: move |e| add_comment.set(e.value()),
                        }
                        button {
                            class: "w-full py-2 text-sm font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 transition-colors disabled:opacity-50",
                            onclick: do_add_rule,
                            disabled: busy(),
                            "Add Rule"
                        }
                    }
                }

                // IP block
                div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                    h3 { class: "text-sm font-semibold text-gray-700 mb-3", "One-Click IP Block" }
                    p { class: "text-xs text-gray-400 mb-3", "Immediately deny all traffic from an IP or CIDR range." }
                    div { class: "space-y-3",
                        input {
                            class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                            placeholder: "IP address or CIDR (e.g. 1.2.3.4 or 1.2.3.0/24)",
                            value: block_ip(),
                            oninput: move |e| block_ip.set(e.value()),
                        }
                        button {
                            class: "w-full py-2 text-sm font-medium bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors disabled:opacity-50",
                            onclick: do_block_ip,
                            disabled: busy() || block_ip().is_empty(),
                            "Block IP / CIDR"
                        }
                    }

                    // Export / Import
                    div { class: "mt-5 pt-5 border-t border-gray-100",
                        h4 { class: "text-sm font-semibold text-gray-700 mb-2", "Export / Import Rules" }
                        div { class: "flex gap-2 flex-wrap",
                            button {
                                class: "px-3 py-1.5 text-xs font-medium bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors",
                                onclick: move |_| {
                                    spawn(async move {
                                        match server_ufw_export_rules().await {
                                            Ok(rules) => ok_msg.set(Some(format!("Exported {} chars. Copy from console.", rules.len()))),
                                            Err(e) => error.set(Some(e.to_string())),
                                        }
                                    });
                                },
                                "Export"
                            }
                            button {
                                class: "px-3 py-1.5 text-xs font-medium bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors",
                                onclick: move |_| show_import.set(!show_import()),
                                "Import"
                            }
                        }
                        if show_import() {
                            div { class: "mt-3 space-y-2",
                                textarea {
                                    class: "w-full h-32 border border-gray-200 rounded-lg px-3 py-2 text-xs font-mono",
                                    placeholder: "Paste iptables-restore format rules here…",
                                    value: import_text(),
                                    oninput: move |e| import_text.set(e.value()),
                                }
                                button {
                                    class: "w-full py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50",
                                    onclick: do_import,
                                    disabled: busy() || import_text().is_empty(),
                                    "Apply Import"
                                }
                            }
                        }
                    }
                }
            }

            // Rules table
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden",
                div { class: "px-5 py-4 border-b border-gray-100 flex items-center justify-between",
                    h3 { class: "text-sm font-semibold text-gray-700", "Current Rules" }
                    button {
                        class: "text-xs text-gray-400 hover:text-gray-600",
                        onclick: move |_| rules_res.restart(),
                        "Refresh"
                    }
                }
                match &*rules_res.read() {
                    Some(Ok(rules)) if rules.is_empty() => rsx! {
                        p { class: "text-sm text-gray-400 px-5 py-8 text-center", "No rules configured." }
                    },
                    Some(Ok(rules)) => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead {
                                    tr { class: "text-xs text-gray-400 uppercase tracking-wide bg-gray-50",
                                        th { class: "px-4 py-3 text-left", "#" }
                                        th { class: "px-4 py-3 text-left", "Action" }
                                        th { class: "px-4 py-3 text-left", "From" }
                                        th { class: "px-4 py-3 text-left", "Port" }
                                        th { class: "px-4 py-3 text-left", "Proto" }
                                        th { class: "px-4 py-3 text-left", "Comment" }
                                        th { class: "px-4 py-3" }
                                    }
                                }
                                tbody {
                                    for rule in rules.iter() {
                                        {
                                            let num = rule.number;
                                            let action_class = match rule.action.to_lowercase().as_str() {
                                                "allow" => "text-green-600",
                                                "deny" | "reject" => "text-red-600",
                                                _ => "text-yellow-600",
                                            };
                                            rsx! {
                                                tr { class: "border-t border-gray-50 hover:bg-gray-50/50",
                                                    td { class: "px-4 py-3 text-gray-400", "{num}" }
                                                    td { class: "px-4 py-3 font-semibold {action_class}", "{rule.action}" }
                                                    td { class: "px-4 py-3 font-mono text-xs", "{rule.from}" }
                                                    td { class: "px-4 py-3 font-mono text-xs", "{rule.to}" }
                                                    td { class: "px-4 py-3 text-gray-500", "-" }
                                                    td { class: "px-4 py-3 text-gray-400 text-xs", "" }
                                                    td { class: "px-4 py-3",
                                                        button {
                                                            class: "text-red-400 hover:text-red-600 transition-colors",
                                                            title: "Delete rule",
                                                            onclick: {
                                                                move |_| {
                                                                    error.set(None); ok_msg.set(None);
                                                                    spawn(async move {
                                                                        match server_ufw_delete_rule(num).await {
                                                                            Ok(()) => { ok_msg.set(Some(format!("Rule #{num} deleted."))); refresh(); }
                                                                            Err(e) => error.set(Some(e.to_string())),
                                                                        }
                                                                    });
                                                                }
                                                            },
                                                            Icon { name: "trash-2", class: "w-4 h-4".to_string() }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => {
                        let msg = e.to_string();
                        if msg.contains("not installed") {
                            rsx! {
                                div { class: "flex items-center gap-2 text-sm text-amber-700 bg-amber-50 rounded-lg px-5 py-4",
                                    Icon { name: "alert-triangle", class: "w-4 h-4 shrink-0".to_string() }
                                    span { "UFW is not installed. No rules to display." }
                                }
                            }
                        } else {
                            rsx! { p { class: "text-sm text-red-500 px-5 py-4", "{msg}" } }
                        }
                    },
                    None => rsx! { p { class: "text-sm text-gray-400 px-5 py-4", "Loading..." } },
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin WAF (ModSecurity)
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminWaf() -> Element {
    let mut status_res = use_resource(move || async move { server_modsec_get_status().await });
    let mut log_res =
        use_resource(move || async move { server_modsec_get_audit_entries(100).await });

    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut ok_msg = use_signal(|| None::<String>);
    let mut engine_mode = use_signal(|| "Off".to_string());

    use_effect(move || {
        if let Some(Ok(ref s)) = *status_res.read() {
            engine_mode.set(s.engine_mode.clone());
        }
    });

    rsx! {
        div { class: "p-6 lg:p-8 max-w-5xl space-y-6",
            div { class: "flex items-center justify-between",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "WAF / ModSecurity" }
                    p { class: "text-sm text-gray-500 mt-1", "Web application firewall protecting all hosted sites." }
                }
                button {
                    class: "px-3 py-2 text-sm font-medium rounded-lg bg-white border border-gray-200 hover:bg-gray-50",
                    onclick: move |_| { status_res.restart(); log_res.restart(); },
                    "Refresh"
                }
            }

            if let Some(msg) = ok_msg() {
                div { class: "bg-green-50 text-green-700 px-4 py-3 rounded-lg text-sm", "{msg}" }
            }
            if let Some(err) = error() {
                div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }

            // Status + install card
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                h3 { class: "text-sm font-semibold text-gray-700 mb-4", "ModSecurity Status" }
                match &*status_res.read() {
                    Some(Ok(s)) => rsx! {
                        div { class: "space-y-4",
                            div { class: "flex flex-wrap gap-4 text-sm",
                                div {
                                    span { class: "text-gray-400", "Installed: " }
                                    span { class: if s.installed { "text-green-600 font-semibold" } else { "text-red-500 font-semibold" },
                                        if s.installed { "Yes" } else { "No" }
                                    }
                                }
                                div {
                                    span { class: "text-gray-400", "Engine: " }
                                    span { class: "font-semibold", "{s.engine_mode}" }
                                }
                                div {
                                    span { class: "text-gray-400", "OWASP CRS: " }
                                    span { class: if s.owasp_installed { "text-green-600" } else { "text-gray-400" },
                                        if s.owasp_installed { "Installed" } else { "Not installed" }
                                    }
                                }
                                div {
                                    span { class: "text-gray-400", "Comodo WAF: " }
                                    span { class: if s.comodo_installed { "text-green-600" } else { "text-gray-400" },
                                        if s.comodo_installed { "Installed" } else { "Not installed" }
                                    }
                                }
                                div {
                                    span { class: "text-gray-400", "Active rules: " }
                                    span { class: "font-medium", "{s.rules_count}" }
                                }
                            }

                            // Engine mode selector
                            if s.installed {
                                div { class: "flex flex-wrap items-center gap-3",
                                    span { class: "text-sm text-gray-600 font-medium", "Engine mode:" }
                                    for mode in ["On", "DetectionOnly", "Off"] {
                                        {
                                            let is_sel = engine_mode() == mode;
                                            rsx! {
                                                button {
                                                    class: if is_sel {
                                                        "px-4 py-1.5 text-xs font-semibold rounded-full bg-rose-600 text-white"
                                                    } else {
                                                        "px-4 py-1.5 text-xs font-semibold rounded-full bg-gray-100 text-gray-600 hover:bg-gray-200"
                                                    },
                                                    onclick: {
                                                        let mode_str = mode.to_string();
                                                        move |_| {
                                                            let m = mode_str.clone();
                                                            engine_mode.set(m.clone());
                                                            error.set(None); ok_msg.set(None); busy.set(true);
                                                            spawn(async move {
                                                                match server_modsec_set_engine_mode(m.clone()).await {
                                                                    Ok(()) => { ok_msg.set(Some(format!("Engine mode set to {m}."))); status_res.restart(); log_res.restart(); }
                                                                    Err(e) => error.set(Some(e.to_string())),
                                                                }
                                                                busy.set(false);
                                                            });
                                                        }
                                                    },
                                                    "{mode}"
                                                }
                                            }
                                        }
                                    }
                                }

                                // Rule packs
                                div { class: "grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2",
                                    div { class: "border border-gray-100 rounded-xl p-4",
                                        div { class: "flex items-center justify-between mb-2",
                                            div {
                                                p { class: "text-sm font-semibold text-gray-800", "OWASP Core Rule Set" }
                                                p { class: "text-xs text-gray-400", "Industry-standard protection against OWASP Top 10" }
                                            }
                                        }
                                        div { class: "flex gap-2 mt-3",
                                            if !s.owasp_installed {
                                                button {
                                                    class: "px-3 py-1.5 text-xs font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:opacity-50",
                                                    disabled: busy(),
                                                    onclick: move |_| {
                                                        error.set(None); ok_msg.set(None); busy.set(true);
                                                        spawn(async move {
                                                            match server_modsec_install_owasp().await {
                                                                Ok(()) => { ok_msg.set(Some("OWASP CRS installed.".to_string())); status_res.restart(); log_res.restart(); }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                            busy.set(false);
                                                        });
                                                    },
                                                    "Install OWASP CRS"
                                                }
                                            } else {
                                                button {
                                                    class: "px-3 py-1.5 text-xs font-medium bg-green-100 text-green-700 rounded-lg hover:bg-red-100 hover:text-red-700 disabled:opacity-50",
                                                    disabled: busy(),
                                                    onclick: move |_| {
                                                        error.set(None); ok_msg.set(None); busy.set(true);
                                                        spawn(async move {
                                                            match server_modsec_set_ruleset_enabled(panel::models::security::ModSecRuleSet::Owasp, false).await {
                                                                Ok(()) => { ok_msg.set(Some("OWASP CRS disabled.".to_string())); status_res.restart(); log_res.restart(); }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                            busy.set(false);
                                                        });
                                                    },
                                                    "Disable OWASP CRS"
                                                }
                                            }
                                        }
                                    }
                                    div { class: "border border-gray-100 rounded-xl p-4",
                                        div { class: "flex items-center justify-between mb-2",
                                            div {
                                                p { class: "text-sm font-semibold text-gray-800", "Comodo WAF Rules" }
                                                p { class: "text-xs text-gray-400", "Additional XSS, SQLi, and traversal protections" }
                                            }
                                        }
                                        div { class: "flex gap-2 mt-3",
                                            if !s.comodo_installed {
                                                button {
                                                    class: "px-3 py-1.5 text-xs font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50",
                                                    disabled: busy(),
                                                    onclick: move |_| {
                                                        error.set(None); ok_msg.set(None); busy.set(true);
                                                        spawn(async move {
                                                            match server_modsec_install_comodo().await {
                                                                Ok(()) => { ok_msg.set(Some("Comodo WAF installed.".to_string())); status_res.restart(); log_res.restart(); }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                            busy.set(false);
                                                        });
                                                    },
                                                    "Install Comodo WAF"
                                                }
                                            } else {
                                                button {
                                                    class: "px-3 py-1.5 text-xs font-medium bg-green-100 text-green-700 rounded-lg hover:bg-red-100 hover:text-red-700 disabled:opacity-50",
                                                    disabled: busy(),
                                                    onclick: move |_| {
                                                        error.set(None); ok_msg.set(None); busy.set(true);
                                                        spawn(async move {
                                                            match server_modsec_set_ruleset_enabled(panel::models::security::ModSecRuleSet::Comodo, false).await {
                                                                Ok(()) => { ok_msg.set(Some("Comodo WAF disabled.".to_string())); status_res.restart(); log_res.restart(); }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                            busy.set(false);
                                                        });
                                                    },
                                                    "Disable Comodo WAF"
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                button {
                                    class: "px-4 py-2 text-sm font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:opacity-50",
                                    disabled: busy(),
                                    onclick: move |_| {
                                        error.set(None); ok_msg.set(None); busy.set(true);
                                        spawn(async move {
                                            match server_modsec_install().await {
                                                Ok(()) => { ok_msg.set(Some("ModSecurity installed.".to_string())); status_res.restart(); log_res.restart(); }
                                                Err(e) => error.set(Some(e.to_string())),
                                            }
                                            busy.set(false);
                                        });
                                    },
                                    "Install ModSecurity"
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "text-sm text-red-500", "{e}" } },
                    None => rsx! { p { class: "text-sm text-gray-400", "Loading..." } },
                }
            }

            // Audit log
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden",
                div { class: "px-5 py-4 border-b border-gray-100",
                    h3 { class: "text-sm font-semibold text-gray-700", "Audit Log (last 100 events)" }
                }
                match &*log_res.read() {
                    Some(Ok(entries)) if entries.is_empty() => rsx! {
                        p { class: "text-sm text-gray-400 px-5 py-8 text-center", "No audit log entries found." }
                    },
                    Some(Ok(entries)) => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead {
                                    tr { class: "text-xs text-gray-400 uppercase tracking-wide bg-gray-50",
                                        th { class: "px-4 py-3 text-left", "Time" }
                                        th { class: "px-4 py-3 text-left", "Client IP" }
                                        th { class: "px-4 py-3 text-left", "Method" }
                                        th { class: "px-4 py-3 text-left", "URI" }
                                        th { class: "px-4 py-3 text-left", "Status" }
                                        th { class: "px-4 py-3 text-left", "Severity" }
                                        th { class: "px-4 py-3 text-left", "Rules" }
                                    }
                                }
                                tbody {
                                    for entry in entries.iter() {
                                        tr { class: "border-t border-gray-50 hover:bg-gray-50/50",
                                            td { class: "px-4 py-3 text-xs text-gray-400 whitespace-nowrap", "{entry.timestamp}" }
                                            td { class: "px-4 py-3 font-mono text-xs", "{entry.client_ip}" }
                                            td { class: "px-4 py-3 text-xs font-medium", "{entry.method}" }
                                            td { class: "px-4 py-3 text-xs max-w-xs truncate", "{entry.uri}" }
                                            td { class: "px-4 py-3 text-xs", "{entry.status}" }
                                            td { class: "px-4 py-3 text-xs font-semibold text-red-600", "{entry.severity}" }
                                            td { class: "px-4 py-3 text-xs text-gray-500", "{entry.matched_rules.join(\", \")}" }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "text-sm text-red-500 px-5 py-4", "{e}" } },
                    None => rsx! { p { class: "text-sm text-gray-400 px-5 py-4", "Loading..." } },
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin ClamAV
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminClamAv() -> Element {
    let db_res = use_resource(move || async move { server_clamav_get_db_info().await });

    let mut scan_path = use_signal(|| "/var/www".to_string());
    let mut scanning = use_signal(|| false);
    let mut scan_result_signal =
        use_signal(|| None::<Result<panel::models::security::ClamScanReport, String>>);
    let mut updating = use_signal(|| false);
    let mut update_output = use_signal(|| None::<String>);
    let mut error = use_signal(|| None::<String>);

    let do_update_db = move |_| {
        error.set(None);
        update_output.set(None);
        updating.set(true);
        spawn(async move {
            match server_clamav_update_db().await {
                Ok(()) => {
                    update_output.set(Some("ClamAV database updated successfully.".to_string()))
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            updating.set(false);
        });
    };

    let do_scan = move |_| {
        let path = scan_path();
        error.set(None);
        scan_result_signal.set(None);
        scanning.set(true);
        spawn(async move {
            match server_clamav_scan(path).await {
                Ok(r) => scan_result_signal.set(Some(Ok(r))),
                Err(e) => scan_result_signal.set(Some(Err(e.to_string()))),
            }
            scanning.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-4xl space-y-6",
            div {
                h2 { class: "text-2xl font-bold text-gray-900", "ClamAV Antivirus" }
                p { class: "text-sm text-gray-500 mt-1", "Scan files for malware and manage the virus database." }
            }

            if let Some(err) = error() {
                div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }

            // DB info card
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                h3 { class: "text-sm font-semibold text-gray-700 mb-4", "Virus Database" }
                match &*db_res.read() {
                    Some(Ok(info)) => rsx! {
                        div { class: "flex flex-wrap gap-6 text-sm mb-4",
                            div {
                                span { class: "text-gray-400", "Version: " }
                                span { class: "font-medium", "{info.version}" }
                            }
                            div {
                                span { class: "text-gray-400", "Signatures: " }
                                span { class: "font-medium", "{info.signatures}" }
                            }
                            div {
                                span { class: "text-gray-400", "Database date: " }
                                span { class: "font-medium", "{info.database_date}" }
                            }
                        }
                    },
                    Some(Err(e)) => {
                        let msg = e.to_string();
                        if msg.contains("not installed") {
                            rsx! {
                                div { class: "flex items-center gap-2 text-sm text-amber-700 bg-amber-50 rounded-lg p-3 mb-4",
                                    Icon { name: "alert-triangle", class: "w-4 h-4 shrink-0".to_string() }
                                    span { "ClamAV is not installed. Install it with: "
                                        code { class: "font-mono bg-amber-100 px-1 rounded", "apt install clamav clamav-daemon" }
                                    }
                                }
                            }
                        } else {
                            rsx! { p { class: "text-sm text-red-500 mb-4", "{msg}" } }
                        }
                    },
                    None => rsx! { p { class: "text-sm text-gray-400 mb-4", "Loading..." } },
                }
                button {
                    class: "px-4 py-2 text-sm font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:opacity-50 flex items-center gap-2",
                    onclick: do_update_db,
                    disabled: updating(),
                    if updating() {
                        Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                        "Updating…"
                    } else {
                        Icon { name: "refresh-cw", class: "w-4 h-4".to_string() }
                        "Update Database (freshclam)"
                    }
                }
                if let Some(out) = update_output() {
                    pre { class: "mt-4 bg-gray-900 text-green-400 text-xs p-4 rounded-xl overflow-x-auto max-h-48", "{out}" }
                }
            }

            // Scan card
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                h3 { class: "text-sm font-semibold text-gray-700 mb-4", "Scan Files" }
                p { class: "text-xs text-gray-400 mb-3", "Only paths under /var/www, /home, /tmp, /srv, and /opt are allowed." }
                div { class: "flex gap-2",
                    input {
                        class: "flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono",
                        value: scan_path(),
                        oninput: move |e| scan_path.set(e.value()),
                    }
                    button {
                        class: "px-4 py-2 text-sm font-medium bg-gray-900 text-white rounded-lg hover:bg-gray-800 disabled:opacity-50 flex items-center gap-2 whitespace-nowrap",
                        onclick: do_scan,
                        disabled: scanning(),
                        if scanning() {
                            Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                            "Scanning…"
                        } else {
                            Icon { name: "search", class: "w-4 h-4".to_string() }
                            "Start Scan"
                        }
                    }
                }

                match scan_result_signal() {
                    Some(Ok(ref report)) => rsx! {
                        div { class: "mt-5 space-y-3",
                            div { class: "flex gap-6 text-sm",
                                div {
                                    span { class: "text-gray-400", "Files scanned: " }
                                    span { class: "font-semibold", "{report.scanned_files}" }
                                }
                                div {
                                    span { class: "text-gray-400", "Infected: " }
                                    span {
                                        class: if report.infected_files > 0 { "font-semibold text-red-600" } else { "font-semibold text-green-600" },
                                        "{report.infected_files}"
                                    }
                                }
                            }
                            if report.threats.is_empty() {
                                div { class: "bg-green-50 text-green-700 px-4 py-3 rounded-lg text-sm font-medium",
                                    "✓ No threats found."
                                }
                            } else {
                                div { class: "border border-red-100 rounded-xl overflow-hidden",
                                    div { class: "bg-red-50 px-4 py-2 text-sm font-semibold text-red-700", "Threats detected" }
                                    table { class: "w-full text-sm",
                                        thead {
                                            tr { class: "text-xs text-gray-400 uppercase bg-gray-50",
                                                th { class: "px-4 py-2 text-left", "Path" }
                                                th { class: "px-4 py-2 text-left", "Virus" }
                                            }
                                        }
                                        tbody {
                                            for threat in report.threats.iter() {
                                                tr { class: "border-t border-gray-100",
                                                    td { class: "px-4 py-2 font-mono text-xs text-red-700", "{threat.path}" }
                                                    td { class: "px-4 py-2 text-xs font-medium text-red-600", "{threat.virus_name}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(ref e)) => rsx! {
                        div { class: "mt-4 bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{e}" }
                    },
                    None => rsx! { div {} },
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin SSH Hardening
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminSshHardening() -> Element {
    let config_res = use_resource(move || async move { server_ssh_get_config().await });
    let active_res = use_resource(move || async move { server_ssh_is_hardening_active().await });

    let mut port = use_signal(|| "22".to_string());
    let mut permit_root = use_signal(|| "prohibit-password".to_string());
    let mut password_auth = use_signal(|| false);
    let mut pubkey_auth = use_signal(|| true);
    let mut max_auth_tries = use_signal(|| "3".to_string());
    let mut login_grace_time = use_signal(|| "60".to_string());
    let mut agent_fwd = use_signal(|| false);
    let mut x11_fwd = use_signal(|| false);
    let mut use_pam = use_signal(|| true);
    let mut ignore_rhosts = use_signal(|| true);
    let mut permit_empty = use_signal(|| false);
    let mut use_dns = use_signal(|| false);
    let mut banner = use_signal(|| true);
    let mut allowed_users = use_signal(|| String::new());
    let mut client_alive_interval = use_signal(|| "300".to_string());
    let mut client_alive_count_max = use_signal(|| "2".to_string());
    let mut max_sessions = use_signal(|| "4".to_string());

    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut ok_msg = use_signal(|| None::<String>);
    let mut warnings = use_signal(|| Vec::<String>::new());

    // Populate form on load
    use_effect(move || {
        if let Some(Ok(ref c)) = *config_res.read() {
            port.set(c.port.to_string());
            permit_root.set(c.permit_root_login.clone());
            password_auth.set(c.password_authentication);
            pubkey_auth.set(c.pubkey_authentication);
            max_auth_tries.set(c.max_auth_tries.to_string());
            login_grace_time.set(c.login_grace_time.to_string());
            agent_fwd.set(c.allow_agent_forwarding);
            x11_fwd.set(c.x11_forwarding);
            use_pam.set(c.use_pam);
            ignore_rhosts.set(c.ignore_rhosts);
            permit_empty.set(c.permit_empty_passwords);
            use_dns.set(c.use_dns);
            banner.set(c.banner_enabled);
            allowed_users.set(c.allowed_users.join(" "));
            client_alive_interval.set(c.client_alive_interval.to_string());
            client_alive_count_max.set(c.client_alive_count_max.to_string());
            max_sessions.set(c.max_sessions.to_string());
        }
    });

    let apply = move |_| {
        let p: u16 = port().parse().unwrap_or(22);
        let mat: u8 = max_auth_tries().parse().unwrap_or(3);
        let lgt: u16 = login_grace_time().parse().unwrap_or(60);
        let cai: u16 = client_alive_interval().parse().unwrap_or(300);
        let cac: u8 = client_alive_count_max().parse().unwrap_or(2);
        let ms: u8 = max_sessions().parse().unwrap_or(4);
        error.set(None);
        ok_msg.set(None);
        warnings.set(vec![]);
        busy.set(true);
        spawn(async move {
            match server_ssh_apply_config(panel::models::security::SshConfig {
                port: p,
                permit_root_login: permit_root(),
                password_authentication: password_auth(),
                pubkey_authentication: pubkey_auth(),
                max_auth_tries: mat,
                login_grace_time: lgt,
                allow_agent_forwarding: agent_fwd(),
                x11_forwarding: x11_fwd(),
                use_pam: use_pam(),
                ignore_rhosts: ignore_rhosts(),
                permit_empty_passwords: permit_empty(),
                use_dns: use_dns(),
                banner_enabled: banner(),
                allowed_users: allowed_users()
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect(),
                client_alive_interval: cai,
                client_alive_count_max: cac,
                max_sessions: ms,
                ..Default::default()
            })
            .await
            {
                Ok(result) => {
                    ok_msg.set(Some(result.message));
                    if !result.warnings.is_empty() {
                        warnings.set(result.warnings);
                    }
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let restore = move |_| {
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ssh_restore_backup().await {
                Ok(()) => ok_msg.set(Some("SSH configuration restored from backup.".to_string())),
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-3xl space-y-6",
            div { class: "flex items-center justify-between",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "SSH Hardening" }
                    p { class: "text-sm text-gray-500 mt-1", "Configure OpenSSH security settings. Applied via drop-in configuration." }
                }
                div { class: "flex items-center gap-3",
                    match &*active_res.read() {
                        Some(Ok(true)) => rsx! {
                            span { class: "text-xs font-semibold px-3 py-1 rounded-full bg-green-100 text-green-700", "Hardening Active" }
                        },
                        Some(Ok(false)) => rsx! {
                            span { class: "text-xs font-semibold px-3 py-1 rounded-full bg-gray-100 text-gray-500", "Default Config" }
                        },
                        _ => rsx! { span {} },
                    }
                }
            }

            if let Some(msg) = ok_msg() {
                div { class: "bg-green-50 text-green-700 px-4 py-3 rounded-lg text-sm font-medium", "{msg}" }
            }
            if let Some(err) = error() {
                div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }
            for warn in warnings().iter() {
                div { class: "bg-yellow-50 text-yellow-800 border border-yellow-200 px-4 py-3 rounded-lg text-sm", "{warn}" }
            }

            match &*config_res.read() {
                Some(Ok(_)) | None => rsx! {
                    div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-6 space-y-6",

                        // Port & Root login
                        div { class: "grid grid-cols-2 gap-4",
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "SSH Port" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "1", max: "65535",
                                    value: port(),
                                    oninput: move |e| port.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Permit Root Login" }
                                select {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    value: permit_root(),
                                    oninput: move |e| permit_root.set(e.value()),
                                    option { value: "no", "No (recommended)" }
                                    option { value: "prohibit-password", "Key-only (no password)" }
                                    option { value: "forced-commands-only", "Forced commands only" }
                                    option { value: "yes", "Yes (dangerous)" }
                                }
                            }
                        }

                        // Auth methods
                        div {
                            label { class: "block text-xs font-semibold text-gray-600 mb-2", "Authentication Methods" }
                            div { class: "space-y-2",
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: pubkey_auth(), oninput: move |e| pubkey_auth.set(e.checked()) }
                                    span { class: "text-sm", "Public key authentication (recommended)" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: password_auth(), oninput: move |e| password_auth.set(e.checked()) }
                                    span { class: "text-sm", "Password authentication" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: permit_empty(), oninput: move |e| permit_empty.set(e.checked()) }
                                    span { class: "text-sm text-red-600", "Permit empty passwords (very dangerous)" }
                                }
                            }
                        }

                        // Limits
                        div { class: "grid grid-cols-3 gap-4",
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Max Auth Tries" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "1", max: "20",
                                    value: max_auth_tries(),
                                    oninput: move |e| max_auth_tries.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Login Grace (sec)" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "10", max: "600",
                                    value: login_grace_time(),
                                    oninput: move |e| login_grace_time.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Max Sessions" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "1", max: "50",
                                    value: max_sessions(),
                                    oninput: move |e| max_sessions.set(e.value()),
                                }
                            }
                        }

                        // Keep-alive
                        div { class: "grid grid-cols-2 gap-4",
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Client Alive Interval (sec)" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "0",
                                    value: client_alive_interval(),
                                    oninput: move |e| client_alive_interval.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Client Alive Count Max" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "0", max: "10",
                                    value: client_alive_count_max(),
                                    oninput: move |e| client_alive_count_max.set(e.value()),
                                }
                            }
                        }

                        // Feature toggles
                        div {
                            label { class: "block text-xs font-semibold text-gray-600 mb-2", "Feature Flags" }
                            div { class: "grid grid-cols-2 gap-2",
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: use_pam(), oninput: move |e| use_pam.set(e.checked()) }
                                    span { class: "text-sm", "Use PAM" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: ignore_rhosts(), oninput: move |e| ignore_rhosts.set(e.checked()) }
                                    span { class: "text-sm", "Ignore .rhosts" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: use_dns(), oninput: move |e| use_dns.set(e.checked()) }
                                    span { class: "text-sm", "UseDNS (reverse lookup)" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: banner(), oninput: move |e| banner.set(e.checked()) }
                                    span { class: "text-sm", "Login banner (/etc/issue.net)" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: agent_fwd(), oninput: move |e| agent_fwd.set(e.checked()) }
                                    span { class: "text-sm", "Agent forwarding" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: x11_fwd(), oninput: move |e| x11_fwd.set(e.checked()) }
                                    span { class: "text-sm", "X11 forwarding" }
                                }
                            }
                        }

                        // AllowUsers
                        div {
                            label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "AllowUsers (space-separated, leave blank for all)" }
                            input {
                                class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                placeholder: "e.g. deploy ubuntu admin",
                                value: allowed_users(),
                                oninput: move |e| allowed_users.set(e.value()),
                            }
                        }

                        // Actions
                        div { class: "flex items-center gap-3 pt-2",
                            button {
                                class: "px-5 py-2.5 text-sm font-semibold bg-rose-600 text-white rounded-xl hover:bg-rose-700 transition-colors disabled:opacity-50",
                                onclick: apply,
                                disabled: busy(),
                                if busy() { "Applying…" } else { "Apply Configuration" }
                            }
                            button {
                                class: "px-4 py-2.5 text-sm font-medium bg-white border border-gray-200 text-gray-600 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50",
                                onclick: restore,
                                disabled: busy(),
                                "Restore Backup"
                            }
                        }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{e}" }
                },
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Backups
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
fn AdminBackups() -> Element {
    let mut stats_res = use_resource(move || async move { server_admin_get_backup_stats().await });
    let mut runs_res = use_resource(move || async move { server_admin_list_backup_runs().await });
    let mut active_tab = use_signal(|| "stats"); // "stats" | "runs"

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Backup Overview" }
                    p { class: "text-gray-500 text-sm mt-1", "Global backup stats and run history across all clients." }
                }
                button {
                    class: "p-2 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors",
                    title: "Refresh",
                    onclick: move |_| { stats_res.restart(); runs_res.restart(); },
                    Icon { name: "refresh-cw", class: "w-5 h-5".to_string() }
                }
            }

            // ── Stats cards
            match &*stats_res.read() {
                Some(Ok(st)) => rsx! {
                    div { class: "grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6",
                        BackupStatCard { label: "Schedules", value: st.total_schedules.to_string(), color: "blue" }
                        BackupStatCard { label: "Active", value: st.enabled_schedules.to_string(), color: "green" }
                        BackupStatCard { label: "Total Runs", value: st.total_runs.to_string(), color: "gray" }
                        BackupStatCard { label: "Successful", value: st.successful_runs.to_string(), color: "green" }
                        BackupStatCard { label: "Failed", value: st.failed_runs.to_string(), color: "red" }
                        BackupStatCard { label: "Total Size", value: fmt_bytes_backup(st.total_size_bytes), color: "purple" }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "mb-6 bg-red-50 rounded-2xl border border-red-200 p-4 text-red-700 text-sm", "Failed to load stats: {e}" }
                },
                None => rsx! { div { class: "mb-6 h-20 bg-gray-50 rounded-2xl animate-pulse" } },
            }

            // ── Tab bar
            div { class: "flex gap-1 bg-gray-100 rounded-xl p-1 w-fit mb-6",
                for (label, id) in [("Stats", "stats"), ("Recent Runs", "runs")] {
                    button {
                        class: if active_tab() == id {
                            "px-4 py-2 rounded-lg text-sm font-medium bg-white text-gray-900 shadow-sm"
                        } else {
                            "px-4 py-2 rounded-lg text-sm font-medium text-gray-500 hover:text-gray-700"
                        },
                        onclick: move |_| active_tab.set(id),
                        "{label}"
                    }
                }
            }

            if active_tab() == "runs" {
                match &*runs_res.read() {
                    Some(Ok(runs)) if runs.is_empty() => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center text-gray-400 text-sm",
                            "No backup runs recorded yet."
                        }
                    },
                    Some(Ok(runs)) => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Schedule ID" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Owner" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Started" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Duration" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Status" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Size" }
                                    }
                                }
                                tbody {
                                    for run in runs.iter() {
                                        AdminBackupRunRow { run: run.clone() }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "bg-red-50 rounded-2xl border border-red-200 p-4 text-red-700 text-sm", "Error: {e}" }
                    },
                    None => rsx! {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-8 text-center text-gray-400 animate-pulse text-sm", "Loading…" }
                    },
                }
            }

            if active_tab() == "stats" {
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center text-gray-400 text-sm",
                    "Select the \"Recent Runs\" tab to see all backup executions, or view per-client details from the Clients page."
                }
            }
        }
    }
}

#[component]
fn AdminBackupRunRow(run: panel::models::backup::BackupRun) -> Element {
    let (status_cls, status_label) = match run.status.as_str() {
        "success" => ("bg-green-100 text-green-700", "Success"),
        "failed" => ("bg-red-100 text-red-700", "Failed"),
        _ => ("bg-yellow-100 text-yellow-700", "Running"),
    };
    let duration = match run.finished_at {
        Some(fin) => {
            let secs = (fin - run.started_at).num_seconds();
            if secs < 60 {
                format!("{}s", secs)
            } else {
                format!("{}m {}s", secs / 60, secs % 60)
            }
        }
        None => "—".to_string(),
    };
    let size_str = run
        .size_bytes
        .map(fmt_bytes_backup)
        .unwrap_or_else(|| "—".to_string());
    let started_at_str = run.started_at.format("%b %d %H:%M:%S").to_string();

    rsx! {
        tr { class: "border-b border-gray-100 hover:bg-gray-50/40 transition-colors",
            td { class: "px-4 py-3 text-xs font-mono text-gray-500", "#{run.schedule_id}" }
            td { class: "px-4 py-3 text-xs font-mono text-gray-500", "#{run.owner_id}" }
            td { class: "px-4 py-3 text-xs font-mono text-gray-700", "{started_at_str}" }
            td { class: "px-4 py-3 text-xs text-gray-500", "{duration}" }
            td { class: "px-4 py-3",
                span { class: "px-2 py-0.5 rounded-full text-xs font-semibold {status_cls}", "{status_label}" }
                if let Some(ref err) = run.error_message {
                    p { class: "text-xs text-red-500 mt-0.5 max-w-xs truncate", title: "{err}", "{err}" }
                }
            }
            td { class: "px-4 py-3 text-xs font-mono text-gray-500", "{size_str}" }
        }
    }
}
