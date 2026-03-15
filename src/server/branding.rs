/// Branding server functions (white-label / reseller).
use crate::models::branding::ResellerBranding;
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Input for saving branding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingInput {
    pub panel_name: String,
    pub logo_path: Option<String>,
    pub accent_color: String,
    pub custom_domain: Option<String>,
    pub custom_ns1: Option<String>,
    pub custom_ns2: Option<String>,
    pub footer_text: Option<String>,
    /// One of: "Default", "Dark", "Corporate"
    pub theme_preset: Option<String>,
}

/// Get branding for the current reseller (or a specific reseller_id for admins).
#[server]
pub async fn server_get_branding(
    reseller_id: Option<i64>,
) -> Result<Option<ResellerBranding>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let target_id = match claims.role {
        crate::models::user::Role::Admin => reseller_id.unwrap_or(claims.sub),
        crate::models::user::Role::Reseller => claims.sub,
        _ => return Err(ServerFnError::new("Access denied")),
    };

    crate::db::branding::get(pool, target_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Public branding lookup by hostname — no auth required (used to theme the login page).
#[server]
pub async fn server_get_active_branding(
    hostname: String,
) -> Result<Option<ResellerBranding>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let pool = get_pool()?;

    // Sanitise: only allow valid hostname chars to prevent injection
    if !hostname
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return Ok(None);
    }

    crate::db::branding::get_by_domain(pool, &hostname)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create or update branding for the current reseller.
#[server]
pub async fn server_save_branding(input: BrandingInput) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_reseller(&claims)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    // Validate accent_color is a CSS hex colour
    if !input.accent_color.starts_with('#') || input.accent_color.len() != 7 {
        return Err(ServerFnError::new(
            "accent_color must be a 7-char hex color (e.g. #F43F5E)",
        ));
    }

    // Validate panel_name length
    let panel_name = input.panel_name.trim().to_string();
    if panel_name.is_empty() || panel_name.len() > 128 {
        return Err(ServerFnError::new("Panel name must be 1–128 characters"));
    }

    // Validate footer_text length
    if input.footer_text.as_deref().unwrap_or("").len() > 512 {
        return Err(ServerFnError::new(
            "Footer text too long (max 512 characters)",
        ));
    }

    // Validate logo_path is confined to /var/www/
    if let Some(ref path) = input.logo_path {
        if !path.is_empty() {
            crate::utils::validators::validate_safe_path(path, "/var/www/")
                .map_err(ServerFnError::new)?;
        }
    }

    // Validate custom nameservers are valid domain names
    for ns in [&input.custom_ns1, &input.custom_ns2].into_iter().flatten() {
        if !ns.is_empty() {
            crate::utils::validators::validate_domain(ns).map_err(ServerFnError::new)?;
        }
    }

    // Validate custom_domain if provided
    if let Some(ref domain) = input.custom_domain {
        if !domain.is_empty() {
            crate::utils::validators::validate_domain(domain).map_err(ServerFnError::new)?;
        }
    }

    // Validate and normalise theme_preset
    let theme_preset = match input.theme_preset.as_deref().unwrap_or("Default") {
        v @ ("Default" | "Dark" | "Corporate") => v.to_string(),
        other => {
            return Err(ServerFnError::new(format!(
                "Invalid theme_preset '{other}'. Must be Default, Dark, or Corporate"
            )))
        }
    };

    let id = crate::db::branding::upsert(
        pool,
        claims.sub,
        panel_name.clone(),
        input.logo_path,
        input.accent_color,
        input.custom_domain,
        input.custom_ns1,
        input.custom_ns2,
        input.footer_text,
        theme_preset,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "save_branding",
        Some("branding"),
        Some(id),
        Some(&panel_name),
        "Success",
        None,
    )
    .await;

    Ok(id)
}

/// Delete branding for the current reseller (reverts to default).
#[server]
pub async fn server_delete_branding() -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_reseller(&claims)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    crate::db::branding::delete(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_branding",
        Some("branding"),
        Some(claims.sub),
        None,
        "Success",
        None,
    )
    .await;

    Ok(())
}
