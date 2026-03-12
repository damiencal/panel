/// Server functions for WAF, ClamAV, and SSH hardening administration.
use crate::models::security::{
    ClamDbInfo, ClamScanReport, ModSecAuditEntry, ModSecRuleSet, ModSecStatus, SshConfig,
    SshHardeningResult,
};
#[cfg(feature = "server")]
use crate::services::{
    modsecurity::ModSecurityService, rspamd::ClamAvService, ssh_hardening::SshHardeningService,
};
use dioxus::prelude::*;

// ─── ModSecurity / WAF ───────────────────────────────────────────────────────

/// Get ModSecurity installation status and current configuration.
#[server]
pub async fn server_modsec_get_status() -> Result<ModSecStatus, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    ModSecurityService
        .get_status()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Install ModSecurity.
#[server]
pub async fn server_modsec_install() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    ModSecurityService
        .install()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "modsec_install",
        Some("security"),
        None,
        Some("ModSecurity"),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Set ModSecurity engine mode (Off / DetectionOnly / On).
#[server]
pub async fn server_modsec_set_engine_mode(mode: String) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    if !matches!(mode.as_str(), "Off" | "DetectionOnly" | "On") {
        return Err(ServerFnError::new("Invalid engine mode"));
    }

    ModSecurityService
        .set_engine_mode(&mode)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "modsec_set_engine_mode",
        Some("security"),
        None,
        Some(&mode),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Download and install OWASP Core Rule Set.
#[server]
pub async fn server_modsec_install_owasp() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    ModSecurityService
        .install_owasp_crs()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "modsec_install_owasp_crs",
        Some("security"),
        None,
        Some("OWASP CRS"),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Download and install Comodo WAF rules.
#[server]
pub async fn server_modsec_install_comodo() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    ModSecurityService
        .install_comodo_waf()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "modsec_install_comodo",
        Some("security"),
        None,
        Some("Comodo WAF"),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Enable or disable a ModSecurity rule set.
#[server]
pub async fn server_modsec_set_ruleset_enabled(
    ruleset: ModSecRuleSet,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    ModSecurityService
        .set_ruleset_enabled(&ruleset, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let name = format!("{ruleset:?} enabled={enabled}");
    audit_log(
        claims.sub,
        "modsec_set_ruleset_enabled",
        Some("security"),
        None,
        Some(&name),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Get parsed ModSecurity audit log entries.
#[server]
pub async fn server_modsec_get_audit_entries(
    limit: usize,
) -> Result<Vec<ModSecAuditEntry>, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    let safe_limit = limit.min(1000);
    ModSecurityService
        .get_audit_entries(safe_limit)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Get last N lines of the ModSecurity audit log as raw text.
#[server]
pub async fn server_modsec_get_audit_log_raw(lines: usize) -> Result<String, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    let safe_lines = lines.min(500);
    ModSecurityService
        .get_audit_log(safe_lines)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ─── ClamAV ──────────────────────────────────────────────────────────────────

/// Get ClamAV virus database information.
#[server]
pub async fn server_clamav_get_db_info() -> Result<ClamDbInfo, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    ClamAvService
        .get_db_info()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Update ClamAV virus database via `freshclam`.
#[server]
pub async fn server_clamav_update_db() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    ClamAvService
        .update_db()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "clamav_update_db",
        Some("security"),
        None,
        Some("ClamAV DB"),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Scan a path with ClamAV.
#[server]
pub async fn server_clamav_scan(path: String) -> Result<ClamScanReport, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Prevent path traversal — only allow absolute paths
    if !path.starts_with('/') {
        return Err(ServerFnError::new("Scan path must be absolute"));
    }

    let report = ClamAvService
        .scan_path(&path)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let status = if report.infected_files > 0 {
        "Threats found"
    } else {
        "Success"
    };
    audit_log(
        claims.sub,
        "clamav_scan",
        Some("security"),
        None,
        Some(&path),
        status,
        None,
    )
    .await;

    Ok(report)
}

// ─── SSH Hardening ───────────────────────────────────────────────────────────

/// Get the current (or default) SSH hardening configuration.
#[server]
pub async fn server_ssh_get_config() -> Result<SshConfig, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    SshHardeningService
        .get_config()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Apply SSH hardening configuration.
#[server]
pub async fn server_ssh_apply_config(
    config: SshConfig,
) -> Result<SshHardeningResult, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    let result = SshHardeningService
        .apply_config(&config)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let status = if result.success { "Success" } else { "Failed" };
    let err_msg = if result.success {
        None
    } else {
        Some(result.message.as_str())
    };
    audit_log(
        claims.sub,
        "ssh_apply_config",
        Some("security"),
        None,
        Some("sshd"),
        status,
        err_msg,
    )
    .await;

    Ok(result)
}

/// Restore SSH configuration from the panel backup.
#[server]
pub async fn server_ssh_restore_backup() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    SshHardeningService
        .restore_backup()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "ssh_restore_backup",
        Some("security"),
        None,
        Some("sshd"),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Check whether the panel SSH hardening drop-in is active.
#[server]
pub async fn server_ssh_is_hardening_active() -> Result<bool, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(SshHardeningService.is_hardening_active().await)
}
