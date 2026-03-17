/// Server functions for UFW firewall management.
/// All functions are admin-only and fully audit-logged.
use crate::models::firewall::{UfwStatus, UfwStatusRule};
#[cfg(feature = "server")]
use crate::services::ufw::UfwService;
use dioxus::prelude::*;

// ─── Status / lifecycle ──────────────────────────────────────────────────────

/// Get UFW status, active rules, and default policies.
#[server]
pub async fn server_ufw_get_status() -> Result<UfwStatus, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    UfwService
        .get_status()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Enable (start) UFW.
#[server]
pub async fn server_ufw_enable() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    UfwService
        .enable()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "ufw_enable",
        Some("firewall"),
        None,
        None,
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Disable (stop) UFW.
#[server]
pub async fn server_ufw_disable() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    UfwService
        .disable()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "ufw_disable",
        Some("firewall"),
        None,
        None,
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Reload UFW (apply pending rule changes without disabling protection).
#[server]
pub async fn server_ufw_reload() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    UfwService
        .reload()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "ufw_reload",
        Some("firewall"),
        None,
        None,
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Reset UFW to defaults (disables and clears all rules).
#[server]
pub async fn server_ufw_reset() -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    UfwService
        .reset()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "ufw_reset",
        Some("firewall"),
        None,
        None,
        "Success",
        None,
    )
    .await;
    Ok(())
}

// ─── Rule management ─────────────────────────────────────────────────────────

/// Get numbered rules (for delete operations).
#[server]
pub async fn server_ufw_get_numbered_rules() -> Result<Vec<UfwStatusRule>, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    UfwService
        .get_numbered_rules()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Add a new UFW rule.
#[server]
pub async fn server_ufw_add_rule(
    action: String,
    direction: String,
    protocol: Option<String>,
    from_ip: Option<String>,
    to_port: Option<String>,
    comment: Option<String>,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use crate::models::firewall::{UfwAction, UfwRule};
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    if !matches!(action.as_str(), "allow" | "deny" | "reject" | "limit") {
        return Err(ServerFnError::new("Invalid action"));
    }
    if !matches!(direction.as_str(), "in" | "out") {
        return Err(ServerFnError::new("Invalid direction"));
    }
    if let Some(ref proto) = protocol {
        if !matches!(proto.as_str(), "tcp" | "udp" | "any") {
            return Err(ServerFnError::new("Invalid protocol"));
        }
    }

    if let Some(ref c) = comment {
        if c.len() > 255 {
            return Err(ServerFnError::new(
                "Comment must be 255 characters or fewer",
            ));
        }
        if c.contains('\n') || c.contains('\r') || c.contains('\0') {
            return Err(ServerFnError::new(
                "Comment must not contain newlines or null bytes",
            ));
        }
    }

    // UFW-01: validate from_ip (must be a valid IP/CIDR or the keyword "any").
    if let Some(ref ip) = from_ip {
        let ip_lower = ip.to_lowercase();
        if ip_lower != "any" && ip_lower != "anywhere" {
            if let Some((addr, prefix)) = ip.split_once('/') {
                let prefix_len: u8 = prefix
                    .parse()
                    .map_err(|_| ServerFnError::new("Invalid CIDR prefix in from_ip"))?;
                if !crate::utils::validators::validate_ip_address(addr) || prefix_len > 128 {
                    return Err(ServerFnError::new("Invalid from_ip: not a valid IP/CIDR"));
                }
            } else if !crate::utils::validators::validate_ip_address(ip) {
                return Err(ServerFnError::new(
                    "Invalid from_ip: not a valid IP address",
                ));
            }
        }
    }

    // UFW-01: validate to_port (must be a numeric port, a port range N:M, or a
    // well-known service name consisting only of ASCII letters, digits, and '-').
    if let Some(ref port_str) = to_port {
        // Accept "N", "N:M" (UFW port range syntax), or a service name.
        let valid = if let Some((low_s, high_s)) = port_str.split_once(':') {
            match (low_s.parse::<u16>(), high_s.parse::<u16>()) {
                (Ok(low), Ok(high)) => {
                    if low == 0 {
                        return Err(ServerFnError::new("Port range must start at 1 or above"));
                    }
                    if low > high {
                        return Err(ServerFnError::new(
                            "Port range low must be ≤ high (e.g. 8000:9000)",
                        ));
                    }
                    true
                }
                _ => false,
            }
        } else if let Ok(n) = port_str.parse::<u16>() {
            n > 0
        } else {
            // Service name: only ASCII alphanumeric and hyphens, ≤ 64 chars.
            port_str.len() <= 64
                && port_str
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        if !valid {
            return Err(ServerFnError::new(
                "Invalid to_port: must be a port number (1-65535), a range (N:M), or a service name",
            ));
        }
    }

    let rule = UfwRule {
        id: None,
        number: None,
        action: action.parse::<UfwAction>().unwrap_or(UfwAction::Allow),
        direction: direction.clone(),
        protocol: protocol.clone(),
        from_ip: from_ip.clone(),
        to_port: to_port.clone(),
        comment: comment.clone(),
        created_at: None,
    };

    UfwService
        .add_rule(&rule)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Persist to DB
    let _ = sqlx::query(
        "INSERT INTO firewall_rules (action, direction, protocol, from_ip, to_port, comment, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(rule.action.as_ufw_arg())
    .bind(&rule.direction)
    .bind(&rule.protocol)
    .bind(&rule.from_ip)
    .bind(&rule.to_port)
    .bind(&rule.comment)
    .bind(claims.sub)
    .execute(pool)
    .await;

    let target_name = format!(
        "{} port={} from={}",
        action,
        to_port.as_deref().unwrap_or("*"),
        from_ip.as_deref().unwrap_or("any")
    );
    audit_log(
        claims.sub,
        "ufw_add_rule",
        Some("firewall"),
        None,
        Some(&target_name),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Delete a UFW rule by its number.
#[server]
pub async fn server_ufw_delete_rule(number: u32) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    if number == 0 || number > 9999 {
        return Err(ServerFnError::new("Invalid rule number"));
    }

    UfwService
        .delete_rule_by_number(number)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let target_name = format!("rule #{number}");
    audit_log(
        claims.sub,
        "ufw_delete_rule",
        Some("firewall"),
        None,
        Some(&target_name),
        "Success",
        None,
    )
    .await;
    Ok(())
}

// ─── Quick actions ───────────────────────────────────────────────────────────

/// One-click block an IP address or CIDR range.
#[server]
pub async fn server_ufw_block_ip(ip: String) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // AUDIT-07: Server-layer IP/CIDR validation — defense-in-depth.
    // Validate both the address part and, if present, the prefix length.
    if let Some((addr, prefix)) = ip.split_once('/') {
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|_| ServerFnError::new("Invalid CIDR prefix length"))?;
        if !crate::utils::validators::validate_ip_address(addr) || prefix_len > 128 {
            return Err(ServerFnError::new("Invalid IP address or CIDR prefix"));
        }
    } else if !crate::utils::validators::validate_ip_address(&ip) {
        return Err(ServerFnError::new("Invalid IP address"));
    }

    UfwService
        .block_ip(&ip)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "ufw_block_ip",
        Some("firewall"),
        None,
        Some(&ip),
        "Success",
        None,
    )
    .await;
    Ok(())
}

/// Set the default UFW policy for a direction.
#[server]
pub async fn server_ufw_set_default(
    direction: String,
    policy: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    if !matches!(direction.as_str(), "incoming" | "outgoing" | "routed") {
        return Err(ServerFnError::new("Invalid direction"));
    }
    if !matches!(policy.as_str(), "allow" | "deny" | "reject") {
        return Err(ServerFnError::new("Invalid policy"));
    }

    UfwService
        .set_default_policy(&direction, &policy)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let target_name = format!("{direction}={policy}");
    audit_log(
        claims.sub,
        "ufw_set_default",
        Some("firewall"),
        None,
        Some(&target_name),
        "Success",
        None,
    )
    .await;
    Ok(())
}

// ─── Export / Import ─────────────────────────────────────────────────────────

/// Export UFW rules as an iptables-restore compatible string.
#[server]
pub async fn server_ufw_export_rules() -> Result<String, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    UfwService
        .export_rules()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Import UFW rules from an iptables-restore format string.
#[server]
pub async fn server_ufw_import_rules(content: String) -> Result<(), ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Size sanity check (256 KB)
    if content.len() > 256 * 1024 {
        return Err(ServerFnError::new("Import content too large (max 256 KB)"));
    }

    UfwService
        .import_rules(&content)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "ufw_import_rules",
        Some("firewall"),
        None,
        None,
        "Success",
        None,
    )
    .await;
    Ok(())
}
