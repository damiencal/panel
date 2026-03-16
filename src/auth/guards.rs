/// Role-based access control guards for server functions.
use crate::models::auth::{AuthError, JwtClaims};
use crate::models::user::Role;
use http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Require authentication. Returns the current user's JWT claims.
pub fn require_auth(_claims: &JwtClaims) -> Result<(), AuthError> {
    Ok(())
}

/// Extract the most useful client IP from forwarded headers.
///
/// Returns `None` when no plausible header is present.
pub fn extract_client_ip_from_headers(headers: &HeaderMap) -> Option<String> {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| crate::utils::validators::validate_ip_address(value));

    if let Some(ip) = forwarded {
        return Some(ip.to_string());
    }

    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| crate::utils::validators::validate_ip_address(value))
        .map(ToString::to_string)
}

/// Check whether a client IP is allowed by a list of exact IPs or CIDR ranges.
pub fn check_ip_allowlist(client_ip: &str, allowed_ips: &[String]) -> Result<(), AuthError> {
    if allowed_ips.is_empty() {
        return Ok(());
    }

    let client_ip: IpAddr = client_ip.parse().map_err(|_| AuthError::AccessDenied)?;

    if allowed_ips
        .iter()
        .any(|entry| matches!(entry.trim(), "0.0.0.0" | "::" | "0.0.0.0/0" | "::/0" | "*"))
    {
        return Ok(());
    }

    if allowed_ips
        .iter()
        .any(|entry| ip_matches_allowlist_entry(client_ip, entry.trim()))
    {
        Ok(())
    } else {
        Err(AuthError::AccessDenied)
    }
}

/// Require Admin role.
pub fn require_admin(claims: &JwtClaims) -> Result<(), AuthError> {
    if claims.role == Role::Admin {
        Ok(())
    } else {
        Err(AuthError::AccessDenied)
    }
}

/// Require Reseller role or higher.
pub fn require_reseller(claims: &JwtClaims) -> Result<(), AuthError> {
    match claims.role {
        Role::Admin | Role::Reseller => Ok(()),
        _ => Err(AuthError::AccessDenied),
    }
}

/// Check ownership of a resource based on role.
/// - Admin can access any resource.
/// - Reseller can access resources owned by their clients or themselves.
/// - Client can only access their own resources.
pub fn check_ownership(
    claims: &JwtClaims,
    resource_owner_id: i64,
    resource_parent_id: Option<i64>,
) -> Result<(), AuthError> {
    match claims.role {
        Role::Admin => Ok(()),
        Role::Reseller => {
            // Reseller can access if:
            // 1. They own it directly, OR
            // 2. The resource's parent is them
            if resource_owner_id == claims.sub || resource_parent_id == Some(claims.sub) {
                Ok(())
            } else {
                Err(AuthError::AccessDenied)
            }
        }
        Role::Client => {
            // Client can only access their own resources
            if resource_owner_id == claims.sub {
                Ok(())
            } else {
                Err(AuthError::AccessDenied)
            }
        }
        Role::Developer => Err(AuthError::AccessDenied),
    }
}

/// Check whether a Developer has been granted access to a specific site.
/// For non-Developer roles this delegates to `check_ownership`.
///
/// This is async because it queries the `team_site_access` table.
#[cfg(feature = "server")]
pub async fn check_developer_site_access(
    pool: &sqlx::SqlitePool,
    claims: &JwtClaims,
    site_owner_id: i64,
    site_id: i64,
) -> Result<(), AuthError> {
    if claims.role != Role::Developer {
        return check_ownership(claims, site_owner_id, None);
    }
    let has_access = crate::db::team::has_site_access(pool, claims.sub, site_id)
        .await
        .map_err(|_| AuthError::AccessDenied)?;
    if has_access {
        Ok(())
    } else {
        Err(AuthError::AccessDenied)
    }
}

/// Guard for Admin panel access.
#[cfg(target_arch = "wasm32")]
pub fn admin_guard(route: &dioxus_router::prelude::RouteState) -> bool {
    // Frontend-side guard (will be checked again on backend)
    // This is a cosmetic guard; real security is server-side
    true
}

fn ip_matches_allowlist_entry(client_ip: IpAddr, entry: &str) -> bool {
    if entry.is_empty() {
        return false;
    }

    if let Ok(exact_ip) = entry.parse::<IpAddr>() {
        return exact_ip == client_ip;
    }

    let Some((network, prefix_len)) = entry.split_once('/') else {
        return false;
    };

    let Ok(network_ip) = network.parse::<IpAddr>() else {
        return false;
    };

    match (client_ip, network_ip) {
        (IpAddr::V4(client), IpAddr::V4(network)) => {
            let Ok(prefix_len) = prefix_len.parse::<u8>() else {
                return false;
            };
            ipv4_in_cidr(client, network, prefix_len)
        }
        (IpAddr::V6(client), IpAddr::V6(network)) => {
            let Ok(prefix_len) = prefix_len.parse::<u8>() else {
                return false;
            };
            ipv6_in_cidr(client, network, prefix_len)
        }
        _ => false,
    }
}

fn ipv4_in_cidr(client: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }

    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };

    (u32::from(client) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_cidr(client: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }

    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    };

    (u128::from(client) & mask) == (u128::from(network) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_claims(user_id: i64, role: Role, parent_id: Option<i64>) -> JwtClaims {
        JwtClaims {
            sub: user_id,
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            role,
            iat: 0,
            exp: 0,
            parent_id,
            impersonated_by: None,
        }
    }

    #[test]
    fn test_admin_can_access_everything() {
        let admin = create_test_claims(1, Role::Admin, None);
        assert!(check_ownership(&admin, 999, Some(888)).is_ok());
    }

    #[test]
    fn test_reseller_can_access_own_resources() {
        let reseller = create_test_claims(2, Role::Reseller, None);
        assert!(check_ownership(&reseller, 2, None).is_ok()); // Own resource
        assert!(check_ownership(&reseller, 999, Some(2)).is_ok()); // Client's resource
        assert!(check_ownership(&reseller, 999, Some(888)).is_err()); // Other reseller's client
    }

    #[test]
    fn test_client_can_only_access_own_resources() {
        let client = create_test_claims(3, Role::Client, Some(2));
        assert!(check_ownership(&client, 3, None).is_ok()); // Own resource
        assert!(check_ownership(&client, 4, None).is_err()); // Another client's resource
    }

    #[test]
    fn test_require_admin() {
        let admin = create_test_claims(1, Role::Admin, None);
        let client = create_test_claims(3, Role::Client, None);

        assert!(require_admin(&admin).is_ok());
        assert!(require_admin(&client).is_err());
    }

    #[test]
    fn test_require_reseller() {
        let admin = create_test_claims(1, Role::Admin, None);
        let reseller = create_test_claims(2, Role::Reseller, None);
        let client = create_test_claims(3, Role::Client, None);

        assert!(require_reseller(&admin).is_ok());
        assert!(require_reseller(&reseller).is_ok());
        assert!(require_reseller(&client).is_err());
    }

    #[test]
    fn test_empty_allowlist_allows_any_ip() {
        assert!(check_ip_allowlist("203.0.113.10", &[]).is_ok());
    }

    #[test]
    fn test_exact_ip_allowlist_match() {
        let allowed = vec!["203.0.113.10".to_string()];
        assert!(check_ip_allowlist("203.0.113.10", &allowed).is_ok());
        assert!(check_ip_allowlist("203.0.113.11", &allowed).is_err());
    }

    #[test]
    fn test_ipv4_cidr_allowlist_match() {
        let allowed = vec!["10.10.0.0/16".to_string()];
        assert!(check_ip_allowlist("10.10.42.5", &allowed).is_ok());
        assert!(check_ip_allowlist("10.11.42.5", &allowed).is_err());
    }

    #[test]
    fn test_ipv6_cidr_allowlist_match() {
        let allowed = vec!["2001:db8::/32".to_string()];
        assert!(check_ip_allowlist("2001:db8::1", &allowed).is_ok());
        assert!(check_ip_allowlist("2001:dead::1", &allowed).is_err());
    }

    #[test]
    fn test_allow_all_shortcuts() {
        let allowed = vec!["0.0.0.0/0".to_string()];
        assert!(check_ip_allowlist("198.51.100.25", &allowed).is_ok());
    }
}
