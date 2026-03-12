/// Role-based access control guards for server functions.
use crate::models::auth::{AuthError, JwtClaims};
use crate::models::user::Role;

/// Require authentication. Returns the current user's JWT claims.
pub fn require_auth(_claims: &JwtClaims) -> Result<(), AuthError> {
    Ok(())
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
}
