/// User management server functions.
use crate::models::user::{AccountStatus, Role, User};
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Reseller info with client count for admin listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResellerInfo {
    pub user: User,
    pub client_count: i64,
}

/// List users visible to the caller (admin: all, reseller: their clients).
#[server]
pub async fn server_list_users() -> Result<Vec<User>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let users = match claims.role {
        Role::Admin => crate::db::users::list_all(pool).await,
        Role::Reseller => crate::db::users::list_clients_for_reseller(pool, claims.sub).await,
        _ => return Err(ServerFnError::new("Access denied")),
    };

    users.map_err(|e| ServerFnError::new(e.to_string()))
}

/// List resellers with client counts (admin only).
#[server]
pub async fn server_list_resellers() -> Result<Vec<ResellerInfo>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    let resellers = crate::db::users::list_resellers(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut result = Vec::with_capacity(resellers.len());
    for user in resellers {
        let client_count = crate::db::users::count_clients_for_reseller(pool, user.id)
            .await
            .unwrap_or(0);
        result.push(ResellerInfo { user, client_count });
    }

    Ok(result)
}

/// Create a new user. Admin can create any role; resellers can only create clients.
#[server]
pub async fn server_create_user(
    username: String,
    email: String,
    password: String,
    role: Role,
    package_id: Option<i64>,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // Authorization
    match claims.role {
        Role::Admin => {}
        Role::Reseller => {
            if role != Role::Client {
                return Err(ServerFnError::new("Resellers can only create clients"));
            }
        }
        _ => return Err(ServerFnError::new("Access denied")),
    }

    // Validate inputs
    crate::utils::validators::validate_username(&username).map_err(ServerFnError::new)?;
    crate::utils::validators::validate_email(&email).map_err(ServerFnError::new)?;
    crate::utils::validators::validate_password(&password).map_err(ServerFnError::new)?;

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ServerFnError::new("Failed to hash password"))?
        .to_string();

    let parent_id = match claims.role {
        Role::Reseller => Some(claims.sub),
        _ => None,
    };

    let user_id = crate::db::users::create(
        pool,
        username.clone(),
        email,
        password_hash,
        role,
        parent_id,
        package_id,
    )
    .await
    .map_err(|e| {
        // Map UNIQUE constraint errors to user-friendly messages that don't
        // expose internal schema details (table/column names).
        let msg = e.to_string();
        if msg.contains("users.username") {
            ServerFnError::new("Username is already taken")
        } else if msg.contains("users.email") {
            ServerFnError::new("Email address is already in use")
        } else {
            ServerFnError::new("Failed to create user")
        }
    })?;

    // Initialize resource usage tracking
    let _ = crate::db::quotas::init_usage(pool, user_id).await;

    audit_log(
        claims.sub,
        "create_user",
        Some("user"),
        Some(user_id),
        Some(&username),
        "Success",
        None,
    )
    .await;

    Ok(user_id)
}

/// Update a user's account status (suspend/activate).
#[server]
pub async fn server_update_user_status(
    user_id: i64,
    status: AccountStatus,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let target = crate::db::users::get(pool, user_id)
        .await
        .map_err(|_| ServerFnError::new("User not found"))?;

    crate::auth::guards::check_ownership(&claims, target.id, target.parent_id)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::users::update_status(pool, user_id, status)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "update_user_status",
        Some("user"),
        Some(user_id),
        Some(&target.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Delete a user.
#[server]
pub async fn server_delete_user(user_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    if user_id == claims.sub {
        return Err(ServerFnError::new("Cannot delete your own account"));
    }

    let target = crate::db::users::get(pool, user_id)
        .await
        .map_err(|_| ServerFnError::new("User not found"))?;

    crate::auth::guards::check_ownership(&claims, target.id, target.parent_id)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::users::delete(pool, user_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_user",
        Some("user"),
        Some(user_id),
        Some(&target.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Get current authenticated user's info.
#[server]
pub async fn server_get_current_user() -> Result<User, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::db::users::get(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Update a user's contact detail fields (company, address, phone).
/// Users can update their own details; admins and resellers can update their subordinates'.
/// Pass `user_id = 0` to update the currently authenticated user's own details.
#[server]
pub async fn server_update_user_details(
    user_id: i64,
    company: Option<String>,
    address: Option<String>,
    phone: Option<String>,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // 0 means "myself"
    let target_id = if user_id == 0 { claims.sub } else { user_id };

    // Allow a user to update their own details, or an admin/reseller to update
    // a subordinate's details (ownership check).
    if claims.sub != target_id {
        let target = crate::db::users::get(pool, target_id)
            .await
            .map_err(|_| ServerFnError::new("User not found"))?;
        crate::auth::guards::check_ownership(&claims, target.id, target.parent_id)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    // Basic length validation to prevent oversized inputs.
    if company.as_deref().map(|s| s.len()).unwrap_or(0) > 200 {
        return Err(ServerFnError::new("Company name too long (max 200 chars)"));
    }
    if address.as_deref().map(|s| s.len()).unwrap_or(0) > 500 {
        return Err(ServerFnError::new("Address too long (max 500 chars)"));
    }
    if phone.as_deref().map(|s| s.len()).unwrap_or(0) > 50 {
        return Err(ServerFnError::new("Phone number too long (max 50 chars)"));
    }

    // Normalise empty strings to None.
    let company = company
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());
    let address = address
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());
    let phone = phone
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());

    crate::db::users::update_details(pool, target_id, company, address, phone)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "update_user_details",
        Some("user"),
        Some(target_id),
        None,
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Impersonate another user (Admin only).
/// Issues a JWT containing the target user's identity with `impersonated_by`
/// set to the calling admin's user_id so the session remains auditable.
#[server]
pub async fn server_impersonate_user(
    target_user_id: i64,
) -> Result<crate::models::auth::LoginResponse, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;

    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;

    // Prevent impersonation nesting
    if claims.impersonated_by.is_some() {
        return Err(ServerFnError::new(
            "Cannot impersonate while already impersonating another user",
        ));
    }

    if target_user_id == claims.sub {
        return Err(ServerFnError::new("Cannot impersonate yourself"));
    }

    let pool = get_pool()?;
    let target = crate::db::users::get(pool, target_user_id)
        .await
        .map_err(|_| ServerFnError::new("User not found"))?;

    // Admins cannot impersonate other admins
    if target.role == Role::Admin {
        return Err(ServerFnError::new("Cannot impersonate another admin"));
    }

    if target.status != crate::models::user::AccountStatus::Active {
        return Err(ServerFnError::new(
            "Cannot impersonate a suspended or pending user",
        ));
    }

    let auth_token = crate::auth::jwt::JwtManager::create_impersonation_token(
        target.id,
        target.username.clone(),
        target.email.clone(),
        target.role,
        target.parent_id,
        claims.sub,
    )
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    set_auth_cookie(&auth_token.access_token, auth_token.expires_in);

    audit_log_impersonated(
        claims.sub,
        "impersonate_user",
        Some("user"),
        Some(target.id),
        Some(&target.username),
        "Success",
        None,
        Some(claims.sub),
    )
    .await;

    Ok(crate::models::auth::LoginResponse {
        user_id: target.id,
        username: target.username,
        email: target.email,
        role: target.role,
        expires_at: chrono::Utc::now().timestamp() + auth_token.expires_in,
        impersonated_by: Some(claims.sub),
    })
}

/// End an impersonation session and restore the original admin JWT.
#[server]
pub async fn server_end_impersonation() -> Result<crate::models::auth::LoginResponse, ServerFnError>
{
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;

    let admin_id = claims
        .impersonated_by
        .ok_or_else(|| ServerFnError::new("Not currently impersonating anyone"))?;

    let pool = get_pool()?;
    let admin = crate::db::users::get(pool, admin_id)
        .await
        .map_err(|_| ServerFnError::new("Original admin account not found"))?;

    if admin.role != Role::Admin {
        return Err(ServerFnError::new(
            "Impersonation origin account is not an admin",
        ));
    }

    // Reject end-impersonation if the admin account was suspended while the
    // impersonation session was active — they should not receive a fresh JWT.
    if admin.status != crate::models::user::AccountStatus::Active {
        return Err(ServerFnError::new(
            "Original admin account is suspended or pending",
        ));
    }

    let auth_token = crate::auth::jwt::JwtManager::create_auth_response(
        admin.id,
        admin.username.clone(),
        admin.email.clone(),
        admin.role,
        admin.parent_id,
    )
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    set_auth_cookie(&auth_token.access_token, auth_token.expires_in);

    audit_log_impersonated(
        admin.id,
        "end_impersonation",
        Some("user"),
        Some(claims.sub),
        Some(&claims.username),
        "Success",
        None,
        Some(admin.id),
    )
    .await;

    Ok(crate::models::auth::LoginResponse {
        user_id: admin.id,
        username: admin.username,
        email: admin.email,
        role: admin.role,
        expires_at: chrono::Utc::now().timestamp() + auth_token.expires_in,
        impersonated_by: None,
    })
}
