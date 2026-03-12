/// Team management server functions.
/// Clients can invite developers to collaborate on specific sites via
/// one-time invitation tokens.
use crate::models::team::{CreateInvitationRequest, TeamInvitation};
use crate::models::user::User;
use dioxus::prelude::*;

// ─── Create Invitation ────────────────────────────────────────────────────────

/// Create a one-time developer invitation.
///
/// Returns the **raw token** (hex-encoded, 64 chars) which must be shared with
/// the invitee out-of-band.  Only the SHA-256 hash is stored — the raw token
/// cannot be recovered after this call.
///
/// Only Clients (and Admins) may send invitations.
#[server]
pub async fn server_create_team_invitation(
    req: CreateInvitationRequest,
) -> Result<String, ServerFnError> {
    use super::helpers::*;
    use crate::models::user::Role;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    if !matches!(claims.role, Role::Client | Role::Admin) {
        return Err(ServerFnError::new("Only clients can send team invitations"));
    }

    crate::utils::validators::validate_email(&req.email).map_err(ServerFnError::new)?;

    if req.site_ids.is_empty() {
        return Err(ServerFnError::new(
            "At least one site must be included in the invitation",
        ));
    }
    if req.site_ids.len() > 100 {
        return Err(ServerFnError::new("Too many sites in invitation (max 100)"));
    }

    // Verify all requested sites belong to this client.
    for &sid in &req.site_ids {
        let site = crate::db::sites::get(pool, sid)
            .await
            .map_err(|_| ServerFnError::new(format!("Site {sid} not found")))?;
        if site.owner_id != claims.sub && claims.role != Role::Admin {
            return Err(ServerFnError::new(format!("You do not own site {sid}")));
        }
    }

    // Generate 32 random bytes → hex string (64 chars). Uses OsRng via argon2's
    // rand_core re-export — no additional dependency needed.
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut raw_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut raw_bytes);
    let raw_token = hex::encode(raw_bytes);

    // Store only the SHA-256 hash; the raw token is never persisted.
    use sha2::{Digest, Sha256};
    let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

    let expires_hours = req.expires_hours.unwrap_or(48).clamp(1, 720) as i64;
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_hours);

    let site_ids_json =
        serde_json::to_string(&req.site_ids).map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::team::create_invitation(
        pool,
        claims.sub,
        &req.email,
        &token_hash,
        &site_ids_json,
        expires_at,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "create_team_invitation",
        Some("invitation"),
        None,
        Some(&req.email),
        "Success",
        None,
    )
    .await;

    Ok(raw_token)
}

// ─── List Invitations ─────────────────────────────────────────────────────────

/// List all invitations created by the current client.
#[server]
pub async fn server_list_team_invitations() -> Result<Vec<TeamInvitation>, ServerFnError> {
    use super::helpers::*;
    use crate::models::user::Role;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    if !matches!(claims.role, Role::Client | Role::Admin) {
        return Err(ServerFnError::new("Not authorized"));
    }

    crate::db::team::list_invitations(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ─── Revoke Invitation ────────────────────────────────────────────────────────

/// Delete (revoke) an unconsumed invitation.
#[server]
pub async fn server_revoke_team_invitation(invitation_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use crate::models::user::Role;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // Verify ownership: only the issuing client (or an Admin) may revoke.
    let inv = crate::db::team::list_invitations(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .into_iter()
        .find(|i| i.id == invitation_id)
        .ok_or_else(|| ServerFnError::new("Invitation not found"))?;

    if inv.client_id != claims.sub && claims.role != Role::Admin {
        return Err(ServerFnError::new("Not authorized"));
    }

    crate::db::team::revoke_invitation(pool, invitation_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "revoke_team_invitation",
        Some("invitation"),
        Some(invitation_id),
        None,
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ─── Accept Invitation ────────────────────────────────────────────────────────

/// Accept a team invitation and create a Developer account.
///
/// This is a **public** endpoint — no prior authentication is required.
/// On success the newly created developer is auto-logged in and a
/// `LoginResponse` (JWT + user record) is returned.
#[server]
pub async fn server_accept_team_invitation(
    raw_token: String,
    username: String,
    password: String,
) -> Result<crate::models::user::LoginResponse, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let pool = get_pool()?;

    // Hash the supplied token and look it up.
    use sha2::{Digest, Sha256};
    let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

    let inv = crate::db::team::get_by_token_hash(pool, &token_hash)
        .await
        .map_err(|_| ServerFnError::new("Invalid or expired invitation"))?
        .ok_or_else(|| ServerFnError::new("Invalid or expired invitation"))?;

    // Guard: not consumed and not expired.
    if inv.consumed_at.is_some() {
        return Err(ServerFnError::new("Invitation has already been used"));
    }
    if chrono::Utc::now() > inv.expires_at {
        return Err(ServerFnError::new("Invitation has expired"));
    }

    // Validate the new account credentials.
    crate::utils::validators::validate_username(&username).map_err(ServerFnError::new)?;
    crate::utils::validators::validate_password(&password).map_err(ServerFnError::new)?;

    // Hash the password with Argon2id.
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .to_string();

    // Create the Developer user (parent = the inviting client; no system UID/GID).
    let user_id = crate::db::users::create(
        pool,
        username,
        inv.email.clone(),
        password_hash,
        crate::models::user::Role::Developer,
        Some(inv.client_id),
        None,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Grant per-site access based on the invitation's site_ids JSON.
    let site_ids: Vec<i64> = serde_json::from_str(&inv.site_ids).unwrap_or_default();
    for sid in site_ids {
        let _ = crate::db::team::grant_site_access(pool, user_id, sid).await;
    }

    // Mark the invitation as consumed (prevents replay).
    crate::db::team::consume_invitation(pool, inv.id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Fetch the created user record and issue a JWT for auto-login.
    let user = crate::db::users::get(pool, user_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let access_token = crate::auth::jwt::create_token(
        user.id,
        user.username.clone(),
        user.email.clone(),
        user.role,
        user.parent_id,
        None,
    )
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(crate::models::user::LoginResponse { access_token, user })
}

// ─── List Team Members ────────────────────────────────────────────────────────

/// Return all Developer users belonging to the current client.
#[server]
pub async fn server_list_team_members() -> Result<Vec<User>, ServerFnError> {
    use super::helpers::*;
    use crate::models::user::Role;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    if !matches!(claims.role, Role::Client | Role::Admin) {
        return Err(ServerFnError::new("Not authorized"));
    }

    crate::db::team::list_developers(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ─── Remove Team Member ───────────────────────────────────────────────────────

/// Remove a developer from the team.
/// Deletes the Developer user account; cascade DELETE removes their
/// `team_site_access` rows automatically.
#[server]
pub async fn server_remove_team_member(developer_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use crate::models::user::Role;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let dev = crate::db::users::get(pool, developer_id)
        .await
        .map_err(|_| ServerFnError::new("Developer not found"))?;

    if dev.role != Role::Developer {
        return Err(ServerFnError::new("Target user is not a Developer"));
    }
    if dev.parent_id != Some(claims.sub) && claims.role != Role::Admin {
        return Err(ServerFnError::new("Not authorized"));
    }

    crate::db::users::delete(pool, developer_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "remove_team_member",
        Some("user"),
        Some(developer_id),
        Some(&dev.username),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ─── Update Member Site Access ────────────────────────────────────────────────

/// Replace the complete set of sites a developer can access.
#[server]
pub async fn server_update_member_sites(
    developer_id: i64,
    site_ids: Vec<i64>,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use crate::models::user::Role;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    if site_ids.len() > 100 {
        return Err(ServerFnError::new("Too many sites (max 100)"));
    }

    let dev = crate::db::users::get(pool, developer_id)
        .await
        .map_err(|_| ServerFnError::new("Developer not found"))?;

    if dev.role != Role::Developer {
        return Err(ServerFnError::new("Target user is not a Developer"));
    }
    if dev.parent_id != Some(claims.sub) && claims.role != Role::Admin {
        return Err(ServerFnError::new("Not authorized"));
    }

    // Verify all requested sites belong to this client.
    for &sid in &site_ids {
        let site = crate::db::sites::get(pool, sid)
            .await
            .map_err(|_| ServerFnError::new(format!("Site {sid} not found")))?;
        if site.owner_id != claims.sub && claims.role != Role::Admin {
            return Err(ServerFnError::new(format!("You do not own site {sid}")));
        }
    }

    // Remove all existing grants then add the new set.
    let existing = crate::db::team::get_developer_sites(pool, developer_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    for sid in existing {
        let _ = crate::db::team::revoke_site_access(pool, developer_id, sid).await;
    }
    for sid in &site_ids {
        crate::db::team::grant_site_access(pool, developer_id, *sid)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    audit_log(
        claims.sub,
        "update_member_sites",
        Some("user"),
        Some(developer_id),
        None,
        "Success",
        None,
    )
    .await;

    Ok(())
}
