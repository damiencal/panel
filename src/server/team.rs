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
    check_token_not_revoked(pool, &claims).await?;

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
    check_token_not_revoked(pool, &claims).await?;

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
    check_token_not_revoked(pool, &claims).await?;

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
) -> Result<crate::models::auth::LoginResponse, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let pool = get_pool()?;

    // Rate-limit by IP + token prefix to slow brute-force token guessing.
    // This endpoint is public (no prior auth), so it is the primary protection
    // against automated token enumeration attacks.
    #[cfg(feature = "server")]
    {
        let client_ip = crate::server::auth::get_client_ip();
        // Use the first 8 bytes of the raw token as a "username" key so that
        // different token prefixes get independent counters, preventing a single
        // bad actor from exhausting all attempts under one IP bucket.
        let token_prefix = &raw_token[..raw_token.len().min(8)];
        crate::server::auth::enforce_login_rate_limit(&client_ip, token_prefix)?;
    }

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
    .map_err(|e| {
        // SEC-B2-05: sanitize DB errors to avoid leaking schema details (column names)
        // to the unauthenticated caller.
        let msg = e.to_string();
        if msg.contains("users.username") {
            ServerFnError::new("Username is already taken")
        } else if msg.contains("users.email") {
            ServerFnError::new("This email address is already registered")
        } else {
            tracing::warn!("DB error in accept_team_invitation: {e}");
            ServerFnError::new("Failed to create account")
        }
    })?;

    // Grant per-site access based on the invitation's site_ids JSON.
    let site_ids: Vec<i64> = serde_json::from_str(&inv.site_ids).unwrap_or_default();
    for sid in site_ids {
        if let Err(e) = crate::db::team::grant_site_access(pool, user_id, sid).await {
            tracing::error!(
                user_id,
                site_id = sid,
                "Failed to grant site access during invitation acceptance: {e}"
            );
        }
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

    // SEC-B2-01: set token as HttpOnly cookie, consistent with server_login.
    // Never return the raw JWT in the response body (XSS-stealable).
    let expires_in: i64 = 24 * 3600;
    set_auth_cookie(&access_token, expires_in);

    Ok(crate::models::auth::LoginResponse {
        user_id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        expires_at: chrono::Utc::now().timestamp() + expires_in,
        impersonated_by: None,
    })
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
    check_token_not_revoked(pool, &claims).await?;

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
    check_token_not_revoked(pool, &claims).await?;

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
    check_token_not_revoked(pool, &claims).await?;

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

    // Replace existing site grants atomically — use a transaction so a crash
    // between the revoke and grant phases cannot leave the developer with zero
    // site access until an admin manually repairs it.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    sqlx::query("DELETE FROM team_site_access WHERE developer_id = ?")
        .bind(developer_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let now = chrono::Utc::now();
    for sid in &site_ids {
        sqlx::query(
            "INSERT OR IGNORE INTO team_site_access (developer_id, site_id, granted_at)
             VALUES (?, ?, ?)",
        )
        .bind(developer_id)
        .bind(sid)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

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
