/// Email management server functions.
use crate::models::email::{
    DkimKey, EmailDomain, EmailDomainWithAccounts, Mailbox, RegexForwarder,
};
use dioxus::prelude::*;

/// List all email domains for the current user, each with their mailboxes and forwarders.
/// Used by the backup UI to pick mailboxes.
#[server]
pub async fn server_list_email_domains_with_accounts(
) -> Result<Vec<EmailDomainWithAccounts>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domains = crate::db::email::list_domains(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut result = Vec::with_capacity(domains.len());
    for d in domains {
        let mailboxes = crate::db::email::list_mailboxes(pool, d.id)
            .await
            .unwrap_or_default();
        result.push(EmailDomainWithAccounts {
            domain: d,
            mailboxes,
            forwarders: vec![],
        });
    }
    Ok(result)
}

/// List all email domains on the server (admin only).
#[server]
pub async fn server_admin_list_email_domains() -> Result<Vec<EmailDomain>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    crate::db::email::list_all_domains(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Set per-domain send limits (admin only).
/// Pass 0 for `limit_per_hour` or `limit_per_day` to remove that limit.
#[server]
pub async fn server_set_send_limits(
    domain_id: i64,
    limit_per_hour: i32,
    limit_per_day: i32,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    crate::auth::guards::require_admin(&claims).map_err(|e| ServerFnError::new(e.to_string()))?;
    let pool = get_pool()?;

    if limit_per_hour < 0 || limit_per_day < 0 {
        return Err(ServerFnError::new(
            "Limits must be non-negative (0 = unlimited)",
        ));
    }

    crate::db::email::set_send_limits(pool, domain_id, limit_per_hour, limit_per_day)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "set_send_limits",
        Some("email_domain"),
        Some(domain_id),
        Some(&format!("hourly={limit_per_hour} daily={limit_per_day}")),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// List email domains for the current user.
#[server]
pub async fn server_list_email_domains() -> Result<Vec<EmailDomain>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::db::email::list_domains(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create an email domain.
#[server]
pub async fn server_create_email_domain(domain: String) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::utils::validators::validate_domain(&domain).map_err(ServerFnError::new)?;

    let id = crate::db::email::create_domain(pool, claims.sub, domain.clone())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "create_email_domain",
        Some("email_domain"),
        Some(id),
        Some(&domain),
        "Success",
        None,
    )
    .await;

    Ok(id)
}

/// List mailboxes for an email domain.
#[server]
pub async fn server_list_mailboxes(domain_id: i64) -> Result<Vec<Mailbox>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::email::list_mailboxes(pool, domain_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a mailbox.
#[server]
pub async fn server_create_mailbox(
    domain_id: i64,
    local_part: String,
    password: String,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Validate password strength — blank or trivial passwords are rejected.
    crate::utils::validators::validate_password(&password).map_err(ServerFnError::new)?;

    // Validate local_part: only RFC 5321-safe characters, no @ or path separators.
    {
        let lp_re = regex::Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        if !lp_re.is_match(&local_part) {
            return Err(ServerFnError::new(
                "Invalid mailbox local part. Use only letters, digits, and standard email special characters."
            ));
        }
    }

    crate::db::quotas::check_and_increment_email_accounts(pool, claims.sub)
        .await
        .map_err(ServerFnError::new)?;

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ServerFnError::new("Failed to hash password"))?
        .to_string();

    let id =
        match crate::db::email::create_mailbox(pool, domain_id, local_part, password_hash).await {
            Ok(id) => id,
            Err(e) => {
                // Roll back the quota increment since we never created the mailbox.
                let _ = crate::db::quotas::increment_email_accounts(pool, claims.sub, -1).await;
                return Err(ServerFnError::new(e.to_string()));
            }
        };

    // Quota already incremented by check_and_increment_email_accounts; no separate call needed.

    audit_log(
        claims.sub,
        "create_mailbox",
        Some("mailbox"),
        Some(id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(id)
}

/// Delete a mailbox.
#[server]
pub async fn server_delete_mailbox(domain_id: i64, mailbox_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Verify the mailbox belongs to this domain before deleting it,
    // preventing cross-domain IDOR attacks.
    let mailbox = crate::db::email::get_mailbox(pool, mailbox_id)
        .await
        .map_err(|_| ServerFnError::new("Mailbox not found"))?;
    if mailbox.domain_id != domain_id {
        return Err(ServerFnError::new("Mailbox not found"));
    }

    crate::db::email::delete_mailbox(pool, mailbox_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let _ = crate::db::quotas::increment_email_accounts(pool, claims.sub, -1).await;

    audit_log(
        claims.sub,
        "delete_mailbox",
        Some("mailbox"),
        Some(mailbox_id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Create an email forwarder.
#[server]
pub async fn server_create_forwarder(
    domain_id: i64,
    local_part: String,
    forward_to: String,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::utils::validators::validate_email(&forward_to).map_err(ServerFnError::new)?;

    let id = crate::db::email::create_forwarder(pool, domain_id, local_part, forward_to)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "create_forwarder",
        Some("email_forwarder"),
        Some(id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(id)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Catch-all
// ═══════════════════════════════════════════════════════════════════════════════

/// Set the catch-all destination for a domain.
/// All mail sent to <anything>@domain that has no matching mailbox or forwarder
/// will be delivered to `address`.  Pass an empty string to disable catch-all.
#[server]
pub async fn server_set_catch_all(domain_id: i64, address: String) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let dest = if address.is_empty() {
        None
    } else {
        crate::utils::validators::validate_email(&address).map_err(ServerFnError::new)?;
        Some(address.as_str())
    };

    // Persist in DB.
    crate::db::email::set_catch_all(pool, domain_id, dest)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Apply to Postfix virtual_aliases.
    let postfix = crate::services::postfix::PostfixService;
    postfix
        .set_catch_all(&domain.domain, dest)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "set_catch_all",
        Some("email_domain"),
        Some(domain_id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Plus-addressing
// ═══════════════════════════════════════════════════════════════════════════════

/// Enable or disable `user+tag@domain` plus-addressing for a domain.
/// The Postfix `recipient_delimiter = +` setting is global; this function
/// updates it based on whether *any* domain has plus-addressing enabled.
#[server]
pub async fn server_set_plus_addressing(
    domain_id: i64,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::email::set_plus_addressing(pool, domain_id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Determine global state.
    let any_enabled = crate::db::email::any_plus_addressing_enabled(pool)
        .await
        .unwrap_or(enabled);

    let postfix = crate::services::postfix::PostfixService;
    postfix
        .set_plus_addressing(any_enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        if enabled {
            "enable_plus_addressing"
        } else {
            "disable_plus_addressing"
        },
        Some("email_domain"),
        Some(domain_id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pattern-based (regex) forwarders
// ═══════════════════════════════════════════════════════════════════════════════

/// List all regex forwarders for an email domain.
#[server]
pub async fn server_list_regex_forwarders(
    domain_id: i64,
) -> Result<Vec<RegexForwarder>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::email::list_regex_forwarders(pool, domain_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a regex forwarder.
/// `pattern` is a POSIX extended regex (e.g. `^info\+.*@example\.com$`).
/// All matching recipients are forwarded to `forward_to`.
#[server]
pub async fn server_create_regex_forwarder(
    domain_id: i64,
    pattern: String,
    forward_to: String,
    description: Option<String>,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    if pattern.is_empty() {
        return Err(ServerFnError::new("Pattern must not be empty"));
    }
    // Validate the regex syntax before persisting — an invalid POSIX pattern
    // would break postmap and silently disrupt all regex-based routing.
    if let Err(e) = regex::Regex::new(&pattern) {
        return Err(ServerFnError::new(format!("Invalid regex pattern: {}", e)));
    }
    crate::utils::validators::validate_email(&forward_to).map_err(ServerFnError::new)?;

    let id =
        crate::db::email::create_regex_forwarder(pool, domain_id, pattern, forward_to, description)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Rebuild the Postfix regexp map.
    rebuild_and_apply_regex_map(pool).await?;

    audit_log(
        claims.sub,
        "create_regex_forwarder",
        Some("email_regex_forwarder"),
        Some(id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(id)
}

/// Delete a regex forwarder.
#[server]
pub async fn server_delete_regex_forwarder(
    domain_id: i64,
    forwarder_id: i64,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Verify the forwarder belongs to this domain before deleting it.
    let forwarder = crate::db::email::get_regex_forwarder(pool, forwarder_id)
        .await
        .map_err(|_| ServerFnError::new("Regex forwarder not found"))?;
    if forwarder.domain_id != domain_id {
        return Err(ServerFnError::new("Regex forwarder not found"));
    }

    crate::db::email::delete_regex_forwarder(pool, forwarder_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    rebuild_and_apply_regex_map(pool).await?;

    audit_log(
        claims.sub,
        "delete_regex_forwarder",
        Some("email_regex_forwarder"),
        Some(forwarder_id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// DKIM key management
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate or regenerate a DKIM signing key for the email domain.
/// Returns the `DkimKey` record containing the DNS TXT value to publish.
#[server]
pub async fn server_generate_dkim_key(domain_id: i64) -> Result<DkimKey, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let selector = "default";

    let dkim = crate::services::dkim::DkimService;
    let public_key_dns = dkim
        .generate_key(&domain.domain, selector)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Enable the DKIM milter in Postfix if not already done.
    let postfix = crate::services::postfix::PostfixService;
    postfix
        .enable_dkim_milter()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Persist key in DB.
    crate::db::email::upsert_dkim_key(pool, domain_id, &domain.domain, selector, &public_key_dns)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let key = crate::db::email::get_dkim_key(pool, domain_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "generate_dkim_key",
        Some("dkim_key"),
        Some(domain_id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(key)
}

/// Get the DKIM key record for a domain (to display the DNS TXT record the user must publish).
#[server]
pub async fn server_get_dkim_key(domain_id: i64) -> Result<Option<DkimKey>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    match crate::db::email::get_dkim_key(pool, domain_id).await {
        Ok(key) => Ok(Some(key)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(e) => Err(ServerFnError::new(e.to_string())),
    }
}

/// Delete the DKIM key for a domain and remove the signing configuration.
#[server]
pub async fn server_delete_dkim_key(domain_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let selector = match crate::db::email::get_dkim_key(pool, domain_id).await {
        Ok(k) => k.selector,
        Err(sqlx::Error::RowNotFound) => return Ok(()), // nothing to delete
        Err(e) => return Err(ServerFnError::new(e.to_string())),
    };

    let dkim = crate::services::dkim::DkimService;
    dkim.delete_key(&domain.domain, &selector)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::email::delete_dkim_key(pool, domain_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_dkim_key",
        Some("dkim_key"),
        Some(domain_id),
        Some(&domain.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ─── Shared helper ────────────────────────────────────────────────────────────

/// Rebuild the Postfix regex virtual-alias map from all active regex forwarders.
#[cfg(feature = "server")]
async fn rebuild_and_apply_regex_map(pool: &sqlx::SqlitePool) -> Result<(), ServerFnError> {
    let all_forwarders = crate::db::email::list_all_active_regex_forwarders(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let pairs: Vec<(String, String)> = all_forwarders
        .into_iter()
        .map(|f| (f.pattern, f.forward_to))
        .collect();

    let postfix = crate::services::postfix::PostfixService;
    postfix
        .rebuild_regex_map(&pairs)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mailbox statistics
// ═══════════════════════════════════════════════════════════════════════════════

/// Return per-mailbox statistics computed from the Maildir on disk.
///
/// Returns message totals, unread count, disk usage, and quota utilisation.
#[server]
pub async fn server_get_mailbox_stats(
    domain_id: i64,
    mailbox_id: i64,
) -> Result<crate::models::email::MailboxStats, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mailbox = crate::db::email::get_mailbox(pool, mailbox_id)
        .await
        .map_err(|_| ServerFnError::new("Mailbox not found"))?;

    if mailbox.domain_id != domain_id {
        return Err(ServerFnError::new("Mailbox does not belong to this domain"));
    }

    let address = format!("{}@{}", mailbox.local_part, domain.domain);
    let maildir = format!("/var/mail/vhosts/{}/{}", domain.domain, address);

    let (messages_total, messages_new, disk_usage_kb) = compute_maildir_stats(&maildir).await;

    let quota_used_pct = if mailbox.quota_mb > 0 {
        let quota_kb = mailbox.quota_mb as f64 * 1024.0;
        (disk_usage_kb as f64 / quota_kb * 100.0).min(100.0)
    } else {
        0.0
    };

    Ok(crate::models::email::MailboxStats {
        mailbox_id,
        address,
        messages_total,
        messages_new,
        disk_usage_kb,
        quota_mb: mailbox.quota_mb,
        quota_used_pct,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mailbox backup
// ═══════════════════════════════════════════════════════════════════════════════

/// Create a compressed backup of a mailbox Maildir and return a one-time
/// download token valid for 5 minutes.
#[server]
pub async fn server_create_mailbox_backup(
    domain_id: i64,
    mailbox_id: i64,
) -> Result<crate::models::email::MailboxBackupToken, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let domain = crate::db::email::get_domain(pool, domain_id)
        .await
        .map_err(|_| ServerFnError::new("Domain not found"))?;

    crate::auth::guards::check_ownership(&claims, domain.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mailbox = crate::db::email::get_mailbox(pool, mailbox_id)
        .await
        .map_err(|_| ServerFnError::new("Mailbox not found"))?;

    if mailbox.domain_id != domain_id {
        return Err(ServerFnError::new("Mailbox does not belong to this domain"));
    }

    let address = format!("{}@{}", mailbox.local_part, domain.domain);
    let maildir = format!("/var/mail/vhosts/{}/{}", domain.domain, address);

    if !tokio::fs::try_exists(&maildir).await.unwrap_or(false) {
        return Err(ServerFnError::new(
            "Mailbox directory not found on disk — no messages to back up.",
        ));
    }

    let today = chrono::Utc::now().format("%Y-%m-%d");
    let token = uuid::Uuid::new_v4().to_string();
    let filename = format!("{address}_{today}.tar.gz");
    let dest_path = format!("/tmp/mailbackup_{}.tar.gz", token);

    // Create tar.gz — tar is on the allowlist.
    crate::services::shell::exec("tar", &["-czf", &dest_path, "-C", &maildir, "."])
        .await
        .map_err(|e| ServerFnError::new(format!("Backup creation failed: {e}")))?;

    let size_bytes = tokio::fs::metadata(&dest_path)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .len();

    // Register one-time download token (5-minute expiry).
    let expires_at = chrono::Utc::now().timestamp() + 300;
    register_backup_token(
        token.clone(),
        claims.sub,
        dest_path,
        filename.clone(),
        expires_at,
    );

    audit_log(
        claims.sub,
        "create_mailbox_backup",
        Some("mailbox"),
        Some(mailbox_id),
        Some(&address),
        "Success",
        None,
    )
    .await;

    Ok(crate::models::email::MailboxBackupToken {
        download_url: format!("/api/mailbox-backup/{token}"),
        filename,
        size_bytes,
    })
}

// ─── Maildir walk helper ──────────────────────────────────────────────────────

/// Walk a Maildir tree and count messages + sum disk usage.
/// Returns `(total_messages, new_messages, disk_usage_kb)`.
#[cfg(feature = "server")]
async fn compute_maildir_stats(maildir: &str) -> (u64, u64, u64) {
    let base = std::path::Path::new(maildir);
    if !base.exists() {
        return (0, 0, 0);
    }

    let mut total: u64 = 0;
    let mut new_msgs: u64 = 0;
    let mut size_bytes: u64 = 0;

    // Iterative DFS over the directory tree.
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut rd = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let Ok(meta) = entry.metadata().await else {
                continue;
            };
            if meta.is_dir() {
                let name = entry.file_name();
                let n = name.to_string_lossy();
                // Descend into all sub-dirs except Maildir "tmp" (incomplete deliveries).
                if n != "tmp" {
                    stack.push(entry.path());
                }
            } else if meta.is_file() {
                // Accumulate disk usage for all files.
                size_bytes += meta.len();
                // Count message files only inside `cur/` and `new/` dirs.
                let parent_name = dir
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                match parent_name.as_str() {
                    "cur" => total += 1,
                    "new" => {
                        total += 1;
                        new_msgs += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    (total, new_msgs, size_bytes / 1024)
}

// ─── Backup token store ───────────────────────────────────────────────────────

/// An in-memory entry for a pending mailbox backup download.
#[cfg(feature = "server")]
pub struct BackupTokenEntry {
    pub user_id: i64,
    pub file_path: String,
    pub filename: String,
    pub expires_at: i64,
}

#[cfg(feature = "server")]
static BACKUP_TOKENS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, BackupTokenEntry>>,
> = std::sync::OnceLock::new();

#[cfg(feature = "server")]
fn backup_tokens_store(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, BackupTokenEntry>> {
    BACKUP_TOKENS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Register a newly created backup token.
#[cfg(feature = "server")]
pub fn register_backup_token(
    token: String,
    user_id: i64,
    file_path: String,
    filename: String,
    expires_at: i64,
) {
    let mut store = backup_tokens_store().lock().unwrap();
    let now = chrono::Utc::now().timestamp();
    // Purge expired entries on every write.
    store.retain(|_, v| v.expires_at > now);
    store.insert(
        token,
        BackupTokenEntry {
            user_id,
            file_path,
            filename,
            expires_at,
        },
    );
}

/// Consume a backup token (one-shot).
///
/// Returns `Some((file_path, filename))` if the token exists, has not expired,
/// and belongs to `user_id`.  The entry is removed on success.
#[cfg(feature = "server")]
pub fn consume_backup_token(token: &str, user_id: i64) -> Option<(String, String)> {
    let mut store = backup_tokens_store().lock().unwrap();
    let now = chrono::Utc::now().timestamp();
    if let Some(entry) = store.get(token) {
        if entry.expires_at <= now {
            store.remove(token);
            return None;
        }
        if entry.user_id != user_id {
            return None;
        }
        let result = (entry.file_path.clone(), entry.filename.clone());
        store.remove(token);
        return Some(result);
    }
    None
}
