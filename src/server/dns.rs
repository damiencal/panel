/// DNS management server functions (Cloudflare-backed).
use crate::models::dns::{DnsRecord, DnsZone, RecordType};
use dioxus::prelude::*;

/// List DNS zones for the current user.
#[server]
pub async fn server_list_dns_zones() -> Result<Vec<DnsZone>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    crate::db::dns::list_zones(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a DNS zone backed by Cloudflare.
#[server]
pub async fn server_create_dns_zone(domain: String) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    crate::utils::validators::validate_domain(&domain).map_err(ServerFnError::new)?;

    // Try Cloudflare; if not configured, create zone locally with Pending status.
    let (cf_zone_id, ns1, ns2, sync_status) = match crate::services::cloudflare::client() {
        Ok(cf) => match cf.create_zone(&domain).await {
            Ok(zone) => {
                let ns1 = zone.name_servers.first().cloned();
                let ns2 = zone.name_servers.get(1).cloned();
                (Some(zone.id), ns1, ns2, "Synced")
            }
            Err(e) => {
                tracing::warn!("Cloudflare zone creation failed for {domain}: {e}");
                (None, None, None, "Error")
            }
        },
        Err(crate::services::cloudflare::CloudflareError::NotConfigured) => {
            tracing::info!("Cloudflare not configured; creating DNS zone locally for {domain}");
            (None, None, None, "Pending")
        }
        Err(e) => {
            tracing::warn!("Cloudflare client error for {domain}: {e}");
            (None, None, None, "Error")
        }
    };

    let zone_id = crate::db::dns::create_zone(
        pool,
        claims.sub,
        domain.clone(),
        cf_zone_id,
        ns1,
        ns2,
        sync_status,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "create_dns_zone",
        Some("dns_zone"),
        Some(zone_id),
        Some(&domain),
        "Success",
        None,
    )
    .await;

    Ok(zone_id)
}

/// List records in a DNS zone.
#[server]
pub async fn server_list_dns_records(zone_id: i64) -> Result<Vec<DnsRecord>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Verify zone ownership
    let zone = crate::db::dns::get_zone(pool, zone_id)
        .await
        .map_err(|_| ServerFnError::new("Zone not found"))?;

    crate::auth::guards::check_ownership(&claims, zone.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::dns::list_records(pool, zone_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Add a DNS record, syncing to Cloudflare.
#[server]
pub async fn server_add_dns_record(
    zone_id: i64,
    name: String,
    record_type: RecordType,
    value: String,
    priority: i32,
    ttl: i32,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Input bounds and character safety checks.
    if name.len() > 253 || name.contains('\n') || name.contains('\r') || name.contains('\0') {
        return Err(ServerFnError::new(
            "DNS record name is invalid (max 253 chars; no control characters).",
        ));
    }
    if value.len() > 2048 || value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(ServerFnError::new(
            "DNS record value is invalid (max 2048 chars; no control characters).",
        ));
    }
    // Per-type format validation (DNS-01): enforce well-formed values per record class.
    match record_type {
        RecordType::A => {
            value.parse::<std::net::Ipv4Addr>().map_err(|_| {
                ServerFnError::new("A record value must be a valid IPv4 address (e.g. 192.0.2.1)")
            })?;
        }
        RecordType::Aaaa => {
            value.parse::<std::net::Ipv6Addr>().map_err(|_| {
                ServerFnError::new(
                    "AAAA record value must be a valid IPv6 address (e.g. 2001:db8::1)",
                )
            })?;
        }
        RecordType::Cname | RecordType::Mx | RecordType::Ns => {
            // Must look like a hostname/FQDN (letters, digits, hyphens, dots).
            if !value.trim_end_matches('.').split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            }) || value.trim_end_matches('.').is_empty()
            {
                return Err(ServerFnError::new(format!(
                    "{} record value must be a valid hostname",
                    record_type
                )));
            }
        }
        // TXT, SRV, CAA have complex formats — control-char check above is sufficient.
        _ => {}
    }
    // TTL: 0 = auto/default; upper bound of one week (RFC 2181 allows up to 2^31-1,
    // but values beyond a week are rarely useful and help cap malformed input).
    if !(0..=604_800).contains(&ttl) {
        return Err(ServerFnError::new(
            "TTL out of range (must be 0–604800 seconds).",
        ));
    }
    // Priority only matters for MX/SRV; cap at the 16-bit DNS wire limit.
    if !(0..=65535).contains(&priority) {
        return Err(ServerFnError::new(
            "Priority out of range (must be 0–65535).",
        ));
    }

    let zone = crate::db::dns::get_zone(pool, zone_id)
        .await
        .map_err(|_| ServerFnError::new("Zone not found"))?;

    crate::auth::guards::check_ownership(&claims, zone.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Sync record to Cloudflare if zone is linked
    let cf_record_id = if let Some(ref cf_zone_id) = zone.cf_zone_id {
        let cf =
            crate::services::cloudflare::client().map_err(|e| ServerFnError::new(e.to_string()))?;

        let type_str = record_type.to_string();
        let prio = if record_type == RecordType::Mx {
            Some(priority)
        } else {
            None
        };

        match cf
            .create_record(cf_zone_id, &type_str, &name, &value, ttl, prio)
            .await
        {
            Ok(rec) => Some(rec.id),
            Err(e) => {
                return Err(ServerFnError::new(format!(
                    "Cloudflare record creation failed: {e}"
                )));
            }
        }
    } else {
        None
    };

    let record_id = crate::db::dns::add_record(
        pool,
        zone_id,
        name,
        record_type,
        value,
        priority,
        ttl,
        cf_record_id,
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "add_dns_record",
        Some("dns_record"),
        Some(record_id),
        Some(&zone.domain),
        "Success",
        None,
    )
    .await;

    Ok(record_id)
}

/// Delete a DNS record, removing from Cloudflare.
#[server]
pub async fn server_delete_dns_record(zone_id: i64, record_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let zone = crate::db::dns::get_zone(pool, zone_id)
        .await
        .map_err(|_| ServerFnError::new("Zone not found"))?;

    crate::auth::guards::check_ownership(&claims, zone.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Delete from Cloudflare first
    let record = crate::db::dns::get_record(pool, record_id)
        .await
        .map_err(|_| ServerFnError::new("Record not found"))?;

    // IDOR guard: ensure the record actually belongs to the requested zone,
    // not to a different user's zone that the caller doesn't own.
    if record.zone_id != zone_id {
        return Err(ServerFnError::new("Record not found"));
    }

    if let (Some(ref cf_zone_id), Some(ref cf_record_id)) = (&zone.cf_zone_id, &record.cf_record_id)
    {
        let cf =
            crate::services::cloudflare::client().map_err(|e| ServerFnError::new(e.to_string()))?;

        if let Err(e) = cf.delete_record(cf_zone_id, cf_record_id).await {
            tracing::warn!("Cloudflare record deletion failed: {e}");
        }
    }

    crate::db::dns::delete_record(pool, record_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_dns_record",
        Some("dns_record"),
        Some(record_id),
        Some(&zone.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Delete a DNS zone and all its records, removing from Cloudflare.
#[server]
pub async fn server_delete_dns_zone(zone_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let zone = crate::db::dns::get_zone(pool, zone_id)
        .await
        .map_err(|_| ServerFnError::new("Zone not found"))?;

    crate::auth::guards::check_ownership(&claims, zone.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Delete zone from Cloudflare
    if let Some(ref cf_zone_id) = zone.cf_zone_id {
        let cf =
            crate::services::cloudflare::client().map_err(|e| ServerFnError::new(e.to_string()))?;

        if let Err(e) = cf.delete_zone(cf_zone_id).await {
            tracing::warn!("Cloudflare zone deletion failed: {e}");
        }
    }

    crate::db::dns::delete_zone(pool, zone_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "delete_dns_zone",
        Some("dns_zone"),
        Some(zone_id),
        Some(&zone.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}
