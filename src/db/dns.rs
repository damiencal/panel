/// DNS zone and record operations (Cloudflare-backed).
use crate::models::dns::{DnsRecord, DnsZone, ZoneType};
use chrono::Utc;
use sqlx::SqlitePool;

/// Get a zone by ID.
pub async fn get_zone(pool: &SqlitePool, zone_id: i64) -> Result<DnsZone, sqlx::Error> {
    sqlx::query_as::<_, DnsZone>("SELECT * FROM dns_zones WHERE id = ?")
        .bind(zone_id)
        .fetch_one(pool)
        .await
}

/// Get a zone by its Cloudflare zone ID.
pub async fn get_zone_by_cf_id(
    pool: &SqlitePool,
    cf_zone_id: &str,
) -> Result<DnsZone, sqlx::Error> {
    sqlx::query_as::<_, DnsZone>("SELECT * FROM dns_zones WHERE cf_zone_id = ?")
        .bind(cf_zone_id)
        .fetch_one(pool)
        .await
}

/// List zones for an owner.
pub async fn list_zones(pool: &SqlitePool, owner_id: i64) -> Result<Vec<DnsZone>, sqlx::Error> {
    sqlx::query_as::<_, DnsZone>("SELECT * FROM dns_zones WHERE owner_id = ? ORDER BY domain")
        .bind(owner_id)
        .fetch_all(pool)
        .await
}

/// Create a DNS zone.
pub async fn create_zone(
    pool: &SqlitePool,
    owner_id: i64,
    domain: String,
    cf_zone_id: Option<String>,
    nameserver1: Option<String>,
    nameserver2: Option<String>,
    sync_status: &str,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO dns_zones (owner_id, domain, zone_type, status, cf_zone_id, nameserver1, nameserver2, sync_status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(owner_id)
    .bind(domain)
    .bind(ZoneType::Primary)
    .bind("Active")
    .bind(cf_zone_id)
    .bind(nameserver1)
    .bind(nameserver2)
    .bind(sync_status)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Update the Cloudflare zone ID and sync status for a zone.
pub async fn update_zone_cf(
    pool: &SqlitePool,
    zone_id: i64,
    cf_zone_id: &str,
    nameserver1: Option<&str>,
    nameserver2: Option<&str>,
    sync_status: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE dns_zones SET cf_zone_id = ?, nameserver1 = ?, nameserver2 = ?, sync_status = ?, updated_at = ? WHERE id = ?",
    )
    .bind(cf_zone_id)
    .bind(nameserver1)
    .bind(nameserver2)
    .bind(sync_status)
    .bind(now)
    .bind(zone_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update zone sync status (e.g. after a Cloudflare error).
pub async fn update_zone_sync_status(
    pool: &SqlitePool,
    zone_id: i64,
    sync_status: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE dns_zones SET sync_status = ?, updated_at = ? WHERE id = ?")
        .bind(sync_status)
        .bind(now)
        .bind(zone_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get a DNS record by ID.
pub async fn get_record(pool: &SqlitePool, record_id: i64) -> Result<DnsRecord, sqlx::Error> {
    sqlx::query_as::<_, DnsRecord>("SELECT * FROM dns_records WHERE id = ?")
        .bind(record_id)
        .fetch_one(pool)
        .await
}

/// List records for a zone.
pub async fn list_records(pool: &SqlitePool, zone_id: i64) -> Result<Vec<DnsRecord>, sqlx::Error> {
    sqlx::query_as::<_, DnsRecord>("SELECT * FROM dns_records WHERE zone_id = ? ORDER BY name")
        .bind(zone_id)
        .fetch_all(pool)
        .await
}

/// Add a DNS record.
pub async fn add_record(
    pool: &SqlitePool,
    zone_id: i64,
    name: String,
    record_type: crate::models::dns::RecordType,
    value: String,
    priority: i32,
    ttl: i32,
    cf_record_id: Option<String>,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO dns_records (zone_id, name, type, value, priority, ttl, cf_record_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(zone_id)
    .bind(name)
    .bind(record_type)
    .bind(value)
    .bind(priority)
    .bind(ttl)
    .bind(cf_record_id)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Delete a DNS record.
pub async fn delete_record(pool: &SqlitePool, record_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM dns_records WHERE id = ?")
        .bind(record_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a DNS zone and all its records.
pub async fn delete_zone(pool: &SqlitePool, zone_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM dns_records WHERE zone_id = ?")
        .bind(zone_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM dns_zones WHERE id = ?")
        .bind(zone_id)
        .execute(pool)
        .await?;
    Ok(())
}
