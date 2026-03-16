/// Tests for quota enforcement helpers in `panel::db::quotas`.
///
/// Each test spins up an in-memory SQLite database, creates the minimum
/// set of tables required (resource_quotas + resource_usage), seeds data,
/// and exercises the public quota API.
use panel::db::quotas::{
    allocate_quota, check_can_create_database, check_can_create_email_account,
    check_can_create_site, get_quota, get_usage, increment_databases, increment_email_accounts,
    increment_sites, init_usage, usage_percent,
};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

/// Bootstrap a transient in-memory SQLite pool with the tables under test.
/// We deliberately omit the full migration set and only create the tables
/// this module actually touches – unit tests should be fast and focused.
async fn make_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to create in-memory pool");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS resource_quotas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            max_clients INTEGER,
            max_sites INTEGER NOT NULL DEFAULT 10,
            max_databases INTEGER NOT NULL DEFAULT 5,
            max_email_accounts INTEGER NOT NULL DEFAULT 100,
            disk_limit_mb INTEGER NOT NULL DEFAULT 102400,
            bandwidth_limit_mb INTEGER NOT NULL DEFAULT 1048576,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create resource_quotas table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS resource_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            sites_used INTEGER DEFAULT 0,
            databases_used INTEGER DEFAULT 0,
            email_accounts_used INTEGER DEFAULT 0,
            disk_used_mb INTEGER DEFAULT 0,
            bandwidth_used_mb INTEGER DEFAULT 0,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create resource_usage table");

    pool
}

// ─── usage_percent (pure function) ───────────────────────────────────────────

#[test]
fn usage_percent_zero_used() {
    assert_eq!(usage_percent(0, 10), 0);
}

#[test]
fn usage_percent_full() {
    assert_eq!(usage_percent(10, 10), 100);
}

#[test]
fn usage_percent_half() {
    assert_eq!(usage_percent(5, 10), 50);
}

#[test]
fn usage_percent_over_limit() {
    // Exceeding the limit rounds above 100
    assert!(usage_percent(12, 10) > 100);
}

#[test]
fn usage_percent_unlimited_returns_zero() {
    assert_eq!(usage_percent(999, 0), 0);
    assert_eq!(usage_percent(999, -1), 0);
}

// ─── allocate_quota / get_quota ──────────────────────────────────────────────

#[tokio::test]
async fn allocate_and_read_quota() {
    let pool = make_pool().await;
    allocate_quota(&pool, 1, None, 5, 3, 20, 10240, 102400)
        .await
        .expect("allocate_quota failed");

    let q = get_quota(&pool, 1).await.expect("get_quota failed");
    assert_eq!(q.max_sites, 5);
    assert_eq!(q.max_databases, 3);
    assert_eq!(q.max_email_accounts, 20);
}

#[tokio::test]
async fn allocate_quota_upserts_on_conflict() {
    let pool = make_pool().await;
    allocate_quota(&pool, 2, None, 5, 3, 20, 10240, 102400)
        .await
        .expect("first insert failed");
    allocate_quota(&pool, 2, None, 10, 6, 50, 20480, 204800)
        .await
        .expect("upsert failed");

    let q = get_quota(&pool, 2).await.expect("get_quota failed");
    assert_eq!(q.max_sites, 10);
    assert_eq!(q.max_databases, 6);
}

// ─── init_usage / get_usage / increment_* ────────────────────────────────────

#[tokio::test]
async fn init_usage_starts_at_zero() {
    let pool = make_pool().await;
    init_usage(&pool, 3).await.expect("init_usage failed");

    let u = get_usage(&pool, 3).await.expect("get_usage failed");
    assert_eq!(u.sites_used, 0);
    assert_eq!(u.databases_used, 0);
    assert_eq!(u.email_accounts_used, 0);
}

#[tokio::test]
async fn increment_sites_increases_count() {
    let pool = make_pool().await;
    init_usage(&pool, 4).await.unwrap();

    increment_sites(&pool, 4, 1).await.unwrap();
    increment_sites(&pool, 4, 1).await.unwrap();

    let u = get_usage(&pool, 4).await.unwrap();
    assert_eq!(u.sites_used, 2);
}

#[tokio::test]
async fn increment_sites_decrements() {
    let pool = make_pool().await;
    init_usage(&pool, 5).await.unwrap();

    increment_sites(&pool, 5, 3).await.unwrap();
    increment_sites(&pool, 5, -1).await.unwrap();

    let u = get_usage(&pool, 5).await.unwrap();
    assert_eq!(u.sites_used, 2);
}

#[tokio::test]
async fn increment_databases_increases_count() {
    let pool = make_pool().await;
    init_usage(&pool, 6).await.unwrap();

    increment_databases(&pool, 6, 2).await.unwrap();

    let u = get_usage(&pool, 6).await.unwrap();
    assert_eq!(u.databases_used, 2);
}

#[tokio::test]
async fn increment_email_accounts_increases_count() {
    let pool = make_pool().await;
    init_usage(&pool, 7).await.unwrap();

    increment_email_accounts(&pool, 7, 5).await.unwrap();

    let u = get_usage(&pool, 7).await.unwrap();
    assert_eq!(u.email_accounts_used, 5);
}

// ─── check_can_create_site ───────────────────────────────────────────────────

#[tokio::test]
async fn check_site_allows_when_no_quota_row() {
    // No quota row → allowed by default
    let pool = make_pool().await;
    assert!(check_can_create_site(&pool, 99).await.is_ok());
}

#[tokio::test]
async fn check_site_allows_when_under_limit() {
    let pool = make_pool().await;
    allocate_quota(&pool, 10, None, 5, 3, 20, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 10).await.unwrap();
    increment_sites(&pool, 10, 2).await.unwrap();

    assert!(check_can_create_site(&pool, 10).await.is_ok());
}

#[tokio::test]
async fn check_site_denies_at_limit() {
    let pool = make_pool().await;
    allocate_quota(&pool, 11, None, 3, 3, 20, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 11).await.unwrap();
    increment_sites(&pool, 11, 3).await.unwrap(); // at the limit

    let result = check_can_create_site(&pool, 11).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Site limit reached"));
}

#[tokio::test]
async fn check_site_allows_when_limit_is_zero_unlimited() {
    let pool = make_pool().await;
    allocate_quota(&pool, 12, None, 0, 3, 20, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 12).await.unwrap();
    increment_sites(&pool, 12, 9999).await.unwrap();

    // max_sites = 0 means unlimited
    assert!(check_can_create_site(&pool, 12).await.is_ok());
}

// ─── check_can_create_database ───────────────────────────────────────────────

#[tokio::test]
async fn check_database_allows_when_no_quota_row() {
    let pool = make_pool().await;
    assert!(check_can_create_database(&pool, 99).await.is_ok());
}

#[tokio::test]
async fn check_database_allows_when_under_limit() {
    let pool = make_pool().await;
    allocate_quota(&pool, 20, None, 5, 5, 20, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 20).await.unwrap();
    increment_databases(&pool, 20, 4).await.unwrap();

    assert!(check_can_create_database(&pool, 20).await.is_ok());
}

#[tokio::test]
async fn check_database_denies_at_limit() {
    let pool = make_pool().await;
    allocate_quota(&pool, 21, None, 5, 2, 20, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 21).await.unwrap();
    increment_databases(&pool, 21, 2).await.unwrap();

    let result = check_can_create_database(&pool, 21).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Database limit reached"));
}

#[tokio::test]
async fn check_database_allows_when_limit_is_zero_unlimited() {
    let pool = make_pool().await;
    allocate_quota(&pool, 22, None, 5, 0, 20, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 22).await.unwrap();
    increment_databases(&pool, 22, 9999).await.unwrap();

    assert!(check_can_create_database(&pool, 22).await.is_ok());
}

// ─── check_can_create_email_account ──────────────────────────────────────────

#[tokio::test]
async fn check_email_allows_when_no_quota_row() {
    let pool = make_pool().await;
    assert!(check_can_create_email_account(&pool, 99).await.is_ok());
}

#[tokio::test]
async fn check_email_allows_when_under_limit() {
    let pool = make_pool().await;
    allocate_quota(&pool, 30, None, 5, 3, 10, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 30).await.unwrap();
    increment_email_accounts(&pool, 30, 9).await.unwrap();

    assert!(check_can_create_email_account(&pool, 30).await.is_ok());
}

#[tokio::test]
async fn check_email_denies_at_limit() {
    let pool = make_pool().await;
    allocate_quota(&pool, 31, None, 5, 3, 5, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 31).await.unwrap();
    increment_email_accounts(&pool, 31, 5).await.unwrap();

    let result = check_can_create_email_account(&pool, 31).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Email account limit reached"));
}

#[tokio::test]
async fn check_email_allows_when_limit_is_zero_unlimited() {
    let pool = make_pool().await;
    allocate_quota(&pool, 32, None, 5, 3, 0, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 32).await.unwrap();
    increment_email_accounts(&pool, 32, 9999).await.unwrap();

    assert!(check_can_create_email_account(&pool, 32).await.is_ok());
}

// ─── Edge cases ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn check_site_denies_exactly_one_over_limit() {
    // One over: sites_used == max_sites + 1 (shouldn't happen in practice, but
    // the check must still deny)
    let pool = make_pool().await;
    allocate_quota(&pool, 40, None, 2, 3, 20, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 40).await.unwrap();
    increment_sites(&pool, 40, 3).await.unwrap(); // already over

    let result = check_can_create_site(&pool, 40).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn allocate_quota_negative_means_unlimited() {
    let pool = make_pool().await;
    allocate_quota(&pool, 50, None, -1, -1, -1, 10240, 102400)
        .await
        .unwrap();
    init_usage(&pool, 50).await.unwrap();
    increment_sites(&pool, 50, 9999).await.unwrap();
    increment_databases(&pool, 50, 9999).await.unwrap();
    increment_email_accounts(&pool, 50, 9999).await.unwrap();

    assert!(check_can_create_site(&pool, 50).await.is_ok());
    assert!(check_can_create_database(&pool, 50).await.is_ok());
    assert!(check_can_create_email_account(&pool, 50).await.is_ok());
}
