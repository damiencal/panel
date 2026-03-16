/// Git repository database operations.
use crate::models::git::SiteGitRepo;
use chrono::Utc;
use sqlx::SqlitePool;

/// Get the git repo record attached to a site, if any.
pub async fn get_by_site(
    pool: &SqlitePool,
    site_id: i64,
) -> Result<Option<SiteGitRepo>, sqlx::Error> {
    sqlx::query_as::<_, SiteGitRepo>("SELECT * FROM site_git_repos WHERE site_id = ?")
        .bind(site_id)
        .fetch_optional(pool)
        .await
}

/// Attach a new git repository to a site.
pub async fn attach(
    pool: &SqlitePool,
    site_id: i64,
    repo_url: &str,
    branch: &str,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO site_git_repos (site_id, repo_url, branch, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(site_id)
    .bind(repo_url)
    .bind(branch)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Remove the git repository attachment from a site.
pub async fn detach(pool: &SqlitePool, site_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM site_git_repos WHERE site_id = ?")
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update the tracked branch for a site's repo.
pub async fn update_branch(
    pool: &SqlitePool,
    site_id: i64,
    branch: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE site_git_repos SET branch = ?, updated_at = ? WHERE site_id = ?")
        .bind(branch)
        .bind(now)
        .bind(site_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update the last-sync metadata after a successful pull or push.
pub async fn update_last_sync(
    pool: &SqlitePool,
    site_id: i64,
    commit_hash: &str,
    commit_msg: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE site_git_repos
         SET last_synced_at = ?, last_commit_hash = ?, last_commit_msg = ?, updated_at = ?
         WHERE site_id = ?",
    )
    .bind(now)
    .bind(commit_hash)
    .bind(commit_msg)
    .bind(now)
    .bind(site_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist an Ed25519 deploy key pair for the site's repo.
pub async fn set_deploy_key(
    pool: &SqlitePool,
    site_id: i64,
    private_key: &str,
    public_key: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE site_git_repos
         SET deploy_key_priv = ?, deploy_key_pub = ?, updated_at = ?
         WHERE site_id = ?",
    )
    .bind(private_key)
    .bind(public_key)
    .bind(now)
    .bind(site_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update the atomic-deploy settings for a site's git repo.
pub async fn set_atomic_deploy(
    pool: &SqlitePool,
    site_id: i64,
    atomic_deploy: bool,
    retain_releases: i64,
    deploy_script: Option<&str>,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE site_git_repos
         SET atomic_deploy = ?, retain_releases = ?, deploy_script = ?, updated_at = ?
         WHERE site_id = ?",
    )
    .bind(atomic_deploy)
    .bind(retain_releases)
    .bind(deploy_script)
    .bind(now)
    .bind(site_id)
    .execute(pool)
    .await?;
    Ok(())
}
