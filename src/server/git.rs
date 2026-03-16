/// Git integration server functions.
use crate::models::git::{GitBranch, GitCommit, SiteGitRepoPublic};
use dioxus::prelude::*;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Strip absolute filesystem paths and home-directory prefixes from git
/// output before sending it to the client.  This prevents information
/// disclosure of the server's directory layout (e.g. `/home/john/sites/…`).
#[cfg(feature = "server")]
fn scrub_git_output(output: &str, doc_root: &str) -> String {
    // Replace the exact doc_root first (longest, most specific match).
    let s = output.replace(doc_root, "[repo]");
    // Replace any remaining /home/<user> prefixes.
    let re_home = regex::Regex::new(r"/home/[^/\s]+").expect("static regex");
    re_home.replace_all(&s, "[home]").into_owned()
}

// ─── Query ───────────────────────────────────────────────────────────────────

/// Return the git-repo record for a site (private key stripped).
#[server]
pub async fn server_get_site_git_repo(
    site_id: i64,
) -> Result<Option<SiteGitRepoPublic>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    // Verify that the caller owns (or administers) the site.
    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let record = crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(record.map(Into::into))
}

// ─── Attach / Detach ─────────────────────────────────────────────────────────

/// Attach a remote git repository to a site and initialise the working tree.
#[server]
pub async fn server_attach_git_repo(
    site_id: i64,
    repo_url: String,
    branch: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::services::git::validate_repo_url(&repo_url).map_err(ServerFnError::new)?;
    crate::services::git::validate_branch(&branch).map_err(ServerFnError::new)?;

    // If there is already a record, detach it first (idempotent re-attach).
    let _ = crate::db::git::detach(pool, site_id).await;

    // Persist the new attachment before touching the filesystem.
    crate::db::git::attach(pool, site_id, &repo_url, &branch)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Initialise the local working tree (or update the remote if already a repo).
    crate::services::git::init_repo(&site.doc_root, &repo_url)
        .await
        .map_err(ServerFnError::new)?;

    audit_log(
        claims.sub,
        "attach_git_repo",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Detach the git repository from a site (DB record only; files remain).
#[server]
pub async fn server_detach_git_repo(site_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::git::detach(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "detach_git_repo",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ─── Deploy Key ──────────────────────────────────────────────────────────────

/// Generate a new Ed25519 deploy key for the site's repo.
/// Returns the **public** key for the user to add to their repository.
#[server]
pub async fn server_git_generate_deploy_key(site_id: i64) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Verify a repo is attached.
    crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    let label = format!("panel-deploy-{}", site.domain);
    let (private_key, public_key) = crate::services::git::generate_deploy_key(&label)
        .await
        .map_err(ServerFnError::new)?;

    crate::db::git::set_deploy_key(pool, site_id, &private_key, &public_key)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "git_generate_deploy_key",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(public_key)
}

// ─── Pull ────────────────────────────────────────────────────────────────────

/// Pull the latest commits from `origin/<branch>` into the site's doc_root.
/// When `atomic_deploy` is enabled on the repo, uses the symlink-swap strategy.
/// Developers with granted site access can also trigger pulls.
#[server]
pub async fn server_git_pull(site_id: i64) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_developer_site_access(pool, &claims, site.owner_id, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let repo = crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    let ssh_key = repo.deploy_key_priv.as_deref();

    let output = if repo.atomic_deploy {
        crate::services::git::atomic_pull(
            &site.doc_root,
            &repo.branch,
            ssh_key,
            repo.retain_releases,
            repo.deploy_script.as_deref(),
        )
        .await
        .map_err(ServerFnError::new)?
    } else {
        crate::services::git::pull(&site.doc_root, &repo.branch, ssh_key)
            .await
            .map_err(ServerFnError::new)?
    };

    // Restore ownership of files potentially written as root by git.
    if let (Some(uid), Some(gid)) = (
        crate::db::users::get(pool, site.owner_id)
            .await
            .ok()
            .and_then(|u| u.system_uid),
        crate::db::users::get(pool, site.owner_id)
            .await
            .ok()
            .and_then(|u| u.system_gid),
    ) {
        let uid_gid = format!("{uid}:{gid}");
        let _ = crate::services::shell::exec("chown", &["-R", &uid_gid, &site.doc_root]).await;
    }

    // Update the cached last-sync info from the most recent commit.
    let log_dir = if repo.atomic_deploy {
        format!("{}/repo", site.doc_root)
    } else {
        site.doc_root.clone()
    };
    if let Ok(commits) = crate::services::git::log(&log_dir, 1).await {
        if let Some(c) = commits.first() {
            let _ = crate::db::git::update_last_sync(pool, site_id, &c.hash, &c.message).await;
        }
    }

    audit_log(
        claims.sub,
        "git_pull",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(scrub_git_output(&output, &site.doc_root))
}

// ─── Commit ──────────────────────────────────────────────────────────────────

/// Stage all changes and create a commit (does **not** push).
#[server]
pub async fn server_git_commit(site_id: i64, message: String) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    crate::services::git::validate_commit_message(&message).map_err(ServerFnError::new)?;

    let user = crate::db::users::get(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let output =
        crate::services::git::add_and_commit(&site.doc_root, &message, &user.username, &user.email)
            .await
            .map_err(ServerFnError::new)?;

    // Update cached commit info.
    if let Ok(commits) = crate::services::git::log(&site.doc_root, 1).await {
        if let Some(c) = commits.first() {
            let _ = crate::db::git::update_last_sync(pool, site_id, &c.hash, &c.message).await;
        }
    }

    audit_log(
        claims.sub,
        "git_commit",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(scrub_git_output(&output, &site.doc_root))
}

// ─── Push ────────────────────────────────────────────────────────────────────

/// Push the current branch to `origin`.
#[server]
pub async fn server_git_push(site_id: i64) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let repo = crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    let ssh_key = repo.deploy_key_priv.as_deref();
    let output = crate::services::git::push(&site.doc_root, &repo.branch, ssh_key)
        .await
        .map_err(|e| ServerFnError::new(scrub_git_output(&e, &site.doc_root)))?;

    audit_log(
        claims.sub,
        "git_push",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(scrub_git_output(&output, &site.doc_root))
}

// ─── Commit + Push ───────────────────────────────────────────────────────────

/// Stage all changes, commit with `message`, then push to origin — in one step.
#[server]
pub async fn server_git_commit_and_push(
    site_id: i64,
    message: String,
) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let repo = crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    crate::services::git::validate_commit_message(&message).map_err(ServerFnError::new)?;

    let user = crate::db::users::get(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Commit…
    let commit_out =
        crate::services::git::add_and_commit(&site.doc_root, &message, &user.username, &user.email)
            .await
            .map_err(ServerFnError::new)?;

    // …then push.
    let ssh_key = repo.deploy_key_priv.as_deref();
    let push_out = crate::services::git::push(&site.doc_root, &repo.branch, ssh_key)
        .await
        .map_err(ServerFnError::new)?;

    // Update cached commit info.
    if let Ok(commits) = crate::services::git::log(&site.doc_root, 1).await {
        if let Some(c) = commits.first() {
            let _ = crate::db::git::update_last_sync(pool, site_id, &c.hash, &c.message).await;
        }
    }

    audit_log(
        claims.sub,
        "git_commit_and_push",
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    let raw = format!("{commit_out}\n{push_out}");
    Ok(scrub_git_output(raw.trim(), &site.doc_root))
}

// ─── Status ──────────────────────────────────────────────────────────────────

/// Return `git status --short` for the site's working tree.
#[server]
pub async fn server_git_status(site_id: i64) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    crate::services::git::status(&site.doc_root)
        .await
        .map(|o| scrub_git_output(&o, &site.doc_root))
        .map_err(|e| ServerFnError::new(scrub_git_output(&e, &site.doc_root)))
}

// ─── Commit History ──────────────────────────────────────────────────────────

/// Return the last `limit` commits on the current branch.
#[server]
pub async fn server_git_log(site_id: i64, limit: u32) -> Result<Vec<GitCommit>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    crate::services::git::log(&site.doc_root, limit.min(200))
        .await
        .map_err(ServerFnError::new)
}

// ─── Branch Management ───────────────────────────────────────────────────────

/// List local and remote-tracking branches for the site's repo.
#[server]
pub async fn server_git_branches(site_id: i64) -> Result<Vec<GitBranch>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    crate::services::git::branches(&site.doc_root)
        .await
        .map_err(ServerFnError::new)
}

/// Check out `branch` in the site's working tree and update the tracked branch.
#[server]
pub async fn server_git_checkout(site_id: i64, branch: String) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    crate::services::git::validate_branch(&branch).map_err(ServerFnError::new)?;

    crate::services::git::checkout(&site.doc_root, &branch)
        .await
        .map_err(ServerFnError::new)?;

    crate::db::git::update_branch(pool, site_id, &branch)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "git_checkout",
        Some("site"),
        Some(site_id),
        Some(&branch),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ─── Atomic Deploy Toggle ─────────────────────────────────────────────────────

/// Enable or disable the atomic symlink-swap deployment strategy for a site.
///
/// When enabling, the git working tree is moved to `{doc_root}/repo/` and the
/// first release snapshot is taken.  When disabling, the current release is
/// restored into `{doc_root}/public` as a plain directory and `repo/` is removed.
///
/// The OLS vhost `docRoot` (`{doc_root}/public`) is unchanged throughout.
#[server]
pub async fn server_set_atomic_deploy(
    site_id: i64,
    enabled: bool,
    retain_releases: i64,
    deploy_script: Option<String>,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Verify a repo is attached.
    crate::db::git::get_by_site(pool, site_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("No repository attached to this site"))?;

    if !(0..=365).contains(&retain_releases) {
        return Err(ServerFnError::new(
            "retain_releases must be between 0 and 365",
        ));
    }

    if let Some(ref script) = deploy_script {
        if !script.trim().is_empty() {
            // Deploy scripts execute shell commands; require the shell_access package entitlement.
            let user = crate::db::users::get(pool, claims.sub)
                .await
                .map_err(|_| ServerFnError::new("User not found"))?;
            if let Some(pkg_id) = user.package_id {
                let pkg = crate::db::packages::get(pool, pkg_id)
                    .await
                    .map_err(|_| ServerFnError::new("Package not found"))?;
                if !pkg.shell_access {
                    return Err(ServerFnError::new(
                        "Your plan does not include shell access; deploy scripts are disabled.",
                    ));
                }
            }
            crate::services::git::validate_deploy_script(script).map_err(ServerFnError::new)?;
        }
    }

    // Apply filesystem changes.
    if enabled {
        crate::services::git::enable_atomic_deploy(&site.doc_root)
            .await
            .map_err(ServerFnError::new)?;
    } else {
        crate::services::git::disable_atomic_deploy(&site.doc_root)
            .await
            .map_err(ServerFnError::new)?;
    }

    // Persist the updated configuration.
    crate::db::git::set_atomic_deploy(
        pool,
        site_id,
        enabled,
        retain_releases,
        deploy_script.as_deref(),
    )
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        if enabled {
            "enable_atomic_deploy"
        } else {
            "disable_atomic_deploy"
        },
        Some("site"),
        Some(site_id),
        Some(&site.domain),
        "Success",
        None,
    )
    .await;

    Ok(())
}
