/// Web statistics server functions (Webalizer / GoAccess / AWStats).
use crate::models::stats::{StatsConfig, StatsTool, StatsToolAvailability};
use dioxus::prelude::*;

/// Base directory under which per-domain stats HTML output is stored.
#[cfg(feature = "server")]
const STATS_BASE_DIR: &str = "/var/www/stats";

/// Path to the OLS combined-format access log for a domain.
#[cfg(feature = "server")]
fn access_log_path(domain: &str) -> String {
    format!("/usr/local/lsws/logs/{}.access.log", domain)
}

/// Output directory for a domain+tool pair.
#[cfg(feature = "server")]
fn output_dir(domain: &str, tool: &str) -> String {
    format!("{}/{}/{}", STATS_BASE_DIR, domain, tool.to_lowercase())
}

// ── List / read ──────────────────────────────────────────────────────────────

/// List all stats configurations for the caller's sites.
#[server]
pub async fn server_list_stats() -> Result<Vec<StatsConfig>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let configs = match claims.role {
        crate::models::user::Role::Admin => crate::db::stats::list_all(pool).await,
        crate::models::user::Role::Reseller => {
            // Collect owner IDs of all clients
            let clients: Vec<crate::models::user::User> =
                crate::db::users::list_clients_for_reseller(pool, claims.sub)
                    .await
                    .map_err(|e| ServerFnError::new(e.to_string()))?;

            let mut result = Vec::new();
            for client in &clients {
                let rows = crate::db::stats::list_for_owner(pool, client.id)
                    .await
                    .map_err(|e| ServerFnError::new(e.to_string()))?;
                result.extend(rows);
            }
            Ok(result)
        }
        crate::models::user::Role::Client => {
            crate::db::stats::list_for_owner(pool, claims.sub).await
        }
        // Developers have no web-stats access.
        crate::models::user::Role::Developer => Ok(Vec::new()),
    }
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(configs)
}

// ── Enable / disable ─────────────────────────────────────────────────────────

/// Enable or disable a stats tool for a site. Creates the config row if needed.
#[server]
pub async fn server_toggle_stats(
    site_id: i64,
    tool: StatsTool,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    // Verify ownership
    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let tool_name = match tool {
        StatsTool::Webalizer => "webalizer",
        StatsTool::GoAccess => "goaccess",
        StatsTool::AwStats => "awstats",
    };
    let out_dir = output_dir(&site.domain, tool_name);

    let config_id = crate::db::stats::ensure_config(pool, site_id, &site.domain, tool, &out_dir)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    crate::db::stats::set_enabled(pool, config_id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        if enabled {
            "enable_stats"
        } else {
            "disable_stats"
        },
        Some("site"),
        Some(site_id),
        Some(&format!("{} {}", tool, site.domain)),
        "Success",
        None,
    )
    .await;

    Ok(())
}

// ── Run ──────────────────────────────────────────────────────────────────────

/// Trigger statistics generation for a site + tool pair.
///
/// Runs synchronously (spawned from the frontend); reports back the outcome.
#[server]
pub async fn server_run_stats(site_id: i64, tool: StatsTool) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use crate::models::stats::StatsRunStatus;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let tool_name = match tool {
        StatsTool::Webalizer => "webalizer",
        StatsTool::GoAccess => "goaccess",
        StatsTool::AwStats => "awstats",
    };
    let out_dir = output_dir(&site.domain, tool_name);
    let log_path = access_log_path(&site.domain);

    let config_id = crate::db::stats::ensure_config(pool, site_id, &site.domain, tool, &out_dir)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Mark as running
    let _ = crate::db::stats::record_run(pool, config_id, StatsRunStatus::Running, None).await;

    let run_result = match tool {
        StatsTool::Webalizer => {
            crate::services::webalizer::generate(&log_path, &out_dir, &site.domain).await
        }
        StatsTool::GoAccess => {
            crate::services::goaccess::generate(&log_path, &out_dir, &site.domain).await
        }
        StatsTool::AwStats => {
            crate::services::awstats::generate(&log_path, &out_dir, &site.domain).await
        }
    };

    match run_result {
        Ok(()) => {
            let _ =
                crate::db::stats::record_run(pool, config_id, StatsRunStatus::Success, None).await;
            audit_log(
                claims.sub,
                "run_stats",
                Some("site"),
                Some(site_id),
                Some(&format!("{} {}", tool, site.domain)),
                "Success",
                None,
            )
            .await;
            Ok(())
        }
        Err(e) => {
            let err_str = e.to_string();
            let _ = crate::db::stats::record_run(
                pool,
                config_id,
                StatsRunStatus::Failed,
                Some(&err_str),
            )
            .await;
            Err(ServerFnError::new(err_str))
        }
    }
}

// ── Tool availability ────────────────────────────────────────────────────────

/// Check which stats tools are installed on the server.
#[server]
pub async fn server_check_stats_tools() -> Result<StatsToolAvailability, ServerFnError> {
    use super::helpers::*;
    ensure_init().await.map_err(ServerFnError::new)?;
    let _ = verify_auth()?;

    Ok(StatsToolAvailability {
        webalizer: crate::services::webalizer::is_installed().await,
        goaccess: crate::services::goaccess::is_installed().await,
        awstats: crate::services::awstats::is_installed().await,
    })
}

/// Install a stats tool (admin only).
#[server]
pub async fn server_install_stats_tool(tool: StatsTool) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    if claims.role != crate::models::user::Role::Admin {
        return Err(ServerFnError::new("Admin only"));
    }

    match tool {
        StatsTool::Webalizer => crate::services::webalizer::install().await,
        StatsTool::GoAccess => crate::services::goaccess::install().await,
        StatsTool::AwStats => crate::services::awstats::install().await,
    }
    .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Return the public URL for a domain's stats report.
#[server]
pub async fn server_get_stats_url(site_id: i64, tool: StatsTool) -> Result<String, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;
    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Verify the config exists and was successful
    let config = crate::db::stats::get_for_site_tool(pool, site_id, tool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Stats not yet generated for this domain/tool"))?;

    match config.last_status {
        Some(crate::models::stats::StatsRunStatus::Success) => {}
        _ => {
            return Err(ServerFnError::new(
                "Stats not yet generated for this domain/tool",
            ))
        }
    }

    let tool_path = match tool {
        StatsTool::Webalizer => "webalizer",
        StatsTool::GoAccess => "goaccess",
        StatsTool::AwStats => "awstats",
    };

    // Convention: stats are served under /stats/<domain>/<tool>/
    // The entry point differs per tool
    let entry = match tool {
        StatsTool::Webalizer | StatsTool::AwStats => "index.html",
        StatsTool::GoAccess => "report.html",
    };

    Ok(format!(
        "https://{}/stats/{}/{}/{}",
        site.domain, site.domain, tool_path, entry
    ))
}
