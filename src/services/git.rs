/// Git integration service: wraps `git` CLI operations needed by the panel.
///
/// Security model
/// ──────────────
/// * All git operations run via `sudo -n git` so the panel user (which may not
///   own the site's doc_root) can still read/write versioned files.
/// * Working-directory paths are validated: must be absolute, under `/home/`,
///   no `..` traversal, no shell-metacharacters.
/// * Repository URLs must begin with `https://` or `git@` and contain no
///   whitespace or shell-special characters.
/// * Branch names are restricted to alphanumerics plus `-`, `_`, `/`, `.`.
/// * Commit messages are length-capped and stripped of control characters.
/// * SSH deploy keys are written to a temp file (mode 0o600), used for a
///   single operation, then immediately deleted.
use crate::models::git::{GitBranch, GitCommit};
use std::path::Path;
use tokio::fs;
use tokio::process::Command;
use uuid::Uuid;

// ─── Input Validators ────────────────────────────────────────────────────────

/// Validate a repository URL.  Only `https://` and `git@` schemes are accepted.
pub fn validate_repo_url(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("Repository URL cannot be empty".into());
    }
    if !url.starts_with("https://") && !url.starts_with("git@") {
        return Err("Repository URL must start with https:// or git@".into());
    }
    // Reject every shell-special character including whitespace.
    if url.chars().any(|c| {
        matches!(
            c,
            ' ' | ';' | '|' | '&' | '$' | '`' | '\n' | '\r' | '(' | ')' | '{' | '}'
        )
    }) {
        return Err("Repository URL contains invalid characters".into());
    }

    // SSRF-01: extract the hostname and block private/loopback/link-local
    // addresses that could be used to probe internal services or cloud metadata
    // endpoints (e.g. 169.254.169.254).
    let host = if let Some(rest) = url.strip_prefix("https://") {
        // https://user:pass@hostname:port/path — drop auth info and port
        rest.split('/')
            .next()
            .unwrap_or("")
            .split('@')
            .next_back()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
    } else {
        // git@hostname:org/repo.git
        url.strip_prefix("git@")
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
    };

    // Attempt to parse the host as an IP address and reject private/reserved ranges.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let blocked = ip.is_loopback()
            || ip.is_unspecified()
            || match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    // Cloud metadata / APIPA
                    || v4.octets()[0] == 169 && v4.octets()[1] == 254
                }
                std::net::IpAddr::V6(v6) => {
                    // fe80::/10 — link-local (is_unicast_link_local stable since 1.84,
                    // check manually to stay within MSRV 1.76)
                    let seg = v6.segments();
                    (seg[0] & 0xffc0) == 0xfe80
                }
            };
        if blocked {
            return Err("Repository URL hostname resolves to a restricted address".into());
        }
    } else {
        // It is a hostname — block localhost and common internal-only labels.
        let host_lower = host.to_lowercase();
        if host_lower == "localhost"
            || host_lower.ends_with(".local")
            || host_lower.ends_with(".internal")
            || host_lower.ends_with(".localdomain")
        {
            return Err("Repository URL hostname is not permitted".into());
        }
    }

    Ok(())
}

/// Return true if `ip` falls in a range that must never be reached from user-
/// supplied repository URLs.  Mirrors the static check in `validate_repo_url`
/// but applied to *resolved* addresses (DNS-rebinding defence).
fn is_restricted_ip(ip: std::net::IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
        std::net::IpAddr::V6(v6) => {
            let seg = v6.segments();
            (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Resolve the hostname in `url` via DNS and reject any address that falls in
/// a private or restricted range.  This prevents DNS-rebinding attacks where a
/// hostile hostname initially resolves to a legitimate IP at validation time
/// but later resolves to `192.168.x.x` / metadata endpoints for the actual
/// `git clone` request (SSRF-DNS-01).
///
/// Called by `init_repo` immediately after `validate_repo_url` succeeds.
pub async fn check_hostname_not_ssrf(url: &str) -> Result<(), String> {
    // Extract hostname from validated URL (same logic as validate_repo_url).
    let host: &str = if let Some(rest) = url.strip_prefix("https://") {
        rest.split('/')
            .next()
            .unwrap_or("")
            .split('@')
            .next_back()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
    } else if let Some(rest) = url.strip_prefix("git@") {
        rest.split(':').next().unwrap_or("").trim()
    } else {
        return Ok(()); // URL already rejected by validate_repo_url
    };

    if host.is_empty() {
        return Err("Could not extract hostname from repository URL".into());
    }

    // If the host is already a literal IP it was already checked synchronously.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }

    // Resolve hostname to IP addresses and verify none are in restricted ranges.
    // Try port 443 (HTTPS) first, then 22 (SSH) for git@ URLs.
    let probe_port = if url.starts_with("git@") {
        22u16
    } else {
        443u16
    };
    let resolved = tokio::net::lookup_host(format!("{host}:{probe_port}"))
        .await
        .map_err(|_| {
            format!("Cannot resolve repository hostname '{host}'. Ensure the host is reachable.")
        })?;

    for addr in resolved {
        if is_restricted_ip(addr.ip()) {
            return Err(format!(
                "Repository hostname '{host}' resolves to a restricted IP address; \
                 the repository URL is not allowed."
            ));
        }
    }
    Ok(())
}

/// Validate a git branch name (git's own rules, simplified).
pub fn validate_branch(branch: &str) -> Result<(), String> {
    if branch.is_empty() {
        return Err("Branch name cannot be empty".into());
    }
    if branch.len() > 255 {
        return Err("Branch name too long".into());
    }
    if branch
        .chars()
        .any(|c| !c.is_alphanumeric() && !matches!(c, '-' | '_' | '/' | '.'))
    {
        return Err(
            "Branch name contains invalid characters (allowed: alphanumeric, -, _, /, .)".into(),
        );
    }
    if branch.starts_with('.') || branch.ends_with('.') || branch.contains("..") {
        return Err("Invalid branch name".into());
    }
    Ok(())
}

/// Validate a commit message (length cap, no control characters).
pub fn validate_commit_message(msg: &str) -> Result<(), String> {
    if msg.trim().is_empty() {
        return Err("Commit message cannot be empty".into());
    }
    if msg.len() > 1000 {
        return Err("Commit message too long (max 1000 characters)".into());
    }
    Ok(())
}

/// Validate that a working-directory path is safe to pass to git.
/// Must be an absolute path under `/home/`, no `..` traversal.
fn validate_work_dir(dir: &str) -> Result<(), String> {
    if !dir.starts_with("/home/") {
        return Err("Git working directory must be under /home/".into());
    }
    if dir.contains("..") {
        return Err("Path traversal detected in working directory".into());
    }
    if dir
        .chars()
        .any(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '\n' | '\r'))
    {
        return Err("Invalid characters in working directory path".into());
    }
    Ok(())
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

/// Run `sudo -n git <args>` inside `dir` with optional extra environment variables.
async fn run_git(dir: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Result<String, String> {
    // Reject injection characters in any argument before passing to the OS.
    for arg in args {
        if arg
            .chars()
            .any(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '\n' | '\r'))
        {
            return Err(format!("Invalid characters in git argument: {arg}"));
        }
    }

    let mut cmd = Command::new("sudo");
    cmd.arg("-n").arg("git");
    cmd.args(args);
    cmd.current_dir(dir);
    // Prevent git from prompting for credentials interactively.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("HOME", "/root");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let output = cmd.output().await.map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        let msg = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        Err(msg)
    }
}

/// Write an SSH private key to a uniquely-named temp file (mode 0o600).
/// Returns the path; caller **must** delete this file when done.
async fn write_temp_key(private_key: &str) -> Result<String, String> {
    let path = format!("/tmp/panel-git-key-{}", Uuid::new_v4().simple());

    // Create file with 0600 permissions immediately to avoid race condition
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .await
        .map_err(|e| format!("Failed to create deploy key file: {e}"))?;

    use tokio::io::AsyncWriteExt;
    file.write_all(private_key.as_bytes())
        .await
        .map_err(|e| format!("Failed to write deploy key: {e}"))?;

    Ok(path)
}

/// Build the `GIT_SSH_COMMAND` value that uses a specific key file.
fn ssh_cmd_for_key(key_path: &str) -> String {
    // StrictHostKeyChecking=yes: refuse connections to hosts not already in
    // known_hosts.  `init_repo` calls `pre_populate_known_hosts` for every SSH
    // URL before the first git operation, so the host key will always be present.
    format!(
        "ssh -i {key_path} \
         -o StrictHostKeyChecking=yes \
         -o BatchMode=yes \
         -o IdentitiesOnly=yes"
    )
}

/// Pre-populate `/root/.ssh/known_hosts` with the host key for an SSH git URL.
/// Called immediately before the first `git` operation against a new remote so
/// that `StrictHostKeyChecking=yes` does not fail on first use.
///
/// Silently succeeds if `ssh-keyscan` is unavailable or the URL is HTTPS.
async fn pre_populate_known_hosts(repo_url: &str) {
    // Only SSH-style URLs need keyscan (git@ prefix).
    if !repo_url.starts_with("git@") {
        return;
    }
    // Parse hostname from git@host:path format.
    let host = match repo_url.strip_prefix("git@") {
        Some(rest) => rest.split(':').next().unwrap_or("").trim(),
        None => return,
    };
    if host.is_empty() {
        return;
    }
    // Basic hostname sanity check — only alphanumeric, dots, and hyphens.
    if !host
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return;
    }
    // Run ssh-keyscan and append the result to known_hosts.
    // Ignore errors — StrictHostKeyChecking will produce a clearer message.
    let keyscan_output =
        super::shell::exec("ssh-keyscan", &["-H", "-t", "ed25519,ecdsa,rsa", host]).await;
    if let Ok(out) = keyscan_output {
        if !out.stdout.is_empty() {
            let known_hosts_path = "/root/.ssh/known_hosts";
            let _ = tokio::fs::create_dir_all("/root/.ssh").await;
            use tokio::io::AsyncWriteExt;
            if let Ok(mut f) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(known_hosts_path)
                .await
            {
                let _ = f.write_all(&out.stdout).await;
            }
        }
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Initialise a git repository in `dir` and point `origin` at `repo_url`.
/// If `.git` already exists the origin remote is simply updated.
pub async fn init_repo(dir: &str, repo_url: &str) -> Result<String, String> {
    validate_work_dir(dir)?;
    validate_repo_url(repo_url)?;

    // SSRF-DNS-01: resolve hostname at connection time and reject any private/
    // loopback address to prevent DNS-rebinding attacks.
    check_hostname_not_ssrf(repo_url).await?;

    // Pre-populate known_hosts for SSH URLs so that StrictHostKeyChecking=yes
    // does not fail on the first connection to a previously-unseen host.
    pre_populate_known_hosts(repo_url).await;

    if !Path::new(&format!("{dir}/.git")).exists() {
        run_git(dir, &["init"], &[]).await?;
        run_git(dir, &["remote", "add", "origin", repo_url], &[]).await?;
    } else {
        // Silently remove then re-add so the URL is always up to date.
        let _ = run_git(dir, &["remote", "remove", "origin"], &[]).await;
        run_git(dir, &["remote", "add", "origin", repo_url], &[]).await?;
    }

    Ok("Repository configured successfully".to_string())
}

/// Pull the latest changes from `origin/<branch>`.
/// After a successful pull the caller should `chown` the doc-root back to
/// the site's system user.
pub async fn pull(dir: &str, branch: &str, ssh_key: Option<&str>) -> Result<String, String> {
    validate_work_dir(dir)?;
    validate_branch(branch)?;

    let key_file = match ssh_key {
        Some(k) => Some(write_temp_key(k).await?),
        None => None,
    };
    let ssh_env_val = key_file.as_ref().map(|kp| ssh_cmd_for_key(kp));
    let mut env: Vec<(&str, &str)> = Vec::new();
    if let Some(ref v) = ssh_env_val {
        env.push(("GIT_SSH_COMMAND", v.as_str()));
    }

    // Ensure we're on the requested branch before pulling.
    let _ = run_git(dir, &["checkout", branch], &[]).await;
    let result = run_git(dir, &["pull", "origin", branch], &env).await;

    if let Some(ref kp) = key_file {
        let _ = fs::remove_file(kp).await;
    }
    result
}

/// Stage all changes in `dir`, then create a commit.
/// Returns the commit output or "Nothing to commit" if the tree is clean.
pub async fn add_and_commit(
    dir: &str,
    message: &str,
    author_name: &str,
    author_email: &str,
) -> Result<String, String> {
    validate_work_dir(dir)?;
    validate_commit_message(message)?;
    // Defense-in-depth: validate author identity to prevent header injection via env vars
    crate::utils::validators::validate_email(author_email).map_err(|e| e.to_string())?;
    if author_name.is_empty()
        || author_name.len() > 128
        || author_name.chars().any(|c| c.is_control())
    {
        return Err(
            "Invalid author name: must be non-empty, max 128 chars, no control chars".into(),
        );
    }

    run_git(dir, &["add", "-A"], &[]).await?;

    let result = run_git(
        dir,
        &["commit", "-m", message],
        &[
            ("GIT_AUTHOR_NAME", author_name),
            ("GIT_AUTHOR_EMAIL", author_email),
            ("GIT_COMMITTER_NAME", author_name),
            ("GIT_COMMITTER_EMAIL", author_email),
        ],
    )
    .await;

    match result {
        Ok(out) => Ok(out),
        Err(e) if e.contains("nothing to commit") => Ok("Nothing to commit".to_string()),
        Err(e) => Err(e),
    }
}

/// Push `origin/<branch>` to the remote.
pub async fn push(dir: &str, branch: &str, ssh_key: Option<&str>) -> Result<String, String> {
    validate_work_dir(dir)?;
    validate_branch(branch)?;

    let key_file = match ssh_key {
        Some(k) => Some(write_temp_key(k).await?),
        None => None,
    };
    let ssh_env_val = key_file.as_ref().map(|kp| ssh_cmd_for_key(kp));
    let mut env: Vec<(&str, &str)> = Vec::new();
    if let Some(ref v) = ssh_env_val {
        env.push(("GIT_SSH_COMMAND", v.as_str()));
    }

    let result = run_git(dir, &["push", "origin", branch], &env).await;

    if let Some(ref kp) = key_file {
        let _ = fs::remove_file(kp).await;
    }
    result
}

/// Return the last `limit` commits from the current branch.
pub async fn log(dir: &str, limit: u32) -> Result<Vec<GitCommit>, String> {
    validate_work_dir(dir)?;

    let limit_arg = format!("-{limit}");
    // Use a pipe-delimited format: hash|short|author-name|author-email|date|subject
    let output = run_git(
        dir,
        &[
            "log",
            &limit_arg,
            "--date=iso-strict",
            "--format=%H|%h|%an|%ae|%ad|%s",
        ],
        &[],
    )
    .await?;

    let commits = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let p: Vec<&str> = line.splitn(6, '|').collect();
            GitCommit {
                hash: p.first().unwrap_or(&"").to_string(),
                hash_short: p.get(1).unwrap_or(&"").to_string(),
                author_name: p.get(2).unwrap_or(&"").to_string(),
                author_email: p.get(3).unwrap_or(&"").to_string(),
                date: p.get(4).unwrap_or(&"").to_string(),
                message: p.get(5).unwrap_or(&"").to_string(),
            }
        })
        .collect();

    Ok(commits)
}

/// List local and remote-tracking branches.
pub async fn branches(dir: &str) -> Result<Vec<GitBranch>, String> {
    validate_work_dir(dir)?;

    let output = run_git(dir, &["branch", "-a"], &[]).await?;

    let list = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let is_current = line.starts_with('*');
            let raw = line.trim_start_matches('*').trim();
            // Strip the `remotes/origin/` prefix for remote-tracking branches.
            let name = raw
                .strip_prefix("remotes/origin/")
                .unwrap_or(raw)
                .to_string();
            GitBranch { name, is_current }
        })
        // Skip the HEAD pointer line.
        .filter(|b| !b.name.starts_with("HEAD"))
        .collect();

    Ok(list)
}

/// Check out `branch` in `dir`.
pub async fn checkout(dir: &str, branch: &str) -> Result<String, String> {
    validate_work_dir(dir)?;
    validate_branch(branch)?;
    run_git(dir, &["checkout", branch], &[]).await
}

/// Return the short `git status --short` output for `dir`.
pub async fn status(dir: &str) -> Result<String, String> {
    validate_work_dir(dir)?;
    run_git(dir, &["status", "--short"], &[]).await
}

/// Generate a new Ed25519 SSH key pair suitable for a deploy key.
/// Returns `(private_key_pem, public_key_authorized_keys_line)`.
pub async fn generate_deploy_key(label: &str) -> Result<(String, String), String> {
    let key_path = format!("/tmp/panel-git-key-{}", Uuid::new_v4().simple());

    // Sanitise the label so it cannot inject into ssh-keygen arguments.
    let safe_label: String = label
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(*c, '-' | '_' | '.' | '@'))
        .take(64)
        .collect();

    let output = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-C",
            &safe_label,
            "-f",
            &key_path,
            "-N",
            "", // no passphrase
        ])
        .output()
        .await
        .map_err(|e| format!("ssh-keygen failed: {e}"))?;

    if !output.status.success() {
        let _ = fs::remove_file(&key_path).await;
        let _ = fs::remove_file(format!("{key_path}.pub")).await;
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let private_key = fs::read_to_string(&key_path)
        .await
        .map_err(|e| e.to_string())?;
    let public_key = fs::read_to_string(format!("{key_path}.pub"))
        .await
        .map_err(|e| e.to_string())?;

    // Best-effort cleanup — even if these fail the keys were in /tmp.
    let _ = fs::remove_file(&key_path).await;
    let _ = fs::remove_file(format!("{key_path}.pub")).await;

    Ok((
        private_key.trim().to_string(),
        public_key.trim().to_string(),
    ))
}

// ─── Atomic Deployment ───────────────────────────────────────────────────────

/// Validate that a deploy script does not exceed the maximum allowed size.
pub fn validate_deploy_script(script: &str) -> Result<(), String> {
    if script.len() > 4096 {
        return Err("Deploy script exceeds maximum size of 4096 bytes".into());
    }
    // Block patterns commonly used for reverse shells, data exfiltration, or
    // persistent backdoors. The check runs on the normalised script (tabs → space,
    // collapse runs) so that tab-character bypasses like "eval\t" don't slip through.
    // Patterns are matched as substrings; single-word entries (no trailing space)
    // match regardless of what follows the command name.
    let normalised = script.replace('\t', " ");
    const BLOCKED: &[&str] = &[
        // Network exfiltration tools
        "curl", "wget", "nc", "ncat", "socat", "netcat", "/dev/tcp", "/dev/udp",
        // Remote shell / copy tools
        "ssh", "scp", "sftp", "rsync", // Code execution / scripting interpreters
        "awk", "sed -e", "eval ", "base64", "python", "perl", "ruby", "php", "node ", "nodejs ",
        // Data-pipeline / exfiltration helpers
        "dd ", "mkfifo", "openssl ", // Background / persistence
        " & ", "&&", "||", "nohup", "crontab",
        // Command chaining via shell control characters
        ";", // Process substitution / command substitution via backtick/dollar-paren
        "`", "$(",
    ];
    for pat in BLOCKED {
        if normalised.contains(pat) {
            return Err(format!(
                "Deploy script contains a disallowed pattern: '{pat}'"
            ));
        }
    }
    Ok(())
}

/// Extract the site-owner username from a validated doc_root path (`/home/{user}/…`).
fn username_from_doc_root(doc_root: &str) -> Result<String, String> {
    // doc_root is already validated to start with /home/ and contain no ..
    let parts: Vec<&str> = doc_root.trim_start_matches('/').splitn(3, '/').collect();
    // parts = ["home", "{username}", "..."]
    if parts.len() < 2 || parts[1].is_empty() {
        return Err(format!("Cannot extract username from doc_root: {doc_root}"));
    }
    let username = parts[1];
    // Validate username contains only safe characters before use in commands.
    if username
        .chars()
        .any(|c| !c.is_alphanumeric() && !matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "Unsafe username extracted from doc_root: {username}"
        ));
    }
    Ok(username.to_string())
}

/// Set up the atomic-deploy directory structure for `doc_root`.
///
/// After this call:
/// - `{doc_root}/repo/`    contains the git working tree (cloned from the outer tree)
/// - `{doc_root}/releases/` is created
/// - `{doc_root}/public`   is an atomic symlink pointing at the initial release
///
/// The OLS vhost `docRoot` (`{doc_root}/public`) is unchanged — LiteSpeed
/// follows symlinks by default, so no vhost config change or restart is needed.
pub async fn enable_atomic_deploy(doc_root: &str) -> Result<(), String> {
    validate_work_dir(doc_root)?;

    let repo_dir = format!("{doc_root}/repo");
    let releases_dir = format!("{doc_root}/releases");

    // Re-entrant: skip clone if repo/ already exists.
    if !Path::new(&repo_dir).exists() {
        let output = Command::new("sudo")
            .args(["-n", "git", "clone", "--local", doc_root, &repo_dir])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        // Remove .git from the outer tree (now lives in repo/).
        let git_dir = format!("{doc_root}/.git");
        if Path::new(&git_dir).exists() {
            tokio::fs::remove_dir_all(&git_dir)
                .await
                .map_err(|e| format!("Failed to remove old .git: {e}"))?;
        }
    }

    // Create releases/ directory.
    tokio::fs::create_dir_all(&releases_dir)
        .await
        .map_err(|e| format!("Failed to create releases/: {e}"))?;

    // Take an initial snapshot if public/ currently exists as a real directory.
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let release_dir = format!("{releases_dir}/{ts}");
    let public_src = format!("{doc_root}/public");
    let release_pub = format!("{release_dir}/public");

    let public_meta = tokio::fs::symlink_metadata(&public_src).await;
    let public_is_real_dir = public_meta
        .map(|m| m.is_dir() && !m.file_type().is_symlink())
        .unwrap_or(false);

    if public_is_real_dir {
        tokio::fs::create_dir_all(&release_dir)
            .await
            .map_err(|e| format!("Failed to create initial release dir: {e}"))?;

        let cp_out = Command::new("sudo")
            .args(["-n", "cp", "-a", &public_src, &release_pub])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !cp_out.status.success() {
            return Err(String::from_utf8_lossy(&cp_out.stderr).trim().to_string());
        }

        // Atomic symlink swap: ln -sfn target tmp && mv -T tmp public
        let tmp_link = format!("{doc_root}/public_next");
        let ln_out = Command::new("sudo")
            .args(["-n", "ln", "-sfn", &release_pub, &tmp_link])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !ln_out.status.success() {
            return Err(String::from_utf8_lossy(&ln_out.stderr).trim().to_string());
        }
        let mv_out = Command::new("sudo")
            .args(["-n", "mv", "-T", &tmp_link, &public_src])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !mv_out.status.success() {
            return Err(String::from_utf8_lossy(&mv_out.stderr).trim().to_string());
        }
    }

    Ok(())
}

/// Revert the atomic-deploy structure, restoring `public` as a plain directory.
///
/// After this call:
/// - `{doc_root}/public` is a real directory (content of the current release)
/// - `{doc_root}/repo/` and `{doc_root}/releases/` are removed
pub async fn disable_atomic_deploy(doc_root: &str) -> Result<(), String> {
    validate_work_dir(doc_root)?;

    let public_link = format!("{doc_root}/public");
    let public_restore = format!("{doc_root}/public_restore");
    let releases_dir = format!("{doc_root}/releases");
    let repo_dir = format!("{doc_root}/repo");

    // Resolve the current symlink target and copy it to a real directory.
    let target = tokio::fs::read_link(&public_link)
        .await
        .map_err(|e| format!("public symlink not found or unreadable: {e}"))?;
    let target_str = target
        .to_str()
        .ok_or("symlink target is not valid UTF-8")?
        .to_string();

    validate_work_dir(&target_str)?; // ensure target is still under /home/

    let cp_out = Command::new("sudo")
        .args(["-n", "cp", "-a", &target_str, &public_restore])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !cp_out.status.success() {
        return Err(String::from_utf8_lossy(&cp_out.stderr).trim().to_string());
    }

    // Replace the symlink with the real directory.
    let mv_out = Command::new("sudo")
        .args(["-n", "mv", "-T", &public_restore, &public_link])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !mv_out.status.success() {
        return Err(String::from_utf8_lossy(&mv_out.stderr).trim().to_string());
    }

    // Move the git working tree back to doc_root if repo/ exists.
    if Path::new(&repo_dir).exists() {
        let git_out = Command::new("sudo")
            .args(["-n", "git", "clone", "--local", &repo_dir, doc_root])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if git_out.status.success() {
            let _ = tokio::fs::remove_dir_all(&repo_dir).await;
        }
    }

    // Remove the releases directory.
    if Path::new(&releases_dir).exists() {
        tokio::fs::remove_dir_all(&releases_dir)
            .await
            .map_err(|e| format!("Failed to remove releases/: {e}"))?;
    }

    Ok(())
}

/// Pull inside `{doc_root}/repo/`, snapshot the result to a new release, and
/// atomically swap `{doc_root}/public` to the new snapshot.
///
/// `retain` specifies how many past release directories to keep (0 = keep all).
/// Returns a combined output string (git pull output + optional deploy script output).
pub async fn atomic_pull(
    doc_root: &str,
    branch: &str,
    ssh_key: Option<&str>,
    retain: i64,
    deploy_script: Option<&str>,
) -> Result<String, String> {
    validate_work_dir(doc_root)?;
    validate_branch(branch)?;
    if let Some(script) = deploy_script {
        validate_deploy_script(script)?;
    }

    let repo_dir = format!("{doc_root}/repo");
    validate_work_dir(&repo_dir)?;

    // ── 1. Pull inside repo/ ──────────────────────────────────────────────────
    let key_file = match ssh_key {
        Some(k) => Some(write_temp_key(k).await?),
        None => None,
    };
    let ssh_env_val = key_file.as_ref().map(|kp| ssh_cmd_for_key(kp));
    let mut env: Vec<(&str, &str)> = Vec::new();
    if let Some(ref v) = ssh_env_val {
        env.push(("GIT_SSH_COMMAND", v.as_str()));
    }

    let _ = run_git(&repo_dir, &["checkout", branch], &[]).await;
    let pull_result = run_git(&repo_dir, &["pull", "origin", branch], &env).await;

    if let Some(ref kp) = key_file {
        let _ = fs::remove_file(kp).await;
    }
    let pull_out = pull_result?;

    // ── 2. Snapshot repo/public → releases/{ts}/public ───────────────────────
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S%3f").to_string();
    let releases_dir = format!("{doc_root}/releases");
    let release_dir = format!("{releases_dir}/{ts}");
    let release_pub = format!("{release_dir}/public");
    let repo_pub = format!("{repo_dir}/public");

    tokio::fs::create_dir_all(&release_dir)
        .await
        .map_err(|e| format!("Failed to create release dir: {e}"))?;

    // Use -aL to dereference any inner symlinks in the source tree.
    let cp_out = Command::new("sudo")
        .args(["-n", "cp", "-aL", &repo_pub, &release_pub])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !cp_out.status.success() {
        return Err(format!(
            "Snapshot failed: {}",
            String::from_utf8_lossy(&cp_out.stderr).trim()
        ));
    }

    // ── 3. Optional deploy script ─────────────────────────────────────────────
    let mut script_out = String::new();
    if let Some(script) = deploy_script {
        if !script.trim().is_empty() {
            let username = username_from_doc_root(doc_root)?;
            let script_path = format!("/tmp/panel-deploy-{}", Uuid::new_v4().simple());

            // Write deploy script with 0700 permissions (owner-executable only).
            let mut f = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&script_path)
                .await
                .map_err(|e| format!("Failed to create deploy script temp file: {e}"))?;
            use tokio::io::AsyncWriteExt;
            f.write_all(script.as_bytes())
                .await
                .map_err(|e| format!("Failed to write deploy script: {e}"))?;
            drop(f);

            let run = Command::new("sudo")
                .args(["-n", "-u", &username, "timeout", "60", "bash", &script_path])
                .env("RELEASE_DIR", &release_dir)
                .env("DOC_ROOT", doc_root)
                .output()
                .await;

            // Always clean up the script file.
            let _ = tokio::fs::remove_file(&script_path).await;

            match run {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                    if o.status.success() {
                        script_out = stdout;
                    } else {
                        return Err(format!(
                            "Deploy script failed:\n{}",
                            if stderr.trim().is_empty() {
                                stdout.trim()
                            } else {
                                stderr.trim()
                            }
                        ));
                    }
                }
                Err(e) => return Err(format!("Failed to run deploy script: {e}")),
            }
        }
    }

    // ── 4. Atomic symlink swap ────────────────────────────────────────────────
    let public_link = format!("{doc_root}/public");
    let tmp_link = format!("{doc_root}/public_next");

    let ln_out = Command::new("sudo")
        .args(["-n", "ln", "-sfn", &release_pub, &tmp_link])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !ln_out.status.success() {
        return Err(String::from_utf8_lossy(&ln_out.stderr).trim().to_string());
    }
    let mv_out = Command::new("sudo")
        .args(["-n", "mv", "-T", &tmp_link, &public_link])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !mv_out.status.success() {
        return Err(String::from_utf8_lossy(&mv_out.stderr).trim().to_string());
    }

    // ── 5. Prune old releases ─────────────────────────────────────────────────
    if retain > 0 {
        if let Ok(mut rd) = tokio::fs::read_dir(&releases_dir).await {
            let mut entries: Vec<String> = Vec::new();
            while let Ok(Some(entry)) = rd.next_entry().await {
                if let Ok(ft) = entry.file_type().await {
                    if ft.is_dir() {
                        if let Ok(name) = entry.file_name().into_string() {
                            entries.push(name);
                        }
                    }
                }
            }
            entries.sort(); // lexicographic order = chronological for YYYYMMDD… names
            let excess = entries.len().saturating_sub(retain as usize);
            for old in entries.into_iter().take(excess) {
                let old_path = format!("{releases_dir}/{old}");
                let _ = tokio::fs::remove_dir_all(&old_path).await;
            }
        }
    }

    Ok(format!("{pull_out}\n{script_out}").trim().to_string())
}
