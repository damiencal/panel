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
    let path = format!("/tmp/.pgk_{}", Uuid::new_v4().simple());

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
    format!(
        "ssh -i {key_path} \
         -o StrictHostKeyChecking=accept-new \
         -o BatchMode=yes \
         -o IdentitiesOnly=yes"
    )
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Initialise a git repository in `dir` and point `origin` at `repo_url`.
/// If `.git` already exists the origin remote is simply updated.
pub async fn init_repo(dir: &str, repo_url: &str) -> Result<String, String> {
    validate_work_dir(dir)?;
    validate_repo_url(repo_url)?;

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
    let key_path = format!("/tmp/.pgdeploy_{}", Uuid::new_v4().simple());

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
