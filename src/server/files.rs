/// File manager server functions.
///
/// Every operation is confined to the requesting user's site document root.
/// Path confinement is enforced via canonicalization *and* structural
/// `..`-component rejection so symlink attacks and traversal attacks are
/// both blocked independently.
use crate::models::files::{FileDownloadToken, FileEntry, TextFileContent};
use dioxus::prelude::*;

// ─── Path confinement ────────────────────────────────────────────────────────

/// Resolve `rel_path` against `doc_root` and enforce confinement.
///
/// Security guarantees (defense-in-depth):
///
/// 1. Rejects null bytes, newlines and carriage returns (injection).
/// 2. Rejects `..` *path components* (traversal without symlinks).
/// 3. Canonicalizes the `doc_root` so its own symlinks are resolved first.
/// 4. For existing paths: canonicalizes (resolves symlinks) and then verifies
///    the result still starts with the canonical doc_root.
/// 5. For non-existing paths: canonicalizes the *parent* directory and
///    verifies it, then reconstructs the full path – so symlinks in parent
///    directories cannot escape containment.
#[cfg(feature = "server")]
pub fn resolve_confined_path(
    doc_root: &str,
    rel_path: &str,
) -> Result<std::path::PathBuf, String> {
    use std::path::Component;

    // 1. Reject injection characters
    if rel_path.contains('\0') || rel_path.contains('\n') || rel_path.contains('\r') {
        return Err("Path contains invalid characters".into());
    }

    // 2. Reject traversal via component inspection (handles both `/..` and `..`)
    for comp in std::path::Path::new(rel_path).components() {
        if matches!(comp, Component::ParentDir) {
            return Err("Path traversal not allowed".into());
        }
    }

    // 3. Canonicalize doc_root (resolves symlinks in the root itself)
    let canonical_root = std::fs::canonicalize(doc_root)
        .map_err(|_| "Site directory not accessible".to_string())?;

    // Build the absolute path by joining canonical_root with the stripped rel_path
    let stripped = rel_path.trim_start_matches('/');
    let joined = if stripped.is_empty() {
        canonical_root.clone()
    } else {
        canonical_root.join(stripped)
    };

    // 4 / 5. Resolve symlinks and re-verify containment
    let resolved = if joined.exists() {
        let canonical = std::fs::canonicalize(&joined)
            .map_err(|e| format!("Cannot resolve path: {}", e))?;
        if !canonical.starts_with(&canonical_root) {
            return Err("Access denied: path outside site directory".into());
        }
        canonical
    } else {
        // New path – canonicalize the parent to catch symlink escapes there
        let parent = joined
            .parent()
            .ok_or_else(|| "Invalid path: no parent directory".to_string())?;
        if parent.as_os_str().is_empty() || !parent.exists() {
            return Err("Parent directory does not exist".into());
        }
        let canonical_parent = std::fs::canonicalize(parent)
            .map_err(|e| format!("Cannot resolve parent: {}", e))?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err("Access denied: path outside site directory".into());
        }
        let file_name = joined
            .file_name()
            .ok_or_else(|| "Invalid filename".to_string())?;
        canonical_parent.join(file_name)
    };

    Ok(resolved)
}

/// Convert raw Unix permission mode bits (lower 9) to an `rwxrwxrwx` string.
#[cfg(feature = "server")]
fn mode_to_str(mode: u32) -> String {
    [
        if mode & 0o400 != 0 { 'r' } else { '-' },
        if mode & 0o200 != 0 { 'w' } else { '-' },
        if mode & 0o100 != 0 { 'x' } else { '-' },
        if mode & 0o040 != 0 { 'r' } else { '-' },
        if mode & 0o020 != 0 { 'w' } else { '-' },
        if mode & 0o010 != 0 { 'x' } else { '-' },
        if mode & 0o004 != 0 { 'r' } else { '-' },
        if mode & 0o002 != 0 { 'w' } else { '-' },
        if mode & 0o001 != 0 { 'x' } else { '-' },
    ]
    .iter()
    .collect()
}

/// Convert an absolute path back to a `/`-prefixed rel_path from `canonical_root`.
#[cfg(feature = "server")]
fn to_rel_path(abs_path: &std::path::Path, canonical_root: &std::path::Path) -> String {
    let stripped = abs_path
        .strip_prefix(canonical_root)
        .unwrap_or(abs_path)
        .to_string_lossy();
    if stripped.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", stripped)
    }
}

// ─── Server functions ────────────────────────────────────────────────────────

/// List the contents of a directory inside the site's doc_root.
///
/// `rel_path` is relative to doc_root (e.g. `"/"` for root, `"/images"` for a
/// sub-directory).  Entries are sorted with directories first, then files,
/// both in case-insensitive alphabetical order.
#[server]
pub async fn server_fm_list_dir(
    site_id: i64,
    rel_path: String,
) -> Result<Vec<FileEntry>, ServerFnError> {
    use super::helpers::*;
    use std::os::unix::fs::PermissionsExt;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_path =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    if !abs_path.is_dir() {
        return Err(ServerFnError::new("Not a directory"));
    }

    let canonical_root = std::fs::canonicalize(&site.doc_root)
        .map_err(|_| ServerFnError::new("Site directory not accessible"))?;

    let mut entries: Vec<FileEntry> = Vec::new();
    let mut read_dir = tokio::fs::read_dir(&abs_path)
        .await
        .map_err(|e| ServerFnError::new(format!("Cannot read directory: {}", e)))?;

    while let Some(entry) = read_dir
        .next_entry()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
    {
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue, // skip entries we can't stat
        };

        let name = entry.file_name().to_string_lossy().to_string();
        let abs_entry = entry.path();
        let rel = to_rel_path(&abs_entry, &canonical_root);

        let mode = meta.permissions().mode();
        let permissions = mode_to_str(mode);

        let modified = meta
            .modified()
            .map(chrono::DateTime::<chrono::Utc>::from)
            .unwrap_or_else(|_| chrono::Utc::now());

        entries.push(FileEntry {
            name,
            rel_path: rel,
            is_dir: meta.is_dir(),
            size: if meta.is_dir() { 0 } else { meta.len() },
            modified,
            permissions,
        });
    }

    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    Ok(entries)
}

/// Create a new directory inside the site's doc_root.
#[server]
pub async fn server_fm_create_dir(
    site_id: i64,
    rel_path: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_path =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    if abs_path.exists() {
        return Err(ServerFnError::new("Path already exists"));
    }

    tokio::fs::create_dir_all(&abs_path)
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to create directory: {}", e)))?;

    audit_log(
        claims.sub,
        "fm_create_dir",
        Some("site"),
        Some(site_id),
        Some(&rel_path),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Rename a file or directory.
///
/// `new_name` must be a bare filename with no path separators; the renamed
/// entry stays in the same directory as the source.
#[server]
pub async fn server_fm_rename(
    site_id: i64,
    rel_path: String,
    new_name: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    // Validate new_name: bare filename only
    if new_name.is_empty()
        || new_name.contains('/')
        || new_name.contains('\0')
        || new_name.contains('\n')
        || new_name.contains('\r')
        || new_name == "."
        || new_name == ".."
    {
        return Err(ServerFnError::new("Invalid filename"));
    }

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_src =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    if !abs_src.exists() {
        return Err(ServerFnError::new("Source not found"));
    }

    // Destination: same parent directory
    let canonical_parent = std::fs::canonicalize(
        abs_src
            .parent()
            .ok_or_else(|| ServerFnError::new("Invalid source path"))?,
    )
    .map_err(|_| ServerFnError::new("Cannot resolve parent directory"))?;

    let canonical_root = std::fs::canonicalize(&site.doc_root)
        .map_err(|_| ServerFnError::new("Site directory not accessible"))?;

    if !canonical_parent.starts_with(&canonical_root) {
        return Err(ServerFnError::new("Access denied"));
    }

    let abs_dst = canonical_parent.join(&new_name);
    if abs_dst.exists() {
        return Err(ServerFnError::new("Destination already exists"));
    }

    tokio::fs::rename(&abs_src, &abs_dst)
        .await
        .map_err(|e| ServerFnError::new(format!("Rename failed: {}", e)))?;

    audit_log(
        claims.sub,
        "fm_rename",
        Some("site"),
        Some(site_id),
        Some(&format!("{} → {}", rel_path, new_name)),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Delete a file or directory (recursive).
///
/// Deleting the site root (`"/"`) is explicitly rejected.
#[server]
pub async fn server_fm_delete(site_id: i64, rel_path: String) -> Result<(), ServerFnError> {
    use super::helpers::*;

    if rel_path == "/" || rel_path.is_empty() {
        return Err(ServerFnError::new(
            "Cannot delete the site root directory",
        ));
    }

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_path =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    if !abs_path.exists() {
        return Err(ServerFnError::new("File or directory not found"));
    }

    if abs_path.is_dir() {
        tokio::fs::remove_dir_all(&abs_path)
            .await
            .map_err(|e| ServerFnError::new(format!("Delete failed: {}", e)))?;
    } else {
        tokio::fs::remove_file(&abs_path)
            .await
            .map_err(|e| ServerFnError::new(format!("Delete failed: {}", e)))?;
    }

    audit_log(
        claims.sub,
        "fm_delete",
        Some("site"),
        Some(site_id),
        Some(&rel_path),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Move a file or directory to a new location, both within the site's doc_root.
#[server]
pub async fn server_fm_move(
    site_id: i64,
    src_path: String,
    dst_path: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_src =
        resolve_confined_path(&site.doc_root, &src_path).map_err(ServerFnError::new)?;
    let abs_dst =
        resolve_confined_path(&site.doc_root, &dst_path).map_err(ServerFnError::new)?;

    if !abs_src.exists() {
        return Err(ServerFnError::new("Source not found"));
    }
    if abs_dst.exists() {
        return Err(ServerFnError::new("Destination already exists"));
    }

    tokio::fs::rename(&abs_src, &abs_dst)
        .await
        .map_err(|e| ServerFnError::new(format!("Move failed: {}", e)))?;

    audit_log(
        claims.sub,
        "fm_move",
        Some("site"),
        Some(site_id),
        Some(&format!("{} → {}", src_path, dst_path)),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Change file/directory permissions to an octal mode (e.g. `"644"`, `"755"`).
///
/// Only the lower 9 permission bits are accepted.  setuid, setgid, and sticky
/// bits (mode > `0o777`) are rejected.
#[server]
pub async fn server_fm_set_permissions(
    site_id: i64,
    rel_path: String,
    mode_str: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;
    use std::os::unix::fs::PermissionsExt;

    let mode = u32::from_str_radix(mode_str.trim(), 8)
        .map_err(|_| ServerFnError::new("Invalid mode: expected 3 octal digits (e.g. 644)"))?;

    if mode > 0o777 {
        return Err(ServerFnError::new(
            "Invalid mode: setuid/setgid/sticky bits are not allowed",
        ));
    }

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_path =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    if !abs_path.exists() {
        return Err(ServerFnError::new("File not found"));
    }

    tokio::fs::set_permissions(&abs_path, std::fs::Permissions::from_mode(mode))
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to set permissions: {}", e)))?;

    audit_log(
        claims.sub,
        "fm_chmod",
        Some("site"),
        Some(site_id),
        Some(&format!("{} → {}", rel_path, mode_str)),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Extract a `.zip`, `.tar.gz`, `.tgz`, or `.tar` archive into its parent
/// directory.  The archive path must be within the site's doc_root.
#[server]
pub async fn server_fm_extract_archive(
    site_id: i64,
    rel_path: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_path =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    if !abs_path.is_file() {
        return Err(ServerFnError::new("Archive file not found"));
    }

    let filename = abs_path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let dest_dir = abs_path
        .parent()
        .ok_or_else(|| ServerFnError::new("Cannot determine extraction directory"))?;

    let abs_str = abs_path.to_string_lossy().to_string();
    let dest_str = dest_dir.to_string_lossy().to_string();

    if filename.ends_with(".zip") {
        crate::services::shell::exec("unzip", &["-o", &abs_str, "-d", &dest_str])
            .await
            .map_err(|e| ServerFnError::new(format!("Extraction failed: {}", e)))?;
    } else if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        crate::services::shell::exec("tar", &["-xzf", &abs_str, "-C", &dest_str])
            .await
            .map_err(|e| ServerFnError::new(format!("Extraction failed: {}", e)))?;
    } else if filename.ends_with(".tar") {
        crate::services::shell::exec("tar", &["-xf", &abs_str, "-C", &dest_str])
            .await
            .map_err(|e| ServerFnError::new(format!("Extraction failed: {}", e)))?;
    } else {
        return Err(ServerFnError::new(
            "Unsupported archive format (supported: .zip, .tar.gz, .tgz, .tar)",
        ));
    }

    audit_log(
        claims.sub,
        "fm_extract",
        Some("site"),
        Some(site_id),
        Some(&rel_path),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Read a text file for in-browser editing.  Capped at 1 MiB.
/// Returns an error for binary files (those containing null bytes) and files
/// that are not valid UTF-8.
#[server]
pub async fn server_fm_read_text_file(
    site_id: i64,
    rel_path: String,
) -> Result<TextFileContent, ServerFnError> {
    use super::helpers::*;

    const MAX_EDIT_BYTES: u64 = 1024 * 1024; // 1 MiB

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_path =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    let meta = tokio::fs::metadata(&abs_path)
        .await
        .map_err(|_| ServerFnError::new("File not found"))?;

    if meta.is_dir() {
        return Err(ServerFnError::new(
            "Cannot read a directory as a text file",
        ));
    }
    if meta.len() > MAX_EDIT_BYTES {
        return Err(ServerFnError::new(
            "File too large for in-browser editing (max 1 MiB)",
        ));
    }

    let bytes = tokio::fs::read(&abs_path)
        .await
        .map_err(|e| ServerFnError::new(format!("Read failed: {}", e)))?;

    if bytes.contains(&0u8) {
        return Err(ServerFnError::new(
            "File appears to be binary and cannot be edited as text",
        ));
    }

    let content =
        String::from_utf8(bytes).map_err(|_| ServerFnError::new("File is not valid UTF-8"))?;

    Ok(TextFileContent {
        rel_path,
        size: meta.len(),
        content,
    })
}

/// Write (overwrite) a text file.  Size is capped at 1 MiB.
///
/// Uses an atomic write (temp file + rename) so a failed write never
/// partially overwrites the original.  The original file's permissions are
/// preserved if the file already exists.
#[server]
pub async fn server_fm_write_text_file(
    site_id: i64,
    rel_path: String,
    content: String,
) -> Result<(), ServerFnError> {
    use super::helpers::*;

    const MAX_WRITE_BYTES: usize = 1024 * 1024; // 1 MiB

    if content.len() > MAX_WRITE_BYTES {
        return Err(ServerFnError::new("Content too large (max 1 MiB)"));
    }

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_path =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    let parent = abs_path
        .parent()
        .ok_or_else(|| ServerFnError::new("Invalid path"))?;

    // Atomic write: temp file in same directory then rename
    let temp_name = format!(".panel_write_{}", uuid::Uuid::new_v4().as_simple());
    let temp_path = parent.join(&temp_name);

    tokio::fs::write(&temp_path, content.as_bytes())
        .await
        .map_err(|e| ServerFnError::new(format!("Write failed: {}", e)))?;

    // Preserve original permissions if file exists
    if abs_path.exists() {
        if let Ok(perm) = tokio::fs::metadata(&abs_path).await.map(|m| m.permissions()) {
            let _ = tokio::fs::set_permissions(&temp_path, perm).await;
        }
    }

    if let Err(e) = tokio::fs::rename(&temp_path, &abs_path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(ServerFnError::new(format!("Write failed: {}", e)));
    }

    audit_log(
        claims.sub,
        "fm_write_file",
        Some("site"),
        Some(site_id),
        Some(&rel_path),
        "Success",
        None,
    )
    .await;

    Ok(())
}

/// Create a short-lived one-time download token for a specific file.
///
/// The token is valid for 10 minutes and consumed on first use.  The caller
/// must present the same JWT cookie that created the token when downloading.
#[server]
pub async fn server_fm_create_download_token(
    site_id: i64,
    rel_path: String,
) -> Result<FileDownloadToken, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let site = crate::db::sites::get(pool, site_id)
        .await
        .map_err(|_| ServerFnError::new("Site not found"))?;

    crate::auth::guards::check_ownership(&claims, site.owner_id, None)
        .map_err(|_| ServerFnError::new("Access denied"))?;

    let abs_path =
        resolve_confined_path(&site.doc_root, &rel_path).map_err(ServerFnError::new)?;

    if !abs_path.is_file() {
        return Err(ServerFnError::new("File not found"));
    }

    let filename = abs_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let abs_str = abs_path.to_string_lossy().to_string();
    let token = uuid::Uuid::new_v4().simple().to_string();
    let expires_at = chrono::Utc::now().timestamp() + 600; // 10 minutes

    register_file_download_token(token.clone(), claims.sub, abs_str, filename.clone(), expires_at);

    Ok(FileDownloadToken {
        download_url: format!("/api/files/download/{}", token),
        token,
        filename,
    })
}

// ─── Download token store ─────────────────────────────────────────────────────

#[cfg(feature = "server")]
struct FileDownloadEntry {
    pub user_id: i64,
    pub file_path: String,
    pub filename: String,
    pub expires_at: i64,
}

#[cfg(feature = "server")]
static FILE_DOWNLOAD_TOKENS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, FileDownloadEntry>>,
> = std::sync::OnceLock::new();

#[cfg(feature = "server")]
fn file_download_store(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, FileDownloadEntry>> {
    FILE_DOWNLOAD_TOKENS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Register a newly minted download token.
#[cfg(feature = "server")]
pub fn register_file_download_token(
    token: String,
    user_id: i64,
    file_path: String,
    filename: String,
    expires_at: i64,
) {
    let mut store = file_download_store().lock().unwrap();
    let now = chrono::Utc::now().timestamp();
    store.retain(|_, v| v.expires_at > now); // purge expired entries
    store.insert(
        token,
        FileDownloadEntry {
            user_id,
            file_path,
            filename,
            expires_at,
        },
    );
}

/// Consume a token (one-shot).  Returns `Some((file_path, filename))` on
/// success and `None` if the token is missing, expired, or belongs to a
/// different user.
#[cfg(feature = "server")]
pub fn consume_file_download_token(token: &str, user_id: i64) -> Option<(String, String)> {
    let mut store = file_download_store().lock().unwrap();
    let now = chrono::Utc::now().timestamp();

    if let Some(entry) = store.get(token) {
        if entry.expires_at <= now {
            store.remove(token);
            return None;
        }
        if entry.user_id != user_id {
            return None; // leave the token in place – don't leak timing
        }
        let result = (entry.file_path.clone(), entry.filename.clone());
        store.remove(token);
        return Some(result);
    }
    None
}
