use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single file or directory entry returned by the file manager.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    /// Filename without any path component.
    pub name: String,
    /// Path relative to the site's doc_root, always starting with '/'.
    pub rel_path: String,
    pub is_dir: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
    pub modified: DateTime<Utc>,
    /// Unix permissions in symbolic form, e.g. "rwxr-xr-x".
    pub permissions: String,
}

/// Text file contents for in-browser editing. Capped at 1 MiB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextFileContent {
    pub rel_path: String,
    pub content: String,
    pub size: u64,
}

/// One-time download token for a specific file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDownloadToken {
    /// UUID token used in the download URL.
    pub token: String,
    /// Original filename for Content-Disposition header.
    pub filename: String,
    /// Pre-built download URL.
    pub download_url: String,
}
