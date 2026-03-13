/// Tests for path confinement and `validate_safe_path`.
///
/// `resolve_confined_path` is the core security boundary for the file manager.
/// These tests verify that every known path-traversal and symlink-escape
/// vector is rejected, and that legitimate paths are accepted.
use panel::server::files::resolve_confined_path;
use panel::utils::validators::{validate_ip_address, validate_passwd_field, validate_safe_path};
use std::fs;
use tempfile::TempDir;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Create a temp directory that acts as a site doc_root with a known file inside.
fn make_doc_root() -> TempDir {
    let dir = tempfile::tempdir().expect("Failed to create tempdir");
    fs::write(dir.path().join("index.html"), b"<html/>")
        .expect("Failed to write test file");
    fs::create_dir(dir.path().join("subdir"))
        .expect("Failed to create subdir");
    fs::write(dir.path().join("subdir").join("page.php"), b"<?php ?>")
        .expect("Failed to write nested file");
    dir
}

// ─── resolve_confined_path: valid paths ──────────────────────────────────────

#[test]
fn confined_path_root_slash_returns_root() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/");
    assert!(result.is_ok(), "Root '/' should be allowed: {:?}", result);
    assert_eq!(result.unwrap(), dir.path().canonicalize().unwrap());
}

#[test]
fn confined_path_empty_rel_returns_root() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "");
    assert!(result.is_ok(), "Empty path should resolve to root: {:?}", result);
}

#[test]
fn confined_path_existing_file() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/index.html");
    assert!(result.is_ok(), "Existing file should resolve: {:?}", result);
    assert!(result.unwrap().ends_with("index.html"));
}

#[test]
fn confined_path_nested_existing_file() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/subdir/page.php");
    assert!(result.is_ok(), "Nested existing file should resolve: {:?}", result);
    assert!(result.unwrap().ends_with("page.php"));
}

#[test]
fn confined_path_non_existing_file_in_root() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/newfile.txt");
    assert!(
        result.is_ok(),
        "New file in root should resolve: {:?}",
        result
    );
}

#[test]
fn confined_path_non_existing_file_in_subdir() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/subdir/new.txt");
    assert!(
        result.is_ok(),
        "New file in existing subdir should resolve: {:?}",
        result
    );
}

// ─── resolve_confined_path: traversal vectors rejected ───────────────────────

#[test]
fn confined_path_rejects_dotdot_at_root() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/..");
    assert!(result.is_err(), "/../ must be rejected");
}

#[test]
fn confined_path_rejects_dotdot_in_middle() {
    let dir = make_doc_root();
    let result =
        resolve_confined_path(dir.path().to_str().unwrap(), "/subdir/../../../etc/passwd");
    assert!(result.is_err(), "Mid-path traversal must be rejected");
}

#[test]
fn confined_path_rejects_dotdot_only() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "..");
    assert!(result.is_err(), "Bare '..' must be rejected");
}

#[test]
fn confined_path_rejects_double_dotdot() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "../../etc/shadow");
    assert!(result.is_err(), "Double '..' traversal must be rejected");
}

#[test]
fn confined_path_rejects_null_byte() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/file\0.txt");
    assert!(result.is_err(), "Null byte in path must be rejected");
}

#[test]
fn confined_path_rejects_newline() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/file\nname");
    assert!(result.is_err(), "Newline in path must be rejected");
}

#[test]
fn confined_path_rejects_carriage_return() {
    let dir = make_doc_root();
    let result = resolve_confined_path(dir.path().to_str().unwrap(), "/file\rname");
    assert!(result.is_err(), "Carriage return in path must be rejected");
}

/// Verify that a symlink pointing *outside* the doc_root is rejected.
#[test]
fn confined_path_rejects_symlink_escape() {
    let dir = make_doc_root();

    // Create /tmp/secret as the escape target
    let secret_dir = tempfile::tempdir().expect("Failed to create secret dir");
    fs::write(secret_dir.path().join("secret.txt"), b"secret data")
        .expect("Failed to write secret");

    // Place a symlink inside the doc_root pointing to the secret dir
    let link_path = dir.path().join("escape_link");
    std::os::unix::fs::symlink(secret_dir.path(), &link_path)
        .expect("Failed to create symlink");

    let result = resolve_confined_path(
        dir.path().to_str().unwrap(),
        "/escape_link/secret.txt",
    );
    assert!(
        result.is_err(),
        "Symlink escape must be rejected: {:?}",
        result
    );
}

/// Symlink *within* the doc_root (pointing to a sibling file) must be allowed.
#[test]
fn confined_path_allows_internal_symlink() {
    let dir = make_doc_root();

    // Create a symlink that stays inside the doc_root
    let link_path = dir.path().join("link_to_index.html");
    std::os::unix::fs::symlink(dir.path().join("index.html"), &link_path)
        .expect("Failed to create symlink");

    let result = resolve_confined_path(
        dir.path().to_str().unwrap(),
        "/link_to_index.html",
    );
    assert!(
        result.is_ok(),
        "Internal symlink must be allowed: {:?}",
        result
    );
}

// ─── validate_safe_path ───────────────────────────────────────────────────────

#[test]
fn safe_path_valid() {
    assert!(validate_safe_path("/home/user/sites/example.com/index.html", "/home/user/sites/example.com").is_ok());
}

#[test]
fn safe_path_rejects_dotdot() {
    assert!(validate_safe_path("/home/user/sites/example.com/../../etc/passwd", "/home/user/sites/example.com").is_err());
}

#[test]
fn safe_path_rejects_null_byte() {
    assert!(validate_safe_path("/home/user/sites/example.com/file\0.txt", "/home/user/sites").is_err());
}

#[test]
fn safe_path_rejects_newline() {
    assert!(validate_safe_path("/home/user/file\nname", "/home/user").is_err());
}

#[test]
fn safe_path_rejects_outside_base() {
    assert!(validate_safe_path("/etc/passwd", "/home/user/sites").is_err());
}

#[test]
fn safe_path_rejects_empty() {
    assert!(validate_safe_path("", "/home/user/sites").is_err());
}

#[test]
fn safe_path_rejects_encoded_traversal_dotdot() {
    // validate_safe_path does string-level check; ".." in the string is caught
    assert!(validate_safe_path("/home/user/sites/../secret", "/home/user/sites").is_err());
}

// ─── validate_passwd_field ────────────────────────────────────────────────────

#[test]
fn passwd_field_valid() {
    assert!(validate_passwd_field("user123", "username").is_ok());
    assert!(validate_passwd_field("My Name", "display").is_ok());
    assert!(validate_passwd_field("/home/user", "homedir").is_ok());
}

#[test]
fn passwd_field_rejects_colon() {
    assert!(validate_passwd_field("us:er", "username").is_err());
    assert!(validate_passwd_field("root:0", "username").is_err());
}

#[test]
fn passwd_field_rejects_newline() {
    assert!(validate_passwd_field("user\nroot", "username").is_err());
}

#[test]
fn passwd_field_rejects_carriage_return() {
    assert!(validate_passwd_field("user\rroot", "username").is_err());
}

#[test]
fn passwd_field_rejects_null_byte() {
    assert!(validate_passwd_field("user\0root", "username").is_err());
}

// ─── validate_ip_address ──────────────────────────────────────────────────────

#[test]
fn ip_valid_ipv4() {
    assert!(validate_ip_address("192.168.1.1"));
    assert!(validate_ip_address("10.0.0.1"));
    assert!(validate_ip_address("255.255.255.255"));
    assert!(validate_ip_address("0.0.0.0"));
}

#[test]
fn ip_valid_ipv6_full() {
    assert!(validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
}

#[test]
fn ip_valid_ipv6_compressed() {
    assert!(validate_ip_address("::1"));
    assert!(validate_ip_address("fe80::1"));
}

#[test]
fn ip_invalid_empty() {
    assert!(!validate_ip_address(""));
}

#[test]
fn ip_invalid_injection_chars() {
    assert!(!validate_ip_address("192.168.1.1; rm -rf /"));
    assert!(!validate_ip_address("192.168.1.1 | cat /etc/passwd"));
    assert!(!validate_ip_address("$(hostname)"));
    assert!(!validate_ip_address("192.168.1.1\n127.0.0.1"));
}

#[test]
fn ip_invalid_too_long() {
    let long = "1".repeat(46);
    assert!(!validate_ip_address(&long));
}

#[test]
fn ip_invalid_letters() {
    assert!(!validate_ip_address("not.an.ip.addr"));
}
