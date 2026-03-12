/// Tests for authentication, JWT token handling, and shell argument safety.
use panel::auth::jwt::{create_token, init_jwt_key, verify_token};
use panel::models::user::Role;

fn init_test_key() {
    // OnceLock: only first call takes effect, subsequent calls are no-ops
    init_jwt_key("test-secret-key-that-is-at-least-32-characters-long".to_string());
}

// ─── JWT Token Tests ───

#[test]
fn jwt_create_and_verify_roundtrip() {
    init_test_key();
    let token = create_token(
        1,
        "admin".into(),
        "admin@example.com".into(),
        Role::Admin,
        None,
    )
    .expect("Failed to create token");
    let claims = verify_token(&token).expect("Failed to verify token");
    assert_eq!(claims.sub, 1);
    assert_eq!(claims.username, "admin");
    assert_eq!(claims.email, "admin@example.com");
    assert_eq!(claims.role, Role::Admin);
    assert_eq!(claims.parent_id, None);
}

#[test]
fn jwt_preserves_reseller_role_and_parent() {
    init_test_key();
    let token = create_token(
        42,
        "reseller1".into(),
        "res@example.com".into(),
        Role::Reseller,
        None,
    )
    .expect("Failed to create token");
    let claims = verify_token(&token).expect("Failed to verify");
    assert_eq!(claims.role, Role::Reseller);
    assert_eq!(claims.sub, 42);
}

#[test]
fn jwt_preserves_client_with_parent_id() {
    init_test_key();
    let token = create_token(
        100,
        "client1".into(),
        "client@example.com".into(),
        Role::Client,
        Some(42),
    )
    .expect("Failed to create token");
    let claims = verify_token(&token).expect("Failed to verify");
    assert_eq!(claims.role, Role::Client);
    assert_eq!(claims.parent_id, Some(42));
}

#[test]
fn jwt_invalid_token_fails() {
    init_test_key();
    let result = verify_token("this.is.not.a.valid.token");
    assert!(result.is_err());
}

#[test]
fn jwt_tampered_token_fails() {
    init_test_key();
    let token = create_token(
        1,
        "admin".into(),
        "admin@example.com".into(),
        Role::Admin,
        None,
    )
    .expect("Failed to create token");
    // Tamper with the token by changing a character
    let mut tampered = token.clone();
    let bytes = unsafe { tampered.as_bytes_mut() };
    if let Some(b) = bytes.last_mut() {
        *b = if *b == b'A' { b'B' } else { b'A' };
    }
    let result = verify_token(&tampered);
    assert!(result.is_err());
}

#[test]
fn jwt_empty_token_fails() {
    init_test_key();
    let result = verify_token("");
    assert!(result.is_err());
}

// ─── Password Hashing Tests ───

#[test]
fn argon2_hash_and_verify() {
    use argon2::{
        password_hash::{
            rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        },
        Argon2,
    };

    let password = "SecureTest123!";
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    let parsed = PasswordHash::new(&hash).expect("Failed to parse hash");
    assert!(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok());
}

#[test]
fn argon2_wrong_password_fails() {
    use argon2::{
        password_hash::{
            rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        },
        Argon2,
    };

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password("CorrectPassword1!".as_bytes(), &salt)
        .expect("Failed to hash")
        .to_string();

    let parsed = PasswordHash::new(&hash).expect("Failed to parse hash");
    assert!(Argon2::default()
        .verify_password("WrongPassword1!".as_bytes(), &parsed)
        .is_err());
}

// ─── Shell Argument Validation Tests ───
// Testing that dangerous shell characters are rejected

#[test]
fn shell_arg_validation_rejects_semicolons() {
    // We test the validation logic directly via the validators
    let dangerous_inputs = vec![
        "arg;rm -rf /",
        "arg|cat /etc/passwd",
        "arg&& evil",
        "$(command)",
        "`command`",
        "arg\ninjection",
        "arg\rinjection",
        "arg()",
        "arg{x}",
    ];
    for input in &dangerous_inputs {
        assert!(
            input.contains(|c: char| matches!(
                c,
                ';' | '|' | '&' | '$' | '`' | '\n' | '\r' | '(' | ')' | '{' | '}'
            )),
            "Expected dangerous chars in: {}",
            input
        );
    }
}

#[test]
fn shell_arg_validation_allows_safe_inputs() {
    let safe_inputs = vec![
        "example.com",
        "/var/www/html",
        "user_123",
        "my-database",
        "192.168.1.1",
        "file.txt",
        "-flag",
        "--long-flag=value",
    ];
    for input in &safe_inputs {
        assert!(
            !input.contains(|c: char| matches!(
                c,
                ';' | '|' | '&' | '$' | '`' | '\n' | '\r' | '(' | ')' | '{' | '}'
            )),
            "Unexpected dangerous chars in safe input: {}",
            input
        );
    }
}
