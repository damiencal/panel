/// Comprehensive tests for input validation.
use panel::utils::validators::*;

// ─── Email Validation ───

#[test]
fn email_valid_basic() {
    assert!(validate_email("user@example.com").is_ok());
}

#[test]
fn email_valid_with_dots() {
    assert!(validate_email("first.last@example.com").is_ok());
}

#[test]
fn email_valid_with_plus() {
    assert!(validate_email("user+tag@example.com").is_ok());
}

#[test]
fn email_valid_subdomain() {
    assert!(validate_email("user@mail.example.com").is_ok());
}

#[test]
fn email_invalid_no_at() {
    assert!(validate_email("userexample.com").is_err());
}

#[test]
fn email_invalid_no_domain() {
    assert!(validate_email("user@").is_err());
}

#[test]
fn email_invalid_no_tld() {
    assert!(validate_email("user@example").is_err());
}

#[test]
fn email_invalid_empty() {
    assert!(validate_email("").is_err());
}

#[test]
fn email_invalid_too_long() {
    let long = format!("{}@example.com", "a".repeat(250));
    assert!(validate_email(&long).is_err());
}

// ─── Domain Validation ───

#[test]
fn domain_valid_basic() {
    assert!(validate_domain("example.com").is_ok());
}

#[test]
fn domain_valid_subdomain() {
    assert!(validate_domain("sub.example.com").is_ok());
}

#[test]
fn domain_valid_long_tld() {
    assert!(validate_domain("example.technology").is_ok());
}

#[test]
fn domain_invalid_double_dots() {
    assert!(validate_domain("example..com").is_err());
}

#[test]
fn domain_invalid_too_short() {
    assert!(validate_domain("a.b").is_err());
}

#[test]
fn domain_invalid_starts_with_hyphen() {
    assert!(validate_domain("-example.com").is_err());
}

#[test]
fn domain_invalid_special_chars() {
    assert!(validate_domain("exam ple.com").is_err());
}

// ─── Username Validation ───

#[test]
fn username_valid_alphanumeric() {
    assert!(validate_username("user123").is_ok());
}

#[test]
fn username_valid_with_underscore() {
    assert!(validate_username("my_user").is_ok());
}

#[test]
fn username_valid_with_hyphen() {
    assert!(validate_username("my-user").is_ok());
}

#[test]
fn username_valid_exactly_3_chars() {
    assert!(validate_username("abc").is_ok());
}

#[test]
fn username_valid_exactly_32_chars() {
    assert!(validate_username(&"a".repeat(32)).is_ok());
}

#[test]
fn username_invalid_too_short() {
    assert!(validate_username("ab").is_err());
}

#[test]
fn username_invalid_too_long() {
    assert!(validate_username(&"a".repeat(33)).is_err());
}

#[test]
fn username_invalid_special_chars() {
    assert!(validate_username("user@name").is_err());
}

#[test]
fn username_invalid_spaces() {
    assert!(validate_username("user name").is_err());
}

// ─── Password Validation ───

#[test]
fn password_valid_strong() {
    assert!(validate_password("SecurePass123!").is_ok());
}

#[test]
fn password_valid_complex() {
    assert!(validate_password("MyP@ssw0rd!!XYZ").is_ok());
}

#[test]
fn password_invalid_too_short() {
    assert!(validate_password("Sh0rt!").is_err());
}

#[test]
fn password_invalid_no_uppercase() {
    assert!(validate_password("securepass123!").is_err());
}

#[test]
fn password_invalid_no_lowercase() {
    assert!(validate_password("SECUREPASS123!").is_err());
}

#[test]
fn password_invalid_no_number() {
    assert!(validate_password("SecurePassWord!").is_err());
}

#[test]
fn password_invalid_no_special() {
    assert!(validate_password("SecurePass1234").is_err());
}

// ─── Database Name Validation ───

#[test]
fn dbname_valid_basic() {
    assert!(validate_db_name("my_database").is_ok());
}

#[test]
fn dbname_valid_alphanumeric() {
    assert!(validate_db_name("db123").is_ok());
}

#[test]
fn dbname_invalid_starts_with_number() {
    assert!(validate_db_name("123db").is_err());
}

#[test]
fn dbname_invalid_starts_with_underscore() {
    assert!(validate_db_name("_mydb").is_err());
}

#[test]
fn dbname_invalid_special_chars() {
    assert!(validate_db_name("my-db").is_err());
}

#[test]
fn dbname_invalid_too_short() {
    assert!(validate_db_name("db").is_err());
}

#[test]
fn dbname_invalid_too_long() {
    assert!(validate_db_name(&format!("d{}", "a".repeat(64))).is_err());
}

#[test]
fn dbname_invalid_sql_injection() {
    assert!(validate_db_name("db; DROP TABLE").is_err());
}
