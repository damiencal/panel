# Testing Guide

Comprehensive testing strategies for the Hosting Control Panel.

## Testing Philosophy

1. **Unit Tests**: Test individual functions in isolation
2. **Integration Tests**: Test module interactions and database operations
3. **E2E Tests**: Test complete user workflows
4. **Security Tests**: Verify access control and input validation

## Unit Tests

### Running Unit Tests

```bash
# Run all tests
cargo test

# Run single test
cargo test test_name

# Run tests in specific module
cargo test db::users::

# Show output (println!, dbg!)
cargo test -- --nocapture

# Run ignored tests
cargo test -- --ignored
```

### Writing Unit Tests

Place tests in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_accepts_valid_email() {
        assert!(validate_email("user@example.com").is_ok());
    }

    #[test]
    fn test_validator_rejects_invalid_email() {
        assert!(validate_email("invalid-email").is_err());
    }
}
```

### Test Organization

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Setup and helpers
    fn setup() -> TestContext {
        // Initialize test data
    }

    // Individual tests grouped by functionality
    mod validation {
        use super::*;

        #[test]
        fn test_email_validation() { }
        
        #[test]
        fn test_domain_validation() { }
    }

    mod authorization {
        use super::*;

        #[test]
        fn test_admin_access() { }
        
        #[test]
        fn test_reseller_access() { }
        
        #[test]
        fn test_client_access() { }
    }
}
```

## Integration Tests

### Database Integration Testing

```rust
#[tokio::test]
async fn test_create_and_retrieve_user() {
    // Setup: Create test database
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::query(include_str!("../../migrations/001_create_users.sql"))
        .execute(&pool)
        .await
        .unwrap();

    // Execute: Create user
    let user_id = db::users::create(
        &pool,
        "testuser".to_string(),
        "test@example.com".to_string(),
        "hashed_password".to_string(),
        Role::Client,
        None,
        None,
    )
    .await
    .unwrap();

    // Assert: Verify creation
    assert!(user_id > 0);
    
    let user = db::users::get(&pool, user_id).await.unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, "test@example.com");
}
```

### Service Integration Testing

```rust
#[tokio::test]
#[ignore] // Only run with actual OpenLiteSpeed installed
async fn test_openlitespeed_vhost_creation() {
    let service = OpenLiteSpeedService;
    
    // Check if service is installed
    if !service.is_installed().await.unwrap_or(false) {
        return; // Skip if not installed
    }

    // Generate vhost config
    let config = service
        .generate_vhost_config(
            "test.example.com",
            "/home/user/public_html",
            true,
        )
        .await
        .unwrap();

    // Verify config contains expected values
    assert!(config.contains("test.example.com"));
    assert!(config.contains("/home/user/public_html"));
}
```

## E2E Tests (Dioxus)

### Server Function Testing

```rust
#[server(TestFunction)]
async fn test_function(input: String) -> Result<String, ServerFnError> {
    Ok(format!("Echo: {}", input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_function_success() {
        // This requires full app context
        // Typically tested through Dioxus test utilities
    }
}
```

## Security Testing

### Access Control Testing

```rust
#[tokio::test]
async fn test_client_cannot_access_other_client_site() {
    let pool = setup_test_db().await;
    
    // Create two clients
    let client1_id = create_test_user(&pool, "client1", Role::Client).await;
    let client2_id = create_test_user(&pool, "client2", Role::Client).await;
    
    // Client 1 creates a site
    let site_id = db::sites::create(
        &pool,
        client1_id,
        "site.example.com".to_string(),
        "/home/user/site".to_string(),
        SiteType::Static,
    )
    .await
    .unwrap();

    // Client 2 should not be able to access it
    let claims = JwtClaims {
        sub: client2_id,
        username: "client2".to_string(),
        email: "client2@example.com".to_string(),
        role: Role::Client,
        iat: 0,
        exp: 9999999999,
        parent_id: None,
    };

    let result = check_ownership(&claims, client1_id, None);
    assert!(result.is_err());
}
```

### Input Validation Testing

```rust
#[cfg(test)]
mod validator_tests {
    use super::*;

    // Email validation
    #[test]
    fn test_valid_emails() {
        let valid = vec![
            "user@example.com",
            "test.user@example.co.uk",
            "user+tag@example.com",
        ];
        for email in valid {
            assert!(validate_email(email).is_ok());
        }
    }

    #[test]
    fn test_invalid_emails() {
        let invalid = vec![
            "invalid",
            "@example.com",
            "user@",
            "user space@example.com",
        ];
        for email in invalid {
            assert!(validate_email(email).is_err());
        }
    }

    // Domain validation
    #[test]
    fn test_valid_domains() {
        let valid = vec![
            "example.com",
            "sub.example.com",
            "name.co.uk",
        ];
        for domain in valid {
            assert!(validate_domain(domain).is_ok());
        }
    }

    #[test]
    fn test_invalid_domains() {
        let invalid = vec![
            "invalid",
            "-example.com",
            "example.com-",
            "exam ple.com",
        ];
        for domain in invalid {
            assert!(validate_domain(domain).is_err());
        }
    }
}
```

## Test Helpers

### Create Test Database

```rust
async fn setup_test_db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    
    // Run all migrations
    sqlx::query(include_str!("../../migrations/001_create_users.sql"))
        .execute(&pool)
        .await
        .unwrap();
    // ... run all migrations
    
    pool
}
```

### Create Test User

```rust
async fn create_test_user(
    pool: &SqlitePool,
    username: &str,
    role: Role,
) -> i64 {
    let password_hash = argon2_hash("password").unwrap();
    
    db::users::create(
        pool,
        username.to_string(),
        format!("{}@example.com", username),
        password_hash,
        role,
        None,
        None,
    )
    .await
    .unwrap()
}
```

### Create Test JWT

```rust
fn create_test_claims(user_id: i64, role: Role) -> JwtClaims {
    JwtClaims {
        sub: user_id,
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        role,
        iat: 0,
        exp: 9999999999,
        parent_id: None,
    }
}
```

## Coverage Testing

### Generate Coverage Report

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --out Html --output-dir coverage
```

### Coverage Goals

- **Critical paths** (auth, RBAC): 85%+
- **Database layer**: 80%+
- **Services**: 75%+
- **Utilities**: 80%+
- **Overall**: 75%+

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - run: cargo test --all
      - run: cargo clippy -- -D warnings
      - run: cargo fmt -- --check
```

## Performance Testing

### Benchmark Template

```rust
#[cfg(test)]
mod benches {
    use super::*;
    use std::time::Instant;

    #[ignore]
    #[test]
    fn bench_user_lookup() {
        let pool = setup_test_db();
        
        let start = Instant::now();
        for _ in 0..1000 {
            db::users::get(&pool, 1).await.unwrap();
        }
        let elapsed = start.elapsed();
        
        println!("1000 lookups: {:?}", elapsed);
        assert!(elapsed.as_millis() < 500); // Should complete in <500ms
    }
}
```

## Test Checklist

Before committing:

- [ ] All tests pass: `cargo test`
- [ ] No warnings: `cargo clippy -- -D warnings`
- [ ] Formatted: `cargo fmt`
- [ ] New functionality has tests
- [ ] Access control is tested
- [ ] Error cases are tested
- [ ] Edge cases are considered

## Documentation

Document complex test setup:

```rust
/// Integration test for site creation workflow
/// 
/// Verifies:
/// - User can create site within quota
/// - Site is properly stored in database
/// - Ownership is set correctly
/// - Audit log entry is created
#[tokio::test]
async fn test_site_creation_workflow() {
    // ...
}
```

## References

- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [SQLx Testing Patterns](https://github.com/launchbadge/sqlx/tree/main/examples)
- [Tokio Testing](https://tokio.rs/tokio/topics/testing)
