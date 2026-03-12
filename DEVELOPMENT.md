# Development Guide

This document provides detailed guidance for developers working on the Hosting Control Panel project.

## Architecture Overview

### Layered Architecture

```
┌─────────────────────────────────────────────┐
│           Frontend (Dioxus/WASM)            │
│    - UI Components (buttons, cards, etc)    │
│    - Page components per role               │
│    - Client-side state management           │
└──────────────┬──────────────────────────────┘
               │
         RPC / Server Fn
               │
┌──────────────▼──────────────────────────────┐
│      Backend (Rust/Axum + Dioxus)           │
│    - Server Functions (auth, CRUD)          │
│    - Authentication & Authorization         │
│    - Error handling                         │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│       Services Layer (Business Logic)       │
│    - OpenLiteSpeed management               │
│    - Database operations                    │
│    - System commands (safe shell)           │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│           Data Layer (SQLx)                 │
│    - Type-safe database queries             │
│    - Migrations                             │
│    - Connection pooling                     │
└─────────────────────────────────────────────┘
```

### Module Organization

- **models/**: Shared data structures (frontend + backend)
- **auth/**: JWT, TOTP, authentication guards
- **db/**: Database access layer
- **services/**: System service managers (OLS, MySQL, etc.)
- **utils/**: Helpers, validators, configuration
- **ui/**: Dioxus components (pages, layouts, widgets)
- **server_fns/**: Dioxus server functions (to be created)

## Development Workflow

### 1. Create a New Feature

**Step 1: Update Models**
```rust
// models/my_feature.rs
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MyFeature {
    pub id: i64,
    pub name: String,
    // ...
}
```

**Step 2: Create Database Migration**
```sql
-- migrations/XXXXXX_create_my_feature.sql
CREATE TABLE IF NOT EXISTS my_feature (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    -- ...
);
```

**Step 3: Implement Database Layer**
```rust
// db/my_feature.rs
pub async fn get(pool: &SqlitePool, id: i64) -> Result<MyFeature, sqlx::Error> {
    sqlx::query_as::<_, MyFeature>("SELECT * FROM my_feature WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
}
```

**Step 4: Create Server Function**
```rust
// server_fns/my_feature.rs
#[server(GetMyFeature)]
async fn get_my_feature(id: i64) -> Result<MyFeature, ServerFnError> {
    let user = require_auth().await?;
    let feature = db::my_feature::get(&pool().await, id)
        .await
        .map_err(|_| ServerFnError::new("Not found"))?;
    
    // Check ownership/permissions
    require_admin(&user)?;
    
    Ok(feature)
}
```

**Step 5: Build UI Component**
```rust
// ui/pages/my_feature.rs
#[component]
fn MyFeaturePage() -> Element {
    let feature_resource = use_resource(move || async move {
        get_my_feature(1).await
    });

    rsx! {
        match &*feature_resource.read() {
            Some(Ok(feature)) => rsx! { /* render feature */ },
            Some(Err(e)) => rsx! { div { class: "text-red-600", "Error: {e}" } },
            None => rsx! { div { class: "animate-pulse", "Loading..." } }
        }
    }
}
```

### 2. Implement Access Control

For every server function, enforce both **role** and **ownership** checks:

```rust
#[server(UpdateSite)]
async fn update_site(site_id: i64, name: String) -> Result<(), ServerFnError> {
    let user = require_auth().await?;
    
    // Get the resource
    let site = db::sites::get(&pool().await, site_id)
        .await
        .map_err(|_| ServerFnError::new("Not found"))?;
    
    // Check ownership based on role
    match user.role {
        Role::Admin => {}, // Admin can update any site
        Role::Reseller => {
            // Reseller must own the client that owns the site
            let owner = db::users::get(&pool().await, site.owner_id).await?;
            if owner.parent_id != Some(user.id) {
                return Err(ServerFnError::new("Access denied"));
            }
        },
        Role::Client => {
            // Client can only update own sites
            if site.owner_id != user.id {
                return Err(ServerFnError::new("Access denied"));
            }
        },
    }
    
    // Perform update
    db::sites::update(&pool().await, site_id, name).await?;
    
    // Log action
    db::audit::log_action(/* ... */).await?;
    
    Ok(())
}
```

### 3. Error Handling

Use `thiserror` for library errors and `anyhow` at boundaries:

```rust
// In services/
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Command failed: {0}")]
    CommandFailed(String),
    #[error("Not installed")]
    NotInstalled,
}

// In server functions - convert to ServerFnError
match service.do_something().await {
    Ok(result) => Ok(result),
    Err(ServiceError::NotInstalled) => {
        Err(ServerFnError::new("Service not installed"))
    },
    Err(e) => Err(ServerFnError::new(format!("Service error: {}", e))),
}
```

### 4. Testing

Write tests for:
- Database operations
- Service commands
- Business logic
- Authorization checks

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_site() {
        // Setup
        let pool = setup_test_db().await;
        
        // Execute
        let result = db::sites::create(
            &pool, 1, "example.com".to_string(),
            "/home/user/sites/example.com".to_string(),
            SiteType::Static
        ).await;
        
        // Assert
        assert!(result.is_ok());
        let site_id = result.unwrap();
        let site = db::sites::get(&pool, site_id).await.unwrap();
        assert_eq!(site.domain, "example.com");
    }
}
```

## Design Patterns

### 1. Resource Ownership Pattern

Every resource belongs to a user. Follow this:

```
User (Admin/Reseller/Client)
  ├─ Site (owned by user)
  ├─ Database (owned by user)
  ├─ Domain (owned by user)
  └─ ...
```

When querying, ALWAYS scope to the user's role:
- Admin: can see all
- Reseller: can see own clients' resources
- Client: can see own resources only

### 2. Audit Logging Pattern

Log every meaningful action:

```rust
db::audit::log_action(
    &pool,
    user.id,
    "create_site",
    Some("site".to_string()),
    Some(site.id),
    Some(site.domain),
    Some("Created new website".to_string()),
    "Success",
    None,
    ip_address,
    impersonation_by,
).await?;
```

### 3. Idempotent Operations

All operations should be idempotent. Example - creating a site that already exists should succeed, not fail.

### 4. Quota Enforcement Pattern

Before creating a resource, check the quota:

```rust
// Check quota
let usage = db::quotas::get_usage(&pool, user.id).await?;
let quota = db::quotas::get_quota(&pool, user.id).await?;

if usage.sites_used >= quota.max_sites {
    return Err(ServerFnError::new("Site quota exceeded"));
}

// Create resource
let site_id = db::sites::create(&pool, ...).await?;

// Update usage
db::quotas::increment_sites(&pool, user.id, 1).await?;

Ok(site_id)
```

## Common Tasks

### Adding a Database Table

1. Create migration: `migrations/TIMESTAMP_name.sql`
2. Add struct to `models/`
3. Add CRUD functions to `db/`
4. Use in server functions

### Adding a System Service

1. Create `services/myservice.rs`
2. Implement `ManagedService` trait
3. Add to service discovery in `services/system.rs`
4. Create server functions to control

### Adding a UI Page

1. Create component in `ui/pages/`
2. Add route in `main.rs` Route enum
3. Add sidebar link if needed
4. Implement server functions

### Connecting UI to Backend

```rust
// Server function
#[server(DoSomething)]
async fn do_something(param: String) -> Result<String, ServerFnError> {
    // Logic
    Ok("result".to_string())
}

// UI Component
#[component]
fn MyComponent() -> Element {
    let mut result = use_future(|| async move {
        do_something("param".to_string()).await
    });

    rsx! {
        match result() {
            Ok(data) => rsx! { div { "{data}" } },
            Err(e) => rsx! { div { "Error: {e}" } },
        }
    }
}
```

## Performance Considerations

1. **Database Queries**: Use indexes. Check migration files for indexed columns.
2. **N+1 Queries**: Load related data in single query when possible.
3. **Authentication**: JWT tokens reduce database hits. Verify token signature, not DB lookup.
4. **Caching**: Consider caching frequently requested data (quotas, configs).
5. **Async**: Never block the event loop. Use async/await everywhere.

## Security Checklist

- [ ] Validate all user input
- [ ] Never trust frontend validation
- [ ] Check auth on every server function
- [ ] Verify ownership before returning/modifying data
- [ ] Use parameterized SQL queries (SQLx does this)
- [ ] Never interpolate user input into shell commands
- [ ] Log failures and security events
- [ ] Use HTTPS in production
- [ ] Rotate secrets regularly

## Debugging

### Enable Debug Logging

```bash
RUST_LOG=debug,panel=trace cargo build
```

### Check Database Schema

```bash
sqlite3 /var/lib/panel/panel.db .schema
```

### Inspect a Server Function

Add `println!` or use `tracing`:

```rust
use tracing::{info, debug, error};

#[server(MyFunction)]
async fn my_function() -> Result<String, ServerFnError> {
    info!("Starting my_function");
    debug!("Debug information here");
    error!("Something went wrong");
    Ok("...".to_string())
}
```

## Code Review Checklist

Before submitting a PR, ensure:

- [ ] Code compiles without warnings: `cargo clippy -- -D warnings`
- [ ] Code is formatted: `cargo fmt`
- [ ] Tests pass: `cargo test`
- [ ] Tests are included for new functionality
- [ ] Database migrations are included if needed
- [ ] Functions are documented
- [ ] Security checks are in place
- [ ] Audit logging is added for operations
- [ ] Error handling is appropriate

## Resources

- [Dioxus Documentation](https://docs.dioxuslabs.com)
- [Axum Guide](https://docs.rs/axum/)
- [SQLx Guide](https://github.com/launchbadge/sqlx)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Rust Book](https://doc.rust-lang.org/book/)
