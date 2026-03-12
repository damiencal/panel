# Architecture Guide

Detailed explanation of system architecture and design decisions.

## System Overview

```
┌──────────────────────────────────────┐
│      Browser / Client                │
└──────────────────┬───────────────────┘
                   │ HTTPS
                   ▼
        ┌──────────────────────┐
        │    Nginx/Reverse     │
        │     Proxy (TLS)      │
        └──────────┬───────────┘
                   │ localhost:3030
                   ▼
         ┌──────────────────┐
         │  Panel (Rust)    │
         │  Dioxus 0.7      │
         ├──────────────────┤
         │ Frontend (WASM)  │
         │ Backend (HTTP)   │
         │ Routing          │
         └─────────┬────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
    ┌────────┐          ┌──────────┐
    │  SQLite│          │ Services │
    │  Pool  │          │ (Trait)  │
    └────────┘          └──────────┘
        │                    │
    ┌───┴────────────────────┴───┐
    │   System Services(systemd) │
    ├─────────────────────────────┤
    │ • OpenLiteSpeed (Web)       │
    │ • MariaDB (DB)              │
    │ • Postfix (SMTP)            │
    │ • Dovecot (IMAPS)            │
    │ • Cloudflare (DNS API)      │
    │ • Pure-FTPd (FTP)           │
    │ • Certbot (SSL)             │
    └─────────────────────────────┘
```

## Concurrency Model

### Async/Await Throughout

All I/O operations use async/await:

```
User Request
    ↓
Tokio Runtime (async)
    ├─ JWT validation (no blocking)
    ├─ Database query (async SQLx)
    └─ Service command (async shell)
    ↓
Response (sent back while others process)
```

**Benefits**:
- Single-threaded request processing
- Thousands of concurrent connections
- No thread pool overhead
- Efficient resource usage

### Tokio Runtime

```rust
#[tokio::main]
async fn main() {
    // Automatically creates thread pool based on CPU cores
    // Distributes work across cores
    // Shutdown on SIGTERM/SIGINT
}
```

### Database Connection Pool

```rust
static DB_POOL: OnceLock<SqlitePool> = OnceLock::new();

pub fn pool() -> // Uses connection pool (default 5 connections)
    // Reuses connections across requests
    // Automatically reconnects on failure
    // Limits concurrent database access
```

## Data Flow

### Request Processing Pipeline

```
1. HTTP Request arrives
   │
2. Dioxus Router matches route
   │
3a. [Client Route] → Render component in WASM
   │
3b. [Server Function] → 
    a. Deserialize parameters
    b. Verify JWT token
    c. Check authentication (require_auth)
    d. Check authorization (role + ownership)
    e. Execute database/service operations
    f. Serialize response
    g. Encrypt if needed (optional)
    │
4. Response sent to client
   │
5. Client-side rendering/update
```

## Authentication Flow

```
┌─ User enters credentials
│
├─ POST /login
│  ├─ Validate email/password
│  └─ Hash password (Argon2id)
│
├─ Database lookup
│  └─ Compare hashes
│
├─ JWT generation
│  ├─ Include user claims
│  ├─ Sign with secret
│  └─ Set 24-hour expiry
│
├─ Return JWT + TOTP requirement
│
├─ Client stores JWT in localStorage
│
└─ All future requests include JWT
   ├─ Verification checks signature
   ├─ Verification checks expiry
   └─ Extract user claims
```

## Authorization Model

### Role Hierarchy

```
Admin
├─ Can manage system
├─ Can create/manage resellers
├─ Can view all resources
└─ Can read/modify everything

Reseller
├─ Can manage own clients
├─ Can create packages for clients
├─ Can view own clients' resources
└─ Cannot modify system settings

Client
├─ Can manage own resources
├─ Cannot create other users
├─ Can view own data
└─ Cannot access other user data
```

### Ownership-Scoped Queries

Every resource belongs to a user:

```sql
-- User creates site (owner_id = user.id)
INSERT INTO sites (owner_id, domain, ...) VALUES (?, ?, ...);

-- Client query: Only own sites
SELECT * FROM sites WHERE owner_id = ?;

-- Reseller query: Own clients' sites (via parent_id)
SELECT s.* FROM sites s
JOIN users u ON s.owner_id = u.id
WHERE u.parent_id = ?;

-- Admin query: All sites
SELECT * FROM sites;
```

### Guard Middleware

Database layer implements guards:

```rust
// Server function example
#[server(UpdateSite)]
async fn update_site(site_id: i64, ...) -> Result<(), ServerFnError> {
    let user = require_auth().await?;  // Check JWT
    let site = db::sites::get(site_id).await?;
    
    // Check ownership based on role
    match user.role {
        Role::Admin => {},  // Allow all
        Role::Reseller => {
            // Must own the site owner
            require_ownership(&user, site.owner_id)?;
        },
        Role::Client => {
            // Must own the site directly
            if site.owner_id != user.id {
                return Err(ServerFnError::new("Access denied"));
            }
        }
    }
    
    db::sites::update(site_id, ...).await?;
    Ok(())
}
```

## Database Architecture

### Schema Design

```
users (master table)
├─ id, username, email, password_hash
├─ role (Admin/Reseller/Client)
├─ parent_id (reference to parent user for resellers)
├─ package_id (assigned package)
└─ created_at, updated_at

packages (templates)
├─ id, name, created_by (reseller who created it)
├─ max_sites, max_databases, max_emails
├─ max_disk_mb, max_bandwidth_mb
└─ php_enabled, ssl_enabled, shell_access, backup_enabled

quotas (user allocations)
├─ user_id (who gets this quota)
├─ max_sites, max_databases, etc
└─ allocated_at

sites (virtual hosts)
├─ id, owner_id (user who owns this site)
├─ domain, doc_root
├─ site_type (Static/PHP/Proxy/Node.js)
├─ status (Active/Suspended/Inactive)
├─ ssl_enabled, certificate, private_key, expiry_date
└─ created_at, updated_at

[databases, dns, email, etc...]
└─ All follow owner_id pattern
```

### Indices

Strategic indices for performance:

```sql
-- User lookups
CREATE UNIQUE INDEX idx_users_username ON users(username);
CREATE UNIQUE INDEX idx_users_email ON users(email);

-- Reseller-to-client relationships
CREATE INDEX idx_users_parent_id ON users(parent_id);

-- Ownership queries
CREATE INDEX idx_sites_owner_id ON sites(owner_id);
CREATE INDEX idx_sites_domain ON sites(domain);
CREATE INDEX idx_databases_owner_id ON databases(owner_id);
CREATE INDEX idx_dns_zones_owner_id ON dns_zones(owner_id);

-- Audit trail
CREATE INDEX idx_audit_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_created_at ON audit_log(created_at);
```

## Service Management

### ManagedService Trait

```rust
#[async_trait]
pub trait ManagedService {
    async fn install() -> Result<(), ServiceError>;
    async fn start() -> Result<(), ServiceError>;
    async fn stop() -> Result<(), ServiceError>;
    async fn restart() -> Result<(), ServiceError>;
    async fn status() -> Result<ServiceStatus, ServiceError>;
    async fn is_installed() -> Result<bool, ServiceError>;
    async fn version() -> Result<String, ServiceError>;
}
```

Each service (OpenLiteSpeed, MariaDB, etc.) implements this trait.
DNS is managed externally via the Cloudflare API rather than a local service.

### Service Discovery

```rust
// Services have:
// 1. Systemd unit name (e.g., "lsws", "mariadb")
// 2. Binary path (e.g., "/usr/bin/mariadb")
// 3. Default port

pub struct ServiceInfo {
    pub service_type: ServiceType,
    pub status: ServiceStatus,
    pub port: u16,
    pub version: String,
    pub uptime_seconds: u64,
}
```

### Shell Safety

All system commands go through safe wrapper:

```rust
async fn exec(binary: &str, args: &[&str]) -> Result<Output> {
    // 1. Validate binary is in allowlist (30+ safe binaries)
    if !ALLOWED_BINARIES.contains(&binary) {
        return Err("Binary not allowed");
    }
    
    // 2. Use Command API (never shell -c)
    let output = Command::new(binary)
        .args(args)  // .bind() style, never format!()
        .output()
        .await?;
    
    // 3. Capture stdout/stderr
    Ok(output)
}
```

## Component Architecture

### Dioxus Component Hierarchy

```
App
├─ LoginPage (public)
│
├─ AdminShell (admin only via guard)
│  ├─ AdminHeader
│  ├─ AdminSidebar
│  └─ Outlet<Route> (nested routes)
│     ├─ AdminDashboard
│     ├─ AdminServers
│     ├─ AdminResellers
│     ├─ AdminClients
│     ├─ AdminPackages
│     ├─ AdminSites
│     ├─ AdminMonitoring
│     ├─ AdminAuditLog
│     └─ AdminSettings
│
├─ ResellerShell (reseller+ only)
│  ├─ ResellerHeader
│  ├─ ResellerSidebar
│  └─ Outlet<Route>
│     ├─ ResellerDashboard
│     ├─ ResellerClients
│     ├─ ResellerPackages
│     ├─ ResellerBranding
│     ├─ ResellerSupport
│     └─ ResellerSettings
│
└─ ClientShell (client+ only)
   ├─ ClientHeader
   ├─ ClientSidebar
   └─ Outlet<Route>
      ├─ ClientDashboard
      ├─ ClientSites
      ├─ ClientDatabases
      ├─ ClientDns
      ├─ ClientEmail
      ├─ ClientFileManager
      ├─ ClientBackups
      ├─ ClientUsage
      ├─ ClientSupport
      └─ ClientSettings
```

### Component Lifecycle

```rust
#[component]
fn MyComponent() -> Element {
    // 1. Create resource (async data fetch)
    let data_resource = use_resource(move || async {
        get_data().await  // Server function
    });
    
    // 2. Render based on state
    rsx! {
        match &*data_resource.read() {
            Some(Ok(data)) => rsx! {
                // Render data
            },
            Some(Err(e)) => rsx! {
                div { class: "error", "Error: {e}" }
            },
            None => rsx! {
                div { class: "loading", "Loading..." }
            }
        }
    }
}
```

## Configuration Management

### Layered Configuration

```
Priority (highest to lowest):
1. Environment variables (PANEL_*)
2. .env file in current directory
3. panel.toml in /opt/panel/
4. Hard-coded defaults
```

### Example Flow

```rust
// Load configuration
let config = PanelConfig::load(Some("panel.toml")).await?;

// Access values
let server_host = env::var("PANEL_BIND_HOST")
    .unwrap_or("0.0.0.0".to_string());
```

## Error Handling Strategy

### Error Types

```rust
// Service-level (thiserror)
#[derive(Error)]
pub enum ServiceError {
    #[error("Command failed: {0}")]
    CommandFailed(String),
}

// Boundary-level (anyhow)
fn main() -> anyhow::Result<()> {
    service.do_something()
        .context("Failed to do something")?;
    Ok(())
}

// API-level (ServerFnError)
#[server(MyFunction)]
async fn my_function() -> Result<String, ServerFnError> {
    action()
        .map_err(|e| ServerFnError::new(format!("{}", e)))?;
    Ok("result".to_string())
}
```

### Error Recovery

All operations are idempotent:
- Creating existing site succeeds silently
- Deleting non-existent resource succeeds
- Restarting stopped service succeeds
- No cascading failures

## Deployment Architecture

### Single Server Deployment

```
┌─────────────────────────────────┐
│       Ubuntu 24.04 LTS          │
├─────────────────────────────────┤
│  Reverse Proxy (nginx)          │
│  - TLS termination              │
│  - HTTP → HTTPS redirect        │
├─────────────────────────────────┤
│  Panel Service (systemd)        │
│  - User: panel:panel            │
│  - Port: localhost:3030         │
│  - Auto-restart on crash        │
├─────────────────────────────────┤
│  OpenLiteSpeed                  │
│  - Web server for hosted sites  │
│  - LSPHP 8.3                    │
├─────────────────────────────────┤
│  MariaDB                        │
│  - Local only (localhost)       │
│  - SSL connections internal     │
├─────────────────────────────────┤
│  Mail Services                  │
│  - Postfix (SMTP)               │
│  - Dovecot (IMAPS)              │
├─────────────────────────────────┤
│  DNS                            │
│  - Cloudflare API               │
├─────────────────────────────────┤
│  FTP                            │
│  - Pure-FTPd                    │
├─────────────────────────────────┤
│  SSL Management                 │
│  - Certbot                      │
│  - Let's Encrypt                │
└─────────────────────────────────┘
```

### Multi-Server (Future)

```
Load Balancer
├─ Panel Server 1 (Dioxus + SQLite)
├─ Panel Server 2 (Dioxus + SQLite)
└─ Panel Server 3 (Dioxus + SQLite)
    └─ Shared Database (MariaDB)
```

## Resource Constraints

### Memory Usage

- Dioxus app: ~50-100 MB
- SQLite in-memory queries: variable
- Rust binary with optimizations: ~30-50 MB stripped

### Disk Usage

- SQLite database: grows with data (typically <1GB)
- Logs: ~100-500 MB daily (configurable rotation)
- User files: hosted on OpenLiteSpeed

### CPU Usage

- Idle: <1% (async I/O based)
- Per user session: ~0.1% (depends on operations)
- Service status checks: minimal overhead

## Monitoring Points

### Key Metrics to Track

```
Application:
- Active sessions count
- Failed login attempts
- Server function error rates
- Database query response times

System:
- Service status (all 8+ services)
- Disk usage (database, logs, user files)
- Memory usage
- CPU usage
- Network I/O

Database:
- Connection pool utilization
- Query counts and durations
- Lock contention

Security:
- Failed authentication attempts
- Unauthorized access attempts
- Configuration changes
- Privilege escalation attempts
```

## Future Scalability

### Database Sharding

When single instance outgrows:

```
Panel App
├─ SQLite (users, packages, audit)
├─ MariaDB (sites, domains, dns)
└─ MariaDB (databases, email)
```

### Horizontal Scaling

```
Load Balancer (HAProxy)
├─ Panel 1 + local SQLite
├─ Panel 2 + local SQLite
└─ Panel 3 + local SQLite
  └─ MariaDB Cluster (shared)
```

### Caching Layer

```
Dioxus App
├─ In-memory cache (quotas, service status)
├─ Redis (distributed cache)
└─ SQLite/MariaDB
```

## References

- [Tokio Architecture](https://tokio.rs/tokio/topics/io-bound)
- [Dioxus Architecture](https://docs.dioxuslabs.com/learn/contribute/contribute/)
- [SQLx Best Practices](https://github.com/launchbadge/sqlx/blob/main/README.md)
- [System Design Patterns](https://github.com/donnemartin/system-design-primer)
