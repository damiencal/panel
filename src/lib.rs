// Panel - Hosting Control Panel in Rust + Dioxus
// Main library module re-exports

#[cfg(feature = "server")]
pub mod auth;
#[cfg(feature = "server")]
pub mod db;
pub mod models;
pub mod server;
#[cfg(feature = "server")]
pub mod services;
pub mod utils;

// Re-export commonly used items
#[cfg(feature = "server")]
pub use auth::{JwtManager, TotpManager};
#[cfg(feature = "server")]
pub use db::pool;
pub use models::{AccountStatus, Role, User};
