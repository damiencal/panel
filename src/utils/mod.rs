//! Utility modules for configuration, validation, and helpers.

#[cfg(feature = "server")]
pub mod config;
pub mod validators;

#[cfg(feature = "server")]
pub use config::PanelConfig;
pub use validators::{validate_domain, validate_email, validate_username};
