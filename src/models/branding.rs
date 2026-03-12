use serde::{Deserialize, Serialize};

/// Theme preset options for reseller branding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(
    feature = "server",
    sqlx(type_name = "TEXT", rename_all = "PascalCase")
)]
pub enum ThemePreset {
    #[default]
    Default,
    Dark,
    Corporate,
}

impl std::fmt::Display for ThemePreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => write!(f, "Default"),
            Self::Dark => write!(f, "Dark"),
            Self::Corporate => write!(f, "Corporate"),
        }
    }
}

impl std::str::FromStr for ThemePreset {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Default" => Ok(Self::Default),
            "Dark" => Ok(Self::Dark),
            "Corporate" => Ok(Self::Corporate),
            other => Err(format!("Unknown theme preset: {other}")),
        }
    }
}

/// Reseller branding configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct ResellerBranding {
    pub id: i64,
    pub reseller_id: i64,
    pub panel_name: String,
    pub logo_path: Option<String>,
    pub accent_color: String,
    pub custom_domain: Option<String>,
    pub custom_ns1: Option<String>,
    pub custom_ns2: Option<String>,
    pub footer_text: Option<String>,
    pub theme_preset: String,
    pub created_at: String,
    pub updated_at: String,
}
