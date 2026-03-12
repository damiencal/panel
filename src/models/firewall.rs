/// Firewall data models shared between frontend and backend.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UfwAction {
    Allow,
    Deny,
    Reject,
    Limit,
}

impl std::fmt::Display for UfwAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UfwAction::Allow => write!(f, "ALLOW"),
            UfwAction::Deny => write!(f, "DENY"),
            UfwAction::Reject => write!(f, "REJECT"),
            UfwAction::Limit => write!(f, "LIMIT"),
        }
    }
}

impl std::str::FromStr for UfwAction {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "DENY" => UfwAction::Deny,
            "REJECT" => UfwAction::Reject,
            "LIMIT" => UfwAction::Limit,
            _ => UfwAction::Allow,
        })
    }
}

impl UfwAction {
    pub fn as_ufw_arg(&self) -> &'static str {
        match self {
            UfwAction::Allow => "allow",
            UfwAction::Deny => "deny",
            UfwAction::Reject => "reject",
            UfwAction::Limit => "limit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UfwRule {
    pub id: Option<i64>,
    pub number: Option<u32>,
    pub action: UfwAction,
    pub direction: String, // "in" | "out"
    pub protocol: Option<String>,
    pub from_ip: Option<String>,
    pub to_port: Option<String>,
    pub comment: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UfwStatus {
    pub active: bool,
    pub logging: String,
    pub default_incoming: String,
    pub default_outgoing: String,
    pub rules: Vec<UfwStatusRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UfwStatusRule {
    pub number: u32,
    pub to: String,
    pub action: String,
    pub from: String,
}
