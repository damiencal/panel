use serde::{Deserialize, Serialize};

/// System service types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub enum ServiceType {
    OpenLiteSpeed,
    PHP,
    MariaDB,
    Postfix,
    Dovecot,
    Ftpd,
    Certbot,
    PhpMyAdmin,
    SpamAssassin,
    Rspamd,
    ClamAV,
    MailScanner,
    Redis,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceType::OpenLiteSpeed => write!(f, "OpenLiteSpeed"),
            ServiceType::PHP => write!(f, "PHP"),
            ServiceType::MariaDB => write!(f, "MariaDB"),
            ServiceType::Postfix => write!(f, "Postfix"),
            ServiceType::Dovecot => write!(f, "Dovecot"),
            ServiceType::Ftpd => write!(f, "FTP"),
            ServiceType::Certbot => write!(f, "Certbot"),
            ServiceType::PhpMyAdmin => write!(f, "phpMyAdmin"),
            ServiceType::SpamAssassin => write!(f, "SpamAssassin"),
            ServiceType::Rspamd => write!(f, "Rspamd"),
            ServiceType::ClamAV => write!(f, "ClamAV"),
            ServiceType::MailScanner => write!(f, "MailScanner"),
            ServiceType::Redis => write!(f, "Redis"),
        }
    }
}

/// Service operational status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Error,
    Unknown,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Running => write!(f, "Running"),
            ServiceStatus::Stopped => write!(f, "Stopped"),
            ServiceStatus::Error => write!(f, "Error"),
            ServiceStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Service information with status and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub service_type: ServiceType,
    pub status: ServiceStatus,
    pub port: Option<u16>,
    pub version: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAction {
    pub service: ServiceType,
    pub action: ServiceCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceCommand {
    Start,
    Stop,
    Restart,
    Status,
}

impl std::fmt::Display for ServiceCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceCommand::Start => write!(f, "start"),
            ServiceCommand::Stop => write!(f, "stop"),
            ServiceCommand::Restart => write!(f, "restart"),
            ServiceCommand::Status => write!(f, "status"),
        }
    }
}
