pub mod auth;
pub mod backup;
pub mod billing;
pub mod branding;
pub mod cron;
pub mod database;
pub mod dns;
pub mod domain;
pub mod email;
pub mod firewall;
pub mod ftp;
pub mod git;
pub mod package;
pub mod quota;
pub mod security;
pub mod service;
pub mod site;
pub mod stats;
pub mod team;
pub mod ticket;
/// Shared data models used across frontend and backend.
/// These types are serializable and must remain consistent between
/// frontend and server components.
pub mod user;

pub use auth::{AuditLogEntry, AuthError, AuthToken, JwtClaims};
pub use backup::{
    BackupRun, BackupSchedule, BackupScheduleWithLatest, BackupStats, CreateBackupScheduleRequest,
    StorageType,
};
pub use billing::{DailyAggregate, MonthlySnapshot, UsageLog};
pub use branding::ResellerBranding;
pub use cron::CronJob;
pub use database::{Database, DatabaseUser};
pub use dns::{DnsRecord, DnsZone, RecordType};
pub use domain::Domain;
pub use email::{EmailDomain, EmailForwarder, Mailbox};
pub use ftp::FtpAccount;
pub use git::{GitBranch, GitCommit, SiteGitRepo, SiteGitRepoPublic};
pub use package::Package;
pub use quota::{ResourceQuota, ResourceUsage};
pub use service::{ServiceStatus, ServiceType};
pub use site::Site;
pub use stats::{StatsConfig, StatsRunStatus, StatsTool, StatsToolAvailability};
pub use ticket::{Ticket, TicketMessage, TicketPriority, TicketStatus};
pub use user::{AccountStatus, Role, User};
