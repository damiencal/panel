use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum TicketStatus {
    #[serde(rename = "Open")]
    Open,
    #[serde(rename = "Answered")]
    Answered,
    #[serde(rename = "ClientReply")]
    ClientReply,
    #[serde(rename = "Closed")]
    Closed,
}

impl std::fmt::Display for TicketStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketStatus::Open => write!(f, "Open"),
            TicketStatus::Answered => write!(f, "Answered"),
            TicketStatus::ClientReply => write!(f, "Client Reply"),
            TicketStatus::Closed => write!(f, "Closed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum TicketPriority {
    #[serde(rename = "Low")]
    Low,
    #[serde(rename = "Medium")]
    Medium,
    #[serde(rename = "High")]
    High,
    #[serde(rename = "Critical")]
    Critical,
}

impl std::fmt::Display for TicketPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketPriority::Low => write!(f, "Low"),
            TicketPriority::Medium => write!(f, "Medium"),
            TicketPriority::High => write!(f, "High"),
            TicketPriority::Critical => write!(f, "Critical"),
        }
    }
}

/// Support ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct Ticket {
    pub id: i64,
    pub subject: String,
    pub status: TicketStatus,
    pub priority: TicketPriority,
    pub department: String,
    pub created_by: i64,
    pub assigned_to: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Ticket message/reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct TicketMessage {
    pub id: i64,
    pub ticket_id: i64,
    pub sender_id: i64,
    pub body: String,
    pub is_internal: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTicketRequest {
    pub subject: String,
    pub body: String,
    pub priority: TicketPriority,
    pub department: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReplyToTicketRequest {
    pub body: String,
    pub is_internal: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TicketWithMessages {
    pub ticket: Ticket,
    pub messages: Vec<TicketMessage>,
}
