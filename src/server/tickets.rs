#[cfg(feature = "server")]
use crate::models::ticket::TicketStatus;
/// Support ticket server functions.
use crate::models::ticket::{Ticket, TicketMessage, TicketPriority};
use dioxus::prelude::*;

/// List tickets for the current user.
#[server]
pub async fn server_list_tickets() -> Result<Vec<Ticket>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    crate::db::tickets::list_tickets(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// List all tickets (admin/reseller only).
#[server]
pub async fn server_list_all_tickets() -> Result<Vec<Ticket>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    if claims.role == crate::models::user::Role::Client {
        return Err(ServerFnError::new("Access denied"));
    }
    let pool = get_pool()?;

    crate::db::tickets::list_all_tickets(pool)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a new support ticket.
#[server]
pub async fn server_create_ticket(
    subject: String,
    body: String,
    priority: TicketPriority,
    department: String,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let ticket_id =
        crate::db::tickets::create_ticket(pool, subject.clone(), priority, department, claims.sub)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Add the initial message
    crate::db::tickets::add_message(pool, ticket_id, claims.sub, body, false)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "create_ticket",
        Some("ticket"),
        Some(ticket_id),
        Some(&subject),
        "Success",
        None,
    )
    .await;

    Ok(ticket_id)
}

/// Get ticket with all messages.
#[server]
pub async fn server_get_ticket(
    ticket_id: i64,
) -> Result<(Ticket, Vec<TicketMessage>), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let ticket = crate::db::tickets::get_ticket(pool, ticket_id)
        .await
        .map_err(|_| ServerFnError::new("Ticket not found"))?;

    // Clients can only see their own tickets
    if claims.role == crate::models::user::Role::Client && ticket.created_by != claims.sub {
        return Err(ServerFnError::new("Access denied"));
    }

    let messages = crate::db::tickets::list_messages(pool, ticket_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok((ticket, messages))
}

/// Reply to a ticket.
#[server]
pub async fn server_reply_to_ticket(
    ticket_id: i64,
    body: String,
    is_internal: bool,
) -> Result<i64, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let ticket = crate::db::tickets::get_ticket(pool, ticket_id)
        .await
        .map_err(|_| ServerFnError::new("Ticket not found"))?;

    // Clients can only reply to their own tickets, and can't send internal notes
    if claims.role == crate::models::user::Role::Client {
        if ticket.created_by != claims.sub {
            return Err(ServerFnError::new("Access denied"));
        }
        if is_internal {
            return Err(ServerFnError::new("Access denied"));
        }
    }

    let msg_id = crate::db::tickets::add_message(pool, ticket_id, claims.sub, body, is_internal)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Update ticket status based on who replied
    let new_status = if claims.role == crate::models::user::Role::Client {
        TicketStatus::ClientReply
    } else {
        TicketStatus::Answered
    };
    let _ = crate::db::tickets::update_status(pool, ticket_id, new_status).await;

    Ok(msg_id)
}

/// Close a ticket.
#[server]
pub async fn server_close_ticket(ticket_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;

    let ticket = crate::db::tickets::get_ticket(pool, ticket_id)
        .await
        .map_err(|_| ServerFnError::new("Ticket not found"))?;

    if claims.role == crate::models::user::Role::Client && ticket.created_by != claims.sub {
        return Err(ServerFnError::new("Access denied"));
    }

    crate::db::tickets::update_status(pool, ticket_id, TicketStatus::Closed)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    audit_log(
        claims.sub,
        "close_ticket",
        Some("ticket"),
        Some(ticket_id),
        Some(&ticket.subject),
        "Success",
        None,
    )
    .await;

    Ok(())
}
