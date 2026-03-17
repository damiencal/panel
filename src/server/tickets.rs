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
    check_token_not_revoked(pool, &claims).await?;

    crate::db::tickets::list_tickets(pool, claims.sub)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// List all tickets (admin/reseller only).
/// Admins see every ticket; Resellers are scoped to tickets from their own clients.
#[server]
pub async fn server_list_all_tickets() -> Result<Vec<Ticket>, ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    // Only Admin and Reseller may list all tickets; Client and Developer see only their own.
    if !matches!(
        claims.role,
        crate::models::user::Role::Admin | crate::models::user::Role::Reseller
    ) {
        return Err(ServerFnError::new("Access denied"));
    }
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    if claims.role == crate::models::user::Role::Admin {
        // Admins see everything.
        crate::db::tickets::list_all_tickets(pool)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    } else {
        // Resellers see only their own clients' tickets — not tickets from clients
        // belonging to other resellers.
        let clients = crate::db::users::list_clients_for_reseller(pool, claims.sub)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let client_ids: Vec<i64> = clients.iter().map(|u| u.id).collect();
        crate::db::tickets::list_tickets_for_owners(pool, &client_ids)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
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
    check_token_not_revoked(pool, &claims).await?;

    // Input-size limits prevent resource exhaustion via OOM and unbounded DB growth.
    if subject.is_empty() || subject.len() > 255 {
        return Err(ServerFnError::new("Subject must be 1–255 characters"));
    }
    if body.len() > 65_536 {
        return Err(ServerFnError::new("Message body must be at most 64 KiB"));
    }
    if department.len() > 100 {
        return Err(ServerFnError::new(
            "Department name must be at most 100 characters",
        ));
    }

    let ticket_id =
        crate::db::tickets::create_ticket(pool, subject.clone(), priority, department, claims.sub)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Add the initial message; on failure, delete the ticket to avoid empty-ticket orphans.
    if let Err(e) = crate::db::tickets::add_message(pool, ticket_id, claims.sub, body, false).await
    {
        if let Err(rb_err) = crate::db::tickets::delete_ticket(pool, ticket_id).await {
            tracing::error!(
                ticket_id,
                "Failed to rollback empty ticket after message-add failure: {rb_err}"
            );
        }
        return Err(ServerFnError::new(e.to_string()));
    }

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
    check_token_not_revoked(pool, &claims).await?;

    let ticket = crate::db::tickets::get_ticket(pool, ticket_id)
        .await
        .map_err(|_| ServerFnError::new("Ticket not found"))?;

    // Clients and Developers can only see their own tickets.
    if matches!(
        claims.role,
        crate::models::user::Role::Client | crate::models::user::Role::Developer
    ) && ticket.created_by != claims.sub
    {
        return Err(ServerFnError::new("Access denied"));
    }
    // Resellers can only see tickets from their own clients (TICKET-01).
    if claims.role == crate::models::user::Role::Reseller {
        let creator = crate::db::users::get(pool, ticket.created_by)
            .await
            .map_err(|_| ServerFnError::new("Access denied"))?;
        if creator.parent_id != Some(claims.sub) {
            return Err(ServerFnError::new("Access denied"));
        }
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
    check_token_not_revoked(pool, &claims).await?;

    // Cap reply body size to prevent resource exhaustion.
    if body.len() > 65_536 {
        return Err(ServerFnError::new("Reply body must be at most 64 KiB"));
    }

    let ticket = crate::db::tickets::get_ticket(pool, ticket_id)
        .await
        .map_err(|_| ServerFnError::new("Ticket not found"))?;

    // Clients and Developers can only reply to their own tickets and cannot post internal notes.
    if matches!(
        claims.role,
        crate::models::user::Role::Client | crate::models::user::Role::Developer
    ) {
        if ticket.created_by != claims.sub {
            return Err(ServerFnError::new("Access denied"));
        }
        if is_internal {
            return Err(ServerFnError::new("Access denied"));
        }
    }
    // Resellers can only reply to tickets from their own clients (TICKET-01).
    if claims.role == crate::models::user::Role::Reseller {
        let creator = crate::db::users::get(pool, ticket.created_by)
            .await
            .map_err(|_| ServerFnError::new("Access denied"))?;
        if creator.parent_id != Some(claims.sub) {
            return Err(ServerFnError::new("Access denied"));
        }
    }

    let msg_id = crate::db::tickets::add_message(pool, ticket_id, claims.sub, body, is_internal)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // Update ticket status based on who replied
    let new_status = if matches!(
        claims.role,
        crate::models::user::Role::Client | crate::models::user::Role::Developer
    ) {
        TicketStatus::ClientReply
    } else {
        TicketStatus::Answered
    };
    if let Err(e) = crate::db::tickets::update_status(pool, ticket_id, new_status).await {
        tracing::warn!(ticket_id, "Failed to update ticket status after reply: {e}");
    }

    audit_log(
        claims.sub,
        "reply_to_ticket",
        Some("ticket"),
        Some(ticket_id),
        Some(&ticket.subject),
        "Success",
        None,
    )
    .await;

    Ok(msg_id)
}

/// Close a ticket.
#[server]
pub async fn server_close_ticket(ticket_id: i64) -> Result<(), ServerFnError> {
    use super::helpers::*;

    ensure_init().await.map_err(ServerFnError::new)?;
    let claims = verify_auth()?;
    let pool = get_pool()?;
    check_token_not_revoked(pool, &claims).await?;

    let ticket = crate::db::tickets::get_ticket(pool, ticket_id)
        .await
        .map_err(|_| ServerFnError::new("Ticket not found"))?;

    if matches!(
        claims.role,
        crate::models::user::Role::Client | crate::models::user::Role::Developer
    ) && ticket.created_by != claims.sub
    {
        return Err(ServerFnError::new("Access denied"));
    }
    // Resellers can only close tickets from their own clients (TICKET-01).
    if claims.role == crate::models::user::Role::Reseller {
        let creator = crate::db::users::get(pool, ticket.created_by)
            .await
            .map_err(|_| ServerFnError::new("Access denied"))?;
        if creator.parent_id != Some(claims.sub) {
            return Err(ServerFnError::new("Access denied"));
        }
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
