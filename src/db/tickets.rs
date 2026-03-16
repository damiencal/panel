/// Support ticket operations.
use crate::models::ticket::{Ticket, TicketMessage, TicketPriority, TicketStatus};
use chrono::Utc;
use sqlx::SqlitePool;

/// Get a ticket by ID.
pub async fn get_ticket(pool: &SqlitePool, ticket_id: i64) -> Result<Ticket, sqlx::Error> {
    sqlx::query_as::<_, Ticket>("SELECT * FROM support_tickets WHERE id = ?")
        .bind(ticket_id)
        .fetch_one(pool)
        .await
}

/// List tickets for a user.
pub async fn list_tickets(pool: &SqlitePool, user_id: i64) -> Result<Vec<Ticket>, sqlx::Error> {
    sqlx::query_as::<_, Ticket>(
        "SELECT * FROM support_tickets WHERE created_by = ? ORDER BY updated_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// List all tickets (for admin staff).
pub async fn list_all_tickets(pool: &SqlitePool) -> Result<Vec<Ticket>, sqlx::Error> {
    sqlx::query_as::<_, Ticket>("SELECT * FROM support_tickets ORDER BY updated_at DESC")
        .fetch_all(pool)
        .await
}

/// List tickets whose `created_by` is in the supplied owner-id slice.
/// Used to scope a reseller's view to their own clients only.
pub async fn list_tickets_for_owners(
    pool: &SqlitePool,
    owner_ids: &[i64],
) -> Result<Vec<Ticket>, sqlx::Error> {
    if owner_ids.is_empty() {
        return Ok(Vec::new());
    }
    // Build a parameterized IN-list dynamically; sqlx doesn't support binding Vec<i64>
    // directly with SQLite, so we construct the placeholder string manually.
    let placeholders = owner_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT * FROM support_tickets WHERE created_by IN ({placeholders}) ORDER BY updated_at DESC"
    );
    let mut q = sqlx::query_as::<_, Ticket>(&sql);
    for id in owner_ids {
        q = q.bind(*id);
    }
    q.fetch_all(pool).await
}

/// Create a new ticket.
pub async fn create_ticket(
    pool: &SqlitePool,
    subject: String,
    priority: TicketPriority,
    department: String,
    created_by: i64,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "INSERT INTO support_tickets (subject, status, priority, department, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(subject)
    .bind(TicketStatus::Open)
    .bind(priority)
    .bind(department)
    .bind(created_by)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Update ticket status.
pub async fn update_status(
    pool: &SqlitePool,
    ticket_id: i64,
    status: TicketStatus,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query("UPDATE support_tickets SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(now)
        .bind(ticket_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get a ticket message by ID.
pub async fn get_message(pool: &SqlitePool, message_id: i64) -> Result<TicketMessage, sqlx::Error> {
    sqlx::query_as::<_, TicketMessage>("SELECT * FROM ticket_messages WHERE id = ?")
        .bind(message_id)
        .fetch_one(pool)
        .await
}

/// List messages for a ticket.
pub async fn list_messages(
    pool: &SqlitePool,
    ticket_id: i64,
) -> Result<Vec<TicketMessage>, sqlx::Error> {
    sqlx::query_as::<_, TicketMessage>(
        "SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at",
    )
    .bind(ticket_id)
    .fetch_all(pool)
    .await
}

/// Add a message to a ticket.
pub async fn add_message(
    pool: &SqlitePool,
    ticket_id: i64,
    sender_id: i64,
    body: String,
    is_internal: bool,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO ticket_messages (ticket_id, sender_id, body, is_internal, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(ticket_id)
    .bind(sender_id)
    .bind(body)
    .bind(is_internal)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}
