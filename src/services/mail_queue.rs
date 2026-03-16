/// Mail queue management using Postfix `mailq` and `postsuper`.
/// Provides operations to list, flush, hold, and delete queued messages.
use super::{shell, ServiceError};
use crate::models::email::MailQueueEntry;
use tracing::info;

/// List all messages currently in the Postfix mail queue.
/// Parses the output of `mailq` / `postqueue -p`.
pub async fn list_queue() -> Result<Vec<MailQueueEntry>, ServiceError> {
    let output = shell::exec("postqueue", &["-p"]).await?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_mailq_output(&text))
}

/// Flush deferred messages — attempt immediate redelivery.
pub async fn flush_queue() -> Result<(), ServiceError> {
    shell::exec("postqueue", &["-f"]).await?;
    info!("Mail queue flushed");
    Ok(())
}

/// Delete a specific message by queue ID.
/// Uses `postsuper -d <id>`.
pub async fn delete_message(queue_id: &str) -> Result<(), ServiceError> {
    // Only allow hex queue IDs to prevent injection
    if !queue_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ServiceError::CommandFailed("Invalid queue ID".to_string()));
    }
    shell::exec("postsuper", &["-d", queue_id]).await?;
    info!("Deleted queued message {queue_id}");
    Ok(())
}

/// Delete all messages in the deferred queue.
pub async fn delete_all_deferred() -> Result<(), ServiceError> {
    shell::exec("postsuper", &["-d", "ALL", "deferred"]).await?;
    info!("Deleted all deferred messages");
    Ok(())
}

/// Hold a message (prevent delivery without discarding).
pub async fn hold_message(queue_id: &str) -> Result<(), ServiceError> {
    if !queue_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ServiceError::CommandFailed("Invalid queue ID".to_string()));
    }
    shell::exec("postsuper", &["-h", queue_id]).await?;
    Ok(())
}

/// Release a held message back into the active queue.
pub async fn release_message(queue_id: &str) -> Result<(), ServiceError> {
    if !queue_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ServiceError::CommandFailed("Invalid queue ID".to_string()));
    }
    shell::exec("postsuper", &["-H", queue_id]).await?;
    Ok(())
}

// ─── Parser ──────────────────────────────────────────────────────────────────

/// Parse `postqueue -p` output into structured entries.
///
/// Example format:
/// ```text
/// -Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
/// 3C2E71E0123     1234 Mon Mar  9 14:00:00  sender@example.com
///                                           (delivery reason)
///                                           recipient@other.com
/// ```
fn parse_mailq_output(text: &str) -> Vec<MailQueueEntry> {
    let mut entries = Vec::new();
    let mut lines = text.lines().peekable();

    // Skip header line
    while let Some(line) = lines.peek() {
        if line.starts_with('-') || line.starts_with('M') {
            lines.next();
            break;
        }
        lines.next();
    }

    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("--") || line.starts_with("Mail queue is empty") {
            continue;
        }

        // Queue entry header: starts with an alphanumeric queue ID
        // Format: <ID>[*!] <size> <date DDDDD> <sender>
        let parts: Vec<&str> = line.splitn(6, ' ').filter(|s| !s.is_empty()).collect();
        if parts.len() < 5 {
            continue;
        }

        let raw_id = parts[0];
        // '*' = active, '!' = hold, no suffix = deferred
        let (queue_id, queue_type) = if raw_id.ends_with('*') {
            (raw_id.trim_end_matches('*').to_string(), "active")
        } else if raw_id.ends_with('!') {
            (raw_id.trim_end_matches('!').to_string(), "hold")
        } else {
            (raw_id.to_string(), "deferred")
        };

        let size: u64 = parts[1].parse().unwrap_or(0);
        // parts[2..5] are the date tokens (e.g. "Mon", "Mar", "9")
        let arrival_time = parts[2..parts.len().saturating_sub(1)].join(" ");
        let sender = parts.last().unwrap_or(&"").to_string();

        let mut reason = String::new();
        let mut recipients: Vec<String> = Vec::new();

        // Read continuation lines (reason + recipients)
        while let Some(next) = lines.peek() {
            let next = next.trim();
            if next.is_empty() {
                lines.next();
                break;
            }
            if next.starts_with('(') {
                reason = next.trim_matches(|c| c == '(' || c == ')').to_string();
            } else if !next.is_empty() && !next.starts_with('-') {
                recipients.push(next.to_string());
            }
            lines.next();
        }

        let recipient = recipients.join(", ");
        entries.push(MailQueueEntry {
            queue_id,
            size,
            arrival_time,
            sender,
            recipient,
            reason,
            queue_type: queue_type.to_string(),
        });
    }

    entries
}
