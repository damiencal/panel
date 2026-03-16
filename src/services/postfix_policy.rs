/// Postfix SMTP access policy daemon for per-domain send-rate limiting.
///
/// This module implements a minimal TCP policy server compatible with
/// Postfix's `check_policy_service inet:127.0.0.1:10031`.
///
/// Protocol (RFC-style key=value pairs terminated by a blank line):
///   request=smtpd_access_policy
///   sasl_username=user@domain.example
///   ...
///   [blank line]
/// Response with a single line:
///   action=DUNNO          (no opinion, continue processing)
///   action=DEFER_IF_PERMIT Service temporarily unavailable
///
/// Only authenticated senders (`sasl_username` present) are checked.
/// Unauthenticated connections always receive DUNNO.
use sqlx::SqlitePool;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

/// TCP port the policy service listens on (localhost only).
pub const POLICY_PORT: u16 = 10031;

/// Start the policy service as a background tokio task.
/// This should be called once during server initialisation.
pub fn start(pool: SqlitePool) {
    tokio::spawn(async move {
        if let Err(e) = run(pool).await {
            error!("Postfix policy service terminated: {e}");
        }
    });
}

async fn run(pool: SqlitePool) -> std::io::Result<()> {
    let bind_addr = format!("127.0.0.1:{POLICY_PORT}");
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("Postfix policy service listening on {bind_addr}");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!("Policy connection from {peer}");
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, pool).await {
                        warn!("Policy connection error from {peer}: {e}");
                    }
                });
            }
            Err(e) => {
                error!("Policy listener accept error: {e}");
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::TcpStream, pool: SqlitePool) -> std::io::Result<()> {
    let (reader_half, mut writer_half) = stream.into_split();
    let reader = BufReader::new(reader_half);
    let mut lines = reader.lines();

    loop {
        let mut attrs: HashMap<String, String> = HashMap::new();

        // Read one policy request (key=value lines ending with a blank line).
        loop {
            match lines.next_line().await? {
                None => return Ok(()),                  // client closed connection
                Some(line) if line.is_empty() => break, // blank line = end of request
                Some(line) => {
                    // Guard against OOM: cap attribute count and per-value size.
                    if attrs.len() >= 64 {
                        // Too many attributes — respond DUNNO and stop reading.
                        writer_half.write_all(b"action=DUNNO\n\n").await?;
                        return Ok(());
                    }
                    if let Some((k, v)) = line.split_once('=') {
                        let v = v.trim();
                        if v.len() <= 512 {
                            attrs.insert(k.trim().to_lowercase(), v.to_string());
                        }
                        // Oversized values are silently dropped.
                    }
                }
            }
        }

        let action = evaluate(&attrs, &pool).await;
        let response = format!("action={action}\n\n");
        writer_half.write_all(response.as_bytes()).await?;
    }
}

/// Evaluate a single policy request and return the action string.
async fn evaluate(attrs: &HashMap<String, String>, pool: &SqlitePool) -> String {
    // Only rate-limit authenticated senders.
    let sasl_username = match attrs.get("sasl_username") {
        Some(u) if !u.is_empty() => u.clone(),
        _ => return "DUNNO".to_string(),
    };

    // Extract domain part of the authenticated user.
    let domain_name = match sasl_username.split_once('@') {
        Some((_, d)) if !d.is_empty() => d.to_lowercase(),
        _ => return "DUNNO".to_string(),
    };

    // Look up the email_domain row.
    let domain_row = sqlx::query_as::<_, (i64, i32, i32)>(
        "SELECT id, send_limit_per_hour, send_limit_per_day
         FROM email_domains WHERE domain = ?",
    )
    .bind(&domain_name)
    .fetch_optional(pool)
    .await;

    let (domain_id, limit_hour, limit_day) = match domain_row {
        Ok(Some(r)) => r,
        Ok(None) => return "DUNNO".to_string(), // unknown domain, don't block
        Err(e) => {
            error!("Policy DB lookup error: {e}");
            return "DUNNO".to_string(); // fail open to avoid blocking legitimate mail
        }
    };

    // If both limits are 0 (unlimited), skip the counter update entirely.
    if limit_hour == 0 && limit_day == 0 {
        return "DUNNO".to_string();
    }

    // check_and_increment_send_count handles window resets and atomic increment.
    match crate::db::email::check_and_increment_send_count(pool, domain_id).await {
        Ok(true) => "DUNNO".to_string(),
        Ok(false) => {
            warn!(
                "Domain {domain_name} exceeded send limit \
                 (hourly={limit_hour}, daily={limit_day})"
            );
            "DEFER_IF_PERMIT Rate limit exceeded for this domain".to_string()
        }
        Err(e) => {
            error!("Policy counter update error for {domain_name}: {e}");
            "DUNNO".to_string() // fail open
        }
    }
}
