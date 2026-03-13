/// UFW (Uncomplicated Firewall) service management.
/// Provides start/stop/reload, rule CRUD, IP block, and export/import.
use super::{shell, ServiceError};
use tokio::fs;
use tracing::{info, warn};

// Re-export shared types from models
pub use crate::models::firewall::{UfwAction, UfwRule, UfwStatus, UfwStatusRule};

// ─── Service ─────────────────────────────────────────────────────────────────

pub struct UfwService;

impl UfwService {
    /// Check if UFW is installed.
    pub async fn is_installed(&self) -> bool {
        shell::command_exists("ufw").await
    }

    /// Install UFW.
    pub async fn install(&self) -> Result<(), ServiceError> {
        info!("Installing UFW…");
        shell::exec("apt-get", &["install", "-y", "ufw"]).await?;
        info!("UFW installed");
        Ok(())
    }

    /// Start / enable UFW (non-interactive).
    pub async fn enable(&self) -> Result<(), ServiceError> {
        info!("Enabling UFW…");
        // Use `--force` to avoid interactive prompt
        shell::exec("ufw", &["--force", "enable"]).await?;
        info!("UFW enabled");
        Ok(())
    }

    /// Disable / stop UFW.
    pub async fn disable(&self) -> Result<(), ServiceError> {
        info!("Disabling UFW…");
        shell::exec("ufw", &["disable"]).await?;
        info!("UFW disabled");
        Ok(())
    }

    /// Reload UFW rules without disabling.
    pub async fn reload(&self) -> Result<(), ServiceError> {
        shell::exec("ufw", &["reload"]).await?;
        info!("UFW reloaded");
        Ok(())
    }

    /// Reset UFW to defaults (removes all rules).
    pub async fn reset(&self) -> Result<(), ServiceError> {
        shell::exec("ufw", &["--force", "reset"]).await?;
        info!("UFW reset to defaults");
        Ok(())
    }

    /// Get UFW status with numbered rules.
    pub async fn get_status(&self) -> Result<UfwStatus, ServiceError> {
        if !self.is_installed().await {
            return Err(ServiceError::NotInstalled);
        }
        let out = shell::exec("ufw", &["status", "verbose"]).await?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        Ok(parse_ufw_status(&text))
    }

    /// Get numbered rules for deletion.
    pub async fn get_numbered_rules(&self) -> Result<Vec<UfwStatusRule>, ServiceError> {
        if !self.is_installed().await {
            return Err(ServiceError::NotInstalled);
        }
        let out = shell::exec("ufw", &["status", "numbered"]).await?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        Ok(parse_numbered_rules(&text))
    }

    /// Add a rule (allow/deny/reject a port or IP).
    pub async fn add_rule(&self, rule: &UfwRule) -> Result<(), ServiceError> {
        let mut args: Vec<&str> = Vec::new();

        // direction: "in" / "out"
        let direction = rule.direction.as_str();

        if let Some(ref from_ip) = rule.from_ip {
            validate_ip_or_cidr(from_ip)?;
            if let Some(ref port) = rule.to_port {
                validate_port_or_service(port)?;
                if let Some(ref proto) = rule.protocol {
                    // e.g. ufw allow from 1.2.3.4 to any port 80 proto tcp
                    let proto_str: &str = proto.as_str();
                    let port_str: &str = port.as_str();
                    let from_str: &str = from_ip.as_str();
                    // Build args dynamically
                    let action_arg = rule.action.as_ufw_arg();
                    let cmd_args = vec![
                        action_arg, direction, "from", from_str, "to", "any", "port", port_str,
                        "proto", proto_str,
                    ];
                    return self.run_ufw(&cmd_args).await;
                } else {
                    let action_arg = rule.action.as_ufw_arg();
                    let from_str: &str = from_ip.as_str();
                    let port_str: &str = port.as_str();
                    let cmd_args = vec![
                        action_arg, direction, "from", from_str, "to", "any", "port", port_str,
                    ];
                    return self.run_ufw(&cmd_args).await;
                }
            } else {
                // Block/allow entire IP
                let action_arg = rule.action.as_ufw_arg();
                let from_str: &str = from_ip.as_str();
                let cmd_args = vec![action_arg, direction, "from", from_str];
                return self.run_ufw(&cmd_args).await;
            }
        } else if let Some(ref port) = rule.to_port {
            validate_port_or_service(port)?;
            let action_arg = rule.action.as_ufw_arg();
            let port_str: &str = port.as_str();
            if let Some(ref proto) = rule.protocol {
                let combined = format!("{}/{}", port, proto);
                // combined owns its string; need to call run_ufw with owned args differently
                return self
                    .run_ufw_owned(vec![action_arg.to_string(), combined])
                    .await;
            } else {
                args.push(action_arg);
                args.push(port_str);
                return self.run_ufw(&args).await;
            }
        } else {
            Err(ServiceError::CommandFailed(
                "Rule must specify either from_ip or to_port".to_string(),
            ))
        }
    }

    /// One-click block an IP address.
    pub async fn block_ip(&self, ip: &str) -> Result<(), ServiceError> {
        validate_ip_or_cidr(ip)?;
        info!("Blocking IP: {ip}");
        shell::exec("ufw", &["deny", "from", ip, "to", "any"]).await?;
        info!("IP {ip} blocked");
        Ok(())
    }

    /// Remove a rule by number.
    pub async fn delete_rule_by_number(&self, number: u32) -> Result<(), ServiceError> {
        if number == 0 || number > 9999 {
            return Err(ServiceError::CommandFailed(
                "Invalid rule number".to_string(),
            ));
        }
        let num_str = number.to_string();
        shell::exec("ufw", &["--force", "delete", &num_str]).await?;
        info!("UFW rule #{number} deleted");
        Ok(())
    }

    /// Set default policy.
    pub async fn set_default_policy(
        &self,
        direction: &str,
        policy: &str,
    ) -> Result<(), ServiceError> {
        if !matches!(direction, "incoming" | "outgoing") {
            return Err(ServiceError::CommandFailed(
                "direction must be 'incoming' or 'outgoing'".to_string(),
            ));
        }
        if !matches!(policy, "allow" | "deny" | "reject") {
            return Err(ServiceError::CommandFailed(
                "policy must be 'allow', 'deny', or 'reject'".to_string(),
            ));
        }
        shell::exec("ufw", &["default", policy, direction]).await?;
        info!("UFW default {direction} -> {policy}");
        Ok(())
    }

    /// Export current rules as text (the contents of /etc/ufw/user.rules).
    pub async fn export_rules(&self) -> Result<String, ServiceError> {
        let paths = &[
            "/etc/ufw/user.rules",
            "/etc/ufw/user6.rules",
            "/etc/ufw/before.rules",
        ];
        let mut out = String::new();
        for path in paths {
            match fs::read_to_string(path).await {
                Ok(content) => {
                    out.push_str(&format!("### {path} ###\n"));
                    out.push_str(&content);
                    out.push('\n');
                }
                Err(e) => warn!("Could not read {path}: {e}"),
            }
        }
        if out.is_empty() {
            // Fall back to `ufw status verbose`
            let cmd_out = shell::exec("ufw", &["status", "verbose"]).await?;
            out = String::from_utf8_lossy(&cmd_out.stdout).to_string();
        }
        Ok(out)
    }

    /// Import rules from exported text by writing to /etc/ufw/user.rules and reloading.
    /// Only accepts content that starts with the expected UFW header to prevent misuse.
    pub async fn import_rules(&self, content: &str) -> Result<(), ServiceError> {
        // Safety: only allow valid UFW rule files (must contain the UFW header)
        if !content.contains("*filter") && !content.contains("### tuple ###") {
            return Err(ServiceError::CommandFailed(
                "Invalid UFW rules file format".to_string(),
            ));
        }
        // Limit size to prevent abuse
        if content.len() > 256 * 1024 {
            return Err(ServiceError::CommandFailed(
                "Rules file too large (max 256 KB)".to_string(),
            ));
        }
        fs::write("/etc/ufw/user.rules", content)
            .await
            .map_err(|e| ServiceError::IoError(e.to_string()))?;
        self.reload().await?;
        info!("UFW rules imported and reloaded");
        Ok(())
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    async fn run_ufw(&self, args: &[&str]) -> Result<(), ServiceError> {
        // Route through shell::exec for allowlist check and argument validation
        shell::exec("ufw", args).await.map(|_| ())
    }

    async fn run_ufw_owned(&self, args: Vec<String>) -> Result<(), ServiceError> {
        // Route through shell::exec for allowlist check and argument validation
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        shell::exec("ufw", &args_refs).await.map(|_| ())
    }
}

// ─── Validation Helpers ──────────────────────────────────────────────────────

/// Validate an IPv4/IPv6 address or CIDR block.
fn validate_ip_or_cidr(ip: &str) -> Result<(), ServiceError> {
    // Max length guard
    if ip.len() > 50 {
        return Err(ServiceError::CommandFailed(
            "IP address too long".to_string(),
        ));
    }
    // Must only contain valid IP / CIDR characters
    let valid = ip
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/' | '[' | ']'));
    if !valid {
        return Err(ServiceError::CommandFailed(format!(
            "Invalid IP/CIDR: {ip}"
        )));
    }
    Ok(())
}

/// Validate a port number or known service name.
fn validate_port_or_service(port: &str) -> Result<(), ServiceError> {
    if port.len() > 20 {
        return Err(ServiceError::CommandFailed("Port too long".to_string()));
    }
    // Port range e.g. "80:443" or single port e.g. "443" or service name e.g. "ssh"
    let valid = port
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '/'));
    if !valid {
        return Err(ServiceError::CommandFailed(format!(
            "Invalid port/service: {port}"
        )));
    }
    Ok(())
}

// ─── Output Parsers ──────────────────────────────────────────────────────────

fn parse_ufw_status(text: &str) -> UfwStatus {
    let active = text.contains("Status: active");
    let mut default_incoming = "deny".to_string();
    let mut default_outgoing = "allow".to_string();
    let mut logging = "on".to_string();

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("Default:") {
            // "Default: deny (incoming), allow (outgoing), disabled (routed)"
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let details = parts[1];
                if let Some(inc) = details.split("(incoming)").next() {
                    default_incoming = inc
                        .split(',')
                        .next_back()
                        .unwrap_or("deny")
                        .trim()
                        .to_string();
                }
                if let Some(out) = details.split("(outgoing)").next() {
                    default_outgoing = out
                        .split(',')
                        .next_back()
                        .unwrap_or("allow")
                        .trim()
                        .to_string();
                }
            }
        } else if line.starts_with("Logging:") {
            logging = line
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("on")
                .trim()
                .to_string();
        }
    }

    let rules = parse_numbered_rules(text);

    UfwStatus {
        active,
        logging,
        default_incoming,
        default_outgoing,
        rules,
    }
}

fn parse_numbered_rules(text: &str) -> Vec<UfwStatusRule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Match lines like: [ 1] 22/tcp                     ALLOW IN    Anywhere
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(close) = rest.find(']') {
                let num_str = rest[..close].trim();
                if let Ok(num) = num_str.parse::<u32>() {
                    let rest2 = rest[close + 1..].trim();
                    // Split on 2+ spaces
                    let parts: Vec<&str> = rest2
                        .splitn(3, "  ")
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if parts.len() >= 3 {
                        rules.push(UfwStatusRule {
                            number: num,
                            to: parts[0].to_string(),
                            action: parts[1].to_string(),
                            from: parts[2].to_string(),
                        });
                    } else if parts.len() == 2 {
                        rules.push(UfwStatusRule {
                            number: num,
                            to: parts[0].to_string(),
                            action: parts[1].to_string(),
                            from: "Anywhere".to_string(),
                        });
                    }
                }
            }
        }
    }
    rules
}
