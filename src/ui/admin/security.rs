#![allow(non_snake_case)]
use dioxus::prelude::*;
use panel::server::*;
use crate::lucide::Icon;

use crate::{BackupStatCard, fmt_bytes_backup};

#[component]
pub fn AdminFirewall() -> Element {
    let mut status_res = use_resource(move || async move { server_ufw_get_status().await });
    let mut rules_res = use_resource(move || async move { server_ufw_get_numbered_rules().await });

    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut ok_msg = use_signal(|| None::<String>);

    // quick-add form
    let mut add_action = use_signal(|| "allow".to_string());
    let mut add_port = use_signal(String::new);
    let mut add_from = use_signal(String::new);
    let mut add_proto = use_signal(|| "tcp".to_string());
    let mut add_comment = use_signal(String::new);

    // ip-block form
    let mut block_ip = use_signal(String::new);

    // import textarea
    let mut import_text = use_signal(String::new);
    let mut show_import = use_signal(|| false);

    let mut refresh = move || {
        status_res.restart();
        rules_res.restart();
    };

    let do_enable = {
        move |_| {
            error.set(None);
            ok_msg.set(None);
            busy.set(true);
            spawn(async move {
                match server_ufw_enable().await {
                    Ok(()) => {
                        ok_msg.set(Some("UFW enabled.".to_string()));
                        refresh();
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
                busy.set(false);
            });
        }
    };

    let do_disable = move |_| {
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_disable().await {
                Ok(()) => {
                    ok_msg.set(Some("UFW disabled.".to_string()));
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let do_reload = move |_| {
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_reload().await {
                Ok(()) => {
                    ok_msg.set(Some("UFW reloaded.".to_string()));
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let do_add_rule = move |_| {
        let port = add_port();
        let from = if add_from().is_empty() {
            None
        } else {
            Some(add_from())
        };
        let comment = if add_comment().is_empty() {
            None
        } else {
            Some(add_comment())
        };
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_add_rule(
                add_action(),
                "in".to_string(),
                Some(add_proto()),
                from,
                if port.is_empty() { None } else { Some(port) },
                comment,
            )
            .await
            {
                Ok(()) => {
                    ok_msg.set(Some("Rule added.".to_string()));
                    add_port.set(String::new());
                    add_from.set(String::new());
                    add_comment.set(String::new());
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let do_block_ip = move |_| {
        let ip = block_ip();
        if ip.is_empty() {
            return;
        }
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_block_ip(ip.clone()).await {
                Ok(()) => {
                    ok_msg.set(Some(format!("Blocked {ip}.")));
                    block_ip.set(String::new());
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let do_import = move |_| {
        let content = import_text();
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ufw_import_rules(content).await {
                Ok(()) => {
                    ok_msg.set(Some("Rules imported.".to_string()));
                    show_import.set(false);
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-5xl space-y-6",
            // Header
            div { class: "flex items-center justify-between",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Firewall (UFW)" }
                    p { class: "text-sm text-gray-500 mt-1", "Manage UFW rules, default policies, and IP blocks." }
                }
                div { class: "flex gap-2",
                    button {
                        class: "px-3 py-2 text-sm font-medium rounded-lg bg-white border border-gray-200 hover:bg-gray-50 transition-colors",
                        onclick: do_reload,
                        disabled: busy(),
                        "Reload"
                    }
                    button {
                        class: "px-3 py-2 text-sm font-medium rounded-lg bg-green-600 text-white hover:bg-green-700 transition-colors",
                        onclick: do_enable,
                        disabled: busy(),
                        "Enable UFW"
                    }
                    button {
                        class: "px-3 py-2 text-sm font-medium rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors",
                        onclick: do_disable,
                        disabled: busy(),
                        "Disable UFW"
                    }
                }
            }

            // Feedback
            if let Some(msg) = ok_msg() {
                div { class: "bg-green-50 text-green-700 px-4 py-3 rounded-lg text-sm", "{msg}" }
            }
            if let Some(err) = error() {
                div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }

            // Status card
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                h3 { class: "text-sm font-semibold text-gray-700 mb-3", "Status" }
                match &*status_res.read() {
                    Some(Ok(s)) => rsx! {
                        div { class: "flex flex-wrap gap-4 text-sm",
                            div {
                                span { class: "text-gray-400", "State: " }
                                span { class: if s.active { "text-green-600 font-semibold" } else { "text-red-600 font-semibold" },
                                    if s.active { "ACTIVE" } else { "INACTIVE" }
                                }
                            }
                            div {
                                span { class: "text-gray-400", "Default incoming: " }
                                span { class: "font-medium", "{s.default_incoming}" }
                            }
                            div {
                                span { class: "text-gray-400", "Default outgoing: " }
                                span { class: "font-medium", "{s.default_outgoing}" }
                            }
                            div {
                                span { class: "text-gray-400", "Logging: " }
                                span { class: "font-medium", "{s.logging}" }
                            }
                        }
                    },
                    Some(Err(e)) => {
                        let msg = e.to_string();
                        if msg.contains("not installed") {
                            rsx! {
                                div { class: "flex items-center gap-2 text-sm text-amber-700 bg-amber-50 rounded-lg p-3",
                                    Icon { name: "alert-triangle", class: "w-4 h-4 shrink-0".to_string() }
                                    span { "UFW is not installed. Install it with: "
                                        code { class: "font-mono bg-amber-100 px-1 rounded", "apt install ufw" }
                                    }
                                }
                            }
                        } else {
                            rsx! { p { class: "text-sm text-red-500", "{msg}" } }
                        }
                    },
                    None => rsx! { p { class: "text-sm text-gray-400", "Loading..." } },
                }
            }

            // Quick-add rule + IP block side-by-side
            div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                // Add rule
                div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                    h3 { class: "text-sm font-semibold text-gray-700 mb-3", "Add Rule" }
                    div { class: "space-y-3",
                        div { class: "grid grid-cols-2 gap-2",
                            select {
                                class: "border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                value: add_action(),
                                oninput: move |e| add_action.set(e.value()),
                                option { value: "allow", "Allow" }
                                option { value: "deny", "Deny" }
                                option { value: "reject", "Reject" }
                                option { value: "limit", "Limit" }
                            }
                            select {
                                class: "border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                value: add_proto(),
                                oninput: move |e| add_proto.set(e.value()),
                                option { value: "tcp", "TCP" }
                                option { value: "udp", "UDP" }
                                option { value: "any", "Any" }
                            }
                        }
                        input {
                            class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                            placeholder: "Port (e.g. 80, 443, 8080:8090)",
                            value: add_port(),
                            oninput: move |e| add_port.set(e.value()),
                        }
                        input {
                            class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                            placeholder: "From IP/CIDR (leave blank for any)",
                            value: add_from(),
                            oninput: move |e| add_from.set(e.value()),
                        }
                        input {
                            class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                            placeholder: "Comment (optional)",
                            value: add_comment(),
                            oninput: move |e| add_comment.set(e.value()),
                        }
                        button {
                            class: "w-full py-2 text-sm font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 transition-colors disabled:opacity-50",
                            onclick: do_add_rule,
                            disabled: busy(),
                            "Add Rule"
                        }
                    }
                }

                // IP block
                div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                    h3 { class: "text-sm font-semibold text-gray-700 mb-3", "One-Click IP Block" }
                    p { class: "text-xs text-gray-400 mb-3", "Immediately deny all traffic from an IP or CIDR range." }
                    div { class: "space-y-3",
                        input {
                            class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                            placeholder: "IP address or CIDR (e.g. 1.2.3.4 or 1.2.3.0/24)",
                            value: block_ip(),
                            oninput: move |e| block_ip.set(e.value()),
                        }
                        button {
                            class: "w-full py-2 text-sm font-medium bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors disabled:opacity-50",
                            onclick: do_block_ip,
                            disabled: busy() || block_ip().is_empty(),
                            "Block IP / CIDR"
                        }
                    }

                    // Export / Import
                    div { class: "mt-5 pt-5 border-t border-gray-100",
                        h4 { class: "text-sm font-semibold text-gray-700 mb-2", "Export / Import Rules" }
                        div { class: "flex gap-2 flex-wrap",
                            button {
                                class: "px-3 py-1.5 text-xs font-medium bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors",
                                onclick: move |_| {
                                    spawn(async move {
                                        match server_ufw_export_rules().await {
                                            Ok(rules) => ok_msg.set(Some(format!("Exported {} chars. Copy from console.", rules.len()))),
                                            Err(e) => error.set(Some(e.to_string())),
                                        }
                                    });
                                },
                                "Export"
                            }
                            button {
                                class: "px-3 py-1.5 text-xs font-medium bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors",
                                onclick: move |_| show_import.set(!show_import()),
                                "Import"
                            }
                        }
                        if show_import() {
                            div { class: "mt-3 space-y-2",
                                textarea {
                                    class: "w-full h-32 border border-gray-200 rounded-lg px-3 py-2 text-xs font-mono",
                                    placeholder: "Paste iptables-restore format rules here…",
                                    value: import_text(),
                                    oninput: move |e| import_text.set(e.value()),
                                }
                                button {
                                    class: "w-full py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50",
                                    onclick: do_import,
                                    disabled: busy() || import_text().is_empty(),
                                    "Apply Import"
                                }
                            }
                        }
                    }
                }
            }

            // Rules table
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden",
                div { class: "px-5 py-4 border-b border-gray-100 flex items-center justify-between",
                    h3 { class: "text-sm font-semibold text-gray-700", "Current Rules" }
                    button {
                        class: "text-xs text-gray-400 hover:text-gray-600",
                        onclick: move |_| rules_res.restart(),
                        "Refresh"
                    }
                }
                match &*rules_res.read() {
                    Some(Ok(rules)) if rules.is_empty() => rsx! {
                        p { class: "text-sm text-gray-400 px-5 py-8 text-center", "No rules configured." }
                    },
                    Some(Ok(rules)) => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead {
                                    tr { class: "text-xs text-gray-400 uppercase tracking-wide bg-gray-50",
                                        th { class: "px-4 py-3 text-left", "#" }
                                        th { class: "px-4 py-3 text-left", "Action" }
                                        th { class: "px-4 py-3 text-left", "From" }
                                        th { class: "px-4 py-3 text-left", "Port" }
                                        th { class: "px-4 py-3 text-left", "Proto" }
                                        th { class: "px-4 py-3 text-left", "Comment" }
                                        th { class: "px-4 py-3" }
                                    }
                                }
                                tbody {
                                    for rule in rules.iter() {
                                        {
                                            let num = rule.number;
                                            let action_class = match rule.action.to_lowercase().as_str() {
                                                "allow" => "text-green-600",
                                                "deny" | "reject" => "text-red-600",
                                                _ => "text-yellow-600",
                                            };
                                            rsx! {
                                                tr { class: "border-t border-gray-50 hover:bg-gray-50/50",
                                                    td { class: "px-4 py-3 text-gray-400", "{num}" }
                                                    td { class: "px-4 py-3 font-semibold {action_class}", "{rule.action}" }
                                                    td { class: "px-4 py-3 font-mono text-xs", "{rule.from}" }
                                                    td { class: "px-4 py-3 font-mono text-xs", "{rule.to}" }
                                                    td { class: "px-4 py-3 text-gray-500", "-" }
                                                    td { class: "px-4 py-3 text-gray-400 text-xs", "" }
                                                    td { class: "px-4 py-3",
                                                        button {
                                                            class: "text-red-400 hover:text-red-600 transition-colors",
                                                            title: "Delete rule",
                                                            onclick: {
                                                                move |_| {
                                                                    error.set(None); ok_msg.set(None);
                                                                    spawn(async move {
                                                                        match server_ufw_delete_rule(num).await {
                                                                            Ok(()) => { ok_msg.set(Some(format!("Rule #{num} deleted."))); refresh(); }
                                                                            Err(e) => error.set(Some(e.to_string())),
                                                                        }
                                                                    });
                                                                }
                                                            },
                                                            Icon { name: "trash-2", class: "w-4 h-4".to_string() }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => {
                        let msg = e.to_string();
                        if msg.contains("not installed") {
                            rsx! {
                                div { class: "flex items-center gap-2 text-sm text-amber-700 bg-amber-50 rounded-lg px-5 py-4",
                                    Icon { name: "alert-triangle", class: "w-4 h-4 shrink-0".to_string() }
                                    span { "UFW is not installed. No rules to display." }
                                }
                            }
                        } else {
                            rsx! { p { class: "text-sm text-red-500 px-5 py-4", "{msg}" } }
                        }
                    },
                    None => rsx! { p { class: "text-sm text-gray-400 px-5 py-4", "Loading..." } },
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin WAF (ModSecurity)
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
pub fn AdminWaf() -> Element {
    let mut status_res = use_resource(move || async move { server_modsec_get_status().await });
    let mut log_res =
        use_resource(move || async move { server_modsec_get_audit_entries(100).await });

    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut ok_msg = use_signal(|| None::<String>);
    let mut engine_mode = use_signal(|| "Off".to_string());

    use_effect(move || {
        if let Some(Ok(ref s)) = *status_res.read() {
            engine_mode.set(s.engine_mode.clone());
        }
    });

    rsx! {
        div { class: "p-6 lg:p-8 max-w-5xl space-y-6",
            div { class: "flex items-center justify-between",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "WAF / ModSecurity" }
                    p { class: "text-sm text-gray-500 mt-1", "Web application firewall protecting all hosted sites." }
                }
                button {
                    class: "px-3 py-2 text-sm font-medium rounded-lg bg-white border border-gray-200 hover:bg-gray-50",
                    onclick: move |_| { status_res.restart(); log_res.restart(); },
                    "Refresh"
                }
            }

            if let Some(msg) = ok_msg() {
                div { class: "bg-green-50 text-green-700 px-4 py-3 rounded-lg text-sm", "{msg}" }
            }
            if let Some(err) = error() {
                div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }

            // Status + install card
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                h3 { class: "text-sm font-semibold text-gray-700 mb-4", "ModSecurity Status" }
                match &*status_res.read() {
                    Some(Ok(s)) => rsx! {
                        div { class: "space-y-4",
                            div { class: "flex flex-wrap gap-4 text-sm",
                                div {
                                    span { class: "text-gray-400", "Installed: " }
                                    span { class: if s.installed { "text-green-600 font-semibold" } else { "text-red-500 font-semibold" },
                                        if s.installed { "Yes" } else { "No" }
                                    }
                                }
                                div {
                                    span { class: "text-gray-400", "Engine: " }
                                    span { class: "font-semibold", "{s.engine_mode}" }
                                }
                                div {
                                    span { class: "text-gray-400", "OWASP CRS: " }
                                    span { class: if s.owasp_installed { "text-green-600" } else { "text-gray-400" },
                                        if s.owasp_installed { "Installed" } else { "Not installed" }
                                    }
                                }
                                div {
                                    span { class: "text-gray-400", "Comodo WAF: " }
                                    span { class: if s.comodo_installed { "text-green-600" } else { "text-gray-400" },
                                        if s.comodo_installed { "Installed" } else { "Not installed" }
                                    }
                                }
                                div {
                                    span { class: "text-gray-400", "Active rules: " }
                                    span { class: "font-medium", "{s.rules_count}" }
                                }
                            }

                            // Engine mode selector
                            if s.installed {
                                div { class: "flex flex-wrap items-center gap-3",
                                    span { class: "text-sm text-gray-600 font-medium", "Engine mode:" }
                                    for mode in ["On", "DetectionOnly", "Off"] {
                                        {
                                            let is_sel = engine_mode() == mode;
                                            rsx! {
                                                button {
                                                    class: if is_sel {
                                                        "px-4 py-1.5 text-xs font-semibold rounded-full bg-rose-600 text-white"
                                                    } else {
                                                        "px-4 py-1.5 text-xs font-semibold rounded-full bg-gray-100 text-gray-600 hover:bg-gray-200"
                                                    },
                                                    onclick: {
                                                        let mode_str = mode.to_string();
                                                        move |_| {
                                                            let m = mode_str.clone();
                                                            engine_mode.set(m.clone());
                                                            error.set(None); ok_msg.set(None); busy.set(true);
                                                            spawn(async move {
                                                                match server_modsec_set_engine_mode(m.clone()).await {
                                                                    Ok(()) => { ok_msg.set(Some(format!("Engine mode set to {m}."))); status_res.restart(); log_res.restart(); }
                                                                    Err(e) => error.set(Some(e.to_string())),
                                                                }
                                                                busy.set(false);
                                                            });
                                                        }
                                                    },
                                                    "{mode}"
                                                }
                                            }
                                        }
                                    }
                                }

                                // Rule packs
                                div { class: "grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2",
                                    div { class: "border border-gray-100 rounded-xl p-4",
                                        div { class: "flex items-center justify-between mb-2",
                                            div {
                                                p { class: "text-sm font-semibold text-gray-800", "OWASP Core Rule Set" }
                                                p { class: "text-xs text-gray-400", "Industry-standard protection against OWASP Top 10" }
                                            }
                                        }
                                        div { class: "flex gap-2 mt-3",
                                            if !s.owasp_installed {
                                                button {
                                                    class: "px-3 py-1.5 text-xs font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:opacity-50",
                                                    disabled: busy(),
                                                    onclick: move |_| {
                                                        error.set(None); ok_msg.set(None); busy.set(true);
                                                        spawn(async move {
                                                            match server_modsec_install_owasp().await {
                                                                Ok(()) => { ok_msg.set(Some("OWASP CRS installed.".to_string())); status_res.restart(); log_res.restart(); }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                            busy.set(false);
                                                        });
                                                    },
                                                    "Install OWASP CRS"
                                                }
                                            } else {
                                                button {
                                                    class: "px-3 py-1.5 text-xs font-medium bg-green-100 text-green-700 rounded-lg hover:bg-red-100 hover:text-red-700 disabled:opacity-50",
                                                    disabled: busy(),
                                                    onclick: move |_| {
                                                        error.set(None); ok_msg.set(None); busy.set(true);
                                                        spawn(async move {
                                                            match server_modsec_set_ruleset_enabled(panel::models::security::ModSecRuleSet::Owasp, false).await {
                                                                Ok(()) => { ok_msg.set(Some("OWASP CRS disabled.".to_string())); status_res.restart(); log_res.restart(); }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                            busy.set(false);
                                                        });
                                                    },
                                                    "Disable OWASP CRS"
                                                }
                                            }
                                        }
                                    }
                                    div { class: "border border-gray-100 rounded-xl p-4",
                                        div { class: "flex items-center justify-between mb-2",
                                            div {
                                                p { class: "text-sm font-semibold text-gray-800", "Comodo WAF Rules" }
                                                p { class: "text-xs text-gray-400", "Additional XSS, SQLi, and traversal protections" }
                                            }
                                        }
                                        div { class: "flex gap-2 mt-3",
                                            if !s.comodo_installed {
                                                button {
                                                    class: "px-3 py-1.5 text-xs font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50",
                                                    disabled: busy(),
                                                    onclick: move |_| {
                                                        error.set(None); ok_msg.set(None); busy.set(true);
                                                        spawn(async move {
                                                            match server_modsec_install_comodo().await {
                                                                Ok(()) => { ok_msg.set(Some("Comodo WAF installed.".to_string())); status_res.restart(); log_res.restart(); }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                            busy.set(false);
                                                        });
                                                    },
                                                    "Install Comodo WAF"
                                                }
                                            } else {
                                                button {
                                                    class: "px-3 py-1.5 text-xs font-medium bg-green-100 text-green-700 rounded-lg hover:bg-red-100 hover:text-red-700 disabled:opacity-50",
                                                    disabled: busy(),
                                                    onclick: move |_| {
                                                        error.set(None); ok_msg.set(None); busy.set(true);
                                                        spawn(async move {
                                                            match server_modsec_set_ruleset_enabled(panel::models::security::ModSecRuleSet::Comodo, false).await {
                                                                Ok(()) => { ok_msg.set(Some("Comodo WAF disabled.".to_string())); status_res.restart(); log_res.restart(); }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                            busy.set(false);
                                                        });
                                                    },
                                                    "Disable Comodo WAF"
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                button {
                                    class: "px-4 py-2 text-sm font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:opacity-50",
                                    disabled: busy(),
                                    onclick: move |_| {
                                        error.set(None); ok_msg.set(None); busy.set(true);
                                        spawn(async move {
                                            match server_modsec_install().await {
                                                Ok(()) => { ok_msg.set(Some("ModSecurity installed.".to_string())); status_res.restart(); log_res.restart(); }
                                                Err(e) => error.set(Some(e.to_string())),
                                            }
                                            busy.set(false);
                                        });
                                    },
                                    "Install ModSecurity"
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "text-sm text-red-500", "{e}" } },
                    None => rsx! { p { class: "text-sm text-gray-400", "Loading..." } },
                }
            }

            // Audit log
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden",
                div { class: "px-5 py-4 border-b border-gray-100",
                    h3 { class: "text-sm font-semibold text-gray-700", "Audit Log (last 100 events)" }
                }
                match &*log_res.read() {
                    Some(Ok(entries)) if entries.is_empty() => rsx! {
                        p { class: "text-sm text-gray-400 px-5 py-8 text-center", "No audit log entries found." }
                    },
                    Some(Ok(entries)) => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead {
                                    tr { class: "text-xs text-gray-400 uppercase tracking-wide bg-gray-50",
                                        th { class: "px-4 py-3 text-left", "Time" }
                                        th { class: "px-4 py-3 text-left", "Client IP" }
                                        th { class: "px-4 py-3 text-left", "Method" }
                                        th { class: "px-4 py-3 text-left", "URI" }
                                        th { class: "px-4 py-3 text-left", "Status" }
                                        th { class: "px-4 py-3 text-left", "Severity" }
                                        th { class: "px-4 py-3 text-left", "Rules" }
                                    }
                                }
                                tbody {
                                    for entry in entries.iter() {
                                        tr { class: "border-t border-gray-50 hover:bg-gray-50/50",
                                            td { class: "px-4 py-3 text-xs text-gray-400 whitespace-nowrap", "{entry.timestamp}" }
                                            td { class: "px-4 py-3 font-mono text-xs", "{entry.client_ip}" }
                                            td { class: "px-4 py-3 text-xs font-medium", "{entry.method}" }
                                            td { class: "px-4 py-3 text-xs max-w-xs truncate", "{entry.uri}" }
                                            td { class: "px-4 py-3 text-xs", "{entry.status}" }
                                            td { class: "px-4 py-3 text-xs font-semibold text-red-600", "{entry.severity}" }
                                            td { class: "px-4 py-3 text-xs text-gray-500", "{entry.matched_rules.join(\", \")}" }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "text-sm text-red-500 px-5 py-4", "{e}" } },
                    None => rsx! { p { class: "text-sm text-gray-400 px-5 py-4", "Loading..." } },
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin ClamAV
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
pub fn AdminClamAv() -> Element {
    let db_res = use_resource(move || async move { server_clamav_get_db_info().await });

    let mut scan_path = use_signal(|| "/var/www".to_string());
    let mut scanning = use_signal(|| false);
    let mut scan_result_signal =
        use_signal(|| None::<Result<panel::models::security::ClamScanReport, String>>);
    let mut updating = use_signal(|| false);
    let mut update_output = use_signal(|| None::<String>);
    let mut error = use_signal(|| None::<String>);

    let do_update_db = move |_| {
        error.set(None);
        update_output.set(None);
        updating.set(true);
        spawn(async move {
            match server_clamav_update_db().await {
                Ok(()) => {
                    update_output.set(Some("ClamAV database updated successfully.".to_string()))
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            updating.set(false);
        });
    };

    let do_scan = move |_| {
        let path = scan_path();
        error.set(None);
        scan_result_signal.set(None);
        scanning.set(true);
        spawn(async move {
            match server_clamav_scan(path).await {
                Ok(r) => scan_result_signal.set(Some(Ok(r))),
                Err(e) => scan_result_signal.set(Some(Err(e.to_string()))),
            }
            scanning.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-4xl space-y-6",
            div {
                h2 { class: "text-2xl font-bold text-gray-900", "ClamAV Antivirus" }
                p { class: "text-sm text-gray-500 mt-1", "Scan files for malware and manage the virus database." }
            }

            if let Some(err) = error() {
                div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }

            // DB info card
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                h3 { class: "text-sm font-semibold text-gray-700 mb-4", "Virus Database" }
                match &*db_res.read() {
                    Some(Ok(info)) => rsx! {
                        div { class: "flex flex-wrap gap-6 text-sm mb-4",
                            div {
                                span { class: "text-gray-400", "Version: " }
                                span { class: "font-medium", "{info.version}" }
                            }
                            div {
                                span { class: "text-gray-400", "Signatures: " }
                                span { class: "font-medium", "{info.signatures}" }
                            }
                            div {
                                span { class: "text-gray-400", "Database date: " }
                                span { class: "font-medium", "{info.database_date}" }
                            }
                        }
                    },
                    Some(Err(e)) => {
                        let msg = e.to_string();
                        if msg.contains("not installed") {
                            rsx! {
                                div { class: "flex items-center gap-2 text-sm text-amber-700 bg-amber-50 rounded-lg p-3 mb-4",
                                    Icon { name: "alert-triangle", class: "w-4 h-4 shrink-0".to_string() }
                                    span { "ClamAV is not installed. Install it with: "
                                        code { class: "font-mono bg-amber-100 px-1 rounded", "apt install clamav clamav-daemon" }
                                    }
                                }
                            }
                        } else {
                            rsx! { p { class: "text-sm text-red-500 mb-4", "{msg}" } }
                        }
                    },
                    None => rsx! { p { class: "text-sm text-gray-400 mb-4", "Loading..." } },
                }
                button {
                    class: "px-4 py-2 text-sm font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:opacity-50 flex items-center gap-2",
                    onclick: do_update_db,
                    disabled: updating(),
                    if updating() {
                        Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                        "Updating…"
                    } else {
                        Icon { name: "refresh-cw", class: "w-4 h-4".to_string() }
                        "Update Database (freshclam)"
                    }
                }
                if let Some(out) = update_output() {
                    pre { class: "mt-4 bg-gray-900 text-green-400 text-xs p-4 rounded-xl overflow-x-auto max-h-48", "{out}" }
                }
            }

            // Scan card
            div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-5",
                h3 { class: "text-sm font-semibold text-gray-700 mb-4", "Scan Files" }
                p { class: "text-xs text-gray-400 mb-3", "Only paths under /var/www, /home, /tmp, /srv, and /opt are allowed." }
                div { class: "flex gap-2",
                    input {
                        class: "flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono",
                        value: scan_path(),
                        oninput: move |e| scan_path.set(e.value()),
                    }
                    button {
                        class: "px-4 py-2 text-sm font-medium bg-gray-900 text-white rounded-lg hover:bg-gray-800 disabled:opacity-50 flex items-center gap-2 whitespace-nowrap",
                        onclick: do_scan,
                        disabled: scanning(),
                        if scanning() {
                            Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                            "Scanning…"
                        } else {
                            Icon { name: "search", class: "w-4 h-4".to_string() }
                            "Start Scan"
                        }
                    }
                }

                match scan_result_signal() {
                    Some(Ok(ref report)) => rsx! {
                        div { class: "mt-5 space-y-3",
                            div { class: "flex gap-6 text-sm",
                                div {
                                    span { class: "text-gray-400", "Files scanned: " }
                                    span { class: "font-semibold", "{report.scanned_files}" }
                                }
                                div {
                                    span { class: "text-gray-400", "Infected: " }
                                    span {
                                        class: if report.infected_files > 0 { "font-semibold text-red-600" } else { "font-semibold text-green-600" },
                                        "{report.infected_files}"
                                    }
                                }
                            }
                            if report.threats.is_empty() {
                                div { class: "bg-green-50 text-green-700 px-4 py-3 rounded-lg text-sm font-medium",
                                    "✓ No threats found."
                                }
                            } else {
                                div { class: "border border-red-100 rounded-xl overflow-hidden",
                                    div { class: "bg-red-50 px-4 py-2 text-sm font-semibold text-red-700", "Threats detected" }
                                    table { class: "w-full text-sm",
                                        thead {
                                            tr { class: "text-xs text-gray-400 uppercase bg-gray-50",
                                                th { class: "px-4 py-2 text-left", "Path" }
                                                th { class: "px-4 py-2 text-left", "Virus" }
                                            }
                                        }
                                        tbody {
                                            for threat in report.threats.iter() {
                                                tr { class: "border-t border-gray-100",
                                                    td { class: "px-4 py-2 font-mono text-xs text-red-700", "{threat.path}" }
                                                    td { class: "px-4 py-2 text-xs font-medium text-red-600", "{threat.virus_name}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(ref e)) => rsx! {
                        div { class: "mt-4 bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{e}" }
                    },
                    None => rsx! { div {} },
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin SSH Hardening
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
pub fn AdminSshHardening() -> Element {
    let config_res = use_resource(move || async move { server_ssh_get_config().await });
    let active_res = use_resource(move || async move { server_ssh_is_hardening_active().await });

    let mut port = use_signal(|| "22".to_string());
    let mut permit_root = use_signal(|| "prohibit-password".to_string());
    let mut password_auth = use_signal(|| false);
    let mut pubkey_auth = use_signal(|| true);
    let mut max_auth_tries = use_signal(|| "3".to_string());
    let mut login_grace_time = use_signal(|| "60".to_string());
    let mut agent_fwd = use_signal(|| false);
    let mut x11_fwd = use_signal(|| false);
    let mut use_pam = use_signal(|| true);
    let mut ignore_rhosts = use_signal(|| true);
    let mut permit_empty = use_signal(|| false);
    let mut use_dns = use_signal(|| false);
    let mut banner = use_signal(|| true);
    let mut allowed_users = use_signal(String::new);
    let mut client_alive_interval = use_signal(|| "300".to_string());
    let mut client_alive_count_max = use_signal(|| "2".to_string());
    let mut max_sessions = use_signal(|| "4".to_string());

    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut ok_msg = use_signal(|| None::<String>);
    let mut warnings = use_signal(Vec::<String>::new);

    // Populate form on load
    use_effect(move || {
        if let Some(Ok(ref c)) = *config_res.read() {
            port.set(c.port.to_string());
            permit_root.set(c.permit_root_login.clone());
            password_auth.set(c.password_authentication);
            pubkey_auth.set(c.pubkey_authentication);
            max_auth_tries.set(c.max_auth_tries.to_string());
            login_grace_time.set(c.login_grace_time.to_string());
            agent_fwd.set(c.allow_agent_forwarding);
            x11_fwd.set(c.x11_forwarding);
            use_pam.set(c.use_pam);
            ignore_rhosts.set(c.ignore_rhosts);
            permit_empty.set(c.permit_empty_passwords);
            use_dns.set(c.use_dns);
            banner.set(c.banner_enabled);
            allowed_users.set(c.allowed_users.join(" "));
            client_alive_interval.set(c.client_alive_interval.to_string());
            client_alive_count_max.set(c.client_alive_count_max.to_string());
            max_sessions.set(c.max_sessions.to_string());
        }
    });

    let apply = move |_| {
        let p: u16 = port().parse().unwrap_or(22);
        let mat: u8 = max_auth_tries().parse().unwrap_or(3);
        let lgt: u16 = login_grace_time().parse().unwrap_or(60);
        let cai: u16 = client_alive_interval().parse().unwrap_or(300);
        let cac: u8 = client_alive_count_max().parse().unwrap_or(2);
        let ms: u8 = max_sessions().parse().unwrap_or(4);
        error.set(None);
        ok_msg.set(None);
        warnings.set(vec![]);
        busy.set(true);
        spawn(async move {
            match server_ssh_apply_config(panel::models::security::SshConfig {
                port: p,
                permit_root_login: permit_root(),
                password_authentication: password_auth(),
                pubkey_authentication: pubkey_auth(),
                max_auth_tries: mat,
                login_grace_time: lgt,
                allow_agent_forwarding: agent_fwd(),
                x11_forwarding: x11_fwd(),
                use_pam: use_pam(),
                ignore_rhosts: ignore_rhosts(),
                permit_empty_passwords: permit_empty(),
                use_dns: use_dns(),
                banner_enabled: banner(),
                allowed_users: allowed_users()
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect(),
                client_alive_interval: cai,
                client_alive_count_max: cac,
                max_sessions: ms,
                ..Default::default()
            })
            .await
            {
                Ok(result) => {
                    ok_msg.set(Some(result.message));
                    if !result.warnings.is_empty() {
                        warnings.set(result.warnings);
                    }
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    let restore = move |_| {
        error.set(None);
        ok_msg.set(None);
        busy.set(true);
        spawn(async move {
            match server_ssh_restore_backup().await {
                Ok(()) => ok_msg.set(Some("SSH configuration restored from backup.".to_string())),
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-3xl space-y-6",
            div { class: "flex items-center justify-between",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "SSH Hardening" }
                    p { class: "text-sm text-gray-500 mt-1", "Configure OpenSSH security settings. Applied via drop-in configuration." }
                }
                div { class: "flex items-center gap-3",
                    match &*active_res.read() {
                        Some(Ok(true)) => rsx! {
                            span { class: "text-xs font-semibold px-3 py-1 rounded-full bg-green-100 text-green-700", "Hardening Active" }
                        },
                        Some(Ok(false)) => rsx! {
                            span { class: "text-xs font-semibold px-3 py-1 rounded-full bg-gray-100 text-gray-500", "Default Config" }
                        },
                        _ => rsx! { span {} },
                    }
                }
            }

            if let Some(msg) = ok_msg() {
                div { class: "bg-green-50 text-green-700 px-4 py-3 rounded-lg text-sm font-medium", "{msg}" }
            }
            if let Some(err) = error() {
                div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }
            for warn in warnings().iter() {
                div { class: "bg-yellow-50 text-yellow-800 border border-yellow-200 px-4 py-3 rounded-lg text-sm", "{warn}" }
            }

            match &*config_res.read() {
                Some(Ok(_)) | None => rsx! {
                    div { class: "bg-white rounded-2xl border border-gray-100 shadow-sm p-6 space-y-6",

                        // Port & Root login
                        div { class: "grid grid-cols-2 gap-4",
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "SSH Port" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "1", max: "65535",
                                    value: port(),
                                    oninput: move |e| port.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Permit Root Login" }
                                select {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    value: permit_root(),
                                    oninput: move |e| permit_root.set(e.value()),
                                    option { value: "no", "No (recommended)" }
                                    option { value: "prohibit-password", "Key-only (no password)" }
                                    option { value: "forced-commands-only", "Forced commands only" }
                                    option { value: "yes", "Yes (dangerous)" }
                                }
                            }
                        }

                        // Auth methods
                        div {
                            label { class: "block text-xs font-semibold text-gray-600 mb-2", "Authentication Methods" }
                            div { class: "space-y-2",
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: pubkey_auth(), oninput: move |e| pubkey_auth.set(e.checked()) }
                                    span { class: "text-sm", "Public key authentication (recommended)" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: password_auth(), oninput: move |e| password_auth.set(e.checked()) }
                                    span { class: "text-sm", "Password authentication" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: permit_empty(), oninput: move |e| permit_empty.set(e.checked()) }
                                    span { class: "text-sm text-red-600", "Permit empty passwords (very dangerous)" }
                                }
                            }
                        }

                        // Limits
                        div { class: "grid grid-cols-3 gap-4",
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Max Auth Tries" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "1", max: "20",
                                    value: max_auth_tries(),
                                    oninput: move |e| max_auth_tries.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Login Grace (sec)" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "10", max: "600",
                                    value: login_grace_time(),
                                    oninput: move |e| login_grace_time.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Max Sessions" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "1", max: "50",
                                    value: max_sessions(),
                                    oninput: move |e| max_sessions.set(e.value()),
                                }
                            }
                        }

                        // Keep-alive
                        div { class: "grid grid-cols-2 gap-4",
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Client Alive Interval (sec)" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "0",
                                    value: client_alive_interval(),
                                    oninput: move |e| client_alive_interval.set(e.value()),
                                }
                            }
                            div {
                                label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "Client Alive Count Max" }
                                input {
                                    class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                    r#type: "number", min: "0", max: "10",
                                    value: client_alive_count_max(),
                                    oninput: move |e| client_alive_count_max.set(e.value()),
                                }
                            }
                        }

                        // Feature toggles
                        div {
                            label { class: "block text-xs font-semibold text-gray-600 mb-2", "Feature Flags" }
                            div { class: "grid grid-cols-2 gap-2",
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: use_pam(), oninput: move |e| use_pam.set(e.checked()) }
                                    span { class: "text-sm", "Use PAM" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: ignore_rhosts(), oninput: move |e| ignore_rhosts.set(e.checked()) }
                                    span { class: "text-sm", "Ignore .rhosts" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: use_dns(), oninput: move |e| use_dns.set(e.checked()) }
                                    span { class: "text-sm", "UseDNS (reverse lookup)" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: banner(), oninput: move |e| banner.set(e.checked()) }
                                    span { class: "text-sm", "Login banner (/etc/issue.net)" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: agent_fwd(), oninput: move |e| agent_fwd.set(e.checked()) }
                                    span { class: "text-sm", "Agent forwarding" }
                                }
                                label { class: "flex items-center gap-2 cursor-pointer",
                                    input { r#type: "checkbox", class: "accent-rose-600", checked: x11_fwd(), oninput: move |e| x11_fwd.set(e.checked()) }
                                    span { class: "text-sm", "X11 forwarding" }
                                }
                            }
                        }

                        // AllowUsers
                        div {
                            label { class: "block text-xs font-semibold text-gray-600 mb-1.5", "AllowUsers (space-separated, leave blank for all)" }
                            input {
                                class: "w-full border border-gray-200 rounded-lg px-3 py-2 text-sm",
                                placeholder: "e.g. deploy ubuntu admin",
                                value: allowed_users(),
                                oninput: move |e| allowed_users.set(e.value()),
                            }
                        }

                        // Actions
                        div { class: "flex items-center gap-3 pt-2",
                            button {
                                class: "px-5 py-2.5 text-sm font-semibold bg-rose-600 text-white rounded-xl hover:bg-rose-700 transition-colors disabled:opacity-50",
                                onclick: apply,
                                disabled: busy(),
                                if busy() { "Applying…" } else { "Apply Configuration" }
                            }
                            button {
                                class: "px-4 py-2.5 text-sm font-medium bg-white border border-gray-200 text-gray-600 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50",
                                onclick: restore,
                                disabled: busy(),
                                "Restore Backup"
                            }
                        }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm", "{e}" }
                },
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Backups
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
pub fn AdminBackups() -> Element {
    let mut stats_res = use_resource(move || async move { server_admin_get_backup_stats().await });
    let mut runs_res = use_resource(move || async move { server_admin_list_backup_runs().await });
    let mut active_tab = use_signal(|| "stats"); // "stats" | "runs"

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Backup Overview" }
                    p { class: "text-gray-500 text-sm mt-1", "Global backup stats and run history across all clients." }
                }
                button {
                    class: "p-2 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors",
                    title: "Refresh",
                    onclick: move |_| { stats_res.restart(); runs_res.restart(); },
                    Icon { name: "refresh-cw", class: "w-5 h-5".to_string() }
                }
            }

            // ── Stats cards
            match &*stats_res.read() {
                Some(Ok(st)) => rsx! {
                    div { class: "grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6",
                        BackupStatCard { label: "Schedules", value: st.total_schedules.to_string(), color: "blue" }
                        BackupStatCard { label: "Active", value: st.enabled_schedules.to_string(), color: "green" }
                        BackupStatCard { label: "Total Runs", value: st.total_runs.to_string(), color: "gray" }
                        BackupStatCard { label: "Successful", value: st.successful_runs.to_string(), color: "green" }
                        BackupStatCard { label: "Failed", value: st.failed_runs.to_string(), color: "red" }
                        BackupStatCard { label: "Total Size", value: fmt_bytes_backup(st.total_size_bytes), color: "purple" }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "mb-6 bg-red-50 rounded-2xl border border-red-200 p-4 text-red-700 text-sm", "Failed to load stats: {e}" }
                },
                None => rsx! { div { class: "mb-6 h-20 bg-gray-50 rounded-2xl animate-pulse" } },
            }

            // ── Tab bar
            div { class: "flex gap-1 bg-gray-100 rounded-xl p-1 w-fit mb-6",
                for (label, id) in [("Stats", "stats"), ("Recent Runs", "runs")] {
                    button {
                        class: if active_tab() == id {
                            "px-4 py-2 rounded-lg text-sm font-medium bg-white text-gray-900 shadow-sm"
                        } else {
                            "px-4 py-2 rounded-lg text-sm font-medium text-gray-500 hover:text-gray-700"
                        },
                        onclick: move |_| active_tab.set(id),
                        "{label}"
                    }
                }
            }

            if active_tab() == "runs" {
                match &*runs_res.read() {
                    Some(Ok(runs)) if runs.is_empty() => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center text-gray-400 text-sm",
                            "No backup runs recorded yet."
                        }
                    },
                    Some(Ok(runs)) => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Schedule ID" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Owner" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Started" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Duration" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Status" }
                                        th { class: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase", "Size" }
                                    }
                                }
                                tbody {
                                    for run in runs.iter() {
                                        AdminBackupRunRow { run: run.clone() }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "bg-red-50 rounded-2xl border border-red-200 p-4 text-red-700 text-sm", "Error: {e}" }
                    },
                    None => rsx! {
                        div { class: "bg-white rounded-2xl border border-gray-100 p-8 text-center text-gray-400 animate-pulse text-sm", "Loading…" }
                    },
                }
            }

            if active_tab() == "stats" {
                div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center text-gray-400 text-sm",
                    "Select the \"Recent Runs\" tab to see all backup executions, or view per-client details from the Clients page."
                }
            }
        }
    }
}

#[component]
pub fn AdminBackupRunRow(run: panel::models::backup::BackupRun) -> Element {
    let (status_cls, status_label) = match run.status.as_str() {
        "success" => ("bg-green-100 text-green-700", "Success"),
        "failed" => ("bg-red-100 text-red-700", "Failed"),
        _ => ("bg-yellow-100 text-yellow-700", "Running"),
    };
    let duration = match run.finished_at {
        Some(fin) => {
            let secs = (fin - run.started_at).num_seconds();
            if secs < 60 {
                format!("{}s", secs)
            } else {
                format!("{}m {}s", secs / 60, secs % 60)
            }
        }
        None => "—".to_string(),
    };
    let size_str = run
        .size_bytes
        .map(fmt_bytes_backup)
        .unwrap_or_else(|| "—".to_string());
    let started_at_str = run.started_at.format("%b %d %H:%M:%S").to_string();

    rsx! {
        tr { class: "border-b border-gray-100 hover:bg-gray-50/40 transition-colors",
            td { class: "px-4 py-3 text-xs font-mono text-gray-500", "#{run.schedule_id}" }
            td { class: "px-4 py-3 text-xs font-mono text-gray-500", "#{run.owner_id}" }
            td { class: "px-4 py-3 text-xs font-mono text-gray-700", "{started_at_str}" }
            td { class: "px-4 py-3 text-xs text-gray-500", "{duration}" }
            td { class: "px-4 py-3",
                span { class: "px-2 py-0.5 rounded-full text-xs font-semibold {status_cls}", "{status_label}" }
                if let Some(ref err) = run.error_message {
                    p { class: "text-xs text-red-500 mt-0.5 max-w-xs truncate", title: "{err}", "{err}" }
                }
            }
            td { class: "px-4 py-3 text-xs font-mono text-gray-500", "{size_str}" }
        }
    }
}
