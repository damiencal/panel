#![allow(non_snake_case)]
use dioxus::prelude::*;
use panel::server::*;
use crate::lucide::Icon;

#[component]
pub fn AdminAntiSpam() -> Element {
    let settings_res = use_resource(move || async move { server_get_spam_filter_settings().await });
    let status_res =
        use_resource(move || async move { server_get_antispam_service_status().await });

    let mut engine = use_signal(|| "none".to_string());
    let mut spam_threshold = use_signal(|| "5.0".to_string());
    let mut add_header = use_signal(|| true);
    let mut quarantine = use_signal(|| false);
    let mut quarantine_mailbox = use_signal(String::new);
    let mut reject_score = use_signal(|| "15.0".to_string());
    let mut clamav = use_signal(|| false);
    let mut mailscanner = use_signal(|| false);
    let mut saving = use_signal(|| false);
    let mut save_error = use_signal(|| None::<String>);
    let mut save_ok = use_signal(|| false);

    // Populate form when settings load
    use_effect(move || {
        if let Some(Ok(ref s)) = *settings_res.read() {
            engine.set(s.engine.clone());
            spam_threshold.set(format!("{:.1}", s.spam_threshold));
            add_header.set(s.add_header_enabled);
            quarantine.set(s.quarantine_enabled);
            quarantine_mailbox.set(s.quarantine_mailbox.clone().unwrap_or_default());
            reject_score.set(format!("{:.1}", s.reject_score));
            clamav.set(s.clamav_enabled);
            mailscanner.set(s.mailscanner_enabled);
        }
    });

    let save = {
        let mut settings_res = settings_res;
        move |_| {
            let eng = engine();
            let thresh: f64 = spam_threshold().parse().unwrap_or(5.0);
            let reject: f64 = reject_score().parse().unwrap_or(15.0);
            let qmb = quarantine_mailbox();
            let qmb_opt = if quarantine() && !qmb.is_empty() {
                Some(qmb)
            } else {
                None
            };
            save_error.set(None);
            save_ok.set(false);
            saving.set(true);
            spawn(async move {
                match server_save_spam_filter_settings(
                    eng,
                    thresh,
                    add_header(),
                    quarantine(),
                    qmb_opt,
                    reject,
                    clamav(),
                    mailscanner(),
                )
                .await
                {
                    Ok(()) => {
                        save_ok.set(true);
                        settings_res.restart();
                    }
                    Err(e) => save_error.set(Some(e.to_string())),
                }
                saving.set(false);
            });
        }
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-4xl",
            div { class: "mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Anti-Spam & Email Security" }
                p { class: "text-sm text-gray-500 mt-1",
                    "Configure SpamAssassin, Rspamd, ClamAV virus scanning, and MailScanner. "
                    "Changes are applied immediately to Postfix."
                }
            }

            // Service status badges
            div { class: "mb-6",
                h3 { class: "text-sm font-semibold text-gray-700 mb-3 uppercase tracking-wide", "Component Status" }
                div { class: "grid grid-cols-2 md:grid-cols-4 gap-3",
                    match &*status_res.read() {
                        Some(Ok(list)) => rsx! {
                            for (name, installed, running) in list.iter() {
                                {
                                    let badge_class = if *running {
                                        "bg-green-50 border-green-200 text-green-700"
                                    } else if *installed {
                                        "bg-yellow-50 border-yellow-200 text-yellow-700"
                                    } else {
                                        "bg-gray-50 border-gray-200 text-gray-500"
                                    };
                                    let status_text = if *running { "Running" } else if *installed { "Stopped" } else { "Not installed" };
                                    rsx! {
                                        div { class: "border rounded-xl p-3 {badge_class}",
                                            p { class: "font-semibold text-sm", "{name}" }
                                            p { class: "text-xs mt-0.5", "{status_text}" }
                                        }
                                    }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! { p { class: "text-sm text-red-500", "{e}" } },
                        None => rsx! { p { class: "text-sm text-gray-400", "Loading..." } },
                    }
                }
            }

            if save_ok() {
                div { class: "bg-green-50 text-green-700 p-3 rounded-lg mb-4 text-sm",
                    "Settings saved and applied to Postfix."
                }
            }
            if let Some(err) = save_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6 space-y-6",

                // Engine selection
                div {
                    h3 { class: "text-sm font-semibold text-gray-700 mb-3", "Spam Filter Engine" }
                    div { class: "grid grid-cols-3 gap-3",
                        for (val, label, desc) in [
                            ("none", "Disabled", "No spam filtering"),
                            ("spamassassin", "SpamAssassin", "Rule-based scoring"),
                            ("rspamd", "Rspamd", "ML-based + Redis cache"),
                        ] {
                            {
                                let is_sel = engine() == val;
                                let card_class = if is_sel {
                                    "border-2 border-rose-500 bg-rose-50"
                                } else {
                                    "border border-gray-200 hover:border-gray-300 bg-white"
                                };
                                rsx! {
                                    button {
                                        class: "rounded-xl p-3 text-left transition-colors {card_class}",
                                        onclick: {
                                            let val = val.to_string();
                                            move |_| engine.set(val.clone())
                                        },
                                        p { class: "font-semibold text-sm text-gray-900", "{label}" }
                                        p { class: "text-xs text-gray-500 mt-0.5", "{desc}" }
                                    }
                                }
                            }
                        }
                    }
                }

                // Threshold settings
                div { class: "grid grid-cols-1 md:grid-cols-2 gap-4",
                    div {
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Spam Score Threshold" }
                        input {
                            r#type: "number",
                            step: "0.5",
                            min: "1",
                            max: "20",
                            class: "w-full border border-gray-300 rounded-lg px-3 py-2 text-sm",
                            value: "{spam_threshold}",
                            oninput: move |e| spam_threshold.set(e.value()),
                        }
                        p { class: "text-xs text-gray-400 mt-1", "Messages scoring above this are tagged as spam (default: 5.0)" }
                    }
                    div {
                        label { class: "block text-sm font-medium text-gray-700 mb-1", "Reject Score (0 = disabled)" }
                        input {
                            r#type: "number",
                            step: "0.5",
                            min: "0",
                            max: "100",
                            class: "w-full border border-gray-300 rounded-lg px-3 py-2 text-sm",
                            value: "{reject_score}",
                            oninput: move |e| reject_score.set(e.value()),
                        }
                        p { class: "text-xs text-gray-400 mt-1", "Messages scoring above this are rejected outright (0 = tag only)" }
                    }
                }

                // Toggle options
                div { class: "space-y-3",
                    h3 { class: "text-sm font-semibold text-gray-700", "Options" }
                    label { class: "flex items-center gap-3 cursor-pointer",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 accent-rose-500",
                            checked: "{add_header}",
                            onchange: move |e| add_header.set(e.checked()),
                        }
                        span { class: "text-sm text-gray-700", "Add X-Spam-Status / X-Spam-Score headers" }
                    }
                    label { class: "flex items-center gap-3 cursor-pointer",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 accent-rose-500",
                            checked: "{quarantine}",
                            onchange: move |e| quarantine.set(e.checked()),
                        }
                        span { class: "text-sm text-gray-700", "Quarantine spam instead of delivering" }
                    }
                    if quarantine() {
                        div { class: "ml-7",
                            input {
                                r#type: "email",
                                placeholder: "quarantine@yourdomain.com",
                                class: "border border-gray-300 rounded-lg px-3 py-2 text-sm w-72",
                                value: "{quarantine_mailbox}",
                                oninput: move |e| quarantine_mailbox.set(e.value()),
                            }
                        }
                    }
                    label { class: "flex items-center gap-3 cursor-pointer",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 accent-rose-500",
                            checked: "{clamav}",
                            onchange: move |e| clamav.set(e.checked()),
                        }
                        span { class: "text-sm text-gray-700", "Enable ClamAV virus scanning (requires Rspamd)" }
                    }
                    label { class: "flex items-center gap-3 cursor-pointer",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 accent-rose-500",
                            checked: "{mailscanner}",
                            onchange: move |e| mailscanner.set(e.checked()),
                        }
                        span { class: "text-sm text-gray-700", "Enable MailScanner (alternative in-transit scanner)" }
                    }
                }

                div { class: "pt-2",
                    button {
                        class: "px-5 py-2.5 bg-rose-500 hover:bg-rose-600 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50",
                        disabled: saving(),
                        onclick: save,
                        if saving() { "Applying..." } else { "Save & Apply" }
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Mail Queue Manager
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
pub fn AdminMailQueue() -> Element {
    let mut queue = use_resource(move || async move { server_list_mail_queue().await });
    let mut action_error = use_signal(|| None::<String>);
    let mut action_ok = use_signal(|| None::<String>);

    let flush = {
        let mut queue = queue;
        move |_| {
            action_error.set(None);
            action_ok.set(None);
            spawn(async move {
                match server_flush_mail_queue().await {
                    Ok(()) => {
                        action_ok.set(Some(
                            "Queue flushed — deferred messages will be retried.".to_string(),
                        ));
                        queue.restart();
                    }
                    Err(e) => action_error.set(Some(e.to_string())),
                }
            });
        }
    };

    let delete_all = {
        let mut queue = queue;
        move |_| {
            action_error.set(None);
            action_ok.set(None);
            spawn(async move {
                match server_delete_all_deferred().await {
                    Ok(()) => {
                        action_ok.set(Some("All deferred messages deleted.".to_string()));
                        queue.restart();
                    }
                    Err(e) => action_error.set(Some(e.to_string())),
                }
            });
        }
    };

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Mail Queue Manager" }
                    p { class: "text-sm text-gray-500 mt-1",
                        "View, flush, hold, and delete messages from the Postfix mail queue."
                    }
                }
                div { class: "flex gap-2",
                    button {
                        class: "px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-xl transition-colors",
                        onclick: flush,
                        "Flush Deferred"
                    }
                    button {
                        class: "px-4 py-2 bg-red-500 hover:bg-red-600 text-white text-sm font-medium rounded-xl transition-colors",
                        onclick: delete_all,
                        "Delete All Deferred"
                    }
                    button {
                        class: "px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm font-medium rounded-xl transition-colors",
                        onclick: move |_| queue.restart(),
                        "Refresh"
                    }
                }
            }

            if let Some(ok) = action_ok() {
                div { class: "bg-green-50 text-green-700 p-3 rounded-lg mb-4 text-sm", "{ok}" }
            }
            if let Some(err) = action_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
            }

            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                match &*queue.read() {
                    Some(Ok(entries)) if !entries.is_empty() => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200/60",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Queue ID" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Type" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Size" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Arrived" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Sender" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Recipient" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Reason" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Actions" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-100",
                                    for entry in entries.iter() {
                                        {
                                            let qid = entry.queue_id.clone();
                                            let queue_type_class = match entry.queue_type.as_str() {
                                                "active" => "bg-green-100 text-green-700",
                                                "hold" => "bg-yellow-100 text-yellow-700",
                                                _ => "bg-gray-100 text-gray-600",
                                            };
                                            let queue2 = queue;
                                            rsx! {
                                                tr { class: "hover:bg-gray-50/50",
                                                    td { class: "px-4 py-3 font-mono text-xs text-gray-700", "{entry.queue_id}" }
                                                    td { class: "px-4 py-3",
                                                        span { class: "px-2 py-0.5 rounded-full text-xs font-medium {queue_type_class}",
                                                            "{entry.queue_type}"
                                                        }
                                                    }
                                                    td { class: "px-4 py-3 text-gray-500", "{entry.size}B" }
                                                    td { class: "px-4 py-3 text-gray-500 text-xs", "{entry.arrival_time}" }
                                                    td { class: "px-4 py-3 text-gray-700 text-xs max-w-32 truncate", "{entry.sender}" }
                                                    td { class: "px-4 py-3 text-gray-700 text-xs max-w-32 truncate", "{entry.recipient}" }
                                                    td { class: "px-4 py-3 text-gray-400 text-xs max-w-40 truncate", "{entry.reason}" }
                                                    td { class: "px-4 py-3",
                                                        div { class: "flex gap-1",
                                                            button {
                                                                class: "px-2 py-1 bg-red-100 hover:bg-red-200 text-red-700 text-xs rounded transition-colors",
                                                                title: "Delete message",
                                                                onclick: move |_| {
                                                                    let id = qid.clone();
                                                                    let mut queue2 = queue2;
                                                                    spawn(async move {
                                                                        server_delete_queued_message(id).await.ok();
                                                                        queue2.restart();
                                                                    });
                                                                },
                                                                "Delete"
                                                            }
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
                    Some(Ok(_)) => rsx! {
                        div { class: "py-16 text-center",
                            Icon { name: "inbox", class: "w-10 h-10 text-gray-300 mx-auto mb-3".to_string() }
                            p { class: "text-gray-400", "Mail queue is empty." }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "p-6 text-red-500 text-sm", "{e}" }
                    },
                    None => rsx! {
                        div { class: "p-6 text-gray-400 text-sm", "Loading queue..." }
                    },
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Email Statistics & Logs Viewer
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
pub fn AdminEmailStats() -> Element {
    let mut days = use_signal(|| 7i64);
    let mut stats = use_resource(move || async move { server_get_email_stats(days()).await });
    let logs = use_resource(move || async move { server_get_mail_logs(100, None).await });
    let mut search = use_signal(String::new);
    let mut search_res: Resource<Result<Vec<panel::models::email::EmailLogEntry>, ServerFnError>> =
        use_resource(move || async move {
            let s = search();
            if s.is_empty() {
                return Ok(vec![]);
            }
            server_get_mail_logs(100, Some(s)).await
        });
    let mut ingest_msg = use_signal(|| None::<String>);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6",
                div {
                    h2 { class: "text-2xl font-bold text-gray-900", "Email Statistics & Logs" }
                    p { class: "text-sm text-gray-500 mt-1",
                        "Aggregated delivery statistics and recent mail log entries."
                    }
                }
                div { class: "flex gap-2 items-center",
                    label { class: "text-sm text-gray-600", "Last" }
                    select {
                        class: "border border-gray-300 rounded-lg px-3 py-2 text-sm",
                        value: "{days}",
                        onchange: move |e| {
                            let v = e.value().parse().unwrap_or(7);
                            days.set(v);
                            stats.restart();
                        },
                        option { value: "1", "1 day" }
                        option { value: "7", selected: true, "7 days" }
                        option { value: "30", "30 days" }
                        option { value: "90", "90 days" }
                    }
                    button {
                        class: "px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm rounded-xl",
                        onclick: move |_| {
                            spawn(async move {
                                match server_ingest_mail_stats().await {
                                    Ok(msg) => ingest_msg.set(Some(msg)),
                                    Err(e) => ingest_msg.set(Some(e.to_string())),
                                }
                                stats.restart();
                            });
                        },
                        "Ingest Today's Stats"
                    }
                }
            }

            if let Some(msg) = ingest_msg() {
                div { class: "bg-blue-50 text-blue-700 p-3 rounded-lg mb-4 text-sm", "{msg}" }
            }

            // Stats table
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden mb-6",
                div { class: "px-6 py-4 border-b border-gray-100",
                    h3 { class: "font-semibold text-gray-900", "Delivery Statistics" }
                }
                match &*stats.read() {
                    Some(Ok(rows)) if !rows.is_empty() => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200/60",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Date" }
                                        th { class: "px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase", "Domain" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Sent" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Received" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Rejected" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Spam" }
                                        th { class: "px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase", "Bounced" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-100",
                                    for row in rows.iter() {
                                        tr { class: "hover:bg-gray-50/50",
                                            td { class: "px-4 py-3 text-gray-700", "{row.stat_date}" }
                                            td { class: "px-4 py-3 text-gray-500", "{row.domain.as_deref().unwrap_or(\"—\")}" }
                                            td { class: "px-4 py-3 text-right text-green-600 font-medium", "{row.sent_count}" }
                                            td { class: "px-4 py-3 text-right text-blue-600 font-medium", "{row.received_count}" }
                                            td { class: "px-4 py-3 text-right text-red-500 font-medium", "{row.rejected_count}" }
                                            td { class: "px-4 py-3 text-right text-yellow-600 font-medium", "{row.spam_count}" }
                                            td { class: "px-4 py-3 text-right text-orange-500 font-medium", "{row.bounced_count}" }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        div { class: "py-10 text-center text-gray-400 text-sm",
                            "No statistics recorded yet. Click \"Ingest Today's Stats\" to parse the mail log."
                        }
                    },
                    Some(Err(e)) => rsx! { div { class: "p-6 text-red-500 text-sm", "{e}" } },
                    None => rsx! { div { class: "p-6 text-gray-400 text-sm", "Loading..." } },
                }
            }

            // Log viewer
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                div { class: "px-6 py-4 border-b border-gray-100 flex items-center gap-4",
                    h3 { class: "font-semibold text-gray-900 shrink-0", "Mail Log" }
                    input {
                        r#type: "text",
                        placeholder: "Filter logs (queue-id, domain, address…)",
                        class: "flex-1 border border-gray-300 rounded-lg px-3 py-1.5 text-sm",
                        value: "{search}",
                        oninput: move |e| {
                            search.set(e.value());
                            search_res.restart();
                        },
                    }
                }
                {
                    let display_logs = if search().is_empty() {
                        &*logs.read()
                    } else {
                        &*search_res.read()
                    };
                    match display_logs {
                        Some(Ok(entries)) if !entries.is_empty() => rsx! {
                            div { class: "overflow-x-auto max-h-96 overflow-y-auto",
                                table { class: "w-full text-xs font-mono",
                                    thead { class: "bg-gray-50 border-b border-gray-200/60 sticky top-0",
                                        tr {
                                            th { class: "px-4 py-2 text-left text-gray-500", "Time" }
                                            th { class: "px-4 py-2 text-left text-gray-500", "Process" }
                                            th { class: "px-4 py-2 text-left text-gray-500", "Queue ID" }
                                            th { class: "px-4 py-2 text-left text-gray-500", "Message" }
                                        }
                                    }
                                    tbody { class: "divide-y divide-gray-100",
                                        for entry in entries.iter() {
                                            tr { class: "hover:bg-gray-50/30",
                                                td { class: "px-4 py-1.5 text-gray-400 whitespace-nowrap", "{entry.timestamp}" }
                                                td { class: "px-4 py-1.5 text-blue-600 whitespace-nowrap", "{entry.process}" }
                                                td { class: "px-4 py-1.5 text-gray-500", "{entry.queue_id}" }
                                                td { class: "px-4 py-1.5 text-gray-700", "{entry.message}" }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Some(Ok(_)) => rsx! {
                            div { class: "py-8 text-center text-gray-400 text-sm", "No log entries found." }
                        },
                        Some(Err(e)) => rsx! { div { class: "p-4 text-red-500 text-sm", "{e}" } },
                        None => rsx! { div { class: "p-4 text-gray-400 text-sm", "Loading..." } },
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Email Debugger
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
pub fn AdminEmailDebug() -> Element {
    let mut target_domain = use_signal(String::new);
    let mut result: Signal<Option<panel::models::email::EmailDebugResult>> = use_signal(|| None);
    let mut running = use_signal(|| false);
    let mut debug_error = use_signal(|| None::<String>);

    let mut do_debug = move || {
        let domain = target_domain().trim().to_string();
        if domain.is_empty() {
            return;
        }
        result.set(None);
        debug_error.set(None);
        running.set(true);
        spawn(async move {
            match server_debug_email(domain).await {
                Ok(r) => result.set(Some(r)),
                Err(e) => debug_error.set(Some(e.to_string())),
            }
            running.set(false);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 max-w-3xl",
            div { class: "mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Email Debugger" }
                p { class: "text-sm text-gray-500 mt-1",
                    "Check MX, SPF, DKIM, and DMARC records for a domain. "
                    "Also probes the primary MX host for SMTP reachability."
                }
            }

            div { class: "flex gap-3 mb-6",
                input {
                    r#type: "text",
                    placeholder: "example.com",
                    class: "flex-1 border border-gray-300 rounded-xl px-4 py-2.5 text-sm",
                    value: "{target_domain}",
                    oninput: move |e| target_domain.set(e.value()),
                    onkeydown: move |e| {
                        if e.key() == Key::Enter {
                            do_debug();
                        }
                    },
                }
                button {
                    class: "px-5 py-2.5 bg-rose-500 hover:bg-rose-600 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50",
                    disabled: running() || target_domain().is_empty(),
                    onclick: move |_| do_debug(),
                    if running() {
                        div { class: "flex items-center gap-2",
                            Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                            "Running…"
                        }
                    } else {
                        "Run Diagnostics"
                    }
                }
            }

            if let Some(err) = debug_error() {
                div { class: "bg-red-50 text-red-700 p-3 rounded-xl mb-4 text-sm", "{err}" }
            }

            if let Some(res) = result() {
                div { class: "space-y-4",
                    // Overview
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-6",
                        h3 { class: "font-semibold text-gray-900 mb-4 flex items-center gap-2",
                            Icon { name: "search", class: "w-4 h-4 text-gray-400".to_string() }
                            "Results for {res.target}"
                        }
                        div { class: "grid grid-cols-2 gap-4",
                            // MX reachable
                            div { class: "flex items-center gap-2",
                                div { class: if res.mx_reachable { "w-2 h-2 rounded-full bg-green-500" } else { "w-2 h-2 rounded-full bg-red-400" } }
                                span { class: "text-sm text-gray-700", "MX Reachable" }
                            }
                            // SPF
                            div { class: "flex items-center gap-2",
                                div { class: if res.spf_record.is_some() { "w-2 h-2 rounded-full bg-green-500" } else { "w-2 h-2 rounded-full bg-yellow-400" } }
                                span { class: "text-sm text-gray-700", "SPF Record" }
                            }
                            // DKIM
                            div { class: "flex items-center gap-2",
                                div { class: if res.dkim_record.is_some() { "w-2 h-2 rounded-full bg-green-500" } else { "w-2 h-2 rounded-full bg-yellow-400" } }
                                span { class: "text-sm text-gray-700", "DKIM Record" }
                            }
                            // DMARC
                            div { class: "flex items-center gap-2",
                                div { class: if res.dmarc_record.is_some() { "w-2 h-2 rounded-full bg-green-500" } else { "w-2 h-2 rounded-full bg-yellow-400" } }
                                span { class: "text-sm text-gray-700", "DMARC Record" }
                            }
                        }
                    }

                    // MX Records
                    if !res.mx_records.is_empty() {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5",
                            h4 { class: "font-medium text-gray-800 mb-3 text-sm uppercase tracking-wide", "MX Records" }
                            div { class: "space-y-1",
                                for mx in res.mx_records.iter() {
                                    p { class: "font-mono text-sm text-gray-700 bg-gray-50 rounded px-3 py-1.5", "{mx}" }
                                }
                            }
                            if let Some(banner) = &res.smtp_banner {
                                p { class: "text-xs text-gray-500 mt-2 font-mono", "SMTP: {banner}" }
                            }
                        }
                    }

                    // DNS records
                    div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 space-y-4",
                        h4 { class: "font-medium text-gray-800 text-sm uppercase tracking-wide", "DNS Records" }
                        for (label, val) in [
                            ("SPF", res.spf_record.as_deref()),
                            ("DKIM (default)", res.dkim_record.as_deref()),
                            ("DMARC", res.dmarc_record.as_deref()),
                        ] {
                            div {
                                p { class: "text-xs font-semibold text-gray-500 mb-1", "{label}" }
                                if let Some(v) = val {
                                    p { class: "font-mono text-xs text-gray-700 bg-gray-50 rounded px-3 py-2 break-all", "{v}" }
                                } else {
                                    p { class: "text-xs text-red-400 italic", "Not found" }
                                }
                            }
                        }
                    }

                    // Notes / recommendations
                    if !res.notes.is_empty() {
                        div { class: "bg-amber-50 border border-amber-200 rounded-2xl p-5",
                            h4 { class: "font-medium text-amber-800 mb-3 text-sm flex items-center gap-2",
                                Icon { name: "alert-triangle", class: "w-4 h-4".to_string() }
                                "Recommendations"
                            }
                            ul { class: "space-y-2",
                                for note in res.notes.iter() {
                                    li { class: "text-sm text-amber-700 flex items-start gap-2",
                                        span { class: "mt-1 shrink-0", "•" }
                                        "{note}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

