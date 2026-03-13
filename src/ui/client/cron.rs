#![allow(non_snake_case)]
use dioxus::prelude::*;
use panel::server::*;
use crate::lucide::Icon;


// ──── Cron Job Manager ──────────────────────────────────────────────────────

#[component]
pub fn ClientCron() -> Element {
    let sites = use_resource(move || async move { server_list_sites().await });
    let mut selected_site_id = use_signal(|| 0i64);

    let mut jobs_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(vec![]);
            }
            server_list_cron_jobs(sid).await
        }
    });

    // Form state
    let mut schedule = use_signal(|| "0 * * * *".to_string());
    let mut command = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut form_error = use_signal(|| None::<String>);
    let mut submitting = use_signal(|| false);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "mb-6",
                h2 { class: "text-2xl font-semibold tracking-tight text-gray-900", "Cron Jobs" }
                p { class: "text-[13px] text-gray-400 mt-1",
                    "Schedule recurring commands for each website. Changes are written directly to the site owner's crontab."
                }
            }

            // ── Site selector ──────────────────────────────────────────────
            div { class: "glass-card rounded-2xl p-5 mb-6",
                label { class: "block text-sm font-medium text-gray-700 mb-2", "Select Website" }
                match &*sites.read() {
                    Some(Ok(site_list)) if !site_list.is_empty() => rsx! {
                        select {
                            class: "w-full max-w-sm px-4 py-2 border border-black/[0.08] rounded-xl focus:ring-2 focus:ring-black/[0.15] bg-white text-sm",
                            value: "{selected_site_id}",
                            onchange: move |e| {
                                let val: i64 = e.value().parse().unwrap_or(0);
                                selected_site_id.set(val);
                                form_error.set(None);
                            },
                            option { value: "0", disabled: true, "-- Choose a website --" }
                            for s in site_list.iter() {
                                option { value: "{s.id}", "{s.domain}" }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        p { class: "text-[13px] text-gray-400", "No websites found. Create one first." }
                    },
                    Some(Err(e)) => rsx! {
                        p { class: "text-red-600 text-sm", "Error loading sites: {e}" }
                    },
                    None => rsx! {
                        p { class: "text-gray-400 text-sm animate-pulse", "Loading websites…" }
                    },
                }
            }

            if selected_site_id() != 0 {
                // ── Add cron job form ──────────────────────────────────────
                div { class: "glass-card rounded-2xl p-5 mb-6",
                    h3 { class: "text-sm font-semibold text-gray-700 mb-4", "Add New Cron Job" }

                    if let Some(ref err) = form_error() {
                        div { class: "mb-4 p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm", "{err}" }
                    }

                    form {
                        onsubmit: move |ev: FormEvent| {
                            ev.prevent_default();
                            submitting.set(true);
                            form_error.set(None);
                            let sid = selected_site_id();
                            let sched = schedule();
                            let cmd = command();
                            let desc = description();
                            spawn(async move {
                                match server_create_cron_job(sid, sched, cmd, desc).await {
                                    Ok(_) => {
                                        command.set(String::new());
                                        description.set(String::new());
                                        jobs_resource.restart();
                                    }
                                    Err(e) => form_error.set(Some(e.to_string())),
                                }
                                submitting.set(false);
                            });
                        },
                        div { class: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-4",
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1",
                                    "Schedule"
                                    span { class: "text-gray-400 font-normal ml-1", "(cron expression or @alias)" }
                                }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-black/[0.08] rounded-xl focus:ring-2 focus:ring-black/[0.15] text-sm font-mono",
                                    placeholder: "*/5 * * * *",
                                    value: "{schedule}",
                                    oninput: move |e| schedule.set(e.value()),
                                    required: true,
                                }
                                p { class: "text-xs text-gray-400 mt-1",
                                    "Examples: "
                                    code { class: "bg-gray-100 px-1 rounded", "0 * * * *" }
                                    " (hourly)  "
                                    code { class: "bg-gray-100 px-1 rounded", "@daily" }
                                    "  "
                                    code { class: "bg-gray-100 px-1 rounded", "*/15 * * * *" }
                                    " (every 15 min)"
                                }
                            }
                            div {
                                label { class: "block text-xs font-medium text-gray-600 mb-1", "Command" }
                                input {
                                    r#type: "text",
                                    class: "w-full px-4 py-2 border border-black/[0.08] rounded-xl focus:ring-2 focus:ring-black/[0.15] text-sm font-mono",
                                    placeholder: "/usr/bin/php /home/user/site.com/artisan schedule:run",
                                    value: "{command}",
                                    oninput: move |e| command.set(e.value()),
                                    required: true,
                                }
                            }
                        }
                        div { class: "mb-4",
                            label { class: "block text-xs font-medium text-gray-600 mb-1",
                                "Description "
                                span { class: "text-gray-400 font-normal", "(optional)" }
                            }
                            input {
                                r#type: "text",
                                class: "w-full px-4 py-2 border border-black/[0.08] rounded-xl focus:ring-2 focus:ring-black/[0.15] text-sm",
                                placeholder: "Laravel scheduler, backup script, etc.",
                                value: "{description}",
                                oninput: move |e| description.set(e.value()),
                                maxlength: "255",
                            }
                        }
                        div { class: "flex justify-end",
                            button {
                                r#type: "submit",
                                class: "flex items-center gap-2 px-5 py-2.5 bg-gray-900 hover:bg-gray-900/90 text-white font-medium rounded-xl transition-all duration-200 disabled:opacity-50 text-sm",
                                disabled: submitting(),
                                Icon { name: "plus", class: "w-4 h-4".to_string() }
                                if submitting() { "Adding…" } else { "Add Cron Job" }
                            }
                        }
                    }
                }

                // ── Cron job list ──────────────────────────────────────────
                div { class: "glass-card rounded-2xl overflow-hidden",
                    div { class: "px-5 py-4 border-b border-black/[0.05] flex items-center justify-between",
                        h3 { class: "text-sm font-semibold text-gray-700", "Scheduled Jobs" }
                        button {
                            class: "flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-500 hover:bg-gray-50 border border-black/[0.08] rounded-xl transition-colors",
                            onclick: move |_| jobs_resource.restart(),
                            Icon { name: "refresh-cw", class: "w-3.5 h-3.5".to_string() }
                            "Refresh"
                        }
                    }
                    match &*jobs_resource.read() {
                        Some(Ok(jobs)) if jobs.is_empty() => rsx! {
                            div { class: "p-10 text-center",
                                div { class: "mx-auto w-12 h-12 rounded-xl bg-gray-50 flex items-center justify-center mb-3",
                                    Icon { name: "clock", class: "w-6 h-6 text-gray-300".to_string() }
                                }
                                p { class: "text-gray-400 text-sm", "No cron jobs yet. Add your first one above." }
                            }
                        },
                        Some(Ok(jobs)) => {
                            let jobs = jobs.clone();
                            rsx! {
                                div { class: "divide-y divide-gray-50",
                                    for job in jobs.iter() {
                                        CronJobRow {
                                            job: job.clone(),
                                            jobs_resource,
                                        }
                                    }
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "p-6 text-center text-red-600 text-sm", "Error: {e}" }
                        },
                        None => rsx! {
                            div { class: "p-6 text-center text-gray-400 text-sm animate-pulse", "Loading…" }
                        },
                    }
                }
            }
        }
    }
}

/// A single cron job row with toggle and delete actions.
#[component]
pub fn CronJobRow(
    job: panel::models::cron::CronJob,
    jobs_resource: Resource<Result<Vec<panel::models::cron::CronJob>, ServerFnError>>,
) -> Element {
    let mut jobs_resource = jobs_resource;
    let mut toggling = use_signal(|| false);
    let mut deleting = use_signal(|| false);
    let mut row_error = use_signal(|| None::<String>);
    let job_id = job.id;
    let enabled = job.enabled;
    let last_run_str = job
        .last_run
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string());

    rsx! {
        div { class: "flex items-start gap-3 px-5 py-4 hover:bg-black/[0.02] transition-colors",
            // Enable/disable toggle
            button {
                class: "mt-0.5 shrink-0 disabled:opacity-50",
                title: if enabled { "Disable job" } else { "Enable job" },
                disabled: toggling() || deleting(),
                onclick: move |_| {
                    toggling.set(true);
                    row_error.set(None);
                    spawn(async move {
                        match server_toggle_cron_job(job_id, !enabled).await {
                            Ok(()) => jobs_resource.restart(),
                            Err(e) => row_error.set(Some(e.to_string())),
                        }
                        toggling.set(false);
                    });
                },
                if enabled {
                    div { class: "w-9 h-5 bg-emerald-500 rounded-full relative transition-colors",
                        div { class: "absolute right-0.5 top-0.5 w-4 h-4 bg-white rounded-full shadow-sm" }
                    }
                } else {
                    div { class: "w-9 h-5 bg-gray-300 rounded-full relative transition-colors",
                        div { class: "absolute left-0.5 top-0.5 w-4 h-4 bg-white rounded-full shadow-sm" }
                    }
                }
            }

            // Job details
            div { class: "flex-1 min-w-0",
                div { class: "flex items-center gap-2 flex-wrap",
                    code { class: "text-xs font-mono bg-black/[0.04] text-gray-600 px-2 py-0.5 rounded", "{job.schedule}" }
                    code { class: "text-xs font-mono text-gray-600 truncate max-w-xs", "{job.command}" }
                }
                if !job.description.is_empty() {
                    p { class: "text-xs text-gray-400 mt-0.5", "{job.description}" }
                }
                div { class: "flex items-center gap-3 mt-1",
                    if !enabled {
                        span { class: "text-xs text-gray-400 italic", "Disabled" }
                    }
                    if let Some(ref last_run_str) = last_run_str {
                        span { class: "text-xs text-gray-400",
                            "Last run: {last_run_str}"
                        }
                    }
                    if let Some(ref err) = row_error() {
                        span { class: "text-xs text-red-600", "{err}" }
                    }
                }
            }

            // Delete button
            button {
                class: "shrink-0 p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-xl transition-all duration-200 disabled:opacity-40",
                title: "Delete cron job",
                disabled: deleting() || toggling(),
                onclick: move |_| {
                    deleting.set(true);
                    row_error.set(None);
                    spawn(async move {
                        match server_delete_cron_job(job_id).await {
                            Ok(()) => jobs_resource.restart(),
                            Err(e) => {
                                row_error.set(Some(e.to_string()));
                                deleting.set(false);
                            }
                        }
                    });
                },
                if deleting() {
                    Icon { name: "loader", class: "w-4 h-4 animate-spin".to_string() }
                } else {
                    Icon { name: "trash-2", class: "w-4 h-4".to_string() }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Anti-Spam Configuration
// ═══════════════════════════════════════════════════════════════════════════════

