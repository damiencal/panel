#![allow(non_snake_case)]
use crate::lucide::Icon;
use dioxus::prelude::*;
use panel::models::service::{ServiceAction, ServiceCommand, ServiceStatus, ServiceType};
use panel::server::*;

use crate::StatusBadge;

#[component]
pub fn AdminMonitoring() -> Element {
    let mut services = use_resource(move || async move { server_get_services_status().await });
    let metrics = use_resource(move || async move { server_get_system_metrics().await });
    let mut action_error = use_signal(|| None::<String>);
    let mut action_loading = use_signal(|| None::<String>);
    let mut active_tab = use_signal(|| "overview");

    let _handle_action = move |svc_type: ServiceType, cmd: ServiceCommand| {
        let label = format!("{}_{}", svc_type, cmd);
        action_loading.set(Some(label));
        action_error.set(None);
        spawn(async move {
            let action = ServiceAction {
                service: svc_type,
                action: cmd,
            };
            match server_manage_service(action).await {
                Ok(_) => {
                    services.restart();
                }
                Err(e) => {
                    action_error.set(Some(e.to_string()));
                }
            }
            action_loading.set(None);
        });
    };

    rsx! {
        div { class: "p-6 lg:p-8 space-y-6",
            // Page header
            div { class: "flex items-center justify-between",
                div {
                    h2 { class: "text-2xl font-semibold tracking-tight text-gray-900", "Monitoring" }
                    p { class: "text-sm text-gray-500 mt-1", "Real-time system health and performance metrics" }
                }
                div { class: "flex items-center gap-3",
                    // Uptime badge
                    match &*metrics.read() {
                        Some(Ok(m)) => {
                            let days = m.uptime_seconds / 86400;
                            let hours = (m.uptime_seconds % 86400) / 3600;
                            let mins = (m.uptime_seconds % 3600) / 60;
                            let uptime_str = if days > 0 { format!("{}d {}h {}m", days, hours, mins) } else { format!("{}h {}m", hours, mins) };
                            rsx! {
                                div { class: "flex items-center gap-2 px-3 py-1.5 bg-emerald-500/[0.08] text-emerald-700 rounded-lg text-xs font-medium",
                                    div { class: "w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" }
                                    "Uptime: {uptime_str}"
                                }
                            }
                        },
                        _ => rsx! {},
                    }
                    button {
                        class: "flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors",
                        onclick: move |_| { services.restart(); },
                        Icon { name: "refresh-cw", class: "w-4 h-4".to_string() }
                        span { class: "hidden sm:inline", "Refresh" }
                    }
                }
            }

            // Error banner
            if let Some(err) = action_error() {
                div { class: "bg-red-50 border border-red-200 text-red-700 p-3 rounded-xl text-sm flex items-center justify-between",
                    div { class: "flex items-center gap-2",
                        Icon { name: "alert-triangle", class: "w-4 h-4".to_string() }
                        span { "{err}" }
                    }
                    button {
                        class: "text-red-400 hover:text-red-600 transition-colors",
                        onclick: move |_| action_error.set(None),
                        Icon { name: "x", class: "w-4 h-4".to_string() }
                    }
                }
            }

            // Tab navigation
            div { class: "flex items-center gap-1 p-1 bg-black/[0.04] rounded-xl w-fit flex-wrap",
                {
                    let tabs: Vec<(&str, &str, &str)> = vec![
                        ("overview", "Overview", "layout-dashboard"),
                        ("history", "History", "trending-up"),
                        ("processes", "Processes", "list"),
                        ("docker", "Docker", "box"),
                        ("network", "Network", "wifi"),
                        ("storage", "Storage", "hard-drive"),
                        ("services", "Services", "server"),
                    ];
                    rsx! {
                        for (key, label, icon) in tabs {
                            {
                                let is_active = active_tab() == key;
                                let cls = if is_active {
                                    "flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-white text-gray-900 shadow-sm transition-all"
                                } else {
                                    "flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg text-gray-500 hover:text-gray-700 transition-all"
                                };
                                rsx! {
                                    button {
                                        class: "{cls}",
                                        onclick: move |_| active_tab.set(key),
                                        Icon { name: icon, class: "w-4 h-4".to_string() }
                                        "{label}"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Tab content
            match active_tab() {
                "overview" => rsx! { MonitoringOverview { metrics: metrics } },
                "history" => rsx! { MonitoringHistory {} },
                "processes" => rsx! { MonitoringProcesses {} },
                "docker" => rsx! { MonitoringDocker { metrics: metrics } },
                "network" => rsx! { MonitoringNetwork { metrics: metrics } },
                "storage" => rsx! { MonitoringStorage { metrics: metrics } },
                "services" => rsx! { MonitoringServicesTab {} },
                _ => rsx! { MonitoringOverview { metrics: metrics } },
            }
        }
    }
}

// ── Overview Tab ─────────────────────────────────────────────────

type MetricsResource = Resource<Result<panel::server::monitoring::SystemMetrics, ServerFnError>>;

#[component]
fn MonitoringOverview(metrics: MetricsResource) -> Element {
    rsx! {
        match &*metrics.read() {
            Some(Ok(m)) => {
                let used_gb = m.total_memory_gb - m.available_memory_gb;
                let mem_pct = if m.total_memory_gb > 0.0 { (used_gb / m.total_memory_gb * 100.0) as u32 } else { 0 };
                let cpu_pct = m.cpu_usage_pct as u32;

                rsx! {
                    // Top gauge cards - CPU, Memory, Load
                    div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5",
                        // CPU Usage
                        GaugeCard {
                            title: "CPU Usage",
                            value: cpu_pct,
                            subtitle: format!("{} cores", m.cpu_cores),
                            icon: "cpu",
                            color: gauge_color(cpu_pct),
                        }
                        // Memory Usage
                        GaugeCard {
                            title: "Memory",
                            value: mem_pct,
                            subtitle: format!("{:.1} / {:.1} GB", used_gb, m.total_memory_gb),
                            icon: "server",
                            color: gauge_color(mem_pct),
                        }
                        // Load Average card
                        div { class: "glass-card rounded-2xl p-5",
                            div { class: "flex items-center justify-between mb-4",
                                div { class: "flex items-center gap-2",
                                    div { class: "p-2 bg-violet-50 rounded-lg",
                                        Icon { name: "activity", class: "w-4 h-4 text-violet-600".to_string() }
                                    }
                                    span { class: "text-sm font-medium text-gray-600", "Load Average" }
                                }
                            }
                            div { class: "flex items-end gap-4",
                                div {
                                    p { class: "text-2xl font-semibold tracking-tight text-gray-900", "{m.load_1:.2}" }
                                    p { class: "text-xs text-gray-400 mt-0.5", "1 min" }
                                }
                                div {
                                    p { class: "text-lg font-semibold text-gray-500", "{m.load_5:.2}" }
                                    p { class: "text-xs text-gray-400 mt-0.5", "5 min" }
                                }
                                div {
                                    p { class: "text-lg font-semibold text-gray-500", "{m.load_15:.2}" }
                                    p { class: "text-xs text-gray-400 mt-0.5", "15 min" }
                                }
                            }
                        }
                        // Uptime card
                        {
                            let days = m.uptime_seconds / 86400;
                            let hours = (m.uptime_seconds % 86400) / 3600;
                            rsx! {
                                div { class: "glass-card rounded-2xl p-5",
                                    div { class: "flex items-center justify-between mb-4",
                                        div { class: "flex items-center gap-2",
                                            div { class: "p-2 bg-emerald-50 rounded-lg",
                                                Icon { name: "clock", class: "w-4 h-4 text-emerald-600".to_string() }
                                            }
                                            span { class: "text-sm font-medium text-gray-600", "Uptime" }
                                        }
                                    }
                                    p { class: "text-2xl font-semibold tracking-tight text-gray-900", "{days}d {hours}h" }
                                    p { class: "text-xs text-gray-400 mt-1", "Since last reboot" }
                                }
                            }
                        }
                    }

                    // Disk overview (compact)
                    if !m.disks.is_empty() {
                        div { class: "glass-card rounded-2xl p-5",
                            div { class: "flex items-center gap-2 mb-4",
                                Icon { name: "hard-drive", class: "w-4 h-4 text-gray-400".to_string() }
                                h3 { class: "text-sm font-semibold text-gray-900", "Storage Overview" }
                            }
                            div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4",
                                for disk in m.disks.iter() {
                                    {
                                        let pct = disk.use_pct;
                                        let bar_color = gauge_bar_color(pct);
                                        rsx! {
                                            div { class: "p-3 bg-black/[0.03] rounded-xl",
                                                div { class: "flex items-center justify-between mb-2",
                                                    span { class: "text-sm font-medium text-gray-700 truncate", "{disk.mount}" }
                                                    span { class: "text-xs font-semibold text-gray-500", "{pct}%" }
                                                }
                                                div { class: "w-full bg-gray-200 rounded-full h-1.5 mb-1.5",
                                                    div { class: "h-1.5 rounded-full {bar_color}", style: "width: {pct}%" }
                                                }
                                                p { class: "text-xs text-gray-400", "{disk.used_gb:.1} / {disk.total_gb:.1} GB" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Network + Docker summary side by side
                    div { class: "grid grid-cols-1 lg:grid-cols-2 gap-5",
                        // Network summary
                        div { class: "glass-card rounded-2xl p-5",
                            div { class: "flex items-center gap-2 mb-4",
                                Icon { name: "wifi", class: "w-4 h-4 text-gray-400".to_string() }
                                h3 { class: "text-sm font-semibold text-gray-900", "Network Interfaces" }
                            }
                            if m.network.is_empty() {
                                div { class: "text-center py-6",
                                    Icon { name: "wifi", class: "w-8 h-8 text-gray-300 mx-auto mb-2".to_string() }
                                    p { class: "text-sm text-gray-500", "No network data available" }
                                }
                            } else {
                                div { class: "space-y-3",
                                    for iface in m.network.iter() {
                                        div { class: "flex items-center justify-between p-3 bg-black/[0.03] rounded-xl",
                                            div { class: "flex items-center gap-3",
                                                div { class: "w-8 h-8 bg-blue-50 rounded-lg flex items-center justify-center",
                                                    Icon { name: "wifi", class: "w-4 h-4 text-blue-600".to_string() }
                                                }
                                                div {
                                                    p { class: "text-sm font-medium text-gray-900", "{iface.name}" }
                                                    p { class: "text-xs text-gray-400", "{iface.rx_packets} / {iface.tx_packets} pkts" }
                                                }
                                            }
                                            div { class: "text-right",
                                                div { class: "flex items-center gap-1 text-xs",
                                                    Icon { name: "arrow-down", class: "w-3 h-3 text-green-500".to_string() }
                                                    span { class: "text-green-600 font-medium", "{format_bytes(iface.rx_bytes)}" }
                                                }
                                                div { class: "flex items-center gap-1 text-xs mt-0.5",
                                                    Icon { name: "arrow-up", class: "w-3 h-3 text-blue-500".to_string() }
                                                    span { class: "text-blue-600 font-medium", "{format_bytes(iface.tx_bytes)}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Docker summary
                        div { class: "glass-card rounded-2xl p-5",
                            div { class: "flex items-center gap-2 mb-4",
                                Icon { name: "box", class: "w-4 h-4 text-gray-400".to_string() }
                                h3 { class: "text-sm font-semibold text-gray-900", "Docker Containers" }
                                if !m.docker.is_empty() {
                                    span { class: "ml-auto text-xs px-2 py-0.5 bg-black/[0.04] text-gray-600 rounded-full font-medium",
                                        "{m.docker.len()}"
                                    }
                                }
                            }
                            if m.docker.is_empty() {
                                div { class: "text-center py-6",
                                    Icon { name: "box", class: "w-8 h-8 text-gray-300 mx-auto mb-2".to_string() }
                                    p { class: "text-sm text-gray-500", "No containers running" }
                                    p { class: "text-xs text-gray-300 mt-1", "Docker may not be installed" }
                                }
                            } else {
                                div { class: "space-y-2",
                                    for c in m.docker.iter().take(5) {
                                        {
                                            let state_color = match c.state.as_str() {
                                                "running" => "bg-green-500",
                                                "exited" => "bg-red-400",
                                                "paused" => "bg-yellow-400",
                                                _ => "bg-gray-400",
                                            };
                                            rsx! {
                                                div { class: "flex items-center justify-between p-3 bg-black/[0.03] rounded-xl",
                                                    div { class: "flex items-center gap-3 min-w-0",
                                                        div { class: "w-2 h-2 rounded-full {state_color} shrink-0" }
                                                        div { class: "min-w-0",
                                                            p { class: "text-sm font-medium text-gray-900 truncate", "{c.name}" }
                                                            p { class: "text-xs text-gray-400 truncate", "{c.image}" }
                                                        }
                                                    }
                                                    div { class: "text-right shrink-0 ml-3",
                                                        p { class: "text-xs font-medium text-gray-600", "{c.cpu_pct:.1}% CPU" }
                                                        p { class: "text-xs text-gray-400", "{c.mem_mb:.0} MB" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if m.docker.len() > 5 {
                                        p { class: "text-xs text-gray-400 text-center pt-1",
                                            "+{m.docker.len() - 5} more containers"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            Some(Err(e)) => rsx! {
                div { class: "bg-red-50 border border-red-200 text-red-600 p-6 rounded-2xl text-sm",
                    div { class: "flex items-center gap-2",
                        Icon { name: "alert-triangle", class: "w-5 h-5".to_string() }
                        span { class: "font-medium", "Failed to load metrics" }
                    }
                    p { class: "mt-2 text-red-500", "{e}" }
                }
            },
            None => rsx! {
                div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5",
                    for _ in 0..4 {
                        div { class: "glass-card rounded-2xl p-5 animate-pulse",
                            div { class: "flex items-center gap-2 mb-4",
                                div { class: "w-8 h-8 bg-gray-200 rounded-lg" }
                                div { class: "h-4 bg-gray-200 rounded w-20" }
                            }
                            div { class: "h-8 bg-gray-200 rounded w-16 mb-2" }
                            div { class: "h-3 bg-gray-200 rounded w-24" }
                        }
                    }
                }
                div { class: "grid grid-cols-1 lg:grid-cols-2 gap-5",
                    for _ in 0..2 {
                        div { class: "glass-card rounded-2xl p-5 animate-pulse h-48" }
                    }
                }
            },
        }
    }
}

// ── Gauge Card Component ─────────────────────────────────────────

#[component]
fn GaugeCard(
    title: String,
    value: u32,
    subtitle: String,
    icon: &'static str,
    color: &'static str,
) -> Element {
    let (ring_color, bg_color, text_color) = match color {
        "green" => ("stroke-emerald-500", "bg-emerald-50", "text-emerald-600"),
        "yellow" => ("stroke-amber-500", "bg-amber-50", "text-amber-600"),
        "red" => ("stroke-red-500", "bg-red-50", "text-red-600"),
        _ => ("stroke-emerald-500", "bg-emerald-50", "text-emerald-600"),
    };
    // SVG circle progress: circumference = 2 * PI * 40 = 251.3
    let circumference = 251.3_f64;
    let offset = circumference - (circumference * value as f64 / 100.0);

    rsx! {
        div { class: "glass-card rounded-2xl p-5",
            div { class: "flex items-center justify-between",
                div {
                    div { class: "flex items-center gap-2 mb-3",
                        div { class: "p-2 {bg_color} rounded-lg",
                            Icon { name: icon, class: format!("w-4 h-4 {text_color}") }
                        }
                        span { class: "text-sm font-medium text-gray-600", "{title}" }
                    }
                    p { class: "text-xs text-gray-400", "{subtitle}" }
                }
                // Circular gauge
                div { class: "relative w-16 h-16",
                    svg { class: "w-16 h-16 -rotate-90", "viewBox": "0 0 100 100",
                        circle {
                            cx: "50", cy: "50", r: "40",
                            fill: "none",
                            stroke: "#f3f4f6",
                            "stroke-width": "8",
                        }
                        circle {
                            cx: "50", cy: "50", r: "40",
                            fill: "none",
                            class: "{ring_color}",
                            "stroke-width": "8",
                            "stroke-linecap": "round",
                            "stroke-dasharray": "{circumference}",
                            "stroke-dashoffset": "{offset}",
                        }
                    }
                    div { class: "absolute inset-0 flex items-center justify-center",
                        span { class: "text-sm font-bold text-gray-900", "{value}%" }
                    }
                }
            }
        }
    }
}

fn gauge_color(pct: u32) -> &'static str {
    if pct > 90 {
        "red"
    } else if pct > 70 {
        "yellow"
    } else {
        "green"
    }
}

fn gauge_bar_color(pct: u32) -> &'static str {
    if pct > 90 {
        "bg-red-500"
    } else if pct > 70 {
        "bg-amber-500"
    } else {
        "bg-emerald-500"
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// ── Docker Tab ───────────────────────────────────────────────────

#[component]
fn MonitoringDocker(metrics: MetricsResource) -> Element {
    rsx! {
        match &*metrics.read() {
            Some(Ok(m)) => {
                let running = m.docker.iter().filter(|c| c.state == "running").count();
                let _stopped = m.docker.iter().filter(|c| c.state != "running").count();
                let total_cpu: f64 = m.docker.iter().map(|c| c.cpu_pct).sum();
                let total_mem: f64 = m.docker.iter().map(|c| c.mem_mb).sum();
                rsx! {
                    // Docker summary cards
                    div { class: "grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6",
                        div { class: "glass-card rounded-xl p-4",
                            p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider tracking-wide", "Total" }
                            p { class: "text-2xl font-semibold tracking-tight text-gray-900 mt-1", "{m.docker.len()}" }
                        }
                        div { class: "glass-card rounded-xl p-4",
                            p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider tracking-wide", "Running" }
                            p { class: "text-2xl font-bold text-green-600 mt-1", "{running}" }
                        }
                        div { class: "glass-card rounded-xl p-4",
                            p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider tracking-wide", "CPU Usage" }
                            p { class: "text-2xl font-semibold tracking-tight text-gray-900 mt-1", "{total_cpu:.1}%" }
                        }
                        div { class: "glass-card rounded-xl p-4",
                            p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider tracking-wide", "Memory" }
                            p { class: "text-2xl font-semibold tracking-tight text-gray-900 mt-1",
                                {if total_mem >= 1024.0 { format!("{:.1} GB", total_mem / 1024.0) } else { format!("{:.0} MB", total_mem) }}
                            }
                        }
                    }

                    if m.docker.is_empty() {
                        div { class: "glass-card rounded-2xl p-12 text-center",
                            div { class: "w-16 h-16 bg-gray-100 rounded-2xl flex items-center justify-center mx-auto mb-4",
                                Icon { name: "box", class: "w-8 h-8 text-gray-400".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-900 mb-2", "No Docker Containers" }
                            p { class: "text-sm text-gray-500", "Docker is not installed or no containers are configured on this server." }
                        }
                    } else {
                        div { class: "glass-card rounded-2xl overflow-hidden",
                            table { class: "w-full",
                                thead { class: "bg-gray-50 border-b border-gray-200",
                                    tr {
                                        th { class: "px-5 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Container" }
                                        th { class: "px-5 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Image" }
                                        th { class: "px-5 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Status" }
                                        th { class: "px-5 py-3 text-right text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "CPU" }
                                        th { class: "px-5 py-3 text-right text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Memory" }
                                        th { class: "px-5 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Ports" }
                                    }
                                }
                                tbody { class: "divide-y divide-black/[0.04]",
                                    for c in m.docker.iter() {
                                        {
                                            let state_color = match c.state.as_str() {
                                                "running" => "bg-green-500",
                                                "exited" => "bg-red-400",
                                                "paused" => "bg-yellow-400",
                                                _ => "bg-gray-400",
                                            };
                                            let badge_cls = match c.state.as_str() {
                                                "running" => "bg-emerald-500/[0.08] text-emerald-700",
                                                "exited" => "bg-red-500/[0.08] text-red-600",
                                                "paused" => "bg-yellow-50 text-yellow-700",
                                                _ => "bg-black/[0.04] text-gray-600",
                                            };
                                            rsx! {
                                                tr { class: "hover:bg-black/[0.02] transition-colors",
                                                    td { class: "px-5 py-3.5",
                                                        div { class: "flex items-center gap-2.5",
                                                            div { class: "w-2 h-2 rounded-full {state_color} shrink-0" }
                                                            span { class: "text-sm font-medium text-gray-900", "{c.name}" }
                                                        }
                                                    }
                                                    td { class: "px-5 py-3.5 text-sm text-gray-500 max-w-[200px] truncate", "{c.image}" }
                                                    td { class: "px-5 py-3.5",
                                                        span { class: "text-xs font-medium px-2 py-0.5 rounded-full {badge_cls}", "{c.state}" }
                                                    }
                                                    td { class: "px-5 py-3.5 text-sm text-right font-mono text-gray-700", "{c.cpu_pct:.1}%" }
                                                    td { class: "px-5 py-3.5 text-sm text-right font-mono text-gray-700",
                                                        {if c.mem_mb >= 1024.0 { format!("{:.1} GB", c.mem_mb / 1024.0) } else { format!("{:.0} MB", c.mem_mb) }}
                                                    }
                                                    td { class: "px-5 py-3.5 text-xs text-gray-500 max-w-[180px] truncate",
                                                        {if c.ports.is_empty() { "—".to_string() } else { c.ports.clone() }}
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
            Some(Err(e)) => rsx! {
                div { class: "bg-red-50 border border-red-200 text-red-600 p-4 rounded-xl text-sm", "Error: {e}" }
            },
            None => rsx! {
                div { class: "grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6",
                    for _ in 0..4 {
                        div { class: "glass-card rounded-xl p-4 animate-pulse",
                            div { class: "h-3 bg-gray-200 rounded w-16 mb-2" }
                            div { class: "h-6 bg-gray-200 rounded w-10" }
                        }
                    }
                }
            },
        }
    }
}

// ── Network Tab ──────────────────────────────────────────────────

#[component]
fn MonitoringNetwork(metrics: MetricsResource) -> Element {
    rsx! {
        match &*metrics.read() {
            Some(Ok(m)) => {
                let total_rx: u64 = m.network.iter().map(|n| n.rx_bytes).sum();
                let total_tx: u64 = m.network.iter().map(|n| n.tx_bytes).sum();
                let total_errors: u64 = m.network.iter().map(|n| n.rx_errors + n.tx_errors).sum();
                rsx! {
                    // Summary cards
                    div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-6",
                        div { class: "glass-card rounded-xl p-4",
                            div { class: "flex items-center gap-2 mb-2",
                                Icon { name: "arrow-down", class: "w-4 h-4 text-green-500".to_string() }
                                p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Total Received" }
                            }
                            p { class: "text-xl font-semibold tracking-tight text-gray-900", "{format_bytes(total_rx)}" }
                        }
                        div { class: "glass-card rounded-xl p-4",
                            div { class: "flex items-center gap-2 mb-2",
                                Icon { name: "arrow-up", class: "w-4 h-4 text-blue-500".to_string() }
                                p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Total Sent" }
                            }
                            p { class: "text-xl font-semibold tracking-tight text-gray-900", "{format_bytes(total_tx)}" }
                        }
                        div { class: "glass-card rounded-xl p-4",
                            div { class: "flex items-center gap-2 mb-2",
                                Icon { name: "alert-triangle", class: "w-4 h-4 text-amber-500".to_string() }
                                p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Total Errors" }
                            }
                            p { class: "text-xl font-semibold tracking-tight text-gray-900", "{total_errors}" }
                        }
                    }

                    if m.network.is_empty() {
                        div { class: "glass-card rounded-2xl p-12 text-center",
                            div { class: "w-16 h-16 bg-gray-100 rounded-2xl flex items-center justify-center mx-auto mb-4",
                                Icon { name: "wifi", class: "w-8 h-8 text-gray-400".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-900 mb-2", "No Network Data" }
                            p { class: "text-sm text-gray-500", "Network interface information is not available." }
                        }
                    } else {
                        // Interface detail cards
                        div { class: "space-y-4",
                            for iface in m.network.iter() {
                                div { class: "glass-card rounded-2xl p-5",
                                    div { class: "flex items-center justify-between mb-4",
                                        div { class: "flex items-center gap-3",
                                            div { class: "w-10 h-10 bg-blue-50 rounded-xl flex items-center justify-center",
                                                Icon { name: "wifi", class: "w-5 h-5 text-blue-600".to_string() }
                                            }
                                            div {
                                                h4 { class: "text-sm font-semibold text-gray-900", "{iface.name}" }
                                                p { class: "text-xs text-gray-400", "Network interface" }
                                            }
                                        }
                                        {
                                            let has_errors = iface.rx_errors + iface.tx_errors > 0;
                                            let badge = if has_errors { "bg-amber-500/[0.08] text-amber-700" } else { "bg-emerald-500/[0.08] text-emerald-700" };
                                            let label = if has_errors { "Errors detected" } else { "Healthy" };
                                            rsx! {
                                                span { class: "text-xs font-medium px-2.5 py-1 rounded-full {badge}", "{label}" }
                                            }
                                        }
                                    }
                                    div { class: "grid grid-cols-2 md:grid-cols-4 gap-4",
                                        div { class: "p-3 bg-green-50/50 rounded-xl",
                                            p { class: "text-xs text-gray-500 mb-1", "Received" }
                                            p { class: "text-sm font-bold text-gray-900", "{format_bytes(iface.rx_bytes)}" }
                                            p { class: "text-xs text-gray-400 mt-0.5", "{iface.rx_packets} packets" }
                                        }
                                        div { class: "p-3 bg-blue-50/50 rounded-xl",
                                            p { class: "text-xs text-gray-500 mb-1", "Sent" }
                                            p { class: "text-sm font-bold text-gray-900", "{format_bytes(iface.tx_bytes)}" }
                                            p { class: "text-xs text-gray-400 mt-0.5", "{iface.tx_packets} packets" }
                                        }
                                        div { class: "p-3 bg-red-50/50 rounded-xl",
                                            p { class: "text-xs text-gray-500 mb-1", "RX Errors" }
                                            p { class: "text-sm font-bold text-gray-900", "{iface.rx_errors}" }
                                        }
                                        div { class: "p-3 bg-red-50/50 rounded-xl",
                                            p { class: "text-xs text-gray-500 mb-1", "TX Errors" }
                                            p { class: "text-sm font-bold text-gray-900", "{iface.tx_errors}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            Some(Err(e)) => rsx! {
                div { class: "bg-red-50 border border-red-200 text-red-600 p-4 rounded-xl text-sm", "Error: {e}" }
            },
            None => rsx! {
                div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-6",
                    for _ in 0..3 {
                        div { class: "glass-card rounded-xl p-4 animate-pulse",
                            div { class: "h-3 bg-gray-200 rounded w-24 mb-2" }
                            div { class: "h-6 bg-gray-200 rounded w-16" }
                        }
                    }
                }
            },
        }
    }
}

// ── Storage Tab ──────────────────────────────────────────────────

#[component]
fn MonitoringStorage(metrics: MetricsResource) -> Element {
    rsx! {
        match &*metrics.read() {
            Some(Ok(m)) => {
                let total_disk: f64 = m.disks.iter().map(|d| d.total_gb).sum();
                let used_disk: f64 = m.disks.iter().map(|d| d.used_gb).sum();
                rsx! {
                    // Summary
                    div { class: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-6",
                        div { class: "glass-card rounded-xl p-4",
                            p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider tracking-wide", "Partitions" }
                            p { class: "text-2xl font-semibold tracking-tight text-gray-900 mt-1", "{m.disks.len()}" }
                        }
                        div { class: "glass-card rounded-xl p-4",
                            p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider tracking-wide", "Total Space" }
                            p { class: "text-2xl font-semibold tracking-tight text-gray-900 mt-1", "{total_disk:.1} GB" }
                        }
                        div { class: "glass-card rounded-xl p-4",
                            p { class: "text-[11px] font-semibold text-gray-500 uppercase tracking-wider tracking-wide", "Used Space" }
                            p { class: "text-2xl font-semibold tracking-tight text-gray-900 mt-1", "{used_disk:.1} GB" }
                        }
                    }

                    if m.disks.is_empty() {
                        div { class: "glass-card rounded-2xl p-12 text-center",
                            div { class: "w-16 h-16 bg-gray-100 rounded-2xl flex items-center justify-center mx-auto mb-4",
                                Icon { name: "hard-drive", class: "w-8 h-8 text-gray-400".to_string() }
                            }
                            h3 { class: "text-lg font-semibold text-gray-900 mb-2", "No Disk Data" }
                            p { class: "text-sm text-gray-500", "Disk partition information is not available." }
                        }
                    } else {
                        div { class: "space-y-4",
                            for disk in m.disks.iter() {
                                {
                                    let pct = disk.use_pct;
                                    let bar_color = gauge_bar_color(pct);
                                    let color = gauge_color(pct);
                                    let ring_color_cls = match color {
                                        "red" => "text-red-600",
                                        "yellow" => "text-amber-600",
                                        _ => "text-emerald-600",
                                    };
                                    rsx! {
                                        div { class: "glass-card rounded-2xl p-5",
                                            div { class: "flex items-start justify-between",
                                                div { class: "flex-1",
                                                    div { class: "flex items-center gap-3 mb-1",
                                                        div { class: "w-10 h-10 bg-black/[0.04] rounded-xl flex items-center justify-center",
                                                            Icon { name: "hard-drive", class: "w-5 h-5 text-gray-500".to_string() }
                                                        }
                                                        div {
                                                            h4 { class: "text-sm font-semibold text-gray-900", "{disk.mount}" }
                                                            p { class: "text-xs text-gray-400", "{disk.device}" }
                                                        }
                                                    }

                                                    div { class: "mt-4",
                                                        div { class: "flex items-center justify-between mb-1.5",
                                                            span { class: "text-xs text-gray-500", "{disk.used_gb:.1} GB used" }
                                                            span { class: "text-xs font-semibold {ring_color_cls}", "{pct}%" }
                                                        }
                                                        div { class: "w-full bg-gray-100 rounded-full h-2",
                                                            div { class: "h-2 rounded-full {bar_color} transition-all", style: "width: {pct}%" }
                                                        }
                                                        div { class: "flex items-center justify-between mt-1.5",
                                                            span { class: "text-xs text-gray-400", "{disk.avail_gb:.1} GB free" }
                                                            span { class: "text-xs text-gray-400", "{disk.total_gb:.1} GB total" }
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
                }
            },
            Some(Err(e)) => rsx! {
                div { class: "bg-red-50 border border-red-200 text-red-600 p-4 rounded-xl text-sm", "Error: {e}" }
            },
            None => rsx! {
                div { class: "space-y-4",
                    for _ in 0..3 {
                        div { class: "glass-card rounded-2xl p-5 animate-pulse h-32" }
                    }
                }
            },
        }
    }
}

// ── History Tab (Load, Disk I/O, Traffic) ────────────────────────

/// A timestamped data point in a ring buffer.
#[derive(Clone, Debug)]
struct HistoryPoint {
    #[allow(dead_code)]
    ts_ms: u64,
    /// CPU load average (1 min)
    load1: f64,
    /// CPU load average (5 min)
    load5: f64,
    /// Disk read bytes/sec (first real device)
    disk_read_bps: f64,
    /// Disk write bytes/sec
    disk_write_bps: f64,
    /// Network RX bytes/sec (first non-lo iface)
    net_rx_bps: f64,
    /// Network TX bytes/sec
    net_tx_bps: f64,
}

const HISTORY_MAX: usize = 60;

/// Platform-agnostic async sleep.
#[cfg(target_arch = "wasm32")]
async fn history_sleep_ms(ms: u32) {
    gloo_timers::future::TimeoutFuture::new(ms).await;
}

#[cfg(not(target_arch = "wasm32"))]
async fn history_sleep_ms(ms: u32) {
    tokio::time::sleep(tokio::time::Duration::from_millis(ms as u64)).await;
}

#[component]
fn MonitoringHistory() -> Element {
    let mut history: Signal<Vec<HistoryPoint>> = use_signal(Vec::new);
    let error: Signal<Option<String>> = use_signal(|| None);
    let loading: Signal<bool> = use_signal(|| false);
    // Whether auto-polling is currently active.
    let mut auto_poll: Signal<bool> = use_signal(|| false);
    // Polling interval in seconds (5, 10, 30, or 60).
    let mut interval_secs: Signal<u32> = use_signal(|| 5);

    // ── shared poll logic ────────────────────────────────────────
    let do_one_sample = {
        let history = history;
        let mut error = error;
        let mut loading = loading;
        move || {
            loading.set(true);
            error.set(None);
            let mut history = history;
            let mut error = error;
            let mut loading = loading;
            spawn(async move {
                let metrics_res = server_get_system_metrics().await;
                let disk_res = server_get_disk_io().await;
                let net_res = server_get_network_rates().await;

                let ts_ms = disk_res.as_ref().map(|d| d.timestamp_ms).unwrap_or(0);

                let disk_read_bps = disk_res
                    .as_ref()
                    .ok()
                    .and_then(|d| d.devices.iter().find(|dev| !dev.name.contains("dm-")))
                    .map(|d| d.read_bps)
                    .unwrap_or(0.0);
                let disk_write_bps = disk_res
                    .as_ref()
                    .ok()
                    .and_then(|d| d.devices.iter().find(|dev| !dev.name.contains("dm-")))
                    .map(|d| d.write_bps)
                    .unwrap_or(0.0);
                let net_rx_bps = net_res
                    .as_ref()
                    .ok()
                    .and_then(|n| n.interfaces.first())
                    .map(|i| i.rx_bps)
                    .unwrap_or(0.0);
                let net_tx_bps = net_res
                    .as_ref()
                    .ok()
                    .and_then(|n| n.interfaces.first())
                    .map(|i| i.tx_bps)
                    .unwrap_or(0.0);
                let (load1, load5) = metrics_res
                    .as_ref()
                    .ok()
                    .map(|m| (m.load_1, m.load_5))
                    .unwrap_or((0.0, 0.0));

                if let Err(e) = &disk_res {
                    error.set(Some(e.to_string()));
                }
                if let Err(e) = &net_res {
                    error.set(Some(e.to_string()));
                }

                let pt = HistoryPoint {
                    ts_ms,
                    load1,
                    load5,
                    disk_read_bps,
                    disk_write_bps,
                    net_rx_bps,
                    net_tx_bps,
                };
                let mut h = history.write();
                h.push(pt);
                let cur_len = h.len();
                if cur_len > HISTORY_MAX {
                    h.drain(0..cur_len - HISTORY_MAX);
                }
                drop(h);
                loading.set(false);
            });
        }
    };

    // ── auto-poll coroutine ───────────────────────────────────────
    // Kick off (or stop) the auto-poll loop whenever auto_poll / interval changes.
    use_effect(move || {
        if !auto_poll() {
            return;
        }
        let interval = interval_secs();
        let auto_poll = auto_poll;
        let mut do_sample = do_one_sample;
        spawn(async move {
            loop {
                if !auto_poll() {
                    break;
                }
                do_sample();
                history_sleep_ms(interval * 1000).await;
                if !auto_poll() {
                    break;
                }
            }
        });
    });

    let data = history.read();

    rsx! {
        div { class: "space-y-6",
            // ── Toolbar ──────────────────────────────────────────
            div { class: "flex flex-wrap items-center justify-between gap-3",
                div { class: "flex items-center gap-2",
                    Icon { name: "trending-up", class: "w-4 h-4 text-gray-400".to_string() }
                    span { class: "text-sm font-medium text-gray-700",
                        "History — last {data.len()} of {HISTORY_MAX} samples"
                    }
                    if let Some(err) = error() {
                        span { class: "text-xs text-red-600 ml-2", "⚠ {err}" }
                    }
                }

                div { class: "flex items-center gap-2 flex-wrap",
                    // Interval selector
                    span { class: "text-xs text-gray-500", "Interval:" }
                    for secs in [5u32, 10, 30, 60] {
                        {
                            let active = interval_secs() == secs;
                            let cls = if active {
                                "px-2.5 py-1 text-xs font-semibold rounded-lg bg-blue-600 text-white"
                            } else {
                                "px-2.5 py-1 text-xs font-medium rounded-lg bg-black/[0.04] text-gray-600 hover:bg-gray-200 disabled:opacity-50"
                            };
                            let label = if secs < 60 { format!("{secs}s") } else { "1m".to_string() };
                            rsx! {
                                button {
                                    class: "{cls}",
                                    disabled: auto_poll(),
                                    onclick: move |_| { interval_secs.set(secs); },
                                    "{label}"
                                }
                            }
                        }
                    }

                    // Auto-poll toggle
                    {
                        let (cls, icon, label) = if auto_poll() {
                            ("flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-red-100 text-red-700 hover:bg-red-200 transition-colors", "pause", "Stop")
                        } else {
                            ("flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-emerald-500/[0.08] text-green-700 hover:bg-green-200 transition-colors", "play", "Auto")
                        };
                        rsx! {
                            button {
                                class: "{cls}",
                                onclick: move |_| {
                                    let new_state = !auto_poll();
                                    auto_poll.set(new_state);
                                },
                                Icon { name: icon, class: "w-3.5 h-3.5".to_string() }
                                "{label}"
                            }
                        }
                    }

                    // Manual sample
                    button {
                        class: "flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-blue-500/[0.08] text-blue-700 hover:bg-blue-100 transition-colors disabled:opacity-50",
                        disabled: loading(),
                        onclick: {
                            let mut do_sample = do_one_sample;
                            move |_| do_sample()
                        },
                        Icon { name: "activity", class: "w-3.5 h-3.5".to_string() }
                        if loading() { "Sampling…" } else { "Sample" }
                    }

                    // Clear
                    if !data.is_empty() {
                        button {
                            class: "flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-xl bg-black/[0.04] text-gray-600 hover:bg-gray-200 transition-colors",
                            onclick: move |_| { history.write().clear(); },
                            Icon { name: "trash-2", class: "w-3.5 h-3.5".to_string() }
                            "Clear"
                        }
                    }
                }
            }

            if data.is_empty() {
                div { class: "glass-card rounded-2xl p-16 text-center",
                    Icon { name: "trending-up", class: "w-12 h-12 text-gray-200 mx-auto mb-3".to_string() }
                    p { class: "text-gray-500 font-medium", "No history yet" }
                    p { class: "text-sm text-gray-400 mt-1",
                        "Press 'Auto' to start polling every {interval_secs()}s, or 'Sample' to take a single snapshot."
                    }
                }
            } else {
                // ── Historical Load Average Graph ─────────────────
                {
                    let max_load = data.iter().map(|p| p.load1.max(p.load5)).fold(0.0_f64, f64::max).max(1.0);
                    let load1_vals: Vec<f64> = data.iter().map(|p| p.load1).collect();
                    let load5_vals: Vec<f64> = data.iter().map(|p| p.load5).collect();
                    let window_secs = (data.len().saturating_sub(1)) as u32 * interval_secs();
                    rsx! {
                        LineChartCard {
                            title: "CPU Load Average".to_string(),
                            icon: "activity",
                            window_secs,
                            series: vec![
                                ChartSeries { label: "1 min".to_string(), color: "#3b82f6".to_string(), values: load1_vals },
                                ChartSeries { label: "5 min".to_string(), color: "#a78bfa".to_string(), values: load5_vals },
                            ],
                            y_max: max_load,
                            y_unit: "".to_string(),
                            format_y: false,
                        }
                    }
                }

                // ── Historical Disk I/O Graph ─────────────────────
                {
                    let max_io = data.iter().map(|p| p.disk_read_bps.max(p.disk_write_bps)).fold(0.0_f64, f64::max).max(1024.0);
                    let read_vals: Vec<f64> = data.iter().map(|p| p.disk_read_bps).collect();
                    let write_vals: Vec<f64> = data.iter().map(|p| p.disk_write_bps).collect();
                    let window_secs = (data.len().saturating_sub(1)) as u32 * interval_secs();
                    rsx! {
                        LineChartCard {
                            title: "Disk I/O".to_string(),
                            icon: "hard-drive",
                            window_secs,
                            series: vec![
                                ChartSeries { label: "Read".to_string(), color: "#10b981".to_string(), values: read_vals },
                                ChartSeries { label: "Write".to_string(), color: "#f59e0b".to_string(), values: write_vals },
                            ],
                            y_max: max_io,
                            y_unit: "/s".to_string(),
                            format_y: true,
                        }
                    }
                }

                // ── Historical Traffic Graph ──────────────────────
                {
                    let max_net = data.iter().map(|p| p.net_rx_bps.max(p.net_tx_bps)).fold(0.0_f64, f64::max).max(1024.0);
                    let rx_vals: Vec<f64> = data.iter().map(|p| p.net_rx_bps).collect();
                    let tx_vals: Vec<f64> = data.iter().map(|p| p.net_tx_bps).collect();
                    let window_secs = (data.len().saturating_sub(1)) as u32 * interval_secs();
                    rsx! {
                        LineChartCard {
                            title: "Network Traffic".to_string(),
                            icon: "wifi",
                            window_secs,
                            series: vec![
                                ChartSeries { label: "RX".to_string(), color: "#22c55e".to_string(), values: rx_vals },
                                ChartSeries { label: "TX".to_string(), color: "#3b82f6".to_string(), values: tx_vals },
                            ],
                            y_max: max_net,
                            y_unit: "/s".to_string(),
                            format_y: true,
                        }
                    }
                }
            }
        }
    }
}

// ── SVG Line Chart ────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
struct ChartSeries {
    label: String,
    /// Hex color, e.g. "#3b82f6"
    color: String,
    values: Vec<f64>,
}

#[component]
fn LineChartCard(
    title: String,
    icon: &'static str,
    /// Total window duration in seconds (used for the X-axis left label).
    /// Pass 0 to show sample-count-based label instead.
    window_secs: u32,
    series: Vec<ChartSeries>,
    y_max: f64,
    y_unit: String,
    format_y: bool,
) -> Element {
    let w: f64 = 600.0;
    let h: f64 = 140.0;
    let pad_l: f64 = 58.0;
    let pad_r: f64 = 12.0;
    let pad_t: f64 = 12.0;
    let pad_b: f64 = 28.0;

    let n = series.first().map(|s| s.values.len()).unwrap_or(0);
    let chart_w = w - pad_l - pad_r;
    let chart_h = h - pad_t - pad_b;

    // Build SVG polyline path for each series
    let make_path = |values: &[f64]| -> String {
        if values.len() < 2 {
            return String::new();
        }
        values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let x = pad_l + (i as f64 / (values.len() - 1).max(1) as f64) * chart_w;
                let y = pad_t + chart_h - (v / y_max).clamp(0.0, 1.0) * chart_h;
                format!("{:.1},{:.1}", x, y)
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    // Y-axis labels (0, 50%, 100% of max)
    let fmt_val = |v: f64| -> String {
        if format_y {
            format_bytes(v as u64)
        } else {
            format!("{:.2}", v)
        }
    };

    let y_labels: Vec<(f64, String)> = vec![
        (pad_t + chart_h, fmt_val(0.0)),
        (pad_t + chart_h / 2.0, fmt_val(y_max / 2.0)),
        (pad_t, fmt_val(y_max)),
    ];

    // X-axis labels: oldest time on the left, "now" on the right
    let x_labels: Vec<(f64, String)> = if n > 1 {
        let left_label = if window_secs == 0 {
            format!("-{}pts", n - 1)
        } else if window_secs >= 60 {
            format!("-{}m", window_secs / 60)
        } else {
            format!("-{}s", window_secs)
        };
        vec![(pad_l, left_label), (pad_l + chart_w, "now".to_string())]
    } else {
        vec![]
    };

    let latest: Vec<String> = series
        .iter()
        .map(|s| {
            let v = s.values.last().copied().unwrap_or(0.0);
            if format_y {
                format!("{}{}", format_bytes(v as u64), y_unit)
            } else {
                format!("{:.2}{}", v, y_unit)
            }
        })
        .collect();

    rsx! {
        div { class: "glass-card rounded-2xl p-5",
            // Header
            div { class: "flex items-center justify-between mb-4",
                div { class: "flex items-center gap-2",
                    Icon { name: icon, class: "w-4 h-4 text-gray-400".to_string() }
                    h3 { class: "text-sm font-semibold text-gray-900", "{title}" }
                }
                // Legend + latest values
                div { class: "flex items-center gap-4 flex-wrap",
                    for (i, s) in series.iter().enumerate() {
                        div { class: "flex items-center gap-1.5",
                            // Colored line swatch using inline style to avoid Tailwind stroke issues
                            div {
                                style: "width: 12px; height: 2px; border-radius: 1px; background: {s.color};",
                            }
                            span { class: "text-xs text-gray-500", "{s.label}" }
                            span { class: "text-xs font-medium text-gray-700",
                                { latest.get(i).cloned().unwrap_or_default() }
                            }
                        }
                    }
                }
            }

            // SVG chart
            svg {
                class: "w-full",
                "viewBox": format!("0 0 {} {}", w, h),
                "preserveAspectRatio": "none",

                // Grid lines
                for i in 0..=4 {
                    {
                        let y = pad_t + (i as f64 / 4.0) * chart_h;
                        rsx! {
                            line {
                                x1: "{pad_l}", y1: "{y}",
                                x2: "{pad_l + chart_w}", y2: "{y}",
                                stroke: "#f3f4f6", "stroke-width": "1",
                            }
                        }
                    }
                }

                // Y-axis labels
                for (y, label) in y_labels.iter() {
                    text {
                        x: "{pad_l - 4.0}",
                        y: "{y + 3.5}",
                        "text-anchor": "end",
                        "font-size": "9",
                        fill: "#9ca3af",
                        "{label}"
                    }
                }

                // X-axis labels
                for (x, label) in x_labels.iter() {
                    {
                        let anchor = if label == "now" { "end" } else { "start" };
                        rsx! {
                            text {
                                x: "{x}",
                                y: "{h - 6.0}",
                                "text-anchor": anchor,
                                "font-size": "9",
                                fill: "#9ca3af",
                                "{label}"
                            }
                        }
                    }
                }

                // Data lines — use inline style for stroke color
                for s in series.iter() {
                    {
                        let path = make_path(&s.values);
                        let stroke_style = format!(
                            "fill: none; stroke: {}; stroke-width: 1.5px; stroke-linejoin: round; stroke-linecap: round;",
                            s.color
                        );
                        if path.is_empty() {
                            rsx! {}
                        } else {
                            rsx! {
                                polyline {
                                    points: "{path}",
                                    style: "{stroke_style}",
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Processes Tab ────────────────────────────────────────────────

#[component]
fn MonitoringProcesses() -> Element {
    let mut procs = use_resource(move || async move { server_get_top_processes(50).await });
    let mut confirm_kill: Signal<Option<(u32, String)>> = use_signal(|| None);
    let mut kill_error = use_signal(|| None::<String>);
    let kill_loading = use_signal(|| false);
    let mut sort_by = use_signal(|| "cpu");

    rsx! {
        div { class: "space-y-5",
            // Toolbar
            div { class: "flex items-center justify-between",
                div { class: "flex items-center gap-2",
                    span { class: "text-sm text-gray-500", "Sort by:" }
                    button {
                        class: if sort_by() == "cpu" { "px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-100 text-blue-700" } else { "px-3 py-1.5 text-xs font-medium rounded-lg bg-black/[0.04] text-gray-600 hover:bg-gray-200" },
                        onclick: move |_| sort_by.set("cpu"),
                        "CPU %"
                    }
                    button {
                        class: if sort_by() == "mem" { "px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-100 text-blue-700" } else { "px-3 py-1.5 text-xs font-medium rounded-lg bg-black/[0.04] text-gray-600 hover:bg-gray-200" },
                        onclick: move |_| sort_by.set("mem"),
                        "Memory"
                    }
                }
                button {
                    class: "flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors",
                    onclick: move |_| { procs.restart(); },
                    Icon { name: "refresh-cw", class: "w-4 h-4".to_string() }
                    "Refresh"
                }
            }

            // Kill error banner
            if let Some(err) = kill_error() {
                div { class: "bg-red-50 border border-red-200 text-red-700 p-3 rounded-xl text-sm flex items-center justify-between",
                    div { class: "flex items-center gap-2",
                        Icon { name: "alert-triangle", class: "w-4 h-4".to_string() }
                        span { "{err}" }
                    }
                    button {
                        class: "text-red-400 hover:text-red-600",
                        onclick: move |_| kill_error.set(None),
                        Icon { name: "x", class: "w-4 h-4".to_string() }
                    }
                }
            }

            // Confirm kill dialog
            if let Some((pid, name)) = confirm_kill() {
                div { class: "fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4",
                    div { class: "bg-white rounded-2xl p-6 max-w-sm w-full shadow-2xl",
                        div { class: "flex items-center gap-3 mb-4",
                            div { class: "p-2 bg-red-100 rounded-xl",
                                Icon { name: "alert-triangle", class: "w-5 h-5 text-red-600".to_string() }
                            }
                            h3 { class: "text-base font-semibold text-gray-900", "Kill process?" }
                        }
                        p { class: "text-sm text-gray-600 mb-2",
                            "Send SIGTERM to "
                            span { class: "font-mono font-medium text-gray-900", "{name}" }
                            " (PID {pid})?"
                        }
                        p { class: "text-xs text-gray-400 mb-5", "Use force kill only if the process ignores SIGTERM." }
                        div { class: "flex items-center gap-3 justify-end",
                            button {
                                class: "px-4 py-2 text-sm font-medium text-gray-700 bg-black/[0.04] rounded-xl hover:bg-gray-200 transition-colors",
                                onclick: move |_| confirm_kill.set(None),
                                "Cancel"
                            }
                            {
                                let mut procs2 = procs;
                                let mut confirm_kill2 = confirm_kill;
                                let mut kill_error2 = kill_error;
                                let mut kill_loading2 = kill_loading;
                                rsx! {
                                    button {
                                        class: "px-4 py-2 text-sm font-medium text-white bg-amber-500 rounded-xl hover:bg-amber-600 transition-colors disabled:opacity-60",
                                        disabled: kill_loading(),
                                        onclick: move |_| {
                                            kill_loading2.set(true);
                                            let (p, _) = confirm_kill2().unwrap();
                                            spawn(async move {
                                                match server_kill_process(p, false).await {
                                                    Ok(_) => { confirm_kill2.set(None); procs2.restart(); }
                                                    Err(e) => { kill_error2.set(Some(e.to_string())); confirm_kill2.set(None); }
                                                }
                                                kill_loading2.set(false);
                                            });
                                        },
                                        "SIGTERM"
                                    }
                                }
                            }
                            {
                                let mut procs3 = procs;
                                let mut confirm_kill3 = confirm_kill;
                                let mut kill_error3 = kill_error;
                                let mut kill_loading3 = kill_loading;
                                rsx! {
                                    button {
                                        class: "px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-xl hover:bg-red-700 transition-colors disabled:opacity-60",
                                        disabled: kill_loading(),
                                        onclick: move |_| {
                                            kill_loading3.set(true);
                                            let (p, _) = confirm_kill3().unwrap();
                                            spawn(async move {
                                                match server_kill_process(p, true).await {
                                                    Ok(_) => { confirm_kill3.set(None); procs3.restart(); }
                                                    Err(e) => { kill_error3.set(Some(e.to_string())); confirm_kill3.set(None); }
                                                }
                                                kill_loading3.set(false);
                                            });
                                        },
                                        "Force Kill (SIGKILL)"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Process table
            div { class: "glass-card rounded-2xl overflow-hidden",
                match &*procs.read() {
                    Some(Ok(list)) => {
                        let mut sorted = list.clone();
                        if sort_by() == "mem" {
                            sorted.sort_by(|a, b| b.mem_mb.partial_cmp(&a.mem_mb).unwrap_or(std::cmp::Ordering::Equal));
                        } else {
                            sorted.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(std::cmp::Ordering::Equal));
                        }
                        rsx! {
                            table { class: "w-full text-sm",
                                thead { class: "bg-gray-50 border-b border-gray-200",
                                    tr {
                                        th { class: "px-4 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider w-16", "PID" }
                                        th { class: "px-4 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Name" }
                                        th { class: "px-4 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "User" }
                                        th { class: "px-4 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider w-10", "St" }
                                        th { class: "px-4 py-3 text-right text-[11px] font-semibold text-gray-500 uppercase tracking-wider w-20", "CPU %" }
                                        th { class: "px-4 py-3 text-right text-[11px] font-semibold text-gray-500 uppercase tracking-wider w-24", "Memory" }
                                        th { class: "px-4 py-3 text-right text-[11px] font-semibold text-gray-500 uppercase tracking-wider w-16", "Threads" }
                                        th { class: "px-4 py-3 text-right text-[11px] font-semibold text-gray-500 uppercase tracking-wider w-20", "Action" }
                                    }
                                }
                                tbody { class: "divide-y divide-gray-50",
                                    for proc in sorted.iter() {
                                        {
                                            let pid = proc.pid;
                                            let name = proc.name.clone();
                                            let name2 = name.clone();
                                            let cpu = proc.cpu_pct;
                                            let mem = proc.mem_mb;
                                            let mem_pct = proc.mem_pct;
                                            let threads = proc.threads;
                                            let user = proc.user.clone();
                                            let state = proc.state.clone();
                                            let cpu_bar_w = (cpu / 200.0 * 100.0).clamp(0.5, 100.0);
                                            let mem_bar_w = mem_pct.clamp(0.5, 100.0);
                                            let state_color = match state.as_str() {
                                                "R" => "text-green-600",
                                                "S" | "I" => "text-gray-400",
                                                "D" => "text-amber-600",
                                                "Z" => "text-red-600",
                                                _ => "text-gray-400",
                                            };
                                            let mut confirm_kill = confirm_kill;
                                            rsx! {
                                                tr { class: "hover:bg-gray-50/60 transition-colors",
                                                    td { class: "px-4 py-2.5 font-mono text-xs text-gray-400", "{pid}" }
                                                    td { class: "px-4 py-2.5 font-medium text-gray-900 max-w-[160px] truncate", "{name}" }
                                                    td { class: "px-4 py-2.5 text-xs text-gray-500", "{user}" }
                                                    td { class: "px-4 py-2.5 text-xs font-bold {state_color}", "{state}" }
                                                    td { class: "px-4 py-2.5 text-right",
                                                        div { class: "flex items-center justify-end gap-2",
                                                            div { class: "w-16 bg-gray-100 rounded-full h-1.5 hidden sm:block",
                                                                div { class: "h-1.5 rounded-full bg-blue-500", style: "width: {cpu_bar_w:.1}%" }
                                                            }
                                                            span { class: "text-xs font-mono text-gray-700 w-12 text-right", "{cpu:.1}%" }
                                                        }
                                                    }
                                                    td { class: "px-4 py-2.5 text-right",
                                                        div { class: "flex items-center justify-end gap-2",
                                                            div { class: "w-16 bg-gray-100 rounded-full h-1.5 hidden sm:block",
                                                                div { class: "h-1.5 rounded-full bg-violet-500", style: "width: {mem_bar_w:.1}%" }
                                                            }
                                                            span { class: "text-xs font-mono text-gray-700",
                                                                {if mem >= 1024.0 { format!("{:.1}G", mem / 1024.0) } else { format!("{:.0}M", mem) }}
                                                            }
                                                        }
                                                    }
                                                    td { class: "px-4 py-2.5 text-xs text-gray-500 text-right", "{threads}" }
                                                    td { class: "px-4 py-2.5 text-right",
                                                        button {
                                                            class: "px-2.5 py-1 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 rounded-xl transition-all duration-200",
                                                            onclick: move |_| { confirm_kill.set(Some((pid, name2.clone()))); },
                                                            "Kill"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if list.is_empty() {
                                p { class: "p-6 text-center text-sm text-gray-500", "No processes found." }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div { class: "p-6 text-red-600 text-sm flex items-center gap-2",
                            Icon { name: "alert-triangle", class: "w-4 h-4".to_string() }
                            "Error: {e}"
                        }
                    },
                    None => rsx! {
                        div { class: "p-6 text-[13px] text-gray-500 animate-pulse", "Loading processes…" }
                    },
                }
            }
        }
    }
}

// ── Services Tab ─────────────────────────────────────────────────

#[component]
fn MonitoringServicesTab() -> Element {
    let services = use_resource(move || async move { server_get_services_status().await });
    let mut action_error = use_signal(|| None::<String>);

    rsx! {
        div { class: "space-y-5",
            if let Some(err) = action_error() {
                div { class: "bg-red-50 border border-red-200 text-red-700 p-3 rounded-xl text-sm flex items-center justify-between",
                    span { "{err}" }
                    button {
                        class: "text-red-400 hover:text-red-600",
                        onclick: move |_| action_error.set(None),
                        Icon { name: "x", class: "w-4 h-4".to_string() }
                    }
                }
            }

            // DNS Provider
            div { class: "glass-card rounded-2xl p-5",
                div { class: "flex items-center gap-4",
                    div { class: "p-3 bg-orange-50 rounded-xl text-orange-500",
                        Icon { name: "globe", class: "w-7 h-7".to_string() }
                    }
                    div {
                        h4 { class: "font-semibold text-gray-900", "Cloudflare DNS" }
                        p { class: "text-sm text-gray-500", "DNS zones are managed via the Cloudflare API." }
                    }
                }
            }

            // Services Table
            div { class: "glass-card rounded-2xl overflow-hidden",
                match &*services.read() {
                    Some(Ok(list)) => rsx! {
                        table { class: "w-full",
                            thead { class: "bg-gray-50 border-b border-gray-200",
                                tr {
                                    th { class: "px-5 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Service" }
                                    th { class: "px-5 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Status" }
                                    th { class: "px-5 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Port" }
                                    th { class: "px-5 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Version" }
                                    th { class: "px-5 py-3 text-right text-[11px] font-semibold text-gray-500 uppercase tracking-wider", "Actions" }
                                }
                            }
                            tbody { class: "divide-y divide-black/[0.04]",
                                for svc in list.iter() {
                                    {
                                        let svc_type = svc.service_type;
                                        let status = svc.status;
                                        let port_str = svc.port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string());
                                        let version_str = svc.version.clone().unwrap_or_else(|| "—".to_string());
                                        let is_stoppable = status == ServiceStatus::Running;
                                        let is_startable = status == ServiceStatus::Stopped || status == ServiceStatus::Unknown;

                                        rsx! {
                                            tr { class: "hover:bg-black/[0.02] transition-colors",
                                                td { class: "px-5 py-3.5",
                                                    div { class: "flex items-center gap-3",
                                                        div { class: "w-2 h-2 rounded-full {status_dot_color(status)}" }
                                                        span { class: "text-sm font-medium text-gray-900", "{svc_type}" }
                                                    }
                                                }
                                                td { class: "px-5 py-3.5",
                                                    StatusBadge { status: status.to_string() }
                                                }
                                                td { class: "px-5 py-3.5 text-sm text-gray-500", "{port_str}" }
                                                td { class: "px-5 py-3.5 text-sm text-gray-500 max-w-[200px] truncate", "{version_str}" }
                                                td { class: "px-5 py-3.5 text-right",
                                                    div { class: "flex items-center justify-end gap-2",
                                                        if is_startable {
                                                            {
                                                                let mut services = services;
                                                                let mut action_error = action_error;
                                                                rsx! {
                                                                    button {
                                                                        class: "px-3 py-1.5 text-xs font-medium text-green-700 bg-green-50 hover:bg-emerald-500/[0.08] rounded-xl transition-all duration-200",
                                                                        onclick: move |_| {
                                                                            spawn(async move {
                                                                                let action = ServiceAction { service: svc_type, action: ServiceCommand::Start };
                                                                                match server_manage_service(action).await {
                                                                                    Ok(_) => services.restart(),
                                                                                    Err(e) => action_error.set(Some(e.to_string())),
                                                                                }
                                                                            });
                                                                        },
                                                                        "Start"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if is_stoppable {
                                                            {
                                                                let mut services = services;
                                                                let mut action_error = action_error;
                                                                rsx! {
                                                                    button {
                                                                        class: "px-3 py-1.5 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 rounded-xl transition-all duration-200",
                                                                        onclick: move |_| {
                                                                            spawn(async move {
                                                                                let action = ServiceAction { service: svc_type, action: ServiceCommand::Stop };
                                                                                match server_manage_service(action).await {
                                                                                    Ok(_) => services.restart(),
                                                                                    Err(e) => action_error.set(Some(e.to_string())),
                                                                                }
                                                                            });
                                                                        },
                                                                        "Stop"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        {
                                                            let mut services = services;
                                                            let mut action_error = action_error;
                                                            rsx! {
                                                                button {
                                                                    class: "px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-xl transition-all duration-200",
                                                                    onclick: move |_| {
                                                                        spawn(async move {
                                                                            let action = ServiceAction { service: svc_type, action: ServiceCommand::Restart };
                                                                            match server_manage_service(action).await {
                                                                                Ok(_) => services.restart(),
                                                                                Err(e) => action_error.set(Some(e.to_string())),
                                                                            }
                                                                        });
                                                                    },
                                                                    "Restart"
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
                        }
                        if list.is_empty() {
                            p { class: "p-6 text-gray-500 text-center", "No services detected." }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "p-6 text-red-600 text-sm", "Error: {e}" } },
                    None => rsx! { p { class: "p-6 text-[13px] text-gray-500", "Loading services..." } },
                }
            }
        }
    }
}

fn status_dot_color(status: ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::Running => "bg-green-500",
        ServiceStatus::Stopped => "bg-red-500",
        ServiceStatus::Error => "bg-red-500",
        ServiceStatus::Unknown => "bg-yellow-500",
    }
}
