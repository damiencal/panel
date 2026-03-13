#![allow(non_snake_case)]
use dioxus::prelude::*;
use panel::server::*;
use crate::lucide::Icon;

#[component]
pub fn ClientGit() -> Element {
    let sites = use_resource(move || async move { server_list_sites().await });
    let mut selected_site_id = use_signal(|| 0i64);

    let mut repo_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(None);
            }
            server_get_site_git_repo(sid).await
        }
    });
    let mut status_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(String::new());
            }
            server_git_status(sid).await
        }
    });
    let mut branches_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(vec![]);
            }
            server_git_branches(sid).await
        }
    });
    let mut log_resource = use_resource(move || {
        let sid = selected_site_id();
        async move {
            if sid == 0 {
                return Ok(vec![]);
            }
            server_git_log(sid, 50).await
        }
    });

    let mut attach_url = use_signal(String::new);
    let mut attach_branch = use_signal(|| "main".to_string());
    let mut attach_error = use_signal(|| None::<String>);
    let mut attaching = use_signal(|| false);

    let mut active_tab = use_signal(|| "status".to_string());
    let mut commit_msg = use_signal(String::new);
    let mut action_output = use_signal(|| None::<String>);
    let mut action_error = use_signal(|| None::<String>);
    let mut action_loading = use_signal(|| false);
    let mut new_deploy_key = use_signal(|| None::<String>);

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "mb-6",
                h2 { class: "text-2xl font-bold text-gray-900", "Git Integration" }
                p { class: "text-gray-500 text-sm mt-1", "Attach and manage Git repositories for your websites." }
            }

            // ── Site selector ──
            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-6",
                label { class: "block text-sm font-medium text-gray-700 mb-2", "Select Website" }
                match &*sites.read() {
                    Some(Ok(site_list)) => rsx! {
                        select {
                            class: "w-full max-w-sm px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 bg-white text-sm",
                            value: "{selected_site_id}",
                            onchange: move |e| {
                                let val: i64 = e.value().parse().unwrap_or(0);
                                selected_site_id.set(val);
                                action_output.set(None);
                                action_error.set(None);
                                new_deploy_key.set(None);
                                active_tab.set("status".to_string());
                            },
                            option { value: "0", disabled: true, "-- Choose a website --" }
                            for s in site_list.iter() {
                                option { value: "{s.id}", "{s.domain}" }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { p { class: "text-red-600 text-sm", "Error loading sites: {e}" } },
                    None => rsx! { p { class: "text-gray-500 text-sm", "Loading sites..." } },
                }
            }

            // ── Git panel (only when a site is chosen) ──
            if selected_site_id() != 0 {
                match &*repo_resource.read() {
                    // ── No repo attached ──────────────────────────────────────────────
                    Some(Ok(None)) => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-10",
                            div { class: "text-center mb-8",
                                div { class: "mx-auto w-14 h-14 rounded-2xl bg-rose-50 flex items-center justify-center mb-4",
                                    Icon { name: "git-branch", class: "w-7 h-7 text-rose-500".to_string() }
                                }
                                h3 { class: "text-lg font-semibold text-gray-800 mb-1", "No Repository Attached" }
                                p { class: "text-gray-500 text-sm", "Attach a Git repository to deploy and manage your site's code." }
                            }
                            if let Some(ref err) = attach_error() {
                                div { class: "max-w-lg mx-auto bg-red-50 border border-red-200 text-red-700 p-3 rounded-lg mb-4 text-sm", "{err}" }
                            }
                            form {
                                onsubmit: move |ev: FormEvent| {
                                    ev.prevent_default();
                                    attaching.set(true);
                                    attach_error.set(None);
                                    let sid = selected_site_id();
                                    let url = attach_url();
                                    let br = attach_branch();
                                    spawn(async move {
                                        match server_attach_git_repo(sid, url, br).await {
                                            Ok(()) => repo_resource.restart(),
                                            Err(e) => attach_error.set(Some(e.to_string())),
                                        }
                                        attaching.set(false);
                                    });
                                },
                                class: "max-w-lg mx-auto space-y-4",
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Repository URL" }
                                    input {
                                        r#type: "text",
                                        class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm",
                                        placeholder: "https://github.com/user/repo.git  or  git@github.com:user/repo.git",
                                        value: "{attach_url}",
                                        oninput: move |e| attach_url.set(e.value()),
                                        required: true,
                                    }
                                }
                                div {
                                    label { class: "block text-sm font-medium text-gray-700 mb-1", "Branch" }
                                    input {
                                        r#type: "text",
                                        class: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-rose-500 text-sm",
                                        placeholder: "main",
                                        value: "{attach_branch}",
                                        oninput: move |e| attach_branch.set(e.value()),
                                        required: true,
                                    }
                                }
                                div { class: "flex justify-center pt-2",
                                    button {
                                        r#type: "submit",
                                        class: "px-8 py-2.5 bg-rose-500 hover:bg-rose-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50 text-sm",
                                        disabled: attaching(),
                                        if attaching() { "Attaching..." } else { "Attach Repository" }
                                    }
                                }
                            }
                        }
                    },

                    // ── Repo attached ─────────────────────────────────────────────────
                    Some(Ok(Some(repo))) => {
                        let repo = repo.clone();
                        rsx! {
                            // Repo info card
                            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-5",
                                div { class: "flex items-start justify-between gap-4 flex-wrap",
                                    div { class: "flex items-center gap-3",
                                        div { class: "w-10 h-10 rounded-xl bg-emerald-50 flex items-center justify-center shrink-0",
                                            Icon { name: "git-branch", class: "w-5 h-5 text-emerald-600".to_string() }
                                        }
                                        div {
                                            p { class: "font-semibold text-gray-900 text-sm break-all", "{repo.repo_url}" }
                                            p { class: "text-xs text-gray-500 mt-0.5",
                                                span { class: "font-medium text-gray-700", "Branch: " }
                                                "{repo.branch}"
                                                if let Some(ref hash) = repo.last_commit_hash {
                                                    span { class: "ml-3",
                                                        span { class: "font-medium text-gray-700", "Last: " }
                                                        span { class: "font-mono text-xs", "{&hash[..7.min(hash.len())]}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "flex gap-2 flex-wrap",
                                        button {
                                            class: "flex items-center gap-1.5 px-3 py-1.5 text-xs border border-gray-200 text-gray-600 hover:bg-gray-50 rounded-lg transition-colors",
                                            onclick: move |_| {
                                                let sid = selected_site_id();
                                                action_error.set(None);
                                                spawn(async move {
                                                    match server_git_generate_deploy_key(sid).await {
                                                        Ok(pub_key) => new_deploy_key.set(Some(pub_key)),
                                                        Err(e) => action_error.set(Some(e.to_string())),
                                                    }
                                                });
                                            },
                                            Icon { name: "key", class: "w-3.5 h-3.5".to_string() }
                                            "(Re)generate Deploy Key"
                                        }
                                        button {
                                            class: "flex items-center gap-1.5 px-3 py-1.5 text-xs border border-red-200 text-red-600 hover:bg-red-50 rounded-lg transition-colors",
                                            onclick: move |_| {
                                                let sid = selected_site_id();
                                                action_loading.set(true);
                                                action_error.set(None);
                                                action_output.set(None);
                                                new_deploy_key.set(None);
                                                spawn(async move {
                                                    match server_detach_git_repo(sid).await {
                                                        Ok(()) => {
                                                            repo_resource.restart();
                                                            status_resource.restart();
                                                            branches_resource.restart();
                                                            log_resource.restart();
                                                        }
                                                        Err(e) => action_error.set(Some(e.to_string())),
                                                    }
                                                    action_loading.set(false);
                                                });
                                            },
                                            Icon { name: "trash-2", class: "w-3.5 h-3.5".to_string() }
                                            "Detach"
                                        }
                                    }
                                }
                                // New deploy key freshly generated
                                if let Some(ref pub_key) = new_deploy_key() {
                                    div { class: "mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg",
                                        p { class: "text-xs font-semibold text-blue-800 mb-1.5",
                                            "Add this deploy key to your repository (GitHub → Settings → Deploy Keys → Add deploy key):"
                                        }
                                        pre { class: "text-xs text-blue-900 font-mono break-all whitespace-pre-wrap select-all", "{pub_key}" }
                                    }
                                // Existing deploy key stored on record
                                } else if let Some(ref pub_key) = repo.deploy_key_pub {
                                    div { class: "mt-4 p-3 bg-gray-50 border border-gray-200 rounded-lg",
                                        p { class: "text-xs font-semibold text-gray-700 mb-1", "Current deploy key (public):" }
                                        pre { class: "text-xs text-gray-700 font-mono break-all whitespace-pre-wrap select-all", "{pub_key}" }
                                    }
                                }
                            }

                            // Action bar
                            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-5 mb-5",
                                div { class: "flex items-start gap-3 flex-wrap",
                                    button {
                                        class: "flex items-center gap-1.5 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50",
                                        disabled: action_loading(),
                                        onclick: move |_| {
                                            let sid = selected_site_id();
                                            action_loading.set(true);
                                            action_error.set(None);
                                            action_output.set(None);
                                            spawn(async move {
                                                match server_git_pull(sid).await {
                                                    Ok(out) => {
                                                        action_output.set(Some(out));
                                                        status_resource.restart();
                                                        log_resource.restart();
                                                        repo_resource.restart();
                                                    }
                                                    Err(e) => action_error.set(Some(e.to_string())),
                                                }
                                                action_loading.set(false);
                                            });
                                        },
                                        Icon { name: "download", class: "w-4 h-4".to_string() }
                                        "Pull"
                                    }
                                    button {
                                        class: "flex items-center gap-1.5 px-4 py-2 bg-purple-500 hover:bg-purple-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50",
                                        disabled: action_loading(),
                                        onclick: move |_| {
                                            let sid = selected_site_id();
                                            action_loading.set(true);
                                            action_error.set(None);
                                            action_output.set(None);
                                            spawn(async move {
                                                match server_git_push(sid).await {
                                                    Ok(out) => {
                                                        action_output.set(Some(out));
                                                        log_resource.restart();
                                                    }
                                                    Err(e) => action_error.set(Some(e.to_string())),
                                                }
                                                action_loading.set(false);
                                            });
                                        },
                                        Icon { name: "upload", class: "w-4 h-4".to_string() }
                                        "Push"
                                    }
                                    div { class: "flex flex-1 gap-2 items-center min-w-[260px]",
                                        input {
                                            r#type: "text",
                                            class: "flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-rose-500",
                                            placeholder: "Commit message…",
                                            value: "{commit_msg}",
                                            oninput: move |e| commit_msg.set(e.value()),
                                        }
                                        button {
                                            class: "flex items-center gap-1.5 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 whitespace-nowrap",
                                            disabled: action_loading() || commit_msg().trim().is_empty(),
                                            onclick: move |_| {
                                                let sid = selected_site_id();
                                                let msg = commit_msg();
                                                action_loading.set(true);
                                                action_error.set(None);
                                                action_output.set(None);
                                                spawn(async move {
                                                    match server_git_commit_and_push(sid, msg).await {
                                                        Ok(out) => {
                                                            action_output.set(Some(out));
                                                            commit_msg.set(String::new());
                                                            status_resource.restart();
                                                            log_resource.restart();
                                                            repo_resource.restart();
                                                        }
                                                        Err(e) => action_error.set(Some(e.to_string())),
                                                    }
                                                    action_loading.set(false);
                                                });
                                            },
                                            Icon { name: "git-commit", class: "w-4 h-4".to_string() }
                                            "Commit & Push"
                                        }
                                    }
                                }
                                if let Some(ref out) = action_output() {
                                    div { class: "mt-3 p-3 bg-gray-950 rounded-lg",
                                        pre { class: "text-xs text-green-400 font-mono overflow-auto max-h-48 whitespace-pre-wrap", "{out}" }
                                    }
                                }
                                if let Some(ref err) = action_error() {
                                    div { class: "mt-3 p-3 bg-red-50 border border-red-200 rounded-lg",
                                        pre { class: "text-xs text-red-700 font-mono overflow-auto max-h-32 whitespace-pre-wrap", "{err}" }
                                    }
                                }
                            }

                            // Tabs
                            div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden",
                                div { class: "flex border-b border-gray-200",
                                    button {
                                        class: "flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 transition-colors",
                                        class: if active_tab() == "status" { "border-rose-500 text-rose-600" } else { "border-transparent text-gray-500 hover:text-gray-700" },
                                        onclick: move |_| active_tab.set("status".to_string()),
                                        Icon { name: "list", class: "w-4 h-4".to_string() }
                                        "Working Tree"
                                    }
                                    button {
                                        class: "flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 transition-colors",
                                        class: if active_tab() == "branches" { "border-rose-500 text-rose-600" } else { "border-transparent text-gray-500 hover:text-gray-700" },
                                        onclick: move |_| active_tab.set("branches".to_string()),
                                        Icon { name: "git-branch", class: "w-4 h-4".to_string() }
                                        "Branches"
                                    }
                                    button {
                                        class: "flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 transition-colors",
                                        class: if active_tab() == "history" { "border-rose-500 text-rose-600" } else { "border-transparent text-gray-500 hover:text-gray-700" },
                                        onclick: move |_| active_tab.set("history".to_string()),
                                        Icon { name: "clock", class: "w-4 h-4".to_string() }
                                        "Commit History"
                                    }
                                }

                                if active_tab() == "status" {
                                    div { class: "p-5",
                                        div { class: "flex items-center justify-between mb-3",
                                            p { class: "text-sm font-medium text-gray-700", "Uncommitted changes (git status)" }
                                            button {
                                                class: "text-xs text-rose-500 hover:text-rose-600 font-medium",
                                                onclick: move |_| status_resource.restart(),
                                                "↻ Refresh"
                                            }
                                        }
                                        match &*status_resource.read() {
                                            Some(Ok(s)) => rsx! {
                                                if s.trim().is_empty() {
                                                    div { class: "flex items-center gap-2 p-4 bg-green-50 border border-green-200 rounded-lg text-sm text-green-700",
                                                        Icon { name: "check-circle", class: "w-4 h-4 shrink-0".to_string() }
                                                        "Working tree is clean — nothing to commit."
                                                    }
                                                } else {
                                                    pre { class: "bg-gray-50 border border-gray-200 rounded-lg p-4 text-xs font-mono text-gray-800 overflow-auto max-h-64 whitespace-pre-wrap", "{s}" }
                                                }
                                            },
                                            Some(Err(e)) => rsx! { p { class: "text-red-600 text-sm", "Error: {e}" } },
                                            None => rsx! { p { class: "text-gray-500 text-sm", "Loading…" } },
                                        }
                                    }
                                } else if active_tab() == "branches" {
                                    div { class: "p-5",
                                        div { class: "flex items-center justify-between mb-3",
                                            p { class: "text-sm font-medium text-gray-700", "Local and remote-tracking branches" }
                                            button {
                                                class: "text-xs text-rose-500 hover:text-rose-600 font-medium",
                                                onclick: move |_| branches_resource.restart(),
                                                "↻ Refresh"
                                            }
                                        }
                                        match &*branches_resource.read() {
                                            Some(Ok(branch_list)) => rsx! {
                                                if branch_list.is_empty() {
                                                    p { class: "text-gray-500 text-sm", "No branches found. Pull from remote first." }
                                                } else {
                                                    div { class: "space-y-2",
                                                        for branch in branch_list.iter() {
                                                            GitBranchRow {
                                                                branch: branch.clone(),
                                                                site_id: selected_site_id(),
                                                                branches_resource,
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            Some(Err(e)) => rsx! { p { class: "text-red-600 text-sm", "Error: {e}" } },
                                            None => rsx! { p { class: "text-gray-500 text-sm", "Loading…" } },
                                        }
                                    }
                                } else {
                                    div { class: "p-5",
                                        div { class: "flex items-center justify-between mb-3",
                                            p { class: "text-sm font-medium text-gray-700", "Recent commits (last 50)" }
                                            button {
                                                class: "text-xs text-rose-500 hover:text-rose-600 font-medium",
                                                onclick: move |_| log_resource.restart(),
                                                "↻ Refresh"
                                            }
                                        }
                                        match &*log_resource.read() {
                                            Some(Ok(commits)) => rsx! {
                                                if commits.is_empty() {
                                                    p { class: "text-gray-500 text-sm",
                                                        "No commits yet. Pull from remote or create your first commit above."
                                                    }
                                                } else {
                                                    div { class: "divide-y divide-gray-100",
                                                        for commit in commits.iter() {
                                                            div { class: "flex items-start gap-3 py-3 hover:bg-gray-50/50 rounded-lg px-2 transition-colors",
                                                                div { class: "w-6 h-6 rounded-full bg-gray-100 flex items-center justify-center shrink-0 mt-0.5",
                                                                    Icon { name: "git-commit", class: "w-3.5 h-3.5 text-gray-400".to_string() }
                                                                }
                                                                div { class: "flex-1 min-w-0",
                                                                    div { class: "flex items-baseline gap-2 flex-wrap",
                                                                        span { class: "font-mono text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded",
                                                                            "{commit.hash_short}"
                                                                        }
                                                                        span { class: "text-sm text-gray-900 font-medium", "{commit.message}" }
                                                                    }
                                                                    div { class: "flex items-center gap-2 mt-0.5",
                                                                        span { class: "text-xs text-gray-500", "{commit.author_name}" }
                                                                        span { class: "text-gray-300", "·" }
                                                                        span { class: "text-xs text-gray-400", "{commit.date}" }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            Some(Err(e)) => rsx! { p { class: "text-red-600 text-sm", "Error: {e}" } },
                                            None => rsx! { p { class: "text-gray-500 text-sm", "Loading…" } },
                                        }
                                    }
                                }
                            }
                        }
                    },

                    Some(Err(e)) => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center",
                            p { class: "text-red-600 text-sm", "Error: {e}" }
                        }
                    },
                    None => rsx! {
                        div { class: "bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center",
                            div { class: "animate-pulse text-gray-400 text-sm", "Loading repository info…" }
                        }
                    },
                }
            }
        }
    }
}

/// A single row in the Branches tab.
#[component]
pub fn GitBranchRow(
    branch: panel::models::git::GitBranch,
    site_id: i64,
    branches_resource: Resource<Result<Vec<panel::models::git::GitBranch>, ServerFnError>>,
) -> Element {
    let mut switching = use_signal(|| false);
    let mut switch_error = use_signal(|| None::<String>);
    let mut branches_resource = branches_resource;
    let branch_name = branch.name.clone();
    let is_current = branch.is_current;
    rsx! {
        div {
            class: "flex items-center justify-between p-3 rounded-lg border",
            class: if is_current { "border-emerald-200 bg-emerald-50" } else { "border-gray-200 bg-white" },
            div { class: "flex items-center gap-2",
                Icon { name: "git-branch", class: "w-4 h-4 text-gray-400".to_string() }
                span { class: "text-sm font-medium text-gray-800", "{branch.name}" }
                if is_current {
                    span { class: "px-1.5 py-0.5 text-xs bg-emerald-500 text-white rounded-full", "current" }
                }
            }
            div { class: "flex items-center gap-2",
                if let Some(ref err) = switch_error() {
                    span { class: "text-xs text-red-600", "{err}" }
                }
                if !is_current {
                    button {
                        class: "flex items-center gap-1.5 px-3 py-1.5 text-xs border border-gray-200 text-gray-600 hover:bg-gray-50 rounded-lg transition-colors disabled:opacity-50",
                        disabled: switching(),
                        onclick: move |_| {
                            switching.set(true);
                            switch_error.set(None);
                            let name = branch_name.clone();
                            spawn(async move {
                                match server_git_checkout(site_id, name).await {
                                    Ok(()) => branches_resource.restart(),
                                    Err(e) => switch_error.set(Some(e.to_string())),
                                }
                                switching.set(false);
                            });
                        },
                        Icon { name: "check", class: "w-3.5 h-3.5".to_string() }
                        if switching() { "Switching…" } else { "Switch" }
                    }
                }
            }
        }
    }
}
