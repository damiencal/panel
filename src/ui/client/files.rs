#![allow(non_snake_case)]
use crate::lucide::Icon;
use dioxus::prelude::*;
use panel::server::*;

/// Format file size in human-readable units.
fn fmt_file_bytes(bytes: u64) -> String {
    if bytes < 1_024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}

/// Parent path: strips the last path segment from a `/`-prefixed rel_path.
fn parent_path(rel_path: &str) -> String {
    let trimmed = rel_path.trim_end_matches('/');
    if let Some(pos) = trimmed.rfind('/') {
        if pos == 0 {
            "/".to_string()
        } else {
            trimmed[..pos].to_string()
        }
    } else {
        "/".to_string()
    }
}

/// Breadcrumb segments for the path bar.
fn breadcrumbs(rel_path: &str) -> Vec<(String, String)> {
    let mut crumbs = vec![("Home".to_string(), "/".to_string())];
    let trimmed = rel_path.trim_start_matches('/').trim_end_matches('/');
    if trimmed.is_empty() {
        return crumbs;
    }
    let mut acc = String::new();
    for seg in trimmed.split('/') {
        acc.push('/');
        acc.push_str(seg);
        crumbs.push((seg.to_string(), acc.clone()));
    }
    crumbs
}

#[component]
pub fn ClientFileManager() -> Element {
    // Site selection
    let sites = use_resource(move || async move { server_list_sites().await });
    let mut selected_site: Signal<Option<panel::models::site::Site>> = use_signal(|| None);
    let mut current_path = use_signal(|| "/".to_string());

    // Directory listing – refreshed whenever site or path changes.
    // Read signals inside the closure so the reactive context tracks them.
    let entries = use_resource(move || {
        let sid = selected_site.read().as_ref().map(|s| s.id);
        let p = current_path.read().clone();
        async move {
            if let Some(id) = sid {
                server_fm_list_dir(id, p).await
            } else {
                Ok(vec![])
            }
        }
    });

    // Modal / action state
    let mut error_msg: Signal<Option<String>> = use_signal(|| None);
    let mut success_msg: Signal<Option<String>> = use_signal(|| None);

    // New-dir modal
    let mut show_new_dir = use_signal(|| false);
    let mut new_dir_name = use_signal(String::new);

    // Rename modal
    let mut show_rename = use_signal(|| false);
    let mut rename_target: Signal<Option<panel::models::files::FileEntry>> = use_signal(|| None);
    let mut rename_value = use_signal(String::new);

    // Delete confirm
    let mut show_delete = use_signal(|| false);
    let mut delete_target: Signal<Option<panel::models::files::FileEntry>> = use_signal(|| None);

    // Permissions modal
    let mut show_chmod = use_signal(|| false);
    let mut chmod_target: Signal<Option<panel::models::files::FileEntry>> = use_signal(|| None);
    let mut chmod_value = use_signal(|| "644".to_string());

    // Move modal
    let mut show_move = use_signal(|| false);
    let mut move_target: Signal<Option<panel::models::files::FileEntry>> = use_signal(|| None);
    let mut move_dest = use_signal(String::new);

    // Text editor modal
    let mut show_editor = use_signal(|| false);
    let mut editor_target: Signal<Option<panel::models::files::FileEntry>> = use_signal(|| None);
    let mut editor_content = use_signal(String::new);
    let mut editor_loading = use_signal(|| false);
    let mut editor_saving = use_signal(|| false);

    // Upload state
    let mut uploading = use_signal(|| false);

    // Helper closures tied to reactive state
    let mut entries_resource = entries;

    // Auto-select first site when list loads
    {
        let sites_read = sites.read();
        if selected_site.read().is_none() {
            if let Some(Ok(list)) = &*sites_read {
                if !list.is_empty() {
                    selected_site.set(Some(list[0].clone()));
                }
            }
        }
    }

    rsx! {
        div { class: "p-6 lg:p-8",
            div { class: "flex items-center justify-between mb-6 flex-wrap gap-4",
                h2 { class: "text-2xl font-semibold tracking-tight text-gray-900", "File Manager" }

                // Site selector
                div { class: "flex items-center gap-3",
                    label { class: "text-sm font-medium text-gray-600", "Site:" }
                    match &*sites.read() {
                        Some(Ok(list)) => rsx! {
                            select {
                                class: "px-3 py-2 border border-gray-300 rounded-lg text-sm bg-white focus:ring-2 focus:ring-black/[0.15] focus:border-transparent",
                                onchange: move |e| {
                                    let val: i64 = e.value().parse().unwrap_or(-1);
                                    if let Some(Ok(list)) = &*sites.read() {
                                        if let Some(site) = list.iter().find(|s| s.id == val) {
                                            selected_site.set(Some(site.clone()));
                                            current_path.set("/".to_string());
                                        }
                                    }
                                },
                                for site in list.iter() {
                                    option { value: "{site.id}", "{site.domain}" }
                                }
                            }
                        },
                        _ => rsx! { span { class: "text-sm text-gray-400", "Loading sites…" } },
                    }
                }
            }

            // Feedback banners
            if let Some(err) = error_msg() {
                div { class: "bg-red-50 border border-red-200 text-red-700 rounded-xl px-4 py-3 mb-4 text-sm flex items-center justify-between",
                    span { "{err}" }
                    button { onclick: move |_| error_msg.set(None), class: "ml-4 text-red-400 hover:text-red-600", "✕" }
                }
            }
            if let Some(ok) = success_msg() {
                div { class: "bg-green-50 border border-green-200 text-green-700 rounded-xl px-4 py-3 mb-4 text-sm flex items-center justify-between",
                    span { "{ok}" }
                    button { onclick: move |_| success_msg.set(None), class: "ml-4 text-green-400 hover:text-green-600", "✕" }
                }
            }

            if selected_site.read().is_none() {
                div { class: "glass-card rounded-2xl p-12 text-center",
                    div { class: "mx-auto w-16 h-16 rounded-2xl bg-black/[0.04] flex items-center justify-center mb-5",
                        Icon { name: "folder", class: "w-8 h-8 text-gray-700".to_string() }
                    }
                    h3 { class: "text-lg font-semibold text-gray-800 mb-2", "No Sites Found" }
                    p { class: "text-gray-500", "Create a site first to use the file manager." }
                }
            } else {
                // Breadcrumb + toolbar
                div { class: "glass-card rounded-2xl mb-4",
                    div { class: "px-5 py-3 border-b border-black/[0.05] flex items-center justify-between flex-wrap gap-3",
                        // Breadcrumb
                        nav { class: "flex items-center gap-1 text-sm flex-wrap",
                            for (label, path) in breadcrumbs(&current_path.read()) {
                                {
                                    let p = path.clone();
                                    rsx! {
                                        button {
                                            class: "text-gray-700 hover:text-red-600 font-medium",
                                            onclick: move |_| current_path.set(p.clone()),
                                            "{label}"
                                        }
                                        span { class: "text-gray-300", "/" }
                                    }
                                }
                            }
                        }
                        // Toolbar actions
                        div { class: "flex items-center gap-2 flex-wrap",
                            // New Folder
                            button {
                                class: "flex items-center gap-1.5 px-3 py-1.5 bg-gray-900 hover:bg-gray-900/90 text-white text-xs font-medium rounded-xl transition-all duration-200",
                                onclick: move |_| { new_dir_name.set(String::new()); show_new_dir.set(true); },
                                Icon { name: "folder-plus", class: "w-3.5 h-3.5".to_string() }
                                "New Folder"
                            }
                            // Upload
                            label {
                                class: "flex items-center gap-1.5 px-3 py-1.5 bg-blue-500 hover:bg-blue-600 text-white text-xs font-medium rounded-xl transition-all duration-200 cursor-pointer",
                                title: "Upload a file to the current directory",
                                input {
                                    r#type: "file",
                                    class: "hidden",
                                    multiple: true,
                                    onchange: {
                                        let current_path = current_path.read().clone();
                                        move |ev: Event<FormData>| {
                                            if let Some(sid) = selected_site.read().as_ref().map(|s| s.id) {
                                                uploading.set(true);
                                                error_msg.set(None);
                                                #[allow(unused_variables)]
                                                let path = current_path.clone();
                                                #[allow(unused_variables)]
                                                let files = ev.files();
                                                spawn(async move {
                                                    #[cfg(target_arch = "wasm32")]
                                                    {
                                                        for file_data in &files {
                                                            let name = file_data.name();
                                                            if let Ok(bytes) = file_data.read_bytes().await {
                                                                let encoded_path = js_sys::encode_uri_component(&path).as_string().unwrap_or_default();
                                                                let encoded_name = js_sys::encode_uri_component(&name).as_string().unwrap_or_default();
                                                                let url = format!("/api/files/upload?site_id={sid}&path={encoded_path}&filename={encoded_name}");
                                                                let arr = js_sys::Uint8Array::from(bytes.as_ref() as &[u8]);
                                                                let blob = web_sys::Blob::new_with_u8_array_sequence(&js_sys::Array::of1(&arr)).unwrap();
                                                                let window = web_sys::window().unwrap();
                                                                let opts = web_sys::RequestInit::new();
                                                                opts.set_method("POST");
                                                                opts.set_body(&blob);
                                                                let request = web_sys::Request::new_with_str_and_init(&url, &opts).unwrap();
                                                                let _ = wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request)).await;
                                                            }
                                                        }
                                                    }
                                                    #[cfg(not(target_arch = "wasm32"))]
                                                    let _ = sid;
                                                    uploading.set(false);
                                                    entries_resource.restart();
                                                });
                                            }
                                        }
                                    },
                                }
                                if uploading() { "Uploading…" } else {
                                    Icon { name: "upload", class: "w-3.5 h-3.5".to_string() }
                                    "Upload"
                                }
                            }
                        }
                    }

                    // File listing table
                    match &*entries_resource.read() {
                        Some(Ok(list)) => rsx! {
                            if list.is_empty() {
                                div { class: "p-10 text-center text-gray-400 text-sm", "This directory is empty." }
                            } else {
                                div { class: "overflow-x-auto",
                                    table { class: "w-full text-sm",
                                        thead { class: "bg-gray-50 border-b border-black/[0.05]",
                                            tr {
                                                th { class: "px-5 py-3 text-left font-medium text-gray-500 text-xs uppercase", "Name" }
                                                th { class: "px-5 py-3 text-left font-medium text-gray-500 text-xs uppercase", "Size" }
                                                th { class: "px-5 py-3 text-left font-medium text-gray-500 text-xs uppercase", "Permissions" }
                                                th { class: "px-5 py-3 text-left font-medium text-gray-500 text-xs uppercase", "Modified" }
                                                th { class: "px-5 py-3 text-right font-medium text-gray-500 text-xs uppercase", "Actions" }
                                            }
                                        }
                                        tbody { class: "divide-y divide-gray-50",
                                            // ".." up-dir row when not at root
                                            if current_path.read().as_str() != "/" {
                                                tr { class: "hover:bg-black/[0.02]",
                                                    td { class: "px-5 py-3 font-medium text-blue-600",
                                                        button {
                                                            class: "flex items-center gap-2",
                                                            onclick: {
                                                                let p = parent_path(&current_path.read());
                                                                move |_| current_path.set(p.clone())
                                                            },
                                                            Icon { name: "corner-left-up", class: "w-4 h-4".to_string() }
                                                            ".."
                                                        }
                                                    }
                                                    td { colspan: "4" }
                                                }
                                            }
                                            for entry in list.iter() {
                                                {
                                                    let e = entry.clone();
                                                    let e2 = entry.clone();
                                                    let e_path = entry.rel_path.clone();
                                                    let is_dir = entry.is_dir;
                                                    let icon = if is_dir { "folder" } else { "file" };
                                                    let icon_color = if is_dir { "text-amber-500" } else { "text-gray-400" };
                                                    let lower_name = entry.name.to_lowercase();
                                                    let modified_str = e.modified.format("%Y-%m-%d %H:%M").to_string();
                                                    let is_archive = lower_name.ends_with(".zip")
                                                        || lower_name.ends_with(".tar.gz")
                                                        || lower_name.ends_with(".tgz")
                                                        || lower_name.ends_with(".tar");
                                                    let is_text = !is_dir && !is_archive && (
                                                        lower_name.ends_with(".html")
                                                        || lower_name.ends_with(".htm")
                                                        || lower_name.ends_with(".php")
                                                        || lower_name.ends_with(".js")
                                                        || lower_name.ends_with(".css")
                                                        || lower_name.ends_with(".json")
                                                        || lower_name.ends_with(".xml")
                                                        || lower_name.ends_with(".txt")
                                                        || lower_name.ends_with(".md")
                                                        || lower_name.ends_with(".toml")
                                                        || lower_name.ends_with(".yaml")
                                                        || lower_name.ends_with(".yml")
                                                        || lower_name.ends_with(".sh")
                                                        || lower_name.ends_with(".env")
                                                        || lower_name.ends_with(".conf")
                                                        || lower_name.ends_with(".ini")
                                                        || lower_name.ends_with(".htaccess")
                                                        || lower_name.ends_with(".gitignore")
                                                        || lower_name.ends_with(".rs")
                                                        || lower_name.ends_with(".py")
                                                        || lower_name.ends_with(".rb")
                                                        || lower_name.ends_with(".ts")
                                                    );
                                                    rsx! {
                                                        tr { class: "hover:bg-gray-50 group",
                                                            td { class: "px-5 py-3 font-medium text-gray-800",
                                                                if is_dir {
                                                                    button {
                                                                        class: "flex items-center gap-2 hover:text-gray-700",
                                                                        onclick: move |_| current_path.set(e_path.clone()),
                                                                        Icon { name: icon, class: format!("w-4 h-4 {}", icon_color) }
                                                                        "{e.name}"
                                                                    }
                                                                } else {
                                                                    div { class: "flex items-center gap-2",
                                                                        Icon { name: icon, class: format!("w-4 h-4 {}", icon_color) }
                                                                        "{e.name}"
                                                                    }
                                                                }
                                                            }
                                                            td { class: "px-5 py-3 text-gray-500 tabular-nums",
                                                                if is_dir { "—" } else { "{fmt_file_bytes(e.size)}" }
                                                            }
                                                            td { class: "px-5 py-3 text-gray-500 font-mono text-xs", "{e.permissions}" }
                                                            td { class: "px-5 py-3 text-gray-400 text-xs",
                                                                "{modified_str}"
                                                            }
                                                            td { class: "px-5 py-3",
                                                                div { class: "flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity",
                                                                    // Rename
                                                                    button {
                                                                        class: "p-1.5 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700",
                                                                        title: "Rename",
                                                                        onclick: {
                                                                            let entry = e.clone();
                                                                            move |_| {
                                                                                rename_value.set(entry.name.clone());
                                                                                rename_target.set(Some(entry.clone()));
                                                                                show_rename.set(true);
                                                                            }
                                                                        },
                                                                        Icon { name: "pencil", class: "w-3.5 h-3.5".to_string() }
                                                                    }
                                                                    // Move
                                                                    button {
                                                                        class: "p-1.5 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700",
                                                                        title: "Move",
                                                                        onclick: {
                                                                            let entry = e.clone();
                                                                            move |_| {
                                                                                move_dest.set(entry.rel_path.clone());
                                                                                move_target.set(Some(entry.clone()));
                                                                                show_move.set(true);
                                                                            }
                                                                        },
                                                                        Icon { name: "move", class: "w-3.5 h-3.5".to_string() }
                                                                    }
                                                                    // Permissions
                                                                    button {
                                                                        class: "p-1.5 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700",
                                                                        title: "Permissions",
                                                                        onclick: {
                                                                            let entry = e.clone();
                                                                            move |_| {
                                                                                chmod_target.set(Some(entry.clone()));
                                                                                chmod_value.set("644".to_string());
                                                                                show_chmod.set(true);
                                                                            }
                                                                        },
                                                                        Icon { name: "shield", class: "w-3.5 h-3.5".to_string() }
                                                                    }
                                                                    // Edit (text files)
                                                                    if is_text {
                                                                        button {
                                                                            class: "p-1.5 rounded-lg hover:bg-blue-50 text-blue-500 hover:text-blue-700",
                                                                            title: "Edit",
                                                                            onclick: {
                                                                                let entry = e.clone();
                                                                                move |_| {
                                                                                    editor_target.set(Some(entry.clone()));
                                                                                    editor_content.set(String::new());
                                                                                    editor_loading.set(true);
                                                                                    show_editor.set(true);
                                                                                    let sid = selected_site.read().as_ref().map(|s| s.id).unwrap_or(0);
                                                                                    let rp = entry.rel_path.clone();
                                                                                    spawn(async move {
                                                                                        match server_fm_read_text_file(sid, rp).await {
                                                                                            Ok(fc) => editor_content.set(fc.content),
                                                                                            Err(e) => {
                                                                                                error_msg.set(Some(e.to_string()));
                                                                                                show_editor.set(false);
                                                                                            }
                                                                                        }
                                                                                        editor_loading.set(false);
                                                                                    });
                                                                                }
                                                                            },
                                                                            Icon { name: "code", class: "w-3.5 h-3.5".to_string() }
                                                                        }
                                                                    }
                                                                    // Extract (archives)
                                                                    if is_archive {
                                                                        button {
                                                                            class: "p-1.5 rounded-lg hover:bg-amber-50 text-amber-500 hover:text-amber-700",
                                                                            title: "Extract archive",
                                                                            onclick: {
                                                                                let entry = e.clone();
                                                                                move |_| {
                                                                                    let sid = selected_site.read().as_ref().map(|s| s.id).unwrap_or(0);
                                                                                    let rp = entry.rel_path.clone();
                                                                                    spawn(async move {
                                                                                        match server_fm_extract_archive(sid, rp).await {
                                                                                            Ok(_) => success_msg.set(Some("Archive extracted.".into())),
                                                                                            Err(e) => error_msg.set(Some(e.to_string())),
                                                                                        }
                                                                                        entries_resource.restart();
                                                                                    });
                                                                                }
                                                                            },
                                                                            Icon { name: "package-open", class: "w-3.5 h-3.5".to_string() }
                                                                        }
                                                                    }
                                                                    // Download (files only)
                                                                    if !is_dir {
                                                                        button {
                                                                            class: "p-1.5 rounded-lg hover:bg-emerald-50 text-emerald-500 hover:text-emerald-700",
                                                                            title: "Download",
                                                                            onclick: {
                                                                                let entry = e.clone();
                                                                                move |_| {
                                                                                    let sid = selected_site.read().as_ref().map(|s| s.id).unwrap_or(0);
                                                                                    let rp = entry.rel_path.clone();
                                                                                    spawn(async move {
                                                                                        match server_fm_create_download_token(sid, rp).await {
                                                                                            Ok(ti) => {
                                                                                                #[cfg(target_arch = "wasm32")]
                                                                                                if let Some(window) = web_sys::window() {
                                                                                                    let _ = window.open_with_url(&ti.download_url);
                                                                                                }
                                                                                                #[cfg(not(target_arch = "wasm32"))]
                                                                                                let _ = ti;
                                                                                            }
                                                                                            Err(e) => error_msg.set(Some(e.to_string())),
                                                                                        }
                                                                                    });
                                                                                }
                                                                            },
                                                                            Icon { name: "download", class: "w-3.5 h-3.5".to_string() }
                                                                        }
                                                                    }
                                                                    // Delete
                                                                    button {
                                                                        class: "p-1.5 rounded-lg hover:bg-red-50 text-gray-400 hover:text-red-600",
                                                                        title: "Delete",
                                                                        onclick: {
                                                                            let entry = e2.clone();
                                                                            move |_| {
                                                                                delete_target.set(Some(entry.clone()));
                                                                                show_delete.set(true);
                                                                            }
                                                                        },
                                                                        Icon { name: "trash-2", class: "w-3.5 h-3.5".to_string() }
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
                            div { class: "p-6 text-red-600 text-sm", "Error loading directory: {e}" }
                        },
                        None => rsx! {
                            div { class: "p-6 text-gray-400 text-sm animate-pulse", "Loading…" }
                        },
                    }
                }
            }

            // ── New Folder Modal ───────────────────────────────────────────
            if show_new_dir() {
                div { class: "fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4",
                    div { class: "bg-white rounded-2xl shadow-xl p-6 w-full max-w-md",
                        h3 { class: "text-lg font-semibold text-gray-900 mb-4", "New Folder" }
                        input {
                            r#type: "text",
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg mb-4 focus:ring-2 focus:ring-black/[0.15] focus:border-transparent",
                            placeholder: "folder-name",
                            value: "{new_dir_name}",
                            oninput: move |e| new_dir_name.set(e.value()),
                            autofocus: true,
                        }
                        div { class: "flex justify-end gap-3",
                            button {
                                class: "px-4 py-2 border border-gray-300 rounded-lg text-sm hover:bg-black/[0.02]",
                                onclick: move |_| show_new_dir.set(false),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 bg-gray-900 hover:bg-gray-900/90 text-white rounded-lg text-sm font-medium",
                                onclick: move |_| {
                                    let sid = match selected_site.read().as_ref().map(|s| s.id) {
                                        Some(id) => id,
                                        None => return,
                                    };
                                    let name = new_dir_name.read().trim().to_string();
                                    if name.is_empty() { return; }
                                    let base = current_path.read().clone();
                                    let rel = if base == "/" {
                                        format!("/{}", name)
                                    } else {
                                        format!("{}/{}", base, name)
                                    };
                                    show_new_dir.set(false);
                                    spawn(async move {
                                        match server_fm_create_dir(sid, rel).await {
                                            Ok(_) => success_msg.set(Some("Folder created.".into())),
                                            Err(e) => error_msg.set(Some(e.to_string())),
                                        }
                                        entries_resource.restart();
                                    });
                                },
                                "Create"
                            }
                        }
                    }
                }
            }

            // ── Rename Modal ───────────────────────────────────────────────
            if show_rename() {
                div { class: "fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4",
                    div { class: "bg-white rounded-2xl shadow-xl p-6 w-full max-w-md",
                        h3 { class: "text-lg font-semibold text-gray-900 mb-4", "Rename" }
                        input {
                            r#type: "text",
                            class: "w-full px-4 py-2 border border-gray-300 rounded-lg mb-4 focus:ring-2 focus:ring-black/[0.15] focus:border-transparent",
                            value: "{rename_value}",
                            oninput: move |e| rename_value.set(e.value()),
                            autofocus: true,
                        }
                        div { class: "flex justify-end gap-3",
                            button {
                                class: "px-4 py-2 border border-gray-300 rounded-lg text-sm hover:bg-black/[0.02]",
                                onclick: move |_| show_rename.set(false),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 bg-gray-900 hover:bg-gray-900/90 text-white rounded-lg text-sm font-medium",
                                onclick: move |_| {
                                    let sid = match selected_site.read().as_ref().map(|s| s.id) {
                                        Some(id) => id,
                                        None => return,
                                    };
                                    let entry = match rename_target.read().clone() {
                                        Some(e) => e,
                                        None => return,
                                    };
                                    let new_name = rename_value.read().trim().to_string();
                                    if new_name.is_empty() { return; }
                                    show_rename.set(false);
                                    spawn(async move {
                                        match server_fm_rename(sid, entry.rel_path, new_name).await {
                                            Ok(_) => success_msg.set(Some("Renamed.".into())),
                                            Err(e) => error_msg.set(Some(e.to_string())),
                                        }
                                        entries_resource.restart();
                                    });
                                },
                                "Rename"
                            }
                        }
                    }
                }
            }

            // ── Delete Confirm Modal ───────────────────────────────────────
            if show_delete() {
                div { class: "fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4",
                    div { class: "bg-white rounded-2xl shadow-xl p-6 w-full max-w-md",
                        h3 { class: "text-lg font-semibold text-gray-900 mb-2", "Confirm Delete" }
                        if let Some(ref entry) = *delete_target.read() {
                            p { class: "text-[13px] text-gray-400 mb-6",
                                "Delete "
                                span { class: "font-mono text-gray-800", "{entry.name}" }
                                "? This cannot be undone."
                            }
                        }
                        div { class: "flex justify-end gap-3",
                            button {
                                class: "px-4 py-2 border border-gray-300 rounded-lg text-sm hover:bg-black/[0.02]",
                                onclick: move |_| show_delete.set(false),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm font-medium",
                                onclick: move |_| {
                                    let sid = match selected_site.read().as_ref().map(|s| s.id) {
                                        Some(id) => id,
                                        None => return,
                                    };
                                    let entry = match delete_target.read().clone() {
                                        Some(e) => e,
                                        None => return,
                                    };
                                    show_delete.set(false);
                                    spawn(async move {
                                        match server_fm_delete(sid, entry.rel_path).await {
                                            Ok(_) => success_msg.set(Some("Deleted.".into())),
                                            Err(e) => error_msg.set(Some(e.to_string())),
                                        }
                                        entries_resource.restart();
                                    });
                                },
                                "Delete"
                            }
                        }
                    }
                }
            }

            // ── Permissions Modal ──────────────────────────────────────────
            if show_chmod() {
                div { class: "fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4",
                    div { class: "bg-white rounded-2xl shadow-xl p-6 w-full max-w-md",
                        h3 { class: "text-lg font-semibold text-gray-900 mb-4", "Change Permissions" }
                        if let Some(ref entry) = *chmod_target.read() {
                            p { class: "text-sm text-gray-500 mb-3",
                                "File: " span { class: "font-mono text-gray-800", "{entry.name}" }
                            }
                        }
                        div { class: "mb-4",
                            label { class: "block text-[13px] font-medium text-gray-700 mb-1.5", "Octal mode (e.g. 644, 755)" }
                            input {
                                r#type: "text",
                                class: "w-full px-4 py-2 border border-black/[0.08] rounded-xl focus:ring-2 focus:ring-black/[0.15] focus:border-transparent font-mono",
                                maxlength: "3",
                                value: "{chmod_value}",
                                oninput: move |e| chmod_value.set(e.value()),
                                placeholder: "644",
                            }
                        }
                        div { class: "flex justify-end gap-3",
                            button {
                                class: "px-4 py-2 border border-gray-300 rounded-lg text-sm hover:bg-black/[0.02]",
                                onclick: move |_| show_chmod.set(false),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 bg-gray-900 hover:bg-gray-900/90 text-white rounded-lg text-sm font-medium",
                                onclick: move |_| {
                                    let sid = match selected_site.read().as_ref().map(|s| s.id) {
                                        Some(id) => id,
                                        None => return,
                                    };
                                    let entry = match chmod_target.read().clone() {
                                        Some(e) => e,
                                        None => return,
                                    };
                                    let mode = chmod_value.read().clone();
                                    show_chmod.set(false);
                                    spawn(async move {
                                        match server_fm_set_permissions(sid, entry.rel_path, mode).await {
                                            Ok(_) => success_msg.set(Some("Permissions updated.".into())),
                                            Err(e) => error_msg.set(Some(e.to_string())),
                                        }
                                        entries_resource.restart();
                                    });
                                },
                                "Apply"
                            }
                        }
                    }
                }
            }

            // ── Move Modal ─────────────────────────────────────────────────
            if show_move() {
                div { class: "fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4",
                    div { class: "bg-white rounded-2xl shadow-xl p-6 w-full max-w-md",
                        h3 { class: "text-lg font-semibold text-gray-900 mb-4", "Move" }
                        if let Some(ref entry) = *move_target.read() {
                            p { class: "text-sm text-gray-500 mb-3",
                                "From: " span { class: "font-mono text-gray-800", "{entry.rel_path}" }
                            }
                        }
                        div { class: "mb-4",
                            label { class: "block text-[13px] font-medium text-gray-700 mb-1.5", "Destination path" }
                            input {
                                r#type: "text",
                                class: "w-full px-4 py-2 border border-black/[0.08] rounded-xl focus:ring-2 focus:ring-black/[0.15] focus:border-transparent font-mono",
                                value: "{move_dest}",
                                oninput: move |e| move_dest.set(e.value()),
                                placeholder: "/images/banner.jpg",
                            }
                        }
                        div { class: "flex justify-end gap-3",
                            button {
                                class: "px-4 py-2 border border-gray-300 rounded-lg text-sm hover:bg-black/[0.02]",
                                onclick: move |_| show_move.set(false),
                                "Cancel"
                            }
                            button {
                                class: "px-4 py-2 bg-gray-900 hover:bg-gray-900/90 text-white rounded-lg text-sm font-medium",
                                onclick: move |_| {
                                    let sid = match selected_site.read().as_ref().map(|s| s.id) {
                                        Some(id) => id,
                                        None => return,
                                    };
                                    let entry = match move_target.read().clone() {
                                        Some(e) => e,
                                        None => return,
                                    };
                                    let dest = move_dest.read().clone();
                                    show_move.set(false);
                                    spawn(async move {
                                        match server_fm_move(sid, entry.rel_path, dest).await {
                                            Ok(_) => success_msg.set(Some("Moved.".into())),
                                            Err(e) => error_msg.set(Some(e.to_string())),
                                        }
                                        entries_resource.restart();
                                    });
                                },
                                "Move"
                            }
                        }
                    }
                }
            }

            // ── Text Editor Modal ──────────────────────────────────────────
            if show_editor() {
                div { class: "fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4",
                    div { class: "bg-white rounded-2xl shadow-xl flex flex-col w-full max-w-4xl h-[80vh]",
                        div { class: "flex items-center justify-between px-6 py-4 border-b border-black/[0.05] shrink-0",
                            h3 { class: "text-lg font-semibold text-gray-900",
                                if let Some(ref entry) = *editor_target.read() {
                                    "{entry.name}"
                                } else {
                                    "Edit File"
                                }
                            }
                            div { class: "flex items-center gap-3",
                                button {
                                    class: "px-4 py-2 bg-gray-900 hover:bg-gray-900/90 text-white rounded-lg text-sm font-medium disabled:opacity-50",
                                    disabled: editor_saving(),
                                    onclick: move |_| {
                                        let sid = match selected_site.read().as_ref().map(|s| s.id) {
                                            Some(id) => id,
                                            None => return,
                                        };
                                        let entry = match editor_target.read().clone() {
                                            Some(e) => e,
                                            None => return,
                                        };
                                        let content = editor_content.read().clone();
                                        editor_saving.set(true);
                                        spawn(async move {
                                            match server_fm_write_text_file(sid, entry.rel_path, content).await {
                                                Ok(_) => success_msg.set(Some("File saved.".into())),
                                                Err(e) => error_msg.set(Some(e.to_string())),
                                            }
                                            editor_saving.set(false);
                                            show_editor.set(false);
                                        });
                                    },
                                    if editor_saving() { "Saving…" } else { "Save" }
                                }
                                button {
                                    class: "px-4 py-2 border border-gray-300 rounded-lg text-sm hover:bg-black/[0.02]",
                                    onclick: move |_| show_editor.set(false),
                                    "Close"
                                }
                            }
                        }
                        div { class: "flex-1 overflow-hidden",
                            if editor_loading() {
                                div { class: "flex items-center justify-center h-full text-gray-400", "Loading file…" }
                            } else {
                                textarea {
                                    class: "w-full h-full p-4 font-mono text-sm resize-none border-0 outline-none",
                                    spellcheck: false,
                                    value: "{editor_content}",
                                    oninput: move |e| editor_content.set(e.value()),
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─── Helper: format bytes ────────────────────────────────────────────────────
