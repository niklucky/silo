//! Tauri host for Silo.
//!
//! Keep this crate thin: the vault lives in the local agent (see [`agent`]),
//! and the UI is `@silo/ui`. Every command is registered in [`specta_builder`],
//! which also produces the TypeScript bindings in `packages/bindings/src/desktop.ts`.

mod agent;
mod site;

use tauri::Manager;
use tauri_specta::{Builder, collect_commands};

/// Core crate version. First round-trip smoke test from the desktop UI.
#[tauri::command]
#[specta::specta]
fn core_version() -> String {
    silo_core::version().to_owned()
}

/// Sends one agent-protocol request (JSON) and returns the response (JSON),
/// `{"ok":…}` or `{"err":…}`. Runs off the main thread: unlocking takes a while.
#[tauri::command]
#[specta::specta]
async fn agent_call(app: tauri::AppHandle, request: String) -> String {
    tauri::async_runtime::spawn_blocking(move || app.state::<agent::Agent>().call_json(&request))
        .await
        .unwrap_or_else(|err| {
            format!(
                r#"{{"err":{{"code":"internal","message":{:?}}}}}"#,
                err.to_string()
            )
        })
}

/// GETs a website saved in a login (for its favicon); see [`site::get`].
#[tauri::command]
#[specta::specta]
async fn fetch_site(url: String, limit: u32) -> Option<site::SiteResponse> {
    tauri::async_runtime::spawn_blocking(move || site::get(&url, limit))
        .await
        .ok()
        .flatten()
}

fn specta_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new().commands(collect_commands![core_version, agent_call, fetch_site])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = specta_builder();

    tauri::Builder::default()
        .manage(agent::Agent::default())
        .invoke_handler(builder.invoke_handler())
        .setup(move |app| {
            builder.mount_events(app);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regenerates the TypeScript bindings. Run after adding or changing a command:
    ///
    /// ```sh
    /// pnpm bindings:desktop
    /// ```
    #[test]
    fn export_bindings() {
        let out = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../packages/bindings/src/desktop.ts"
        );
        specta_builder()
            .export(specta_typescript::Typescript::default(), out)
            .expect("failed to export typescript bindings");
    }
}
