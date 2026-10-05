//! Tauri host for Secret.
//!
//! Keep this crate thin: commands validate input and delegate to `secret_core`.
//! Every command is registered in [`specta_builder`], which also produces the
//! TypeScript bindings in `packages/bindings/src/desktop.ts`.

use tauri_specta::{Builder, collect_commands};

/// Core crate version. First round-trip smoke test from the desktop UI.
#[tauri::command]
#[specta::specta]
fn core_version() -> String {
    secret_core::version().to_owned()
}

fn specta_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new().commands(collect_commands![core_version])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = specta_builder();

    tauri::Builder::default()
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
