import init, * as core from "@secret/bindings/wasm";
import wasmUrl from "@secret/bindings/wasm/secret_wasm_bg.wasm?url";

let ready: Promise<typeof core> | undefined;

/**
 * Loads the Rust core once per JS context (popup, background, content script).
 * Each context has its own module instance, so each calls this on its own.
 */
export function loadCore(): Promise<typeof core> {
  ready ??= init({ module_or_path: wasmUrl }).then(() => core);
  return ready;
}
