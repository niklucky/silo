import { defineConfig } from "wxt";

// https://wxt.dev/api/config.html
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "Secret",
    description:
      "Passwords, env vars and secret files, including HTTP Basic Auth autofill.",
    // The Rust core runs as WebAssembly; MV3 requires this directive to instantiate it.
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';",
    },
  },
});
