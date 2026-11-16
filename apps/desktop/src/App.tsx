import { useMemo } from "react";
import { commands } from "@silo/bindings/desktop";
import { createAgentClient, createMockClient, VaultApp } from "@silo/ui";

/** Inside Tauri: the local agent. In a plain browser (`pnpm dev`): made-up data, for UI work. */
const inTauri = "__TAURI_INTERNALS__" in window;

// macOS draws the traffic lights over the content (titleBarStyle: Overlay).
if (inTauri && navigator.userAgent.includes("Mac")) document.documentElement.dataset.titlebar = "overlay";

export default function App() {
  const client = useMemo(() => (inTauri ? createAgentClient(commands.agentCall) : createMockClient()), []);
  return <VaultApp client={client} host="desktop" />;
}
