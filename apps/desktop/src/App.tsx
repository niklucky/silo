import { useMemo } from "react";
import { commands } from "@silo/bindings/desktop";
import { createAgentClient, createMockClient, type SiteFetcher, VaultApp } from "@silo/ui";

/** Inside Tauri: the local agent. In a plain browser (`pnpm dev`): made-up data, for UI work. */
const inTauri = "__TAURI_INTERNALS__" in window;

// macOS draws the traffic lights over the content (titleBarStyle: Overlay).
if (inTauri && navigator.userAgent.includes("Mac")) document.documentElement.dataset.titlebar = "overlay";

/** Website GETs for favicons, made by the Rust host: the webview cannot read other origins. */
const fetchSite: SiteFetcher = async (url, limit) => {
  const response = await commands.fetchSite(url, limit);
  if (!response) return null;
  const body = Uint8Array.from(atob(response.body), (c) => c.charCodeAt(0));
  return { url: response.url, contentType: response.content_type, body };
};

export default function App() {
  const client = useMemo(() => (inTauri ? createAgentClient(commands.agentCall) : createMockClient()), []);
  return <VaultApp client={client} host="desktop" fetchSite={inTauri ? fetchSite : undefined} />;
}
