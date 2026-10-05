import { loadCore } from "@/lib/core";

export default defineBackground(() => {
  // Basic Auth handling (declarativeNetRequest session rules + onAuthRequired)
  // will live here. For now: prove the core loads in the service worker.
  loadCore()
    .then((core) => console.log("[secret] core", core.version(), "ready in background"))
    .catch((err: unknown) => console.error("[secret] core failed to load", err));
});
