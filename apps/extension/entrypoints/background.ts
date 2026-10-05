import { browser } from "wxt/browser";
import { Agent, AgentError, type Credentials } from "@/lib/agent";
import type { AuthEvent, PopupRequest, PopupResponse } from "@/lib/messages";

const ALL_URLS = { urls: ["<all_urls>"] };
const MAX_EVENTS = 20;
/** Background requests re-check with the agent this often, so a lock or removal reaches them too. */
const REVALIDATE_AFTER_MS = 30_000;
/** Navigations re-check every time, except right after the retry that followed a 401. */
const NAVIGATION_GRACE_MS = 2_000;

interface Header {
  name: string;
  value?: string;
}

interface RequestDetails {
  requestId: string;
  url: string;
  method: string;
  type: string;
  requestHeaders?: Header[];
}

interface ResponseDetails extends RequestDetails {
  statusCode: number;
  responseHeaders?: Header[];
}

interface AuthChallenge extends RequestDetails {
  isProxy: boolean;
}

interface BlockingResponse {
  redirectUrl?: string;
  requestHeaders?: Header[];
  authCredentials?: { username: string; password: string };
}

/** What this extension already did for one in-flight request. */
type RequestState = "injected" | "lookup_failed";

export default defineBackground({
  // Firefox (MV2): keep the page alive so the native port stays open.
  persistent: true,
  main() {
    const agent = new Agent();
    const events: AuthEvent[] = [];
    /** Credentials in use per origin. On Firefox they go into our own header, never into the browser's cache. */
    const sessions = new Map<string, { creds: Credentials; at: number }>();
    const refreshing = new Map<string, Promise<Credentials | null>>();
    const requests = new Map<string, RequestState>();

    const record = (event: Omit<AuthEvent, "at">) => {
      events.unshift({ at: Date.now(), ...event });
      events.splice(MAX_EVENTS);
    };

    const badge = (text: string) => {
      const action = browser.action ?? browser.browserAction;
      void action.setBadgeBackgroundColor({ color: "#b3261e" });
      void action.setBadgeText({ text });
    };

    /** Asks the agent for the best login; records why when nothing comes back. */
    async function lookup(url: string, origin: string): Promise<Credentials | null> {
      try {
        const found = await agent.credentialsFor(url);
        if (!found) record({ origin, outcome: "no_match" });
        return found;
      } catch (err) {
        if (err instanceof AgentError && err.code === "locked") {
          badge("!");
          record({ origin, outcome: "locked" });
        } else {
          record({ origin, outcome: "error", detail: errorText(err) });
        }
        return null;
      }
    }

    /** Refreshes one origin's session entry, with at most one agent call in flight per origin. */
    function refresh(origin: string, url: string): Promise<Credentials | null> {
      let inflight = refreshing.get(origin);
      if (!inflight) {
        inflight = lookup(url, origin)
          .then((creds) => {
            if (creds) sessions.set(origin, { creds, at: Date.now() });
            else sessions.delete(origin);
            return creds;
          })
          .finally(() => refreshing.delete(origin));
        refreshing.set(origin, inflight);
      }
      return inflight;
    }

    // ---- Firefox only: blocking request hooks. -------------------------------
    // The browser caches credentials it supplied itself until it restarts, and
    // an extension cannot clear or even see that cache. So we never let it fill:
    // a 401 is answered by retrying with our own Authorization header, and the
    // header is re-validated with the agent on every navigation.

    async function onBeforeSendHeaders(details: RequestDetails): Promise<BlockingResponse> {
      const origin = originOf(details.url);
      const entry = sessions.get(origin);
      if (!entry) return {};
      const navigation = details.type === "main_frame" || details.type === "sub_frame";
      const age = Date.now() - entry.at;
      let creds: Credentials | null = entry.creds;
      if (navigation ? age > NAVIGATION_GRACE_MS : age > REVALIDATE_AFTER_MS) {
        creds = await refresh(origin, details.url);
        if (!creds) {
          requests.set(details.requestId, "lookup_failed");
          return {};
        }
        if (navigation) {
          badge("");
          record({ origin, outcome: "filled", detail: creds.path });
        }
      }
      requests.set(details.requestId, "injected");
      return { requestHeaders: withAuthorization(details.requestHeaders ?? [], creds) };
    }

    async function onHeadersReceived(details: ResponseDetails): Promise<BlockingResponse> {
      if (details.statusCode !== 401 || !hasBasicChallenge(details.responseHeaders)) return {};
      // Already tried for this request: let onAuthRequired decide.
      if (requests.has(details.requestId)) return {};
      // A redirect re-issues the request as GET, so other methods take the fallback.
      if (details.method !== "GET" && details.method !== "HEAD") return {};
      const origin = originOf(details.url);
      const creds = await refresh(origin, details.url);
      if (!creds) {
        requests.set(details.requestId, "lookup_failed");
        return {};
      }
      badge("");
      record({ origin, outcome: "filled", detail: creds.path });
      // Retry the same URL; the retry passes through onBeforeSendHeaders and gets the header.
      return { redirectUrl: details.url };
    }

    // ---- Both engines: the browser's own challenge. ---------------------------
    // The only path on Chromium, and the fallback on Firefox (non-GET first
    // requests, Digest). Credentials returned here land in the browser's cache.

    async function onAuthRequired(details: AuthChallenge): Promise<BlockingResponse> {
      if (details.isProxy) return {};
      const origin = originOf(details.url);
      const state = requests.get(details.requestId);
      if (state === "injected") {
        // The server rejected what we sent; step aside so the browser can ask.
        sessions.delete(origin);
        record({ origin, outcome: "rejected" });
        return {};
      }
      if (state === "lookup_failed") return {};
      const creds = await refresh(origin, details.url);
      if (!creds) {
        requests.set(details.requestId, "lookup_failed");
        return {};
      }
      requests.set(details.requestId, "injected");
      badge("");
      record({ origin, outcome: "filled", detail: creds.path });
      return { authCredentials: { username: creds.username, password: creds.password } };
    }

    type AuthListener = Parameters<typeof browser.webRequest.onAuthRequired.addListener>[0];
    type SendListener = Parameters<typeof browser.webRequest.onBeforeSendHeaders.addListener>[0];
    type ReceiveListener = Parameters<typeof browser.webRequest.onHeadersReceived.addListener>[0];
    if (import.meta.env.FIREFOX) {
      // Firefox resolves promises returned from blocking listeners.
      browser.webRequest.onBeforeSendHeaders.addListener(
        onBeforeSendHeaders as unknown as SendListener,
        ALL_URLS,
        ["blocking", "requestHeaders"],
      );
      browser.webRequest.onHeadersReceived.addListener(
        onHeadersReceived as unknown as ReceiveListener,
        ALL_URLS,
        ["blocking", "responseHeaders"],
      );
      browser.webRequest.onAuthRequired.addListener(
        onAuthRequired as unknown as AuthListener,
        ALL_URLS,
        ["blocking"],
      );
    } else {
      // Chromium wants the answer through a callback ("asyncBlocking", webRequestAuthProvider).
      const listener = ((details: AuthChallenge, callback?: (r: BlockingResponse) => void) => {
        void onAuthRequired(details).then((result) => callback?.(result));
      }) as unknown as AuthListener;
      browser.webRequest.onAuthRequired.addListener(listener, ALL_URLS, ["asyncBlocking"]);
    }
    const forget = (details: { requestId: string }) => {
      requests.delete(details.requestId);
    };
    browser.webRequest.onCompleted.addListener(forget, ALL_URLS);
    browser.webRequest.onErrorOccurred.addListener(forget, ALL_URLS);

    async function handle(message: PopupRequest): Promise<PopupResponse> {
      if (message.kind === "events") return { kind: "events", events };
      try {
        const reply = await agent.call(message.request);
        if (message.request.method === "unlock") badge("");
        if (message.request.method === "lock") sessions.clear();
        return { kind: "agent", response: { ok: reply } };
      } catch (err) {
        if (err instanceof AgentError) return { kind: "agent", response: { err: err.info } };
        return { kind: "bridge_error", message: errorText(err) };
      }
    }

    browser.runtime.onMessage.addListener(
      (message: unknown, _sender, sendResponse: (response: PopupResponse) => void) => {
        void handle(message as PopupRequest).then(sendResponse);
        return true;
      },
    );
  },
});

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

function withAuthorization(headers: Header[], creds: Credentials): Header[] {
  const kept = headers.filter((h) => h.name.toLowerCase() !== "authorization");
  kept.push({ name: "Authorization", value: basic(creds.username, creds.password) });
  return kept;
}

/** RFC 7617 with UTF-8, which is what servers expect from a modern browser. */
function basic(username: string, password: string): string {
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

function hasBasicChallenge(headers?: Header[]): boolean {
  return (headers ?? []).some(
    (h) => h.name.toLowerCase() === "www-authenticate" && /(^|,)\s*basic\b/i.test(h.value ?? ""),
  );
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
