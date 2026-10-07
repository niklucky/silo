import { browser } from "wxt/browser";
import { Agent, AgentError, type Credentials } from "@/lib/agent";
import type { AuthEvent, ChallengeView, UiRequest, UiResponse } from "@/lib/messages";
import { secretPath } from "@/lib/protocol";
import { errorText, originOf } from "@/lib/util";

const ALL_URLS = { urls: ["<all_urls>"] };
const MAX_EVENTS = 20;
/** Background requests re-check with the agent this often, so a lock or removal reaches them too. */
const REVALIDATE_AFTER_MS = 30_000;
/** Navigations re-check every time, except right after the retry that followed a 401. */
const NAVIGATION_GRACE_MS = 2_000;
/** After Cancel on the auth page, leave the site to the browser for this long. */
const BYPASS_MS = 15_000;
/** An auth page left open longer than this is stale. */
const CHALLENGE_TTL_MS = 10 * 60_000;

interface Header {
  name: string;
  value?: string;
}

interface RequestDetails {
  requestId: string;
  url: string;
  method: string;
  type: string;
  tabId: number;
  requestHeaders?: Header[];
}

interface ResponseDetails extends RequestDetails {
  statusCode: number;
  responseHeaders?: Header[];
}

interface AuthChallenge extends RequestDetails {
  isProxy: boolean;
  realm?: string;
}

interface BlockingResponse {
  cancel?: boolean;
  redirectUrl?: string;
  requestHeaders?: Header[];
  authCredentials?: { username: string; password: string };
}

/** What this extension already did for one in-flight request. */
type RequestState = "injected" | "lookup_failed";

type Lookup =
  | { kind: "found"; creds: Credentials }
  | { kind: "none" }
  | { kind: "locked" }
  | { kind: "error"; message: string };

interface Challenge extends ChallengeView {
  at: number;
}

export default defineBackground({
  // Firefox (MV2): keep the page alive so the native port stays open.
  persistent: true,
  main() {
    const agent = new Agent();
    const events: AuthEvent[] = [];
    /** Credentials in use per origin. On Firefox they go into our own header, never into the browser's cache. */
    const sessions = new Map<string, { creds: Credentials; at: number }>();
    /** "Use once" credentials: this browser session only, never stored. */
    const transient = new Map<string, Credentials>();
    const refreshing = new Map<string, Promise<Lookup>>();
    const requests = new Map<string, RequestState>();
    /** 401s taken over from the browser, keyed by the id in the auth page URL. */
    const challenges = new Map<string, Challenge>();
    /** Origins handed back to the browser after Cancel, until the given time. */
    const bypass = new Map<string, number>();

    const record = (event: Omit<AuthEvent, "at">) => {
      events.unshift({ at: Date.now(), ...event });
      events.splice(MAX_EVENTS);
    };

    const badge = (text: string) => {
      const action = browser.action ?? browser.browserAction;
      void action.setBadgeBackgroundColor({ color: "#b3261e" });
      void action.setBadgeText({ text });
    };

    async function lookup(url: string): Promise<Lookup> {
      try {
        const found = await agent.credentialsFor(url);
        return found ? { kind: "found", creds: found } : { kind: "none" };
      } catch (err) {
        if (err instanceof AgentError && err.code === "locked") return { kind: "locked" };
        return { kind: "error", message: errorText(err) };
      }
    }

    /**
     * Refreshes one origin's session entry, with at most one agent call in
     * flight per origin. "Use once" credentials stand in when the agent has
     * nothing saved; a lock discards them.
     */
    function refresh(origin: string, url: string): Promise<Lookup> {
      let inflight = refreshing.get(origin);
      if (!inflight) {
        inflight = lookup(url)
          .then((result): Lookup => {
            if (result.kind === "none") {
              const once = transient.get(origin);
              if (once) result = { kind: "found", creds: once };
            }
            if (result.kind === "locked") transient.clear();
            if (result.kind === "found") sessions.set(origin, { creds: result.creds, at: Date.now() });
            else sessions.delete(origin);
            return result;
          })
          .finally(() => refreshing.delete(origin));
        refreshing.set(origin, inflight);
      }
      return inflight;
    }

    /** Leaves the request to the browser and notes why. */
    function giveUp(details: RequestDetails, origin: string, result: Exclude<Lookup, { kind: "found" }>) {
      requests.set(details.requestId, "lookup_failed");
      if (result.kind === "locked") {
        badge("!");
        record({ origin, outcome: "locked" });
      } else if (result.kind === "none") {
        record({ origin, outcome: "no_match" });
      } else {
        record({ origin, outcome: "error", detail: result.message });
      }
    }

    /** Only top-level navigations get our page; frames and fetches keep the browser's dialog. */
    function canTakeOver(details: RequestDetails, origin: string): boolean {
      const until = bypass.get(origin);
      if (until !== undefined) {
        if (Date.now() < until) return false;
        bypass.delete(origin);
      }
      return details.type === "main_frame" && details.tabId >= 0;
    }

    /** Remembers the challenge and returns the URL of the auth page that resolves it. */
    function takeOver(
      details: RequestDetails,
      origin: string,
      realm: string | null,
      state: Challenge["state"],
    ): string {
      const id = crypto.randomUUID();
      challenges.set(id, {
        id,
        url: details.url,
        origin,
        host: new URL(details.url).host,
        realm,
        state,
        at: Date.now(),
      });
      requests.set(details.requestId, "lookup_failed");
      record({ origin, outcome: "asked" });
      return `${browser.runtime.getURL("/auth.html")}?id=${id}`;
    }

    function liveChallenge(id: string): Challenge | null {
      const challenge = challenges.get(id);
      if (!challenge) return null;
      if (Date.now() - challenge.at > CHALLENGE_TTL_MS) {
        challenges.delete(id);
        return null;
      }
      return challenge;
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
      let creds = entry.creds;
      if (navigation ? age > NAVIGATION_GRACE_MS : age > REVALIDATE_AFTER_MS) {
        const result = await refresh(origin, details.url);
        // Nothing to send: the 401 that follows is handled in onHeadersReceived.
        if (result.kind !== "found") return {};
        creds = result.creds;
        if (navigation) {
          badge("");
          record({ origin, outcome: "filled", detail: creds.path });
        }
      }
      requests.set(details.requestId, "injected");
      return { requestHeaders: withAuthorization(details.requestHeaders ?? [], creds) };
    }

    async function onHeadersReceived(details: ResponseDetails): Promise<BlockingResponse> {
      if (details.statusCode !== 401) return {};
      const challenge = basicChallenge(details.responseHeaders);
      if (!challenge) return {};
      // Already tried for this request: let onAuthRequired decide.
      if (requests.has(details.requestId)) return {};
      // A redirect re-issues the request as GET, so other methods take the fallback.
      if (details.method !== "GET" && details.method !== "HEAD") return {};
      const origin = originOf(details.url);
      const result = await refresh(origin, details.url);
      if (result.kind === "found") {
        badge("");
        record({ origin, outcome: "filled", detail: result.creds.path });
        // Retry the same URL; the retry passes through onBeforeSendHeaders and gets the header.
        return { redirectUrl: details.url };
      }
      if (result.kind !== "error" && canTakeOver(details, origin)) {
        return { redirectUrl: takeOver(details, origin, challenge.realm, stateFor(result)) };
      }
      giveUp(details, origin, result);
      return {};
    }

    // ---- Both engines: the browser's own challenge. ---------------------------
    // The only path on Chromium, and the fallback on Firefox (non-GET first
    // requests, Digest, frames and fetches). Credentials returned here land in
    // the browser's cache.

    async function onAuthRequired(details: AuthChallenge): Promise<BlockingResponse> {
      if (details.isProxy) return {};
      const origin = originOf(details.url);
      const state = requests.get(details.requestId);
      if (state === "injected") {
        // The server rejected what we sent; step aside so the browser can ask.
        sessions.delete(origin);
        transient.delete(origin);
        record({ origin, outcome: "rejected" });
        return {};
      }
      if (state === "lookup_failed") return {};
      const result = await refresh(origin, details.url);
      if (result.kind === "found") {
        requests.set(details.requestId, "injected");
        badge("");
        record({ origin, outcome: "filled", detail: result.creds.path });
        return { authCredentials: { username: result.creds.username, password: result.creds.password } };
      }
      if (result.kind !== "error" && !import.meta.env.FIREFOX && canTakeOver(details, origin)) {
        // Chromium cannot redirect from here, so cancel and send the tab to the auth page.
        const page = takeOver(details, origin, details.realm ?? null, stateFor(result));
        void browser.tabs.update(details.tabId, { url: page });
        return { cancel: true };
      }
      giveUp(details, origin, result);
      return {};
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

    // ---- Popup and auth page. -------------------------------------------------

    async function handle(message: UiRequest): Promise<UiResponse> {
      switch (message.kind) {
        case "events":
          return { kind: "events", events };
        case "agent":
          try {
            const reply = await agent.call(message.request);
            if (message.request.method === "unlock") badge("");
            if (message.request.method === "lock") {
              sessions.clear();
              transient.clear();
            }
            return { kind: "agent", response: { ok: reply } };
          } catch (err) {
            if (err instanceof AgentError) return { kind: "agent", response: { err: err.info } };
            return { kind: "bridge_error", message: errorText(err) };
          }
        case "challenge": {
          const challenge = liveChallenge(message.id);
          if (!challenge) return { kind: "unknown_challenge" };
          const { at: _at, ...view } = challenge;
          return { kind: "challenge", challenge: view };
        }
        case "challenge_retry": {
          const challenge = liveChallenge(message.id);
          if (!challenge) return { kind: "unknown_challenge" };
          const result = await refresh(challenge.origin, challenge.url);
          if (result.kind === "found") {
            challenges.delete(challenge.id);
            record({ origin: challenge.origin, outcome: "filled", detail: result.creds.path });
            return { kind: "continue", url: challenge.url };
          }
          if (result.kind === "none") {
            challenge.state = "no_match";
            return { kind: "save" };
          }
          if (result.kind === "locked") return { kind: "error", message: "The vault is still locked." };
          return { kind: "error", message: result.message };
        }
        case "challenge_save": {
          const challenge = liveChallenge(message.id);
          if (!challenge) return { kind: "unknown_challenge" };
          const folder = message.folder.trim();
          const title = message.title.trim();
          const creds: Credentials = {
            username: message.username,
            password: message.password,
            path: folder ? `${folder}/${title}` : title,
          };
          if (message.remember) {
            try {
              const added = await agent.add({
                title,
                folder: folder || undefined,
                urls: [challenge.origin],
                body: { login: { username: creds.username, password: creds.password, totp: null, notes: "" } },
              });
              creds.path = secretPath(added.meta);
            } catch (err) {
              if (err instanceof AgentError) return { kind: "error", message: err.message };
              return { kind: "bridge_error", message: errorText(err) };
            }
          } else {
            transient.set(challenge.origin, creds);
          }
          sessions.set(challenge.origin, { creds, at: Date.now() });
          challenges.delete(challenge.id);
          record({ origin: challenge.origin, outcome: "filled", detail: creds.path });
          return { kind: "continue", url: challenge.url };
        }
        case "challenge_cancel": {
          const challenge = challenges.get(message.id);
          if (!challenge) return { kind: "unknown_challenge" };
          challenges.delete(challenge.id);
          bypass.set(challenge.origin, Date.now() + BYPASS_MS);
          return { kind: "continue", url: challenge.url };
        }
      }
    }

    browser.runtime.onMessage.addListener(
      (message: unknown, _sender, sendResponse: (response: UiResponse) => void) => {
        void handle(message as UiRequest).then(sendResponse);
        return true;
      },
    );
  },
});

function stateFor(result: Exclude<Lookup, { kind: "found" | "error" }>): Challenge["state"] {
  return result.kind === "locked" ? "locked" : "no_match";
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

/** The Basic challenge in a 401, with its realm, or null when the site wants another scheme. */
function basicChallenge(headers?: Header[]): { realm: string | null } | null {
  for (const header of headers ?? []) {
    if (header.name.toLowerCase() !== "www-authenticate") continue;
    const value = header.value ?? "";
    if (!/(^|,)\s*basic\b/i.test(value)) continue;
    const realm = /realm\s*=\s*(?:"([^"]*)"|([^,\s]+))/i.exec(value);
    return { realm: realm?.[1] ?? realm?.[2] ?? null };
  }
  return null;
}
