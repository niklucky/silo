import { browser } from "wxt/browser";
import { Agent, AgentError, BridgeError, type Credentials } from "@/lib/agent";
import { HeaderRules } from "@/lib/header-rules";
import {
  type AuthEvent,
  type ChallengeView,
  type LinkOption,
  type LoginOption,
  PAGE_KINDS,
  type PageRequest,
  type PageResponse,
  type SameSiteLogin,
  type SaveChoice,
  type SaveOffer,
  type TabMessage,
  type UiRequest,
  type UiResponse,
  type UpdateTarget,
} from "@/lib/messages";
import { isBasicAuth, type SecretSummary, secretPath } from "@/lib/protocol";
import { loadSettings, saveSettings } from "@/lib/settings";
import { patternHosts, widening } from "@/lib/site";
import { errorText, originOf } from "@/lib/util";

const ALL_URLS = { urls: ["<all_urls>"] };
const MAX_EVENTS = 20;
/** Background requests re-check with the agent this often, so a lock or removal reaches them too. */
const REVALIDATE_AFTER_MS = 30_000;
/** Navigations re-check every time, except right after the retry that followed a 401. */
const NAVIGATION_GRACE_MS = 2_000;
/** Check for external locks while the background holds credentials or refusals. */
const LOCK_CHECK_MS = 5_000;
/** After Cancel on the auth page, leave the site to the browser for this long. */
const BYPASS_MS = 15_000;
/** An auth page left open longer than this is stale. */
const CHALLENGE_TTL_MS = 10 * 60_000;
/** A 401 tries at most this many saved logins before asking: each refused one is a failed sign-in. */
const MAX_BASIC_TRIES = 3;
/** The form-fill menu lists at most this many logins. */
const MAX_OPTIONS = 8;
/** A save looks at this many same-site logins for the same username, and offers at most MAX_CONFLICTS. */
const MAX_SITE_LOGINS = 20;
const MAX_CONFLICTS = 3;
/** A login the user signed in with is offered for saving this long. */
const OFFER_TTL_MS = 3 * 60_000;
/** The username from the first step of a two-step sign-in is kept this long for the second. */
const FIRST_STEP_TTL_MS = 5 * 60_000;

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
  scheme?: string;
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

/** Who sent a page message, as the browser reports it. */
interface PageSender {
  url: string;
  tabId?: number;
  frameId?: number;
}

/** A login the user signed in with, waiting for an answer in the tab's top frame. Memory only. */
interface PendingOffer {
  id: string;
  tabId: number;
  url: string;
  username: string;
  password: string;
  previous?: string;
  at: number;
}

/** A same-site login with its password and URL patterns, which stay in the background. */
interface SiteLogin extends SameSiteLogin {
  password: string;
  urls: string[];
}

/** A login the auth page just made fill on an origin, with its URL patterns from before. */
interface Link {
  id: string;
  /** The revision the link made; a later edit keeps the link. */
  revision: number;
  urls: string[];
}

export default defineBackground({
  // Firefox and Safari (MV2): keep the page alive, with the native port on
  // Firefox and the sessions on both.
  persistent: true,
  main() {
    const agent = new Agent();
    const events: AuthEvent[] = [];
    /**
     * Credentials in use per origin. They go into our own Authorization header,
     * never into the browser's cache: from onBeforeSendHeaders on Firefox, from
     * a session rule on Chromium and Safari.
     */
    const sessions = new Map<string, { creds: Credentials; at: number; challengeUrl?: string }>();
    const rules = import.meta.env.FIREFOX ? null : new HeaderRules();
    void rules?.reset();
    /** The credentials each request to a session origin went out with. */
    const sentWith = new Map<string, Credentials>();
    /**
     * Credentials a server answered with another 401, by origin and realm. They are
     * skipped until the vault locks; a changed password is tried again.
     */
    const refused = new Map<string, Map<string | null, Credentials[]>>();
    /** Realms learned from challenges; an unchallenged path has no refusal history yet. */
    const realms = new Map<string, string | null>();
    /** Requests retrying a Basic challenge, with the URL that actually challenged them. */
    const basicRequests = new Map<string, string>();
    /** Logins already being marked for Basic Auth, so a page load asks the agent once. */
    const marking = new Set<string>();
    /** "Use once" credentials: this browser session only, never stored. */
    const transient = new Map<string, Credentials>();
    const refreshing = new Map<string, Promise<Lookup>>();
    let sessionGeneration = 0;
    const requests = new Map<string, RequestState>();
    /** 401s taken over from the browser, keyed by the id in the auth page URL. */
    const challenges = new Map<string, Challenge>();
    /** Origins handed back to the browser after Cancel, until the given time. */
    const bypass = new Map<string, number>();
    /** Save offers by tab. */
    const offers = new Map<number, PendingOffer>();
    /** Username sent by the first step of a two-step sign-in, by tab. */
    const firstSteps = new Map<number, { origin: string; username: string; at: number }>();
    /** Links from the auth page by origin, until the site accepts the login or refuses it. */
    const linked = new Map<string, Link>();

    const record = (event: Omit<AuthEvent, "at">) => {
      events.unshift({ at: Date.now(), ...event });
      events.splice(MAX_EVENTS);
    };

    const badge = (text: string) => {
      const action = browser.action ?? browser.browserAction;
      void action.setBadgeBackgroundColor({ color: "#b3261e" });
      void action.setBadgeText({ text });
    };

    async function startSession(origin: string, creds: Credentials, challengeUrl?: string): Promise<void> {
      sessions.set(origin, { creds, at: Date.now(), challengeUrl });
      await rules?.set(origin, basic(creds.username, creds.password)).catch((err: unknown) => {
        record({ origin, outcome: "error", detail: `header rule: ${errorText(err)}` });
      });
    }

    async function endSession(origin: string): Promise<void> {
      sessions.delete(origin);
      await rules?.remove(origin).catch(() => undefined);
    }

    async function endAllSessions(): Promise<void> {
      sessionGeneration++;
      sessions.clear();
      transient.clear();
      refused.clear();
      realms.clear();
      sentWith.clear();
      requests.clear();
      basicRequests.clear();
      marking.clear();
      refreshing.clear();
      linked.clear();
      await rules?.clear().catch(() => undefined);
    }

    function refusals(origin: string, realm: string | null | undefined): Credentials[] {
      return realm === undefined ? [] : (refused.get(origin)?.get(realm) ?? []);
    }

    /** A retry can teach us about this challenged URL, never an unrelated public navigation. */
    function expectBasic(origin: string, url: string, creds: Credentials): void {
      const session = sessions.get(origin);
      if (session && sameCredentials(session.creds, creds)) session.challengeUrl = url;
    }

    /** The best login for this URL's known realm, Basic Auth logins first. */
    async function lookup(origin: string, url: string): Promise<Lookup> {
      try {
        const skip = refusals(origin, realms.get(authPath(url)));
        const matches = await agent.matches(url);
        for (const match of basicAuth(matches, "first").slice(0, MAX_BASIC_TRIES)) {
          const creds = await agent.credentials(match.id);
          if (creds && !skip.some((c) => sameCredentials(c, creds))) return { kind: "found", creds };
        }
        return { kind: "none" };
      } catch (err) {
        if (err instanceof AgentError && err.code === "locked") return { kind: "locked" };
        return { kind: "error", message: errorText(err) };
      }
    }

    /**
     * Refreshes one origin's session entry, with one lookup in flight per URL.
     * Different paths may challenge with different realms. "Use once"
     * credentials stand in when the agent has nothing saved; a lock discards them.
     */
    function refresh(origin: string, url: string): Promise<Lookup> {
      let inflight = refreshing.get(url);
      if (!inflight) {
        const generation = sessionGeneration;
        inflight = lookup(origin, url)
          .then(async (result): Promise<Lookup> => {
            // A lookup begun before a lock cannot restore its cached credentials afterward.
            if (generation !== sessionGeneration) return { kind: "locked" };
            if (result.kind === "none") {
              const once = transient.get(origin);
              if (once) result = { kind: "found", creds: once };
            }
            if (result.kind === "locked") {
              await endAllSessions();
              return result;
            }
            if (result.kind === "found") {
              const current = sessions.get(origin);
              const challengeUrl = current && sameCredentials(current.creds, result.creds)
                ? current.challengeUrl
                : undefined;
              await startSession(origin, result.creds, challengeUrl);
            } else await endSession(origin);
            if (result.kind === "found" && generation !== sessionGeneration) return { kind: "locked" };
            return result;
          })
          .finally(() => {
            if (refreshing.get(url) === inflight) refreshing.delete(url);
          });
        refreshing.set(url, inflight);
      }
      return inflight;
    }

    /**
     * The server answered `sent` with another 401: skip it from now on, so the
     * next lookup gets the next saved login, and end the session it came from.
     */
    async function refuse(origin: string, realm: string | null, sent: Credentials): Promise<void> {
      const list = refusals(origin, realm);
      if (!list.some((c) => sameCredentials(c, sent))) {
        const byRealm = refused.get(origin) ?? new Map<string | null, Credentials[]>();
        byRealm.set(realm, [...list, sent]);
        refused.set(origin, byRealm);
        record({ origin, outcome: "rejected", detail: sent.path });
      }
      const once = transient.get(origin);
      if (once && sameCredentials(once, sent)) transient.delete(origin);
      const current = sessions.get(origin)?.creds;
      if (current && sameCredentials(current, sent)) await endSession(origin);
      const link = linked.get(origin);
      if (link && link.id === sent.id) {
        linked.delete(origin);
        await unlink(origin, link);
      }
    }

    /** Takes back a link the site refused, unless the login was edited since. */
    async function unlink(origin: string, link: Link): Promise<void> {
      try {
        const view = await agent.get(link.id);
        if (view.revision !== link.revision) return;
        await agent.update({ selector: view.id, revision: view.revision, urls: link.urls });
        record({ origin, outcome: "rejected", detail: `${secretPath(view.meta)} (link undone)` });
      } catch {
        // Locked, removed or edited meanwhile: the link stays.
      }
    }

    /** A page load that went out with `sent` got through: mark the login so it goes first from now on. */
    function accept(origin: string, sent: Credentials): void {
      const { id } = sent;
      if (id && linked.get(origin)?.id === id) linked.delete(origin);
      if (!id || sent.basicAuth || marking.has(id)) return;
      marking.add(id);
      agent.markBasicAuth(id).then(
        () => record({ origin, outcome: "saved", detail: `${sent.path} (marked for Basic Auth)` }),
        // Locked, removed or edited meanwhile: the next page load after the lock tries again.
        () => marking.delete(id),
      );
    }

    /** Leaves the request to the browser and notes why. */
    function giveUp(details: RequestDetails, origin: string, result: Exclude<Lookup, { kind: "found" }>) {
      requests.set(details.requestId, "lookup_failed");
      sentWith.delete(details.requestId);
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
        refused: refusals(origin, realm).map((c) => c.path),
        at: Date.now(),
      });
      requests.set(details.requestId, "lookup_failed");
      sentWith.delete(details.requestId);
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
      sentWith.set(details.requestId, creds);
      basicRequests.delete(details.requestId);
      if (sessions.get(origin)?.challengeUrl === details.url) basicRequests.set(details.requestId, details.url);
      return { requestHeaders: withAuthorization(details.requestHeaders ?? [], creds) };
    }

    async function onHeadersReceived(details: ResponseDetails): Promise<BlockingResponse> {
      if (details.statusCode !== 401) return {};
      const challenge = basicChallenge(details.responseHeaders);
      if (!challenge) return {};
      const state = requests.get(details.requestId);
      if (state === "lookup_failed") return {};
      // A redirect re-issues the request as GET, so other methods take the fallback.
      if (details.method !== "GET" && details.method !== "HEAD") return {};
      const origin = originOf(details.url);
      realms.set(authPath(details.url), challenge.realm);
      // The server refused what we sent: retry with the next saved login, or ask.
      const sent = sentWith.get(details.requestId);
      if (state === "injected" && sent) await refuse(origin, challenge.realm, sent);
      const result = await refresh(origin, details.url);
      if (result.kind === "found") {
        badge("");
        record({ origin, outcome: "filled", detail: result.creds.path });
        // Retry the challenged URL; only that retry can mark this login as Basic Auth.
        expectBasic(origin, details.url, result.creds);
        return { redirectUrl: details.url };
      }
      if (result.kind !== "error" && canTakeOver(details, origin)) {
        return { redirectUrl: takeOver(details, origin, challenge.realm, stateFor(result)) };
      }
      giveUp(details, origin, result);
      return {};
    }

    // ---- Chromium and Safari: session rules. -----------------------------------
    // Without blocking request hooks, a 401 is answered by adding a header rule
    // for the origin and loading the page again (onAuthRequired below). Requests
    // to an origin with a rule re-check with the agent as on Firefox, but cannot
    // wait for the answer: when it says no, the rule goes and a navigation is
    // loaded again, which lands on the sign-in page. A lock from the CLI or the
    // agent's timeout is noticed within LOCK_CHECK_MS.

    /** A first visit Chromium can load again once the header rule is in place. */
    function canReload(details: RequestDetails): boolean {
      return details.type === "main_frame" && details.tabId >= 0 && details.method === "GET";
    }

    async function reload(details: RequestDetails): Promise<BlockingResponse> {
      // Navigating first makes the cancel below land on a request the tab has already left.
      await browser.tabs.update(details.tabId, { url: details.url }).catch(() => undefined);
      return { cancel: true };
    }

    async function revalidate(details: RequestDetails, origin: string, sent: Credentials): Promise<void> {
      const result = await refresh(origin, details.url);
      const navigation = details.type === "main_frame" || details.type === "sub_frame";
      if (result.kind === "found") {
        if (navigation) {
          badge("");
          record({ origin, outcome: "filled", detail: result.creds.path });
        }
        if (sameCredentials(result.creds, sent) || !canReload(details)) return;
      }
      // The page went out with credentials the vault no longer gives.
      if (canReload(details)) await browser.tabs.update(details.tabId, { url: details.url }).catch(() => undefined);
    }

    function onBeforeRequest(details: RequestDetails): void {
      const origin = originOf(details.url);
      const entry = sessions.get(origin);
      if (!entry) return;
      requests.set(details.requestId, "injected");
      sentWith.set(details.requestId, entry.creds);
      basicRequests.delete(details.requestId);
      if (entry.challengeUrl === details.url) basicRequests.set(details.requestId, details.url);
      const navigation = details.type === "main_frame" || details.type === "sub_frame";
      const age = Date.now() - entry.at;
      if (navigation ? age > NAVIGATION_GRACE_MS : age > REVALIDATE_AFTER_MS) {
        void revalidate(details, origin, entry.creds);
      }
    }

    async function checkLock(): Promise<void> {
      if (
        sessions.size === 0 &&
        refused.size === 0 &&
        sentWith.size === 0 &&
        transient.size === 0 &&
        refreshing.size === 0
      ) return;
      try {
        if (!(await agent.status()).unlocked) await endAllSessions();
      } catch {
        await endAllSessions();
      }
    }

    // ---- All engines: the browser's own challenge. ----------------------------
    // On Chromium the first 401 of a page load; on Firefox the fallback for
    // non-GET first requests, Digest, frames and fetches. Credentials returned
    // here land in the browser's cache, so Chromium returns them only for
    // requests it cannot load again. Safari has no such event: onUnauthorized
    // below calls this for page loads, and its own dialog handles the rest.

    async function onAuthRequired(details: AuthChallenge): Promise<BlockingResponse> {
      if (details.isProxy) return {};
      const origin = originOf(details.url);
      const state = requests.get(details.requestId);
      const isBasic = details.scheme?.toLowerCase() === "basic";
      const realm = details.realm ?? null;
      if (isBasic) realms.set(authPath(details.url), realm);
      if (state === "injected") {
        const sent = sentWith.get(details.requestId);
        if (!import.meta.env.FIREFOX && sent) {
          // The rule may have changed while the request was out (a new password in the vault).
          await refreshing.get(details.url);
          const current = sessions.get(origin)?.creds;
          if (current && !sameCredentials(current, sent) && canReload(details)) return reload(details);
        }
        if (!sent) return {};
        // The server refused what we sent: try the next saved login, or ask.
        if (isBasic) await refuse(origin, realm, sent);
        else return {};
      }
      if (state === "lookup_failed") return {};
      const result = await refresh(origin, details.url);
      if (result.kind === "found") {
        badge("");
        record({ origin, outcome: "filled", detail: result.creds.path });
        if (isBasic) expectBasic(origin, details.url, result.creds);
        if (!import.meta.env.FIREFOX && canReload(details)) return reload(details);
        if (isBasic) basicRequests.set(details.requestId, details.url);
        requests.set(details.requestId, "injected");
        sentWith.set(details.requestId, result.creds);
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

    /** Safari: a 401 to a page load, while Safari's own dialog opens. Loading the tab again closes it. */
    function onUnauthorized(details: ResponseDetails): void {
      if (details.statusCode !== 401 || !canReload(details)) return;
      const challenge = basicChallenge(details.responseHeaders);
      if (!challenge) return;
      void onAuthRequired({ ...details, isProxy: false, realm: challenge.realm ?? undefined, scheme: "basic" });
    }

    type AuthListener = Parameters<typeof browser.webRequest.onAuthRequired.addListener>[0];
    type SendListener = Parameters<typeof browser.webRequest.onBeforeSendHeaders.addListener>[0];
    type ReceiveListener = Parameters<typeof browser.webRequest.onHeadersReceived.addListener>[0];
    type RequestListener = Parameters<typeof browser.webRequest.onBeforeRequest.addListener>[0];
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
      if (import.meta.env.SAFARI) {
        browser.webRequest.onHeadersReceived.addListener(
          onUnauthorized as unknown as ReceiveListener,
          ALL_URLS,
          ["responseHeaders"],
        );
      } else {
        // Chromium wants the answer through a callback ("asyncBlocking", webRequestAuthProvider).
        const listener = ((details: AuthChallenge, callback?: (r: BlockingResponse) => void) => {
          void onAuthRequired(details).then((result) => callback?.(result));
        }) as unknown as AuthListener;
        browser.webRequest.onAuthRequired.addListener(listener, ALL_URLS, ["asyncBlocking"]);
      }
      browser.webRequest.onBeforeRequest.addListener(onBeforeRequest as unknown as RequestListener, ALL_URLS);
    }
    setInterval(() => void checkLock(), LOCK_CHECK_MS);
    const forget = (details: { requestId: string }) => {
      requests.delete(details.requestId);
      sentWith.delete(details.requestId);
      basicRequests.delete(details.requestId);
    };
    browser.webRequest.onCompleted.addListener((details) => {
      const sent = sentWith.get(details.requestId);
      if (
        sent &&
        details.type === "main_frame" &&
        basicRequests.get(details.requestId) === details.url &&
        details.statusCode >= 200 &&
        details.statusCode < 300
      ) {
        accept(originOf(details.url), sent);
      }
      forget(details);
    }, ALL_URLS);
    browser.webRequest.onErrorOccurred.addListener(forget, ALL_URLS);

    // ---- Saving next to logins of the same site. --------------------------------
    // dev.example.com and example.com are separate logins that never fill on each
    // other. A save that finds the same username elsewhere on the site asks
    // whether it is a new login or a new password for the existing one.

    /** Logins for this site (this host first), with passwords, at most MAX_SITE_LOGINS. */
    async function siteLogins(url: string): Promise<SiteLogin[]> {
      const here = new Set((await agent.matches(url)).map((m) => m.id));
      const found: SiteLogin[] = [];
      for (const summary of (await agent.matches(url, { site: true })).slice(0, MAX_SITE_LOGINS)) {
        const view = await agent.get(summary.id);
        if (!("login" in view.body)) continue;
        const { username, password } = view.body.login;
        const urls = view.meta.urls ?? [];
        found.push({ id: view.id, path: secretPath(view.meta), username, password, urls, here: here.has(view.id) });
      }
      return found;
    }

    /** Same-site logins saved under `username`; any username when it is empty. */
    async function sameSiteLogins(url: string, username: string): Promise<SiteLogin[]> {
      const wanted = username.trim();
      return (await siteLogins(url))
        .filter((login) => !wanted || sameUsername(login.username, wanted))
        .slice(0, MAX_CONFLICTS);
    }

    /**
     * Logins of other hosts of the site that the challenged host could use
     * instead of a new one, minus any it refused.
     */
    async function linkOptions(challenge: Challenge): Promise<LinkOption[]> {
      const skip = refusals(challenge.origin, challenge.realm);
      return (await siteLogins(challenge.url))
        .filter((login) => !login.here && !skip.some((c) => sameCredentials(c, login)))
        .slice(0, MAX_OPTIONS)
        .map(({ id, path, username, urls }) => ({
          id,
          path,
          username,
          hosts: patternHosts(urls),
          wildcard: widening(urls, challenge.url)?.wildcard ?? null,
        }));
    }

    /**
     * Stores `password` in a login the user picked, adds `username` if it has
     * none, and makes it fill on `url` too. The agent keeps the replaced
     * revision. Nothing changes when the login already has all of that.
     */
    async function overwrite(target: SameSiteLogin, url: string, username: string, password: string): Promise<string> {
      const view = await agent.get(target.id);
      if (!("login" in view.body)) throw new Error(`${target.path} is not a login`);
      const { login } = view.body;
      const next = { ...login, username: login.username || username, password };
      const changed = next.username !== login.username || next.password !== login.password;
      if (!changed && target.here) return secretPath(view.meta);
      const updated = await agent.update({
        selector: view.id,
        revision: view.revision,
        urls: target.here ? undefined : [...(view.meta.urls ?? []), originOf(url)],
        body: changed ? { login: next } : undefined,
      });
      return secretPath(updated.meta);
    }

    /** A new login in `web/`, titled after the host (`host (2)` when taken), filling on its origin. */
    async function addWebLogin(url: string, username: string, password: string, notes: string): Promise<string> {
      const { host, origin } = new URL(url);
      const taken = new Set((await agent.list({ folder: "web", exact_folder: true })).map((m) => m.meta.title));
      let title = host;
      for (let n = 2; taken.has(title); n++) title = `${host} (${n})`;
      const added = await agent.add({
        title,
        folder: "web",
        urls: [origin],
        body: { login: { username, password, totp: null, notes } },
      });
      return secretPath(added.meta);
    }

    /**
     * Where a save goes: the conflicts to ask about when there is no choice yet,
     * otherwise the login to overwrite, or null for a new login.
     */
    async function resolveSave(
      url: string,
      username: string,
      choice: SaveChoice | undefined,
    ): Promise<{ conflicts: SiteLogin[] } | { target: SiteLogin | null }> {
      const conflicts = await sameSiteLogins(url, username);
      if (!choice) return conflicts.length > 0 ? { conflicts } : { target: null };
      if (choice.kind === "new") return { target: null };
      // Only a login that was offered for this page, whatever id the caller sends.
      const target = conflicts.find((c) => c.id === choice.id);
      if (!target) throw new Error("That login is not saved for this site.");
      return { target };
    }

    // ---- Offering to save what the user signed in with. ------------------------
    // The content script reports a sent login form; nothing is stored until the
    // user answers the offer, which the tab's top frame shows, on this page or
    // the next one. The password never goes back to a page.

    /**
     * Logins the sent one could update instead of being added, or null when a
     * login for this page already has it. With no username: logins for this
     * page whose password is the form's current one, else all of the site's.
     */
    async function updateTargets(offer: PendingOffer): Promise<UpdateTarget[] | null> {
      const logins = await siteLogins(offer.url);
      const wanted = offer.username.trim();
      const named = (login: SiteLogin) => wanted !== "" && sameUsername(login.username, wanted);
      if (logins.some((login) => login.here && login.password === offer.password && (!wanted || named(login)))) {
        return null;
      }
      const changing = (login: SiteLogin) => offer.previous !== undefined && login.password === offer.previous;
      return logins
        .filter((login) => {
          if (named(login)) return true;
          if (login.here && (!login.username || changing(login))) return true;
          return !wanted && offer.previous === undefined;
        })
        .slice(0, MAX_CONFLICTS)
        .map((login) => ({ ...pageLogin(login), samePassword: login.password === offer.password }));
    }

    /** What to show for a pending offer, or null when there is nothing to offer (any more). */
    async function offerView(offer: PendingOffer): Promise<SaveOffer | null> {
      const view = { id: offer.id, host: new URL(offer.url).host, username: offer.username };
      try {
        const logins = await updateTargets(offer);
        return logins && { ...view, locked: false, logins };
      } catch (err) {
        if (err instanceof AgentError && err.code === "locked") return { ...view, locked: true, logins: [] };
        // No agent or no vault: stay out of the way.
        return null;
      }
    }

    function liveOffer(tabId: number | undefined): PendingOffer | null {
      if (tabId === undefined) return null;
      const offer = offers.get(tabId);
      if (!offer) return null;
      if (Date.now() - offer.at > OFFER_TTL_MS) {
        offers.delete(tabId);
        return null;
      }
      return offer;
    }

    async function submitted(
      message: Extract<PageRequest, { kind: "page_submitted" }>,
      url: string,
      tabId: number,
    ): Promise<PageResponse> {
      const origin = originOf(url);
      const now = Date.now();
      if (!message.password) {
        firstSteps.set(tabId, { origin, username: message.username.trim(), at: now });
        return { kind: "ok" };
      }
      let username = message.username.trim();
      const step = firstSteps.get(tabId);
      if (!username && step && step.origin === origin && now - step.at < FIRST_STEP_TTL_MS) username = step.username;
      firstSteps.delete(tabId);
      const known = liveOffer(tabId);
      const same =
        known &&
        originOf(known.url) === origin &&
        known.username === username &&
        known.password === message.password;
      const offer: PendingOffer = same
        ? { ...known, at: now }
        : { id: crypto.randomUUID(), tabId, url, username, password: message.password, previous: message.previous, at: now };
      if (!(await offerView(offer))) {
        offers.delete(tabId);
        return { kind: "ok" };
      }
      offers.set(tabId, offer);
      // Pages that sign in without navigating show it now; the others ask when the next page loads.
      const show: TabMessage = { kind: "offer_save" };
      void browser.tabs.sendMessage(tabId, show, { frameId: 0 }).catch(() => undefined);
      return { kind: "ok" };
    }

    async function answerOffer(
      message: Extract<PageRequest, { kind: "page_offer_answer" }>,
      tabId: number,
    ): Promise<PageResponse> {
      const offer = liveOffer(tabId);
      if (!offer || offer.id !== message.id) return { kind: "failed", message: "This offer has expired." };
      const { answer } = message;
      const origin = originOf(offer.url);
      if (answer.kind === "dismiss" || answer.kind === "never") {
        offers.delete(tabId);
        if (answer.kind === "never") {
          const { neverSave } = await loadSettings();
          if (!neverSave.includes(origin)) await saveSettings({ neverSave: [...neverSave, origin] });
        }
        return { kind: "ok" };
      }
      const targets = await updateTargets(offer);
      if (!targets) {
        // Saved in the meantime, from another tab or the CLI.
        offers.delete(tabId);
        return { kind: "ok" };
      }
      let path: string;
      if (answer.kind === "overwrite") {
        // Only a login that was offered for this page, whatever id the caller sends.
        const target = targets.find((t) => t.id === answer.id);
        if (!target) throw new Error("That login is not saved for this site.");
        path = await overwrite(target, offer.url, offer.username, offer.password);
        record({ origin, outcome: "saved", detail: `${path} (updated after sign-in)` });
      } else {
        const notes = `Saved from the browser after signing in on ${new Date().toISOString().slice(0, 10)}.`;
        path = await addWebLogin(offer.url, offer.username, offer.password, notes);
        record({ origin, outcome: "saved", detail: path });
      }
      offers.delete(tabId);
      return { kind: "saved", path, updated: answer.kind === "overwrite" };
    }

    browser.tabs.onRemoved.addListener((tabId) => {
      offers.delete(tabId);
      firstSteps.delete(tabId);
    });

    // ---- Login forms (content script). ----------------------------------------
    // `url` is the sending frame's URL as the browser reports it.

    async function handlePage(message: PageRequest, sender: PageSender): Promise<PageResponse> {
      const { url, tabId, frameId } = sender;
      if (!/^https?:/.test(url)) return { kind: "unavailable" };
      try {
        switch (message.kind) {
          case "page_logins": {
            // On a sign-in form the site's own logins come first.
            const matches = basicAuth(await agent.matches(url), "last");
            const logins: LoginOption[] = [];
            for (const summary of matches.slice(0, MAX_OPTIONS)) {
              const view = await agent.get(summary.id);
              if (!("login" in view.body)) continue;
              const path = secretPath(view.meta);
              logins.push({ id: view.id, title: view.meta.title, path, username: view.body.login.username });
            }
            return { kind: "logins", logins };
          }
          case "page_fill": {
            // Only a login that matches this frame's URL, whatever id the page asks for.
            const matches = await agent.matches(url);
            if (!matches.some((m) => m.id === message.id)) return { kind: "unavailable" };
            const view = await agent.get(message.id);
            if (!("login" in view.body)) return { kind: "unavailable" };
            record({ origin: originOf(url), outcome: "filled", detail: `form → ${secretPath(view.meta)}` });
            return { kind: "credentials", username: view.body.login.username, password: view.body.login.password };
          }
          case "page_save_generated": {
            const origin = originOf(url);
            const resolved = await resolveSave(url, message.username, message.choice);
            if ("conflicts" in resolved) return { kind: "conflict", logins: resolved.conflicts.map(pageLogin) };
            if (resolved.target) {
              const path = await overwrite(resolved.target, url, message.username, message.password);
              record({ origin, outcome: "saved", detail: `${path} (new password)` });
              return { kind: "saved", path, updated: true };
            }
            const notes = `Generated in the browser on ${new Date().toISOString().slice(0, 10)}.`;
            const path = await addWebLogin(url, message.username, message.password, notes);
            record({ origin, outcome: "saved", detail: path });
            return { kind: "saved", path, updated: false };
          }
          case "page_submitted":
            if (tabId === undefined) return { kind: "unavailable" };
            return await submitted(message, url, tabId);
          case "page_offer": {
            // The offer shows in the top frame only, whichever frame the login was sent from.
            if (frameId !== 0) return { kind: "offer", offer: null };
            const offer = liveOffer(tabId);
            const view = offer && (await offerView(offer));
            if (offer && !view) offers.delete(offer.tabId);
            return { kind: "offer", offer: view ?? null };
          }
          case "page_offer_answer":
            if (frameId !== 0 || tabId === undefined) return { kind: "unavailable" };
            return await answerOffer(message, tabId);
          case "page_unlock":
            await browser.windows.create({
              url: browser.runtime.getURL("/unlock.html"),
              type: "popup",
              width: 360,
              height: 240,
            });
            return { kind: "ok" };
        }
      } catch (err) {
        if (err instanceof AgentError && err.code === "locked") {
          await endAllSessions();
          return { kind: "locked" };
        }
        if (message.kind === "page_save_generated" || message.kind === "page_offer_answer") {
          return { kind: "failed", message: errorText(err) };
        }
        return { kind: "unavailable" };
      }
    }

    // ---- Popup, auth and unlock pages. ----------------------------------------

    async function handle(message: UiRequest): Promise<UiResponse> {
      switch (message.kind) {
        case "events":
          return { kind: "events", events };
        case "agent":
          try {
            const reply = await agent.call(message.request);
            if (message.request.method === "unlock") badge("");
            if (message.request.method === "lock") await endAllSessions();
            return { kind: "agent", response: { ok: reply } };
          } catch (err) {
            if (err instanceof AgentError) {
              if (err.code === "locked") await endAllSessions();
              return { kind: "agent", response: { err: err.info } };
            }
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
          realms.set(authPath(challenge.url), challenge.realm);
          const result = await refresh(challenge.origin, challenge.url);
          if (result.kind === "found") {
            expectBasic(challenge.origin, challenge.url, result.creds);
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
            creds.basicAuth = true;
            try {
              const resolved = await resolveSave(challenge.url, creds.username, message.choice);
              if ("conflicts" in resolved) {
                const host = new URL(challenge.url).hostname;
                const logins = resolved.conflicts.map((login) => ({
                  ...pageLogin(login),
                  elsewhere: patternHosts(login.urls).filter((h) => h !== host),
                }));
                return { kind: "conflict", logins };
              }
              if (resolved.target) {
                creds.path = await overwrite(resolved.target, challenge.url, creds.username, creds.password);
                await agent.markBasicAuth(resolved.target.id);
                creds.id = resolved.target.id;
              } else {
                const added = await agent.add({
                  title,
                  folder: folder || undefined,
                  basic_auth: true,
                  urls: [challenge.origin],
                  body: { login: { username: creds.username, password: creds.password, totp: null, notes: "" } },
                });
                creds.path = secretPath(added.meta);
                creds.id = added.id;
              }
            } catch (err) {
              return failure(err);
            }
          } else {
            transient.set(challenge.origin, creds);
          }
          // Typed in by hand: worth another try even if the site refused it before.
          const byRealm = refused.get(challenge.origin);
          const skip = byRealm?.get(challenge.realm)?.filter((c) => !sameCredentials(c, creds));
          if (skip) byRealm?.set(challenge.realm, skip);
          realms.set(authPath(challenge.url), challenge.realm);
          await startSession(challenge.origin, creds, challenge.url);
          challenges.delete(challenge.id);
          record({ origin: challenge.origin, outcome: "filled", detail: creds.path });
          return { kind: "continue", url: challenge.url };
        }
        case "challenge_logins": {
          const challenge = liveChallenge(message.id);
          if (!challenge) return { kind: "unknown_challenge" };
          try {
            return { kind: "link_options", logins: await linkOptions(challenge) };
          } catch (err) {
            return failure(err);
          }
        }
        case "challenge_link": {
          const challenge = liveChallenge(message.id);
          if (!challenge) return { kind: "unknown_challenge" };
          let creds: Credentials;
          try {
            // Only a login that was offered for this challenge, whatever id the page sends.
            const option = (await linkOptions(challenge)).find((o) => o.id === message.login);
            if (!option) return { kind: "error", message: "That login is not saved for this site." };
            const view = await agent.get(option.id);
            if (!("login" in view.body)) return { kind: "error", message: `${option.path} is not a login.` };
            const before = view.meta.urls ?? [];
            const wide = message.wildcard ? widening(before, challenge.url) : null;
            const urls = wide
              ? [...before.filter((u) => !wide.replaces.includes(u)), wide.wildcard]
              : [...before, challenge.origin];
            const updated = await agent.update({ selector: view.id, revision: view.revision, urls });
            linked.set(challenge.origin, { id: view.id, revision: updated.revision, urls: before });
            const { username, password } = view.body.login;
            creds = { username, password, path: secretPath(updated.meta), id: view.id, basicAuth: isBasicAuth(updated.meta) };
            const where = wide ? wide.wildcard : challenge.host;
            record({ origin: challenge.origin, outcome: "saved", detail: `${creds.path} (now on ${where})` });
          } catch (err) {
            return failure(err);
          }
          realms.set(authPath(challenge.url), challenge.realm);
          await startSession(challenge.origin, creds, challenge.url);
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
        case "basic_auth": {
          const logins = [...(refused.get(message.origin)?.values() ?? [])].flat();
          const refusedIds = new Set(logins.flatMap((c) => (c.id ? [c.id] : [])));
          return { kind: "basic_auth", refused: [...refusedIds] };
        }
        case "fill_tab": {
          const request: TabMessage = { kind: "fill", id: message.id };
          const filled: unknown = await browser.tabs.sendMessage(message.tabId, request).catch(() => false);
          if (filled === true) return { kind: "filled" };
          return { kind: "error", message: "No login form on this page." };
        }
      }
    }

    const extensionPages = browser.runtime.getURL("/");
    browser.runtime.onMessage.addListener(
      (message: unknown, sender, sendResponse: (response: UiResponse | PageResponse) => void) => {
        const url = sender.url ?? "";
        if (sender.id !== browser.runtime.id) return false;
        if (url.startsWith(extensionPages)) {
          void handle(message as UiRequest).then(sendResponse);
          return true;
        }
        // Content scripts in web pages get the page vocabulary and nothing else.
        const kind = (message as { kind?: unknown } | null)?.kind;
        if (typeof kind !== "string" || !PAGE_KINDS.has(kind)) return false;
        void handlePage(message as PageRequest, { url, tabId: sender.tab?.id, frameId: sender.frameId }).then(
          sendResponse,
        );
        return true;
      },
    );
  },
});

/** What a web page may see of a same-site login: no password, no other hosts. */
function pageLogin({ id, path, username, here }: SameSiteLogin): SameSiteLogin {
  return { id, path, username, here };
}

/** An agent or bridge failure as an answer to an extension page. */
function failure(err: unknown): UiResponse {
  if (err instanceof AgentError) return { kind: "error", message: err.message };
  if (err instanceof BridgeError) return { kind: "bridge_error", message: errorText(err) };
  return { kind: "error", message: errorText(err) };
}

/** `matches` in their order, with the Basic Auth logins moved to the front or the back. */
function basicAuth(matches: SecretSummary[], where: "first" | "last"): SecretSummary[] {
  const marked = matches.filter((m) => isBasicAuth(m.meta));
  const rest = matches.filter((m) => !isBasicAuth(m.meta));
  return where === "first" ? [...marked, ...rest] : [...rest, ...marked];
}

/** Learn realms per resource path instead of assuming one realm for the whole origin. */
function authPath(url: string): string {
  const { origin, pathname } = new URL(url);
  return `${origin}${pathname}`;
}

function sameCredentials(a: Credentials, b: Credentials): boolean {
  return a.username === b.username && a.password === b.password;
}

function sameUsername(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

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
