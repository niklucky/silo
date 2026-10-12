import { type Browser, browser } from "wxt/browser";

type ResourceType = Browser.declarativeNetRequest.ResourceType;

/** Every type, listed: leaving them out, or excluding none, skips main_frame. */
const RESOURCE_TYPES: `${ResourceType}`[] = [
  "main_frame",
  "sub_frame",
  "stylesheet",
  "script",
  "image",
  "font",
  "object",
  "xmlhttprequest",
  "ping",
  "csp_report",
  "media",
  "websocket",
  "webtransport",
  "webbundle",
  "other",
];

/**
 * Chromium only: one session rule per origin that sets the Authorization
 * header on every request to it. This stands in for Firefox's blocking
 * onBeforeSendHeaders, so Chrome never caches Basic Auth credentials and a lock
 * can take them away. Session rules outlive the service worker but not the
 * browser; a new worker starts by dropping the old ones, whose credentials it
 * no longer knows.
 */
export class HeaderRules {
  private readonly ids = new Map<string, number>();
  private readonly values = new Map<string, string>();
  private next = 1;
  /** Updates run one at a time, so rule ids never race. */
  private queue: Promise<void> = Promise.resolve();

  /** Removes every rule, including those of an earlier service worker. */
  reset(): Promise<void> {
    return this.run(async () => {
      const old = await browser.declarativeNetRequest.getSessionRules();
      await browser.declarativeNetRequest.updateSessionRules({ removeRuleIds: old.map((r) => r.id) });
      this.ids.clear();
      this.values.clear();
    });
  }

  /** Sends `authorization` on every request to `origin` from now on. */
  set(origin: string, authorization: string): Promise<void> {
    return this.run(async () => {
      if (this.values.get(origin) === authorization) return;
      const old = this.ids.get(origin);
      const id = old ?? this.next++;
      await browser.declarativeNetRequest.updateSessionRules({
        removeRuleIds: old === undefined ? [] : [old],
        addRules: [
          {
            id,
            action: {
              type: "modifyHeaders",
              requestHeaders: [{ header: "Authorization", operation: "set", value: authorization }],
            },
            condition: { urlFilter: `|${origin}/`, resourceTypes: RESOURCE_TYPES },
          },
        ],
      });
      this.ids.set(origin, id);
      this.values.set(origin, authorization);
    });
  }

  remove(origin: string): Promise<void> {
    return this.run(async () => {
      const id = this.ids.get(origin);
      if (id === undefined) return;
      await browser.declarativeNetRequest.updateSessionRules({ removeRuleIds: [id] });
      this.ids.delete(origin);
      this.values.delete(origin);
    });
  }

  clear(): Promise<void> {
    return this.run(async () => {
      if (this.ids.size === 0) return;
      await browser.declarativeNetRequest.updateSessionRules({ removeRuleIds: [...this.ids.values()] });
      this.ids.clear();
      this.values.clear();
    });
  }

  private run(task: () => Promise<void>): Promise<void> {
    const result = this.queue.then(task);
    this.queue = result.catch(() => undefined);
    return result;
  }
}
