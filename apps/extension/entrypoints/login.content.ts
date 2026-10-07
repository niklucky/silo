import { browser } from "wxt/browser";
import { defaultLoginFields, fillLogin, type LoginFields, loginFieldsFor } from "@/lib/forms";
import { Menu, type MenuContent } from "@/lib/menu";
import type { PageRequest, PageResponse, TabMessage } from "@/lib/messages";

/**
 * Offers saved logins under username and password fields. Nothing is filled
 * until the user picks a login, here or in the popup; the password travels from
 * the background only at that moment.
 */
export default defineContentScript({
  matches: ["http://*/*", "https://*/*"],
  allFrames: true,
  runAt: "document_idle",
  main() {
    /** How long a lookup answers repeated focus events on the same page. */
    const CACHE_MS = 5_000;
    let cached: { url: string; at: number; content: MenuContent | null } | null = null;
    let current: { field: HTMLInputElement; fields: LoginFields } | null = null;
    /** Escape or a fill closes the menu until the user moves to another field. */
    let dismissed: HTMLInputElement | null = null;
    let filling = false;

    const send = async (message: PageRequest) => (await browser.runtime.sendMessage(message)) as PageResponse;

    const menu = new Menu({
      pick: (login) => void fillWith(login.id, current?.fields ?? null),
      unlock: () => void send({ kind: "page_unlock" }),
    });

    async function lookup(): Promise<MenuContent | null> {
      if (cached && cached.url === location.href && Date.now() - cached.at < CACHE_MS) return cached.content;
      let content: MenuContent | null = null;
      try {
        const response = await send({ kind: "page_logins" });
        if (response.kind === "locked") content = { kind: "locked" };
        else if (response.kind === "logins" && response.logins.length > 0) {
          content = { kind: "logins", logins: response.logins, insecure: !window.isSecureContext };
        }
      } catch {
        // Extension reloaded or background unavailable: behave as if there is nothing to offer.
      }
      cached = { url: location.href, at: Date.now(), content };
      return content;
    }

    async function offer(field: HTMLInputElement) {
      if (filling || dismissed === field) return;
      dismissed = null;
      const fields = loginFieldsFor(field);
      if (!fields) return;
      current = { field, fields };
      const content = await lookup();
      // The user may have moved on while we waited.
      if (current?.field !== field || document.activeElement !== field) return;
      if (content) menu.show(field, content);
      else menu.hide();
    }

    async function fillWith(id: string, fields: LoginFields | null): Promise<boolean> {
      const target = fields ?? defaultLoginFields(document);
      if (!target) return false;
      const response = await send({ kind: "page_fill", id });
      if (response.kind !== "credentials") return false;
      menu.hide();
      // Filling moves focus between the fields; that must not reopen the menu.
      filling = true;
      try {
        fillLogin(target, response.username, response.password);
      } finally {
        filling = false;
      }
      dismissed = target.password ?? target.username;
      return true;
    }

    document.addEventListener(
      "focusin",
      (event) => {
        // composedPath reaches inputs inside open shadow roots.
        const [target] = event.composedPath();
        if (target instanceof HTMLInputElement) void offer(target);
      },
      true,
    );
    document.addEventListener(
      "focusout",
      (event) => {
        if (current && event.composedPath()[0] === current.field) {
          current = null;
          menu.hide();
        }
      },
      true,
    );
    document.addEventListener(
      "keydown",
      (event) => {
        if (event.key !== "Escape" || !menu.anchoredTo) return;
        dismissed = current?.field ?? null;
        menu.hide();
      },
      true,
    );
    // Back from the unlock window: show what is now available.
    window.addEventListener("focus", () => {
      cached = null;
      const active = document.activeElement;
      if (active instanceof HTMLInputElement && active === current?.field) void offer(active);
    });

    // The popup's Fill button. Frames without a login form stay silent.
    browser.runtime.onMessage.addListener(
      (message: unknown, _sender, sendResponse: (filled: boolean) => void) => {
        const request = message as TabMessage;
        if (request.kind !== "fill" || !defaultLoginFields(document)) return false;
        void fillWith(request.id, null).then(sendResponse);
        return true;
      },
    );
  },
});
