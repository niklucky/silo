import { browser } from "wxt/browser";
import { FieldButton } from "@/lib/field-button";
import {
  defaultLoginFields,
  fillLogin,
  fillNewPassword,
  type LoginFields,
  loginFieldsFor,
  type NewPasswordFields,
  newPasswordFieldsFor,
} from "@/lib/forms";
import { type Generated, generate } from "@/lib/generate";
import { Menu, type MenuContent, type Saving } from "@/lib/menu";
import type { LoginOption, PageRequest, PageResponse, SaveChoice, TabMessage } from "@/lib/messages";
import { DEFAULT_SETTINGS, loadSettings, onSettingsChanged, type Trigger } from "@/lib/settings";

/**
 * Offers saved logins under username and password fields, and generated
 * passwords under new-password fields. Nothing is filled until the user picks
 * something, here or in the popup; a saved password travels from the
 * background only at that moment. A generated password is stored in the vault
 * before the page sees it when the vault is unlocked, and filled unsaved (with
 * a warning) when it is not.
 */
export default defineContentScript({
  matches: ["http://*/*", "https://*/*"],
  allFrames: true,
  runAt: "document_idle",
  main() {
    /** How long a lookup answers repeated focus events on the same page. */
    const CACHE_MS = 5_000;
    /** How long "Saved as …" stays under the field. */
    const NOTE_MS = 4_000;
    type Vault = { kind: "logins"; logins: LoginOption[] } | { kind: "locked" } | { kind: "offline" };
    let cached: { url: string; at: number; vault: Vault } | null = null;
    let current: {
      field: HTMLInputElement;
      login: LoginFields | null;
      fresh: NewPasswordFields | null;
      content: MenuContent;
    } | null = null;
    /** Escape or a fill closes the menu until the user moves to another field. */
    let dismissed: HTMLInputElement | null = null;
    let filling = false;
    let noteTimer: ReturnType<typeof setTimeout> | undefined;
    let trigger: Trigger = DEFAULT_SETTINGS.trigger;
    void loadSettings().then((settings) => (trigger = settings.trigger));
    onSettingsChanged((settings) => {
      trigger = settings.trigger;
      hideAll();
    });

    const send = async (message: PageRequest) => (await browser.runtime.sendMessage(message)) as PageResponse;
    const insecure = !window.isSecureContext;

    const menu = new Menu({
      pick: (login) => void fillWith(login.id, current?.login ?? null),
      unlock: () => void send({ kind: "page_unlock" }).catch(() => undefined),
      suggest: () => {
        if (current) menu.show(current.field, suggestions(savingFor(cached?.vault)));
      },
      useGenerated: (option, saving, choice) => void useGenerated(option, saving, choice),
    });
    const button = new FieldButton(() => {
      if (!current) return;
      if (menu.anchoredTo) menu.hide();
      else menu.show(current.field, current.content);
    });

    function hideAll() {
      menu.hide();
      button.hide();
    }

    function suggestions(saving: Saving): MenuContent {
      return { kind: "generate", options: [generate("easy"), generate("random")], insecure, saving };
    }

    function savingFor(vault: Vault | undefined): Saving {
      if (vault?.kind === "logins") return "saved";
      return vault?.kind === "locked" ? "locked" : "offline";
    }

    /** What the vault has for this page. */
    async function lookup(): Promise<Vault> {
      if (cached && cached.url === location.href && Date.now() - cached.at < CACHE_MS) return cached.vault;
      let vault: Vault = { kind: "offline" };
      try {
        const response = await send({ kind: "page_logins" });
        if (response.kind === "locked") vault = { kind: "locked" };
        else if (response.kind === "logins") vault = { kind: "logins", logins: response.logins };
      } catch {
        // Extension reloaded or background unavailable: nothing saved to offer.
      }
      cached = { url: location.href, at: Date.now(), vault };
      return vault;
    }

    async function offer(field: HTMLInputElement) {
      if (filling || dismissed === field) return;
      dismissed = null;
      const login = loginFieldsFor(field);
      const fresh = newPasswordFieldsFor(field);
      if (!login && !fresh) return;
      const vault = await lookup();
      // The user may have moved on while we waited.
      if (document.activeElement !== field || dismissed === field) return;
      const content = contentFor(vault, login, fresh);
      if (!content) {
        current = null;
        hideAll();
        return;
      }
      current = { field, login, fresh, content };
      if (trigger === "button") {
        menu.hide();
        button.show(field);
      } else {
        button.hide();
        menu.show(field, content);
      }
    }

    function contentFor(vault: Vault, login: LoginFields | null, fresh: NewPasswordFields | null): MenuContent | null {
      const saving = savingFor(vault);
      // Sign-up and change-password forms: suggestions, whatever the vault's state.
      if (fresh?.signup) return suggestions(saving);
      const logins = login && vault.kind === "logins" ? vault.logins : [];
      const locked = login !== null && vault.kind === "locked";
      if (logins.length === 0 && !locked && !fresh) return null;
      return { kind: "logins", logins, locked, insecure, generate: fresh ? saving : null };
    }

    /** Runs a fill without the focus changes it causes reopening or closing the menu. */
    function quietly(fill: () => void) {
      filling = true;
      try {
        fill();
      } finally {
        filling = false;
      }
    }

    function note(field: HTMLInputElement, text: string) {
      button.hide();
      menu.show(field, { kind: "note", text });
      clearTimeout(noteTimer);
      noteTimer = setTimeout(() => {
        if (menu.anchoredTo === field) menu.hide();
      }, NOTE_MS);
    }

    async function fillWith(id: string, fields: LoginFields | null): Promise<boolean> {
      const target = fields ?? defaultLoginFields(document);
      if (!target) return false;
      const response = await send({ kind: "page_fill", id });
      if (response.kind !== "credentials") return false;
      hideAll();
      quietly(() => fillLogin(target, response.username, response.password));
      dismissed = target.password ?? target.username;
      return true;
    }

    /** `choice` answers the question asked when the username is already saved for this site. */
    async function useGenerated(option: Generated, saving: Saving, choice?: SaveChoice) {
      const target = current;
      if (!target?.fresh) return;
      const { fresh } = target;
      const username = fresh.username?.value.trim() ?? "";
      let unsaved: string;
      if (saving === "saved") {
        let response: PageResponse;
        try {
          response = await send({ kind: "page_save_generated", username, password: option.password, choice });
        } catch (err) {
          response = { kind: "failed", message: err instanceof Error ? err.message : String(err) };
        }
        if (response.kind === "conflict") {
          // Nothing is filled until the user answers.
          const content: MenuContent = { kind: "conflict", option, username, host: location.host, logins: response.logins };
          current = { ...target, content };
          button.hide();
          menu.show(target.field, content);
          return;
        }
        if (response.kind === "saved") {
          const done = response.updated ? `New password saved in ${response.path}` : `Saved as ${response.path}`;
          use(target, fresh, option, done, false);
          return;
        }
        if (response.kind === "locked") unsaved = "Secret got locked";
        else if (response.kind === "failed") unsaved = `saving failed: ${response.message}`;
        else unsaved = "Secret is not reachable";
      } else {
        unsaved = saving === "locked" ? "Secret is locked" : "Secret is not reachable";
      }
      use(target, fresh, option, `Filled but not saved: ${unsaved}. Keep a copy before you leave the page.`, true);
    }

    function use(
      target: NonNullable<typeof current>,
      fresh: NewPasswordFields,
      option: Generated,
      message: string,
      warning: boolean,
    ) {
      quietly(() => fillNewPassword(fresh, option.password));
      const field = fresh.passwords[0] ?? target.field;
      dismissed = field;
      current = { ...target, field };
      if (warning) {
        // Stays until the user leaves the field: the password exists nowhere else.
        clearTimeout(noteTimer);
        button.hide();
        menu.show(field, { kind: "unsaved", text: message, password: option.password });
      } else {
        note(field, message);
      }
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
        if (filling || !current || event.composedPath()[0] !== current.field) return;
        current = null;
        clearTimeout(noteTimer);
        hideAll();
      },
      true,
    );
    document.addEventListener(
      "keydown",
      (event) => {
        if (event.key !== "Escape" || !(menu.anchoredTo || button.anchoredTo)) return;
        dismissed = current?.field ?? null;
        hideAll();
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
