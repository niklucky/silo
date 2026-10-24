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
  submissionIn,
} from "@/lib/forms";
import { type Generated, generate } from "@/lib/generate";
import { Menu, type MenuContent, type Saving } from "@/lib/menu";
import type {
  LoginOption,
  OfferAnswer,
  PageRequest,
  PageResponse,
  SaveChoice,
  SaveOffer,
  TabMessage,
} from "@/lib/messages";
import { SavePrompt } from "@/lib/save-prompt";
import { DEFAULT_SETTINGS, loadSettings, onSettingsChanged, type Settings } from "@/lib/settings";

/**
 * Offers saved logins under username and password fields, and generated
 * passwords under new-password fields. Nothing is filled until the user picks
 * something, here or in the popup; a saved password travels from the
 * background only at that moment. A generated password is stored in the vault
 * before the page sees it when the vault is unlocked, and filled unsaved (with
 * a warning) when it is not.
 *
 * When the user sends a login form, what they typed goes to the background,
 * which offers to save it (or update a saved login) in the tab's top frame.
 */
export default defineContentScript({
  matches: ["http://*/*", "https://*/*"],
  allFrames: true,
  runAt: "document_idle",
  main() {
    /** How long a lookup answers repeated focus events on the same page. */
    const CACHE_MS = 5_000;
    /** How long "Saved as …" stays under the field or in the save panel. */
    const NOTE_MS = 4_000;
    /** A click and the submit it causes report the same login once. */
    const RESEND_MS = 3_000;
    /** Buttons outside a form that look like they send a login. */
    const SEND_LABEL =
      /log\s*in|sign\s*(in|up)|register|continue|next|submit|create|save|change|update|reset|confirm|войти|вход|далее|продолжить|зарегистр|сохранить/i;
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
    let settings: Settings = DEFAULT_SETTINGS;
    void loadSettings().then((loaded) => (settings = loaded));
    onSettingsChanged((changed) => {
      settings = changed;
      hideAll();
    });
    let lastReport: { key: string; at: number } | null = null;
    let promptTimer: ReturnType<typeof setTimeout> | undefined;

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
    // Save offers show in the top frame only, whichever frame sent the login.
    const prompt =
      window === window.top
        ? new SavePrompt({
            answer: (offer, answer) => void answerOffer(offer, answer),
            unlock: () => void send({ kind: "page_unlock" }).catch(() => undefined),
          })
        : null;
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
      if (settings.trigger === "button") {
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
        if (response.kind === "locked") unsaved = "Silo got locked";
        else if (response.kind === "failed") unsaved = `saving failed: ${response.message}`;
        else unsaved = "Silo is not reachable";
      } else {
        unsaved = saving === "locked" ? "Silo is locked" : "Silo is not reachable";
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

    /** Tells the background about a sent login form; it decides whether to offer saving. */
    function report(scope: ParentNode) {
      if (!settings.offerToSave || settings.neverSave.includes(location.origin)) return;
      const submission = submissionIn(scope);
      if (!submission) return;
      const key = `${submission.username}\n${submission.password}`;
      if (lastReport && lastReport.key === key && Date.now() - lastReport.at < RESEND_MS) return;
      lastReport = { key, at: Date.now() };
      void send({ kind: "page_submitted", ...submission }).catch(() => undefined);
    }

    async function showOffer() {
      if (!prompt) return;
      let offer: SaveOffer | null = null;
      try {
        const response = await send({ kind: "page_offer" });
        if (response.kind === "offer") offer = response.offer;
      } catch {
        // Background unavailable: nothing to offer.
      }
      clearTimeout(promptTimer);
      if (offer) prompt.show(offer);
      else if (prompt.offer) prompt.hide();
    }

    async function answerOffer(offer: SaveOffer, answer: OfferAnswer) {
      if (!prompt) return;
      let response: PageResponse;
      try {
        response = await send({ kind: "page_offer_answer", id: offer.id, answer });
      } catch (err) {
        response = { kind: "failed", message: err instanceof Error ? err.message : String(err) };
      }
      if (response.kind === "locked") {
        // Locked since the offer was shown: show the unlock version.
        await showOffer();
        return;
      }
      if (response.kind === "saved") {
        prompt.note(response.updated ? `Updated ${response.path}` : `Saved as ${response.path}`);
      } else if (response.kind === "ok" && answer.kind === "never") {
        prompt.note(`Silo will not offer to save logins on ${new URL(location.href).host} again. Settings can undo this.`);
      } else if (response.kind === "ok") {
        prompt.hide();
        return;
      } else {
        const why = response.kind === "failed" ? response.message : "Silo is not reachable";
        prompt.note(`Not saved: ${why}`, true);
      }
      clearTimeout(promptTimer);
      promptTimer = setTimeout(() => prompt.hide(), NOTE_MS);
    }

    // Registered before the sign-in listeners below, so an Enter the menu takes never reports the form.
    document.addEventListener(
      "keydown",
      (event) => {
        if (!event.isTrusted || !(menu.anchoredTo || button.anchoredTo)) return;
        if (event.key === "Escape") {
          dismissed = current?.field ?? null;
          hideAll();
          return;
        }
        // Arrows move through the menu; Enter takes the highlighted row instead of sending the form.
        if (!menu.anchoredTo || event.isComposing || event.altKey || event.metaKey || event.ctrlKey) return;
        const handled =
          event.key === "ArrowDown" ? menu.move(1) : event.key === "ArrowUp" ? menu.move(-1) : event.key === "Enter" && menu.activate();
        if (handled) {
          event.preventDefault();
          event.stopImmediatePropagation();
        }
      },
      true,
    );
    document.addEventListener(
      "submit",
      (event) => {
        if (event.isTrusted && event.target instanceof HTMLFormElement) report(event.target);
      },
      true,
    );
    // Pages that sign in from script, without a submit event: a click on a
    // send-like button, or Enter in a field. The submit that may follow is deduplicated.
    document.addEventListener(
      "click",
      (event) => {
        if (!event.isTrusted) return;
        const [first] = event.composedPath();
        if (!(first instanceof Element)) return;
        const clicked = first.closest("button, input[type=submit], input[type=button], [role=button]");
        if (!clicked) return;
        const form = clicked instanceof HTMLButtonElement || clicked instanceof HTMLInputElement ? clicked.form : null;
        const label = [clicked.textContent, (clicked as HTMLInputElement).value, clicked.getAttribute("aria-label")];
        const sends = (form && (clicked as HTMLButtonElement).type === "submit") || SEND_LABEL.test(label.join(" "));
        if (sends) report(form ?? clicked.ownerDocument);
      },
      true,
    );
    document.addEventListener(
      "keydown",
      (event) => {
        if (!event.isTrusted || event.key !== "Enter" || event.isComposing) return;
        const [target] = event.composedPath();
        if (target instanceof HTMLInputElement) report(target.form ?? target.ownerDocument);
      },
      true,
    );
    if (prompt) void showOffer();

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
    // Back from the unlock window: show what is now available.
    window.addEventListener("focus", () => {
      cached = null;
      if (prompt?.offer?.locked) void showOffer();
      const active = document.activeElement;
      if (active instanceof HTMLInputElement && active === current?.field) void offer(active);
    });

    // The popup's Fill button (frames without a login form stay silent), and save offers.
    browser.runtime.onMessage.addListener(
      (message: unknown, _sender, sendResponse: (filled: boolean) => void) => {
        const request = message as TabMessage;
        if (request.kind === "offer_save") {
          if (prompt) void showOffer();
          return false;
        }
        if (request.kind !== "fill" || !defaultLoginFields(document)) return false;
        void fillWith(request.id, null).then(sendResponse);
        return true;
      },
    );
  },
});
