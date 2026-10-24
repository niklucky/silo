import { avatar, icon, logo, text, trustedButton } from "./dom";
import { updateNote } from "./menu";
import type { OfferAnswer, SaveOffer } from "./messages";
import { TOKENS } from "./theme";

/**
 * The "Save login?" panel in the top-right corner of the page, shown after
 * the user signs in with a login Silo does not have. Same rules as the
 * menu: closed shadow root, trusted clicks and keys only. It never holds the
 * password; the user can rename a new login and fix its username here.
 */

export interface SavePromptActions {
  answer(offer: SaveOffer, answer: OfferAnswer): void;
  unlock(): void;
}

const STYLE = `${TOKENS}
.save { top: 14px; right: 14px; width: 340px; max-width: calc(100vw - 28px); padding: 12px; }
.head { display: flex; align-items: center; gap: 8px; }
.head .title { font-weight: 600; font-size: 14px; flex: 1; }
.site { display: flex; align-items: center; gap: 10px; margin: 10px 0; padding: 8px; border-radius: 9px; background: var(--surface); }
.site .text { display: flex; flex-direction: column; min-width: 0; }
.site .host { font-weight: 600; overflow-wrap: anywhere; }
.site .who { font-size: 12px; color: var(--muted); overflow-wrap: anywhere; }
.choices { display: flex; flex-direction: column; gap: 4px; margin-bottom: 8px; }
.choice { display: flex; align-items: flex-start; gap: 9px; width: 100%; padding: 7px 8px; border-radius: 8px; border: 1px solid var(--line); }
.choice:hover { background: var(--surface); }
.choice.on { border-color: var(--accent); background: var(--accent-soft); }
.radio { flex: none; width: 14px; height: 14px; margin-top: 2px; border-radius: 50%; border: 1.5px solid var(--muted); }
.choice.on .radio { border: 4px solid var(--accent); }
.choice .text { display: flex; flex-direction: column; min-width: 0; }
.choice .name { font-weight: 600; overflow-wrap: anywhere; }
.choice .sub { font-size: 12px; color: var(--muted); }
.fields { display: grid; grid-template-columns: auto 1fr; align-items: center; gap: 6px 10px; margin-bottom: 4px; }
.fields[hidden] { display: none; }
label { font-size: 12px; color: var(--muted); }
input {
  all: unset; box-sizing: border-box; width: 100%; padding: 6px 8px; border-radius: 7px;
  font: 13px/1.3 var(--font); color: var(--fg); background: var(--bg); border: 1px solid var(--line);
}
input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 25%, transparent); }
.dots { display: flex; align-items: baseline; gap: 8px; padding: 0 2px; color: var(--muted); white-space: nowrap; }
.dots span { letter-spacing: 2px; }
.dots small { font-size: 11px; }
.notice { display: flex; gap: 8px; align-items: flex-start; margin: 4px 0 8px; padding: 8px; border-radius: 8px; background: var(--warn-soft); color: var(--warn); font-size: 12px; }
.notice svg.icon { width: 14px; height: 14px; margin-top: 1px; }
.foot { display: flex; align-items: center; gap: 6px; margin-top: 10px; }
.foot .grow { flex: 1; }
.done { display: flex; align-items: center; gap: 10px; }
.done .badge { display: inline-flex; padding: 5px; border-radius: 50%; background: var(--accent-soft); color: var(--accent); }
.done.error .badge { background: var(--error-soft); color: var(--error); }
.done .text { overflow-wrap: anywhere; }
`;

/** "new" or the id of the login to update. */
type Target = string;

export class SavePrompt {
  private readonly host: HTMLElement;
  private readonly box: HTMLDivElement;
  private current: SaveOffer | null = null;
  /** An answer is on its way: further clicks are ignored. */
  private busy = false;
  private submit: (() => void) | null = null;

  constructor(private readonly actions: SavePromptActions) {
    this.host = document.createElement("silo-save-prompt");
    this.host.style.setProperty("all", "initial", "important");
    const root = this.host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.box = document.createElement("div");
    this.box.className = "panel save";
    this.box.setAttribute("role", "dialog");
    this.box.setAttribute("aria-label", "Silo");
    // Typing here is not for the page: keep its shortcuts (and our own field menu) out of it.
    for (const type of ["keydown", "keyup", "keypress"] as const) {
      this.box.addEventListener(type, (event) => {
        event.stopPropagation();
        if (type !== "keydown" || !event.isTrusted) return;
        const key = (event as KeyboardEvent).key;
        if (key === "Enter" && event.target instanceof HTMLInputElement) {
          event.preventDefault();
          this.submit?.();
        } else if (key === "Escape") {
          this.answer({ kind: "dismiss" });
        }
      });
    }
    root.append(style, this.box);
  }

  get offer(): SaveOffer | null {
    return this.current;
  }

  show(offer: SaveOffer) {
    // The same offer again (a page that re-asks): keep what the user typed.
    if (this.current?.id === offer.id && this.current.locked === offer.locked && this.host.isConnected) {
      this.current = offer;
      return;
    }
    this.current = offer;
    this.busy = false;
    this.box.replaceChildren(...this.render(offer));
    if (!this.host.isConnected) document.documentElement.append(this.host);
  }

  /** Replaces the panel with a short message (the offer is answered). */
  note(message: string, error = false) {
    this.current = null;
    this.busy = false;
    this.submit = null;
    const node = document.createElement("div");
    node.className = error ? "done error" : "done";
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.append(icon(error ? "alert" : "check"));
    node.append(badge, text("span", "text", message));
    this.box.replaceChildren(node);
    if (!this.host.isConnected) document.documentElement.append(this.host);
  }

  hide() {
    this.current = null;
    this.busy = false;
    this.submit = null;
    this.host.remove();
  }

  private render(offer: SaveOffer): HTMLElement[] {
    const { host, username, logins } = offer;
    const updating = !offer.locked && logins.length > 0;

    const head = document.createElement("div");
    head.className = "head";
    const close = trustedButton(() => this.answer({ kind: "dismiss" }));
    close.className = "icon-btn";
    close.title = "Not now";
    close.setAttribute("aria-label", "Close");
    close.append(icon("close"));
    head.append(logo(), text("span", "title", updating ? "Update a saved login?" : "Save this login?"), close);

    const site = document.createElement("div");
    site.className = "site";
    const siteText = document.createElement("span");
    siteText.className = "text";
    siteText.append(
      text("span", "host", host),
      text("span", "who", username ? `Signed in as ${username}` : "Signed in without a username"),
    );
    site.append(avatar(host), siteText);

    const nodes: HTMLElement[] = [head, site];
    const foot = document.createElement("div");
    foot.className = "foot";
    const never = this.button("Never for this site", "btn link", () => this.answer({ kind: "never" }));
    const grow = text("span", "grow", "");

    if (offer.locked) {
      const notice = document.createElement("div");
      notice.className = "notice";
      notice.append(icon("lock"), text("span", "", "Silo is locked. Unlock it, then choose how to save this login."));
      nodes.push(notice);
      this.submit = () => this.actions.unlock();
      foot.append(never, grow, this.button("Unlock Silo", "btn primary", () => this.actions.unlock()));
      nodes.push(foot);
      return nodes;
    }

    // A new login: what to call it and the username, which the user may fix.
    const fields = document.createElement("div");
    fields.className = "fields";
    const input = (label: string, value: string, placeholder: string) => {
      const id = `silo-${label.toLowerCase()}`;
      const field = document.createElement("input");
      field.id = id;
      field.value = value;
      field.placeholder = placeholder;
      field.autocomplete = "off";
      field.spellcheck = false;
      const caption = text("label", "", label);
      caption.setAttribute("for", id);
      fields.append(caption, field);
      return field;
    };
    const user = input("Username", username, "none");
    const dots = document.createElement("span");
    dots.className = "dots";
    dots.append(text("span", "", "••••••••"), text("small", "", "from the form you sent"));
    fields.append(text("label", "", "Password"), dots);
    const title = input("Name", offer.title, host);
    const folder = input("Folder", offer.folder, "top level");

    let target: Target = updating ? (logins[0]?.id ?? "new") : "new";
    const primary = this.button("", "btn primary", () => this.submit?.());
    const choices: { id: Target; node: HTMLElement }[] = [];
    const select = (next: Target) => {
      target = next;
      for (const choice of choices) choice.node.classList.toggle("on", choice.id === next);
      choices.forEach((c) => c.node.setAttribute("aria-checked", String(c.id === next)));
      fields.hidden = next !== "new";
      primary.textContent = next === "new" ? "Save" : "Update";
    };

    if (updating) {
      const list = document.createElement("div");
      list.className = "choices";
      list.setAttribute("role", "radiogroup");
      const option = (id: Target, name: string, sub: string) => {
        const node = trustedButton(() => select(id));
        node.className = "choice";
        node.setAttribute("role", "radio");
        const body = document.createElement("span");
        body.className = "text";
        body.append(text("span", "name", name), text("span", "sub", sub));
        node.append(text("span", "radio", ""), body);
        choices.push({ id, node });
        list.append(node);
      };
      for (const login of logins) {
        const who = username ? "" : ` (${login.username || "no username"})`;
        option(login.id, `Update ${login.path}${who}`, updateNote(login, host, login.samePassword));
      }
      option("new", "Save as a new login", `For ${host}`);
      nodes.push(list);
    }
    nodes.push(fields);

    this.submit = () => {
      if (target !== "new") return this.answer({ kind: "overwrite", id: target });
      this.answer({ kind: "new", as: { title: title.value, folder: folder.value, username: user.value } });
    };
    select(target);
    foot.append(never, grow, this.button("Not now", "btn", () => this.answer({ kind: "dismiss" })), primary);
    nodes.push(foot);
    return nodes;
  }

  private answer(answer: OfferAnswer) {
    if (this.busy || !this.current) return;
    this.busy = true;
    this.actions.answer(this.current, answer);
  }

  private button(label: string, className: string, run: () => void): HTMLButtonElement {
    const button = trustedButton(run);
    button.className = className;
    button.textContent = label;
    return button;
  }
}
