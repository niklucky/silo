import { avatar, icon, logo, text, trustedButton } from "./dom";
import { type Generated, strength } from "./generate";
import type { IconName } from "./icons";
import type { LoginOption, SameSiteLogin, SaveChoice } from "./messages";
import { TOKENS } from "./theme";

/**
 * The dropdown under a login field: matching logins, generated passwords, an
 * unlock prompt, or a short confirmation. Plain
 * DOM in a closed shadow root, so page styles cannot reach in and page scripts
 * cannot read it. Clicks only count when the browser marks them as trusted;
 * the content script passes on trusted arrow and Enter keys from the field.
 */

/** Whether a generated password goes into the vault before the page gets it. */
export type Saving = "saved" | "locked" | "offline";

export type MenuContent =
  /**
   * `locked` adds an unlock row; `generate` adds a row that switches to
   * suggestions (lone password fields).
   */
  | { kind: "logins"; logins: LoginOption[]; locked: boolean; insecure: boolean; generate: Saving | null }
  | { kind: "generate"; options: Generated[]; insecure: boolean; saving: Saving }
  /** The picked password's username is already saved for this site: new login or overwrite? */
  | { kind: "conflict"; option: Generated; username: string; host: string; logins: SameSiteLogin[] }
  | { kind: "note"; text: string; error?: boolean }
  /** A generated password that is filled but not in the vault: show it so it can be kept. */
  | { kind: "unsaved"; text: string; password: string };

const SAVING_NOTE: Record<Saving, string> = {
  saved: "Saved to Silo when you pick one",
  locked: "Silo is locked: it will not be saved",
  offline: "Silo is not reachable: it will not be saved",
};

export interface MenuActions {
  pick(login: LoginOption): void;
  unlock(): void;
  /** Show (fresh) suggestions. */
  suggest(): void;
  useGenerated(option: Generated, saving: Saving, choice?: SaveChoice): void;
}

const STYLE_LABEL: Record<Generated["style"], string> = { easy: "Easy to type", random: "Random" };

const STYLE = `${TOKENS}
.menu { min-width: 260px; max-width: 380px; padding: 4px; overflow-y: auto; border-radius: 10px; }
.head { display: flex; align-items: center; gap: 7px; padding: 5px 6px 6px; font-size: 12px; font-weight: 600; }
.head .host { margin-left: auto; font-weight: 400; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 55%; }
.notice { display: flex; gap: 6px; align-items: flex-start; margin: 0 2px 4px; padding: 6px 8px; border-radius: 7px; font-size: 12px; }
.notice.warn { background: var(--warn-soft); color: var(--warn); }
.notice.error { background: var(--error-soft); color: var(--error); }
.notice svg.icon { width: 14px; height: 14px; margin-top: 1px; }
.item { display: flex; align-items: center; gap: 10px; width: 100%; padding: 6px; border-radius: 7px; }
.item.active { background: var(--surface); }
.lead { display: inline-flex; align-items: center; justify-content: center; flex: none; width: 28px; height: 28px; border-radius: 7px; background: var(--surface-2); color: var(--muted); }
.lead.accent { background: var(--accent-soft); color: var(--accent); }
.text { display: flex; flex-direction: column; min-width: 0; flex: 1; }
.title { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sub { font-size: 12px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sep { height: 1px; margin: 4px 6px; background: var(--line); }
.pw { display: block; font: 13px/1.4 var(--mono); overflow-wrap: anywhere; }
.meter { display: flex; align-items: center; gap: 6px; margin-top: 4px; font-size: 11px; color: var(--muted); }
.bars { display: inline-flex; gap: 2px; }
.bars i { display: block; width: 14px; height: 4px; border-radius: 2px; background: var(--surface-2); }
.l1 i.on { background: #d93025; } .l2 i.on { background: #f29900; }
.l3 i.on { background: #34a853; } .l4 i.on { background: #188038; }
.option { display: block; width: 100%; padding: 8px; border-radius: 7px; }
.option.active { background: var(--surface); }
.note { display: flex; align-items: center; gap: 8px; padding: 8px; }
.note .lead { width: 24px; height: 24px; border-radius: 50%; }
.note.error .lead { background: var(--error-soft); color: var(--error); }
.secret { margin: 2px 8px 6px; padding: 8px; border-radius: 7px; background: var(--surface); user-select: all; }
.foot { display: flex; gap: 10px; padding: 6px 8px 3px; font-size: 11px; color: var(--muted); border-top: 1px solid var(--line); margin-top: 4px; }
kbd { font: 10px/1 var(--mono); padding: 2px 4px; border-radius: 4px; border: 1px solid var(--line); }
`;

interface Choice {
  node: HTMLElement;
  run: () => void;
}

export class Menu {
  private readonly host: HTMLElement;
  private readonly root: ShadowRoot;
  private readonly box: HTMLDivElement;
  private anchor: HTMLElement | null = null;
  private choices: Choice[] = [];
  /** Highlighted by the arrow keys or the mouse; -1 until then. */
  private active = -1;
  /** The highlight came from the arrow keys: only then does Enter take it rather than send the form. */
  private armed = false;
  private readonly reposition = () => this.place();

  constructor(private readonly actions: MenuActions) {
    this.host = document.createElement("silo-fill-menu");
    // Inline !important outranks any page stylesheet aimed at the host element.
    this.host.style.setProperty("all", "initial", "important");
    this.root = this.host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.box = document.createElement("div");
    this.box.className = "panel menu";
    this.box.setAttribute("role", "listbox");
    this.box.setAttribute("aria-label", "Silo");
    // Keep focus in the field while the user clicks the menu.
    this.box.addEventListener("mousedown", (event) => event.preventDefault());
    this.root.append(style, this.box);
  }

  get anchoredTo(): HTMLElement | null {
    return this.anchor;
  }

  show(anchor: HTMLElement, content: MenuContent) {
    this.choices = [];
    this.active = -1;
    this.armed = false;
    this.box.replaceChildren(...this.render(content));
    if (!this.host.isConnected) document.documentElement.append(this.host);
    if (this.anchor !== anchor) {
      this.anchor = anchor;
      window.addEventListener("scroll", this.reposition, true);
      window.addEventListener("resize", this.reposition);
    }
    this.place();
  }

  hide() {
    this.anchor = null;
    this.choices = [];
    this.host.remove();
    window.removeEventListener("scroll", this.reposition, true);
    window.removeEventListener("resize", this.reposition);
  }

  /** Arrow keys: moves the highlight, wrapping around. */
  move(step: 1 | -1): boolean {
    if (this.choices.length === 0) return false;
    const next = this.active < 0 ? (step > 0 ? 0 : this.choices.length - 1) : this.active + step;
    this.highlight((next + this.choices.length) % this.choices.length);
    this.armed = true;
    return true;
  }

  /** Typing in the field: Enter sends the form again until the arrow keys pick a row. */
  disarm() {
    this.armed = false;
  }

  /** Enter: runs the row picked with the arrow keys, if any. A row under the mouse is not enough. */
  activate(): boolean {
    const choice = this.armed ? this.choices[this.active] : undefined;
    if (!choice) return false;
    choice.run();
    return true;
  }

  private highlight(index: number) {
    this.choices[this.active]?.node.classList.remove("active");
    this.active = index;
    const choice = this.choices[index];
    if (!choice) return;
    choice.node.classList.add("active");
    choice.node.scrollIntoView({ block: "nearest" });
  }

  private place() {
    if (!this.anchor?.isConnected) {
      this.hide();
      return;
    }
    const rect = this.anchor.getBoundingClientRect();
    // Below the field if it fits, else above; in a short frame, the roomier side, scrolling.
    this.box.style.maxHeight = "";
    const height = this.box.offsetHeight;
    const roomBelow = window.innerHeight - rect.bottom - 8;
    const roomAbove = rect.top - 8;
    const above = height > roomBelow && roomAbove > roomBelow;
    if (height > (above ? roomAbove : roomBelow)) this.box.style.maxHeight = `${Math.max(48, above ? roomAbove : roomBelow)}px`;
    const top = above ? rect.top - 6 - this.box.offsetHeight : rect.bottom + 6;
    this.box.style.top = `${top}px`;
    this.box.style.width = `${Math.max(260, Math.min(380, rect.width))}px`;
    this.box.style.left = `${Math.max(4, Math.min(rect.left, window.innerWidth - this.box.offsetWidth - 4))}px`;
  }

  private render(content: MenuContent): HTMLElement[] {
    switch (content.kind) {
      case "note": {
        const node = document.createElement("div");
        node.className = content.error ? "note error" : "note";
        const lead = document.createElement("span");
        lead.className = content.error ? "lead" : "lead accent";
        lead.append(icon(content.error ? "alert" : "check"));
        node.append(lead, text("span", "text", content.text));
        return [node];
      }
      case "unsaved": {
        const password = text("div", "pw secret", content.password);
        return [
          this.head("Password not saved"),
          notice("warn", content.text),
          password,
          this.item(icon("copy"), "Copy password", "Keep it somewhere until Silo can save it", () => {
            void copyText(content.password, password);
          }),
        ];
      }
      case "logins": {
        const nodes: HTMLElement[] = [this.head(content.logins.length > 0 ? "Fill with Silo" : "Silo")];
        if (content.insecure && content.logins.length > 0) nodes.push(insecureWarning());
        if (content.locked) {
          nodes.push(this.item(lead("lock"), "Silo is locked", "Unlock to fill your saved logins", () => this.actions.unlock()));
        }
        for (const login of content.logins) {
          nodes.push(
            this.item(avatar(login.title), login.username || "(no username)", login.path, () =>
              this.actions.pick(login),
            ),
          );
        }
        if (content.generate) {
          if (content.logins.length > 0 || content.locked) nodes.push(text("div", "sep", ""));
          nodes.push(
            this.item(lead("sparkle", true), "Suggest a strong password", SAVING_NOTE[content.generate], () =>
              this.actions.suggest(),
            ),
          );
        }
        nodes.push(keysHint("fill"));
        return nodes;
      }
      case "conflict": {
        const { option, username, host, logins } = content;
        const nodes: HTMLElement[] = [
          this.head(username ? `${username} is already saved here` : "Logins already saved for this site"),
        ];
        nodes.push(
          this.item(lead("plus", true), `Add a new login for ${host}`, keepNote(logins), () =>
            this.actions.useGenerated(option, "saved", { kind: "new" }),
          ),
        );
        for (const login of logins) {
          const who = username ? "" : ` (${login.username || "no username"})`;
          nodes.push(
            this.item(lead("refresh"), `Update ${login.path}${who}`, updateNote(login, host), () =>
              this.actions.useGenerated(option, "saved", { kind: "overwrite", id: login.id }),
            ),
          );
        }
        nodes.push(keysHint("choose"));
        return nodes;
      }
      case "generate": {
        const nodes: HTMLElement[] = [this.head("Suggested passwords")];
        if (content.saving !== "saved") nodes.push(notice("warn", SAVING_NOTE[content.saving]));
        if (content.insecure) nodes.push(insecureWarning());
        for (const option of content.options) {
          const button = trustedButton(() => this.actions.useGenerated(option, content.saving));
          button.className = "option";
          const { label, level } = strength(option.bits);
          const bars = document.createElement("span");
          bars.className = `bars l${level}`;
          for (let i = 1; i <= 4; i++) {
            const bar = document.createElement("i");
            if (i <= level) bar.className = "on";
            bars.append(bar);
          }
          const meter = document.createElement("span");
          meter.className = "meter";
          meter.append(bars, `${STYLE_LABEL[option.style]} · ${label} · ${option.bits} bits`);
          button.append(text("span", "pw", option.password), meter);
          nodes.push(this.choice(button, () => this.actions.useGenerated(option, content.saving)));
        }
        nodes.push(text("div", "sep", ""));
        nodes.push(this.item(lead("refresh"), "Other suggestions", "", () => this.actions.suggest()));
        if (content.saving === "locked") {
          nodes.push(this.item(lead("lock"), "Unlock Silo", "To save the password you pick", () => this.actions.unlock()));
        }
        if (content.saving === "saved") {
          nodes.push(text("div", "sub foot", "The one you pick is saved to Silo before it is filled."));
        }
        return nodes;
      }
    }
  }

  private head(title: string): HTMLElement {
    const node = document.createElement("div");
    node.className = "head";
    node.append(logo(), text("span", "", title), text("span", "host", location.host));
    return node;
  }

  private item(leading: Element, title: string, sub: string, run: () => void): HTMLButtonElement {
    const button = trustedButton(run);
    button.className = "item";
    const body = document.createElement("span");
    body.className = "text";
    body.append(text("span", "title", title));
    if (sub) body.append(text("span", "sub", sub));
    button.append(leading, body);
    return this.choice(button, run);
  }

  private choice<T extends HTMLElement>(node: T, run: () => void): T {
    const index = this.choices.length;
    node.setAttribute("role", "option");
    node.addEventListener("mousemove", () => {
      if (this.active === index) return;
      this.highlight(index);
      this.armed = false;
    });
    this.choices.push({ node, run });
    return node;
  }
}

function lead(name: IconName, accent = false): HTMLElement {
  const node = document.createElement("span");
  node.className = accent ? "lead accent" : "lead";
  node.append(icon(name));
  return node;
}

function notice(kind: "warn" | "error", message: string): HTMLElement {
  const node = document.createElement("div");
  node.className = `notice ${kind}`;
  node.append(icon("alert"), text("span", "", message));
  return node;
}

function keysHint(verb: string): HTMLElement {
  const node = document.createElement("div");
  node.className = "foot";
  const key = (label: string) => text("kbd", "", label);
  const part = (keys: HTMLElement[], label: string) => {
    const span = document.createElement("span");
    span.append(...keys, ` ${label}`);
    return span;
  };
  node.append(part([key("↑"), key("↓")], "move"), part([key("↵")], verb), part([key("esc")], "close"));
  return node;
}

/** Clipboard when the page allows it (secure contexts); otherwise select the text for ⌘C / Ctrl+C. */
async function copyText(value: string, shown: HTMLElement) {
  try {
    await navigator.clipboard.writeText(value);
    shown.textContent = "Copied to the clipboard.";
  } catch {
    const range = document.createRange();
    range.selectNodeContents(shown);
    const selection = shown.ownerDocument.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
  }
}

/** What updating `login` with a password used on `host` does. */
export function updateNote(login: SameSiteLogin, host: string, samePassword = false): string {
  if (samePassword) return login.here ? "Add the username to it" : `Same password: fill it on ${host} too`;
  return login.here
    ? "Replace its password; the old one stays in its history"
    : `Replace its password and fill it on ${host} too`;
}

function keepNote(logins: SameSiteLogin[]): string {
  const [first] = logins;
  if (logins.length === 1 && first) return `${first.path} stays as it is`;
  return "The saved logins stay as they are";
}

function insecureWarning(): HTMLElement {
  return notice("error", "This page is not HTTPS; anyone on the network can read what you send.");
}
