import { text, trustedButton } from "./dom";
import { type Generated, strength } from "./generate";
import type { LoginOption, SameSiteLogin, SaveChoice } from "./messages";

/**
 * The dropdown under a login field: matching logins, generated passwords, an
 * unlock prompt, or a short confirmation. Plain
 * DOM in a closed shadow root, so page styles cannot reach in and page scripts
 * cannot read it. Clicks only count when the browser marks them as trusted.
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

const STYLE = `
:host { all: initial; }
.menu {
  position: fixed; z-index: 2147483647; box-sizing: border-box;
  min-width: 220px; max-width: 360px; padding: 4px;
  font: 13px/1.35 system-ui, sans-serif; color: #1d1d1f;
  background: #fff; border: 1px solid rgba(0,0,0,.15); border-radius: 8px;
  box-shadow: 0 6px 24px rgba(0,0,0,.18); overflow-y: auto;
}
@media (prefers-color-scheme: dark) {
  .menu { color: #f2f2f2; background: #2b2b2e; border-color: rgba(255,255,255,.15); }
}
.head { padding: 4px 8px 2px; font-size: 11px; opacity: .6; }
.head.unsaved { opacity: 1; color: #b06000; }
.warn { padding: 2px 8px 4px; font-size: 11px; color: #b3261e; }
.note { padding: 6px 8px; }
.note.error { color: #b3261e; }
.secret { padding: 2px 8px 4px; user-select: all; }
.pw { display: block; font: 13px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
.meter { display: flex; align-items: center; gap: 6px; margin-top: 3px; font-size: 11px; opacity: .8; }
.bars { display: inline-flex; gap: 2px; }
.bars i { display: block; width: 14px; height: 4px; border-radius: 2px; background: rgba(127,127,127,.3); }
.l1 i.on { background: #d93025; } .l2 i.on { background: #f29900; }
.l3 i.on { background: #34a853; } .l4 i.on { background: #188038; }
.more { font-size: 12px; opacity: .75; }
button {
  all: unset; box-sizing: border-box; display: block; width: 100%;
  padding: 6px 8px; border-radius: 6px; cursor: pointer;
}
button:hover, button:focus-visible { background: rgba(127,127,127,.18); }
.title { display: block; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sub { display: block; font-size: 12px; opacity: .7; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
`;

export class Menu {
  private readonly host: HTMLElement;
  private readonly root: ShadowRoot;
  private readonly box: HTMLDivElement;
  private anchor: HTMLElement | null = null;
  private readonly reposition = () => this.place();

  constructor(private readonly actions: MenuActions) {
    this.host = document.createElement("silo-fill-menu");
    // Inline !important outranks any page stylesheet aimed at the host element.
    this.host.style.setProperty("all", "initial", "important");
    this.root = this.host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.box = document.createElement("div");
    this.box.className = "menu";
    // Keep focus in the field while the user clicks the menu.
    this.box.addEventListener("mousedown", (event) => event.preventDefault());
    this.root.append(style, this.box);
  }

  get anchoredTo(): HTMLElement | null {
    return this.anchor;
  }

  show(anchor: HTMLElement, content: MenuContent) {
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
    this.host.remove();
    window.removeEventListener("scroll", this.reposition, true);
    window.removeEventListener("resize", this.reposition);
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
    const top = above ? rect.top - 4 - this.box.offsetHeight : rect.bottom + 4;
    this.box.style.top = `${top}px`;
    this.box.style.left = `${Math.max(4, Math.min(rect.left, window.innerWidth - this.box.offsetWidth - 4))}px`;
    this.box.style.width = `${Math.max(220, Math.min(360, rect.width))}px`;
  }

  private render(content: MenuContent): HTMLElement[] {
    switch (content.kind) {
      case "note":
        return [text("div", content.error ? "note error" : "note", content.text)];
      case "unsaved": {
        const password = text("div", "pw secret", content.password);
        const copy = this.button(() => void copyText(content.password, password));
        copy.append(text("span", "more", "Copy password"));
        return [text("div", "note error", content.text), password, copy];
      }
      case "logins": {
        const nodes: HTMLElement[] = [];
        if (content.locked) {
          nodes.push(this.option("Silo is locked", "Unlock to fill your saved logins", () => this.actions.unlock()));
        }
        if (content.logins.length > 0) nodes.push(text("div", "head", "Fill with Silo"));
        if (content.insecure && content.logins.length > 0) nodes.push(insecureWarning());
        for (const login of content.logins) {
          nodes.push(this.option(login.username || "(no username)", login.path, () => this.actions.pick(login)));
        }
        if (content.generate) {
          nodes.push(this.option("Generate password…", SAVING_NOTE[content.generate], () => this.actions.suggest()));
        }
        return nodes;
      }
      case "conflict": {
        const { option, username, host, logins } = content;
        const head = username ? `${username} is already saved for this site` : "Logins already saved for this site";
        const nodes: HTMLElement[] = [text("div", "head", head)];
        nodes.push(
          this.option(`Add a new login for ${host}`, keepNote(logins), () =>
            this.actions.useGenerated(option, "saved", { kind: "new" }),
          ),
        );
        for (const login of logins) {
          const who = username ? "" : ` (${login.username || "no username"})`;
          nodes.push(
            this.option(`Overwrite ${login.path}${who}`, updateNote(login, host), () =>
              this.actions.useGenerated(option, "saved", { kind: "overwrite", id: login.id }),
            ),
          );
        }
        return nodes;
      }
      case "generate": {
        const nodes: HTMLElement[] = [
          text("div", content.saving === "saved" ? "head" : "head unsaved", `Generated password · ${SAVING_NOTE[content.saving]}`),
        ];
        if (content.insecure) nodes.push(insecureWarning());
        for (const option of content.options) {
          const button = this.button(() => this.actions.useGenerated(option, content.saving));
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
          nodes.push(button);
        }
        const again = this.button(() => this.actions.suggest());
        again.append(text("span", "more", "↻ Other suggestions"));
        nodes.push(again);
        if (content.saving === "locked") {
          nodes.push(this.option("Unlock Silo", "To save the password you pick", () => this.actions.unlock()));
        }
        return nodes;
      }
    }
  }

  private option(title: string, sub: string, run: () => void): HTMLButtonElement {
    const button = this.button(run);
    button.append(text("span", "title", title), text("span", "sub", sub));
    return button;
  }

  private button(run: () => void): HTMLButtonElement {
    return trustedButton(run);
  }
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
  return text("div", "warn", "This page is not HTTPS; anyone on the network can read what you send.");
}
