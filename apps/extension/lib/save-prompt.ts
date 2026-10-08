import { text, trustedButton } from "./dom";
import { updateNote } from "./menu";
import type { OfferAnswer, SaveOffer } from "./messages";

/**
 * The "Save login?" panel in the top-right corner of the page, shown after
 * the user signs in with a login Secret does not have. Same rules as the
 * menu: closed shadow root, trusted clicks only. It never holds the password.
 */

export interface SavePromptActions {
  answer(offer: SaveOffer, answer: OfferAnswer): void;
  unlock(): void;
}

const STYLE = `
:host { all: initial; }
.panel {
  position: fixed; z-index: 2147483647; top: 12px; right: 12px; box-sizing: border-box;
  width: 320px; max-width: calc(100vw - 24px); padding: 8px;
  font: 13px/1.35 system-ui, sans-serif; color: #1d1d1f;
  background: #fff; border: 1px solid rgba(0,0,0,.15); border-radius: 10px;
  box-shadow: 0 8px 28px rgba(0,0,0,.22);
}
@media (prefers-color-scheme: dark) {
  .panel { color: #f2f2f2; background: #2b2b2e; border-color: rgba(255,255,255,.15); }
}
.head { padding: 2px 8px; font-weight: 600; font-size: 14px; }
.who { padding: 0 8px 6px; font-size: 12px; opacity: .7; overflow-wrap: anywhere; }
.note { padding: 4px 8px; }
.note.error { color: #b3261e; }
button {
  all: unset; box-sizing: border-box; display: block; width: 100%;
  padding: 6px 8px; border-radius: 6px; cursor: pointer;
}
button:hover, button:focus-visible { background: rgba(127,127,127,.18); }
.title { display: block; font-weight: 600; overflow-wrap: anywhere; }
.sub { display: block; font-size: 12px; opacity: .7; }
.foot { display: flex; gap: 4px; margin-top: 4px; }
.foot button { width: auto; font-size: 12px; opacity: .8; }
`;

export class SavePrompt {
  private readonly host: HTMLElement;
  private readonly box: HTMLDivElement;
  private current: SaveOffer | null = null;
  /** An answer is on its way: further clicks are ignored. */
  private busy = false;

  constructor(private readonly actions: SavePromptActions) {
    this.host = document.createElement("secret-save-prompt");
    this.host.style.setProperty("all", "initial", "important");
    const root = this.host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.box = document.createElement("div");
    this.box.className = "panel";
    this.box.setAttribute("role", "dialog");
    this.box.setAttribute("aria-label", "Secret");
    root.append(style, this.box);
  }

  get offer(): SaveOffer | null {
    return this.current;
  }

  show(offer: SaveOffer) {
    this.current = offer;
    this.busy = false;
    this.box.replaceChildren(...this.render(offer));
    if (!this.host.isConnected) document.documentElement.append(this.host);
  }

  /** Replaces the panel with a short message (the offer is answered). */
  note(message: string, error = false) {
    this.current = null;
    this.busy = false;
    this.box.replaceChildren(text("div", error ? "note error" : "note", message));
    if (!this.host.isConnected) document.documentElement.append(this.host);
  }

  hide() {
    this.current = null;
    this.busy = false;
    this.host.remove();
  }

  private render(offer: SaveOffer): HTMLElement[] {
    const { host, username, logins } = offer;
    const nodes: HTMLElement[] = [
      text("div", "head", logins.length > 0 ? "Update a saved login?" : `Save login for ${host}?`),
      text("div", "who", username ? `Signed in as ${username}` : "Signed in without a username"),
    ];
    if (offer.locked) {
      nodes.push(this.option("Unlock Secret", "Then choose how to save it", () => this.actions.unlock()));
    } else if (logins.length === 0) {
      nodes.push(this.option("Save", "As a new login in web/", () => this.answer({ kind: "new" })));
    } else {
      for (const login of logins) {
        const who = username ? "" : ` (${login.username || "no username"})`;
        nodes.push(
          this.option(`Update ${login.path}${who}`, updateNote(login, host, login.samePassword), () =>
            this.answer({ kind: "overwrite", id: login.id }),
          ),
        );
      }
      nodes.push(this.option("Save as a new login", `For ${host}`, () => this.answer({ kind: "new" })));
    }
    const foot = document.createElement("div");
    foot.className = "foot";
    foot.append(this.small("Not now", { kind: "dismiss" }), this.small("Never for this site", { kind: "never" }));
    nodes.push(foot);
    return nodes;
  }

  private answer(answer: OfferAnswer) {
    if (this.busy || !this.current) return;
    this.busy = true;
    this.actions.answer(this.current, answer);
  }

  private option(title: string, sub: string, run: () => void): HTMLButtonElement {
    const button = trustedButton(run);
    button.append(text("span", "title", title), text("span", "sub", sub));
    return button;
  }

  private small(label: string, answer: OfferAnswer): HTMLButtonElement {
    const button = trustedButton(() => this.answer(answer));
    button.textContent = label;
    return button;
  }
}
