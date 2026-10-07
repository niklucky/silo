import type { LoginOption } from "./messages";

/**
 * The dropdown under a login field: matching logins, or an unlock prompt. Plain
 * DOM in a closed shadow root, so page styles cannot reach in and page scripts
 * cannot read it. Clicks only count when the browser marks them as trusted.
 */

export type MenuContent =
  | { kind: "logins"; logins: LoginOption[]; insecure: boolean }
  | { kind: "locked" };

export interface MenuActions {
  pick(login: LoginOption): void;
  unlock(): void;
}

const STYLE = `
:host { all: initial; }
.menu {
  position: fixed; z-index: 2147483647; box-sizing: border-box;
  min-width: 220px; max-width: 360px; padding: 4px;
  font: 13px/1.35 system-ui, sans-serif; color: #1d1d1f;
  background: #fff; border: 1px solid rgba(0,0,0,.15); border-radius: 8px;
  box-shadow: 0 6px 24px rgba(0,0,0,.18);
}
@media (prefers-color-scheme: dark) {
  .menu { color: #f2f2f2; background: #2b2b2e; border-color: rgba(255,255,255,.15); }
}
.head { padding: 4px 8px 2px; font-size: 11px; opacity: .6; }
.warn { padding: 2px 8px 4px; font-size: 11px; color: #b3261e; }
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
    this.host = document.createElement("secret-fill-menu");
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
    const height = this.box.offsetHeight;
    const below = rect.bottom + 4;
    const top = below + height > window.innerHeight && rect.top - height - 4 > 0 ? rect.top - height - 4 : below;
    this.box.style.top = `${top}px`;
    this.box.style.left = `${Math.max(4, Math.min(rect.left, window.innerWidth - this.box.offsetWidth - 4))}px`;
    this.box.style.width = `${Math.max(220, Math.min(360, rect.width))}px`;
  }

  private render(content: MenuContent): HTMLElement[] {
    if (content.kind === "locked") {
      return [
        this.option("Secret is locked", "Unlock to fill this form", () => this.actions.unlock()),
      ];
    }
    const nodes: HTMLElement[] = [];
    nodes.push(text("div", "head", "Fill with Secret"));
    if (content.insecure) nodes.push(text("div", "warn", "This page is not HTTPS; anyone on the network can read what you send."));
    for (const login of content.logins) {
      nodes.push(this.option(login.username || "(no username)", login.path, () => this.actions.pick(login)));
    }
    return nodes;
  }

  private option(title: string, sub: string, run: () => void): HTMLButtonElement {
    const button = document.createElement("button");
    button.type = "button";
    button.append(text("span", "title", title), text("span", "sub", sub));
    button.addEventListener("click", (event) => {
      // A page script can dispatch a synthetic click but cannot make it trusted.
      if (!event.isTrusted) return;
      event.preventDefault();
      event.stopPropagation();
      run();
    });
    return button;
  }
}

function text(tag: string, className: string, value: string): HTMLElement {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = value;
  return node;
}
