/**
 * The small Silo button inside a login field, for the "show button" setting:
 * the menu opens only when it is clicked, which leaves the field's focus to
 * other password managers (Apple Passwords, the browser's own). Closed shadow
 * root and trusted clicks only, like the menu.
 */

const SIZE = 22;

const STYLE = `
:host { all: initial; }
button {
  all: unset; position: fixed; z-index: 2147483646; box-sizing: border-box;
  width: ${SIZE}px; height: ${SIZE}px; border-radius: 6px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  color: #2e7d32; background: rgba(255,255,255,.9); border: 1px solid rgba(0,0,0,.15);
}
button:hover { background: #fff; border-color: #2e7d32; }
@media (prefers-color-scheme: dark) {
  button { color: #81c784; background: rgba(43,43,46,.9); border-color: rgba(255,255,255,.2); }
  button:hover { background: #2b2b2e; border-color: #81c784; }
}
svg { width: 14px; height: 14px; }
`;

const SVG = "http://www.w3.org/2000/svg";

function keyIcon(): SVGSVGElement {
  const svg = document.createElementNS(SVG, "svg");
  const attrs: Record<string, string> = {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": "2.4",
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
  };
  for (const [name, value] of Object.entries(attrs)) svg.setAttribute(name, value);
  const circle = document.createElementNS(SVG, "circle");
  circle.setAttribute("cx", "8");
  circle.setAttribute("cy", "15");
  circle.setAttribute("r", "4");
  const path = document.createElementNS(SVG, "path");
  path.setAttribute("d", "M10.8 12.2 20 3M16 7l3 3M14 9l2 2");
  svg.append(circle, path);
  return svg;
}

export class FieldButton {
  private readonly host: HTMLElement;
  private readonly button: HTMLButtonElement;
  private anchor: HTMLElement | null = null;
  private readonly reposition = () => this.place();

  constructor(onClick: () => void) {
    this.host = document.createElement("silo-fill-button");
    this.host.style.setProperty("all", "initial", "important");
    const root = this.host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.button = document.createElement("button");
    this.button.type = "button";
    this.button.title = "Silo";
    this.button.setAttribute("aria-label", "Open Silo");
    this.button.append(keyIcon());
    // Keep focus in the field.
    this.button.addEventListener("mousedown", (event) => event.preventDefault());
    this.button.addEventListener("click", (event) => {
      if (!event.isTrusted) return;
      event.preventDefault();
      event.stopPropagation();
      onClick();
    });
    root.append(style, this.button);
  }

  get anchoredTo(): HTMLElement | null {
    return this.anchor;
  }

  show(anchor: HTMLElement) {
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
    // Inside the right edge; just outside it when the field is too narrow to share.
    const inside = rect.width >= 120;
    const left = inside ? rect.right - SIZE - 6 : rect.right + 4;
    this.button.style.left = `${Math.min(left, window.innerWidth - SIZE - 2)}px`;
    this.button.style.top = `${rect.top + (rect.height - SIZE) / 2}px`;
  }
}
