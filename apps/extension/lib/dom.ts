/** Small DOM helpers for the extension's own UI inside web pages (closed shadow roots). */

import { avatarFor } from "./avatar";
import { type IconName, ICONS } from "./icons";

export function text(tag: string, className: string, value: string): HTMLElement {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = value;
  return node;
}

/** A button that runs `run` on real clicks only: a page script can dispatch a click but cannot make it trusted. */
export function trustedButton(run: () => void): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.addEventListener("click", (event) => {
    if (!event.isTrusted) return;
    event.preventDefault();
    event.stopPropagation();
    run();
  });
  return button;
}

const SVG = "http://www.w3.org/2000/svg";

export function icon(name: IconName, strokeWidth = 2): SVGSVGElement {
  const svg = document.createElementNS(SVG, "svg");
  const attrs: Record<string, string> = {
    class: "icon",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": String(strokeWidth),
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
  };
  for (const [key, value] of Object.entries(attrs)) svg.setAttribute(key, value);
  const path = document.createElementNS(SVG, "path");
  path.setAttribute("d", ICONS[name]);
  svg.append(path);
  return svg;
}

/** The Silo mark: a key on the accent color. */
export function logo(): HTMLElement {
  const mark = document.createElement("span");
  mark.className = "logo";
  mark.append(icon("key", 2.6));
  return mark;
}

export function avatar(label: string): HTMLElement {
  const { letter, color } = avatarFor(label);
  const node = text("span", "avatar", letter);
  node.style.background = color;
  return node;
}
