/** Small DOM helpers for the extension's own UI inside web pages (closed shadow roots). */

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
