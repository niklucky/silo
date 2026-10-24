/**
 * Styles shared by the UI inside web pages (menu, save panel, field button):
 * the same tokens as assets/base.css, on the shadow host, plus the pieces
 * every panel uses. `:host { all: initial }` keeps page styles out.
 */

export const TOKENS = `
:host {
  all: initial;
  --bg: #ffffff; --surface: #f4f5f6; --surface-2: #e9ebed; --fg: #16181a; --muted: #687078;
  --line: #e1e4e7; --accent: #1d7a4c; --accent-hover: #17663f; --accent-fg: #ffffff; --accent-soft: #e2f3e9;
  --error: #c0392b; --error-soft: #fdecea; --warn: #a86400; --warn-soft: #fff3df;
  --shadow: 0 2px 6px rgba(0,0,0,.08), 0 12px 32px rgba(0,0,0,.16);
  --font: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :host {
    --bg: #1f2225; --surface: #272b2f; --surface-2: #31363b; --fg: #eceef0; --muted: #98a0a8;
    --line: #363b40; --accent: #3fbf7f; --accent-hover: #5ccd93; --accent-fg: #08180f; --accent-soft: #163122;
    --error: #ff7b6b; --error-soft: #3a1d1a; --warn: #f0b357; --warn-soft: #3a2b12;
    --shadow: 0 2px 6px rgba(0,0,0,.3), 0 12px 32px rgba(0,0,0,.45);
  }
}
* { box-sizing: border-box; }
.panel {
  position: fixed; z-index: 2147483647;
  font: 13px/1.4 var(--font); color: var(--fg); text-align: left;
  background: var(--bg); border: 1px solid var(--line); border-radius: 12px;
  box-shadow: var(--shadow);
  animation: silo-in .14s ease-out;
}
@keyframes silo-in { from { opacity: 0; transform: translateY(-4px); } }
@media (prefers-reduced-motion: reduce) { .panel { animation: none; } }
svg.icon { width: 16px; height: 16px; flex: none; display: block; }
.logo {
  display: inline-flex; align-items: center; justify-content: center; flex: none;
  width: 20px; height: 20px; border-radius: 5px; background: var(--accent); color: var(--accent-fg);
}
.logo svg.icon { width: 13px; height: 13px; }
.avatar {
  display: inline-flex; align-items: center; justify-content: center; flex: none;
  width: 28px; height: 28px; border-radius: 7px; color: #fff; font-weight: 600; font-size: 13px;
  text-transform: uppercase;
}
button { all: unset; box-sizing: border-box; cursor: pointer; }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  padding: 6px 12px; border-radius: 8px; font-weight: 500; border: 1px solid var(--line);
}
.btn:hover { background: var(--surface); }
.btn.primary { background: var(--accent); color: var(--accent-fg); border-color: transparent; }
.btn.primary:hover { background: var(--accent-hover); }
.btn.link { border-color: transparent; padding: 6px 8px; color: var(--muted); }
.btn.link:hover { color: var(--fg); background: var(--surface); }
.btn[disabled] { opacity: .5; cursor: default; }
.icon-btn {
  display: inline-flex; align-items: center; justify-content: center; flex: none;
  width: 26px; height: 26px; border-radius: 7px; color: var(--muted);
}
.icon-btn:hover { background: var(--surface); color: var(--fg); }
`;
