import { browser } from "wxt/browser";

/** User preferences, in `storage.local`; the options page writes them, content scripts read them. */

/** What focusing a login field does: open the menu, or show a button that opens it. */
export type Trigger = "menu" | "button";

export interface Settings {
  trigger: Trigger;
}

export const DEFAULT_SETTINGS: Settings = { trigger: "menu" };

const KEY = "settings";

export async function loadSettings(): Promise<Settings> {
  const stored = await browser.storage.local.get(KEY);
  return parse(stored[KEY]);
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = { ...(await loadSettings()), ...patch };
  await browser.storage.local.set({ [KEY]: next });
  return next;
}

export function onSettingsChanged(listener: (settings: Settings) => void) {
  browser.storage.onChanged.addListener((changes, area) => {
    const change = changes[KEY];
    if (area === "local" && change) listener(parse(change.newValue));
  });
}

function parse(value: unknown): Settings {
  const stored = (value ?? {}) as Partial<Settings>;
  return { trigger: stored.trigger === "button" ? "button" : DEFAULT_SETTINGS.trigger };
}
