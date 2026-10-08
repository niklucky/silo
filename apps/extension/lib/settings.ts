import { browser } from "wxt/browser";

/** User preferences, in `storage.local`; the options page writes them, content scripts read them. */

/** What focusing a login field does: open the menu, or show a button that opens it. */
export type Trigger = "menu" | "button";

export interface Settings {
  trigger: Trigger;
  /** Offer to save the login after the user signs in with one Secret does not have. */
  offerToSave: boolean;
  /** Origins where the user chose "Never for this site". */
  neverSave: string[];
}

export const DEFAULT_SETTINGS: Settings = { trigger: "menu", offerToSave: true, neverSave: [] };

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
  return {
    trigger: stored.trigger === "button" ? "button" : DEFAULT_SETTINGS.trigger,
    offerToSave: stored.offerToSave !== false,
    neverSave: Array.isArray(stored.neverSave) ? stored.neverSave.filter((o) => typeof o === "string") : [],
  };
}
