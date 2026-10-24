import { useEffect, useState } from "react";
import { Logo } from "@/components/Icon";
import { loadSettings, type Settings, saveSettings, type Trigger } from "@/lib/settings";
import { errorText } from "@/lib/util";

const TRIGGERS: { value: Trigger; title: string; detail: string }[] = [
  {
    value: "menu",
    title: "Show the menu",
    detail: "Saved logins and password suggestions drop down as soon as you click into the field.",
  },
  {
    value: "button",
    title: "Show a button",
    detail:
      "A small Silo key appears inside the field; click it for the menu. Pick this when another " +
      "password manager, such as Apple Passwords, opens its own menu in the same place.",
  },
];

export default function App() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [status, setStatus] = useState<string>("");

  useEffect(() => {
    loadSettings()
      .then(setSettings)
      .catch((err: unknown) => setStatus(errorText(err)));
  }, []);

  async function update(patch: Partial<Settings>) {
    try {
      setSettings(await saveSettings(patch));
      setStatus("Saved. Open pages pick it up right away.");
    } catch (err) {
      setStatus(errorText(err));
    }
  }

  return (
    <main>
      <div className="title">
        <Logo size={28} />
        <h1>Silo settings</h1>
      </div>
      {settings && (
        <fieldset>
          <legend>Login and password fields</legend>
          <p className="muted">When you click into a username or password field:</p>
          {TRIGGERS.map((t) => (
            <label key={t.value} className="choice">
              <input
                type="radio"
                name="trigger"
                value={t.value}
                checked={settings.trigger === t.value}
                onChange={() => void update({ trigger: t.value })}
              />
              <span>
                {t.title}
                {t.value === "menu" && <span className="muted"> (default)</span>}
              </span>
              <span className="muted">{t.detail}</span>
            </label>
          ))}
        </fieldset>
      )}
      {settings && (
        <fieldset>
          <legend>Saving logins</legend>
          <label className="choice">
            <input
              type="checkbox"
              checked={settings.offerToSave}
              onChange={(e) => void update({ offerToSave: e.target.checked })}
            />
            <span>Offer to save logins when you sign in</span>
            <span className="muted">
              After you sign in with a login Silo does not have, or with a new password for one it has, a
              small panel asks whether to save it. Nothing is stored until you answer.
            </span>
          </label>
          {settings.neverSave.length > 0 && (
            <>
              <p className="muted">Never offered on:</p>
              <ul className="never">
                {settings.neverSave.map((origin) => (
                  <li key={origin}>
                    <span>{origin}</span>
                    <button
                      type="button"
                      onClick={() => void update({ neverSave: settings.neverSave.filter((o) => o !== origin) })}
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </fieldset>
      )}
      <p className="saved">{status}</p>
    </main>
  );
}
