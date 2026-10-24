import { type FormEvent, useState } from "react";
import { Icon, Logo } from "@/components/Icon";
import { call } from "@/lib/client";
import { errorText } from "@/lib/util";

/**
 * Small window the form-fill menu opens when the vault is locked. The master
 * password is typed here, never into the web page.
 */
export default function App() {
  const [password, setPassword] = useState("");
  const [shown, setShown] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function unlock(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call({ method: "unlock", params: { password } });
      window.close();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <main>
      <div className="title">
        <Logo size={28} />
        <h1>Unlock Silo</h1>
      </div>
      <form onSubmit={(e) => void unlock(e)}>
        <div className="input-group">
          <input
            type={shown ? "text" : "password"}
            aria-label="Master password"
            placeholder="Master password"
            autoFocus
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
          <button type="button" className="icon-button" title={shown ? "Hide" : "Show"} onClick={() => setShown(!shown)}>
            <Icon name={shown ? "eyeOff" : "eye"} />
          </button>
        </div>
        <button type="submit" className="primary" disabled={busy || password.length === 0}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
        {error && <p className="error">{error}</p>}
      </form>
    </main>
  );
}
