import { type FormEvent, useEffect, useState } from "react";
import { Icon, Logo } from "@/components/Icon";
import { AgentFailure, call } from "@/lib/client";
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
  const [biometric, setBiometric] = useState(false);
  const biometricLabel = /Mac/i.test(navigator.userAgent) ? "Touch ID" : "Biometrics";

  useEffect(() => {
    call({ method: "status" })
      .then((reply) => {
        if (typeof reply === "object" && "status" in reply) {
          if (reply.status.unlocked) {
            window.close();
            return;
          }
          setBiometric(Boolean(reply.status.biometric_available && reply.status.biometric_enabled));
        }
      })
      .catch(() => undefined);
  }, []);

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

  async function unlockBiometric() {
    setBusy(true);
    setError(null);
    try {
      await call({ method: "unlock_biometric", params: {} });
      window.close();
    } catch (err) {
      if (!(err instanceof AgentFailure && err.info.code === "biometric_cancelled")) {
        setError(errorText(err));
      }
      setBusy(false);
    }
  }

  return (
    <main>
      <div className="title">
        <Logo size={32} />
        <h1>Unlock Silo</h1>
      </div>
      <form onSubmit={(e) => void unlock(e)}>
        {biometric && (
          <>
            <button type="button" className="primary" disabled={busy} onClick={() => void unlockBiometric()}>
              <Icon name="fingerprint" size={16} />
              {busy ? "Waiting…" : `Unlock with ${biometricLabel}`}
            </button>
            <div className="unlock-divider">
              <span>or</span>
            </div>
          </>
        )}
        <div className="input-group">
          <input
            type={shown ? "text" : "password"}
            aria-label="Master password"
            placeholder="Master password"
            autoFocus={!biometric}
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
          <button type="button" className="icon-button" title={shown ? "Hide" : "Show"} onClick={() => setShown(!shown)}>
            <Icon name={shown ? "eyeOff" : "eye"} />
          </button>
        </div>
        <button type="submit" className={biometric ? undefined : "primary"} disabled={busy || password.length === 0}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
        {error && <p className="error">{error}</p>}
      </form>
    </main>
  );
}
