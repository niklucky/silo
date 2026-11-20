import { useState, type FormEvent } from "react";
import { Logo } from "../icons";

interface VaultOnboardingProps {
  host: string;
  createVault(password: string): Promise<void>;
  signIn(server: string, username: string, password: string): Promise<void>;
}

export function VaultOnboarding({ host, createVault, signIn }: VaultOnboardingProps) {
  const [mode, setMode] = useState<"create" | "signIn" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const creating = mode === "create";
  const title = creating ? "Create local vault" : "Sign in to a sync server";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const password = String(fields.get("password"));
    if (creating && password !== fields.get("confirmation")) {
      setError("Passwords do not match.");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      if (creating) {
        await createVault(password);
      } else {
        await signIn(String(fields.get("server")).trim(), String(fields.get("username")).trim(), password);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="unlock" data-host={host} data-tauri-drag-region>
      {mode === null ? (
        <div className="unlock-card">
          <Logo size={64} />
          <h1>Set up your vault</h1>
          <button className="btn primary wide" onClick={() => setMode("create")}>Create local vault</button>
          <button className="btn wide" onClick={() => setMode("signIn")}>Sign in to a sync server</button>
        </div>
      ) : (
        <form className="unlock-card" onSubmit={submit}>
          <Logo size={64} />
          <h1>{title}</h1>
          {!creating && (
            <>
              <label className="vault-setup-field">
                Server URL
                <input name="server" type="url" autoFocus required disabled={busy} placeholder="https://silo.example.com" />
              </label>
              <label className="vault-setup-field">
                Username
                <input name="username" autoComplete="username" required disabled={busy} />
              </label>
            </>
          )}
          <label className="vault-setup-field">
            Master password
            <input
              name="password"
              type="password"
              autoComplete={creating ? "new-password" : "current-password"}
              autoFocus={creating}
              minLength={creating ? 8 : undefined}
              required
              disabled={busy}
            />
          </label>
          {creating && (
            <label className="vault-setup-field">
              Confirm master password
              <input name="confirmation" type="password" autoComplete="new-password" required disabled={busy} />
            </label>
          )}
          {error && <p className="error" role="alert">{error}</p>}
          <button className="btn primary wide" type="submit" disabled={busy}>
            {busy ? (creating ? "Creating vault…" : "Signing in…") : creating ? "Create vault" : "Sign in"}
          </button>
          <button
            type="button"
            className="btn wide"
            disabled={busy}
            onClick={() => {
              setError(null);
              setMode(null);
            }}
          >
            Back
          </button>
        </form>
      )}
    </div>
  );
}
