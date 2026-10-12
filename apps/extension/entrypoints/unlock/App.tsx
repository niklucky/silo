import { type FormEvent, useState } from "react";
import { browser } from "wxt/browser";
import type { UiRequest, UiResponse } from "@/lib/messages";
import { describe } from "@/lib/protocol";
import { errorText } from "@/lib/util";

/**
 * Small window the form-fill menu opens when the vault is locked. The master
 * password is typed here, never into the web page.
 */

async function send(message: UiRequest): Promise<UiResponse> {
  return (await browser.runtime.sendMessage(message)) as UiResponse;
}

export default function App() {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function unlock(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await send({ kind: "agent", request: { method: "unlock", params: { password } } });
      if (response.kind === "bridge_error") throw new Error(response.message);
      if (response.kind === "agent" && "err" in response.response) {
        throw new Error(describe(response.response.err));
      }
      window.close();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <main>
      <h1>Unlock Silo</h1>
      <form onSubmit={(e) => void unlock(e)}>
        <label htmlFor="password">Master password</label>
        <input
          id="password"
          type="password"
          autoFocus
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
        />
        <button type="submit" className="primary" disabled={busy || password.length === 0}>
          Unlock
        </button>
        {error && <p className="error">{error}</p>}
      </form>
    </main>
  );
}
