import { type FormEvent, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import type { ChallengeView, UiRequest, UiResponse } from "@/lib/messages";
import { describe } from "@/lib/protocol";
import { errorText } from "@/lib/util";

/**
 * Replaces the browser's Basic Auth dialog. The background script sends a tab
 * here when a site challenges and the vault is locked or has no login for it.
 */

type Phase =
  | { step: "loading" }
  | { step: "unknown" }
  | { step: "unlock"; challenge: ChallengeView }
  | { step: "save"; challenge: ChallengeView }
  | { step: "leaving" };

async function send(message: UiRequest): Promise<UiResponse> {
  return (await browser.runtime.sendMessage(message)) as UiResponse;
}

export default function App() {
  const id = new URLSearchParams(location.search).get("id") ?? "";
  // Never render inside another page: nothing here should be clickjackable.
  const framed = window.top !== window;
  const [phase, setPhase] = useState<Phase>({ step: "loading" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [master, setMaster] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [folder, setFolder] = useState("web");
  const [title, setTitle] = useState("");

  useEffect(() => {
    if (framed || !id) {
      setPhase({ step: "unknown" });
      return;
    }
    send({ kind: "challenge", id })
      .then((response) => {
        if (response.kind !== "challenge") {
          setPhase({ step: "unknown" });
          return;
        }
        const { challenge } = response;
        setTitle(challenge.host);
        setPhase({ step: challenge.state === "locked" ? "unlock" : "save", challenge });
      })
      .catch((err: unknown) => setError(errorText(err)));
  }, [id, framed]);

  function leave(url: string) {
    setPhase({ step: "leaving" });
    location.replace(url);
  }

  function follow(response: UiResponse, challenge: ChallengeView) {
    switch (response.kind) {
      case "continue":
        leave(response.url);
        break;
      case "save":
        setPhase({ step: "save", challenge });
        break;
      case "unknown_challenge":
        setPhase({ step: "unknown" });
        break;
      case "error":
      case "bridge_error":
        setError(response.message);
        break;
      default:
        setError("Unexpected reply from the extension.");
    }
  }

  async function unlock(event: FormEvent, challenge: ChallengeView) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await send({
        kind: "agent",
        request: { method: "unlock", params: { password: master } },
      });
      if (response.kind === "bridge_error") throw new Error(response.message);
      if (response.kind === "agent" && "err" in response.response) {
        throw new Error(describe(response.response.err));
      }
      setMaster("");
      follow(await send({ kind: "challenge_retry", id }), challenge);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function save(remember: boolean, challenge: ChallengeView) {
    setBusy(true);
    setError(null);
    try {
      follow(
        await send({ kind: "challenge_save", id, username, password, folder, title, remember }),
        challenge,
      );
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    const response = await send({ kind: "challenge_cancel", id });
    if (response.kind === "continue") leave(response.url);
    else setPhase({ step: "unknown" });
  }

  if (phase.step === "loading") return <main className="card" />;

  if (phase.step === "leaving") {
    return (
      <main className="card">
        <p className="muted">Signing in…</p>
      </main>
    );
  }

  if (phase.step === "unknown") {
    return (
      <main className="card">
        <h1>Secret</h1>
        <p>Nothing to do here.</p>
        <p className="muted">
          This page opens by itself when a site asks for a password. You can close it.
        </p>
        {error && <p className="error">{error}</p>}
      </main>
    );
  }

  const { challenge } = phase;
  const site = (
    <>
      <h1>
        <strong>{challenge.host}</strong> asks for a password
      </h1>
      {challenge.realm && <p className="muted">Realm: {challenge.realm}</p>}
    </>
  );

  if (phase.step === "unlock") {
    return (
      <main className="card">
        {site}
        <p>Unlock your vault to look for a saved login.</p>
        <form onSubmit={(e) => void unlock(e, challenge)}>
          <label htmlFor="master">Master password</label>
          <input
            id="master"
            type="password"
            autoFocus
            autoComplete="current-password"
            value={master}
            onChange={(e) => setMaster(e.target.value)}
            disabled={busy}
          />
          <div className="row">
            <button type="submit" className="primary" disabled={busy || master.length === 0}>
              Unlock
            </button>
            <button type="button" onClick={() => void cancel()} disabled={busy}>
              Cancel
            </button>
          </div>
          {error && <p className="error">{error}</p>}
        </form>
      </main>
    );
  }

  return (
    <main className="card">
      {site}
      <p>No saved login for this site. Enter it once:</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save(true, challenge);
        }}
      >
        <label htmlFor="username">Username</label>
        <input
          id="username"
          autoFocus
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={busy}
        />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
        />
        <fieldset>
          <legend className="muted">Save as</legend>
          <div className="row">
            <input
              aria-label="Folder"
              value={folder}
              onChange={(e) => setFolder(e.target.value)}
              placeholder="folder"
              disabled={busy}
            />
            <span className="muted">/</span>
            <input
              aria-label="Title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="title"
              disabled={busy}
            />
          </div>
        </fieldset>
        <div className="row">
          <button type="submit" className="primary" disabled={busy || !username || !title.trim()}>
            Save and continue
          </button>
          <button type="button" onClick={() => void save(false, challenge)} disabled={busy || !username}>
            Use once
          </button>
          <button type="button" onClick={() => void cancel()} disabled={busy}>
            Cancel
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </form>
    </main>
  );
}
