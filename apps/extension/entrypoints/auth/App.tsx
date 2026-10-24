import { type FormEvent, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import type { ChallengeView, LinkOption, SameSiteLogin, SaveChoice, UiRequest, UiResponse } from "@/lib/messages";
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
  /** Same-site logins with this username: the save waits for "add new" or "overwrite". */
  const [conflicts, setConflicts] = useState<SameSiteLogin[] | null>(null);
  /** Logins of other hosts of the site, offered instead of typing one. */
  const [options, setOptions] = useState<LinkOption[]>([]);
  /** A login picked from `options` that could cover the whole subdomain: asks how widely. */
  const [picked, setPicked] = useState<LinkOption | null>(null);

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

  const saving = phase.step === "save";
  useEffect(() => {
    if (!saving) return;
    // Nothing to offer is not worth an error: the form below still works.
    send({ kind: "challenge_logins", id })
      .then((response) => {
        if (response.kind === "link_options") setOptions(response.logins);
      })
      .catch(() => undefined);
  }, [id, saving]);

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
      case "conflict":
        setConflicts(response.logins);
        break;
      case "link_changed":
        setOptions(response.logins);
        setPicked(null);
        setError("That login changed since this page showed it. Check it and pick again.");
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

  async function save(remember: boolean, challenge: ChallengeView, choice?: SaveChoice) {
    setBusy(true);
    setError(null);
    try {
      follow(
        await send({ kind: "challenge_save", id, username, password, folder, title, remember, choice }),
        challenge,
      );
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function link(option: LinkOption, wildcard: boolean, challenge: ChallengeView) {
    setBusy(true);
    setError(null);
    try {
      const request: UiRequest = {
        kind: "challenge_link",
        id,
        login: option.id,
        revision: option.revision,
        wildcard: wildcard ? option.wildcard : null,
      };
      follow(await send(request), challenge);
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
        <h1>Silo</h1>
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

  if (conflicts) {
    const saveAs = folder.trim() ? `${folder.trim()}/${title.trim()}` : title.trim();
    return (
      <main className="card">
        {site}
        <p>
          <strong>{username}</strong> is already saved for this site. Is this the same login, or another one?
        </p>
        <div className="choices">
          <button
            type="button"
            className="primary"
            onClick={() => void save(true, challenge, { kind: "new" })}
            disabled={busy}
          >
            Add a new login: {saveAs}
          </button>
          {conflicts.map((login) => (
            <button
              key={login.id}
              type="button"
              onClick={() => void save(true, challenge, { kind: "overwrite", id: login.id })}
              disabled={busy}
            >
              Overwrite {login.path}
              <span className="muted">{overwriteText(login, challenge.host)}</span>
            </button>
          ))}
          <button type="button" onClick={() => setConflicts(null)} disabled={busy}>
            Back
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </main>
    );
  }

  if (picked?.wildcard) {
    const option = picked;
    return (
      <main className="card">
        {site}
        <p>
          Use <strong>{option.path}</strong> on {challenge.host}?
        </p>
        <p className="muted">It already signs in on {option.hosts.join(", ")}.</p>
        <div className="choices">
          <button
            type="button"
            className="primary"
            autoFocus
            onClick={() => void link(option, true, challenge)}
            disabled={busy}
          >
            Use on all of {option.wildcard}
            <span className="muted">Any other host there signs in with it too, without asking</span>
          </button>
          <button type="button" onClick={() => void link(option, false, challenge)} disabled={busy}>
            Only on {challenge.host}
          </button>
          <button type="button" onClick={() => setPicked(null)} disabled={busy}>
            Back
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </main>
    );
  }

  const refusedText =
    challenge.refused.length === 0
      ? null
      : `The site refused ${challenge.refused.length === 1 ? "the saved login" : "the saved logins"} ${challenge.refused.join(", ")}.`;

  return (
    <main className="card">
      {site}
      {options.length === 0 ? (
        <p>{refusedText ? `${refusedText} Enter the right one:` : "No saved login for this site. Enter it once:"}</p>
      ) : (
        <>
          <p>
            {refusedText ?? `No login saved for ${challenge.host} yet.`} Use one saved for another host of this
            site:
          </p>
          <div className="choices">
            {options.map((option) => (
              <button
                key={option.id}
                type="button"
                onClick={() => (option.wildcard ? setPicked(option) : void link(option, false, challenge))}
                disabled={busy}
              >
                {option.path}
                <span className="muted">
                  {option.username || "no username"}
                  {option.hosts.length > 0 && ` · on ${option.hosts.join(", ")}`}
                </span>
              </button>
            ))}
          </div>
          <p className="muted">Or enter it:</p>
        </>
      )}
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

/** What overwriting `login` from the conflict screen changes. */
function overwriteText(login: SameSiteLogin, host: string): string {
  const elsewhere = login.elsewhere ?? [];
  if (login.here) {
    return elsewhere.length === 0
      ? "Replace its password; the old one stays in its history"
      : `Replace its password here and on ${elsewhere.join(", ")}; the old one stays in its history`;
  }
  return elsewhere.length === 0
    ? `Replace its password and use it on ${host} too`
    : `Replace its password on ${elsewhere.join(", ")} and use it on ${host} too`;
}
