import { type FormEvent, useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import type { AuthEvent, UiRequest, UiResponse } from "@/lib/messages";
import type { AgentError, Reply, Request, SecretSummary, StatusInfo } from "@/lib/protocol";
import { describe, isBasicAuth, secretPath } from "@/lib/protocol";
import { originOf } from "@/lib/util";

type View =
  | { state: "loading" }
  | { state: "bridge_error"; message: string }
  | { state: "no_account"; home: string }
  | { state: "locked"; info: StatusInfo }
  | { state: "unlocked"; info: StatusInfo };

class BridgeFailure extends Error {}

class AgentFailure extends Error {
  constructor(readonly info: AgentError) {
    super(describe(info));
  }
}

async function send(message: UiRequest): Promise<UiResponse> {
  return (await browser.runtime.sendMessage(message)) as UiResponse;
}

async function call(request: Request): Promise<Reply> {
  const response = await send({ kind: "agent", request });
  if (response.kind === "bridge_error") throw new BridgeFailure(response.message);
  if (response.kind !== "agent") throw new Error("unexpected response from background");
  if ("err" in response.response) throw new AgentFailure(response.response.err);
  return response.response.ok;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export default function App() {
  const [view, setView] = useState<View>({ state: "loading" });
  const [tab, setTab] = useState<{ id: number; url: string } | null>(null);
  const tabUrl = tab?.url ?? null;
  const [matches, setMatches] = useState<SecretSummary[]>([]);
  const [refused, setRefused] = useState<string[]>([]);
  const [events, setEvents] = useState<AuthEvent[]>([]);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const reply = await call({ method: "status" });
      if (typeof reply !== "object" || !("status" in reply)) throw new Error("bad status reply");
      const info = reply.status;
      if (!info.has_account) setView({ state: "no_account", home: info.home });
      else setView({ state: info.unlocked ? "unlocked" : "locked", info });
    } catch (err) {
      setView({ state: "bridge_error", message: message(err) });
    }
    const response = await send({ kind: "events" });
    if (response.kind === "events") setEvents(response.events);
  }, []);

  useEffect(() => {
    void refresh();
    browser.tabs
      .query({ active: true, currentWindow: true })
      .then(([active]) =>
        setTab(active?.id !== undefined && active.url ? { id: active.id, url: active.url } : null),
      )
      .catch(() => setTab(null));
  }, [refresh]);

  useEffect(() => {
    if (view.state !== "unlocked" || !tabUrl || !/^https?:/.test(tabUrl)) {
      setMatches([]);
      return;
    }
    call({ method: "match", params: { url: tabUrl } })
      .then((reply) => {
        if (typeof reply === "object" && "matches" in reply) setMatches(reply.matches);
      })
      .catch(() => setMatches([]));
    send({ kind: "basic_auth", origin: originOf(tabUrl) })
      .then((response) => {
        if (response.kind === "basic_auth") setRefused(response.refused);
      })
      .catch(() => undefined);
  }, [view.state, tabUrl]);

  async function unlock(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call({ method: "unlock", params: { password } });
      setPassword("");
      await refresh();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }

  async function lock() {
    setBusy(true);
    try {
      await call({ method: "lock" });
      await refresh();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }

  async function fill(id: string) {
    if (!tab) return;
    setError(null);
    const response = await send({ kind: "fill_tab", tabId: tab.id, id });
    if (response.kind === "filled") window.close();
    else if (response.kind === "error") setError(response.message);
  }

  const host = tabUrl && /^https?:/.test(tabUrl) ? new URL(tabUrl).host : null;

  return (
    <main>
      <header>
        <h1>Silo</h1>
        <span className={`dot ${view.state}`} title={view.state} />
        <button
          className="settings"
          title="Settings"
          onClick={() => {
            void browser.runtime.openOptionsPage();
            window.close();
          }}
        >
          Settings
        </button>
      </header>

      {view.state === "loading" && <p className="muted">Connecting to the agent…</p>}

      {view.state === "bridge_error" && (
        <section>
          <p>The extension can't reach the Silo agent.</p>
          <pre className="error">{view.message}</pre>
          {import.meta.env.SAFARI ? (
            <ol>
              <li>
                Install the CLI: <code>cargo install --path crates/cli --locked</code>
              </li>
              <li>
                Start the agent: <code>silo unlock</code>
              </li>
            </ol>
          ) : (
            <ol>
              <li>
                Install the CLI: <code>cargo install --path crates/cli --locked</code>
              </li>
              <li>
                Connect this browser: <code>silo browser install</code>
              </li>
              <li>Reload the extension.</li>
            </ol>
          )}
          <button onClick={() => void refresh()}>Retry</button>
        </section>
      )}

      {view.state === "no_account" && (
        <section>
          <p>No account yet.</p>
          <p className="muted">
            Run <code>silo init</code> in a terminal, then reopen this popup.
          </p>
          <button onClick={() => void refresh()}>Retry</button>
        </section>
      )}

      {view.state === "locked" && (
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
          <button type="submit" disabled={busy || password.length === 0}>
            Unlock
          </button>
          {error && <p className="error">{error}</p>}
        </form>
      )}

      {view.state === "unlocked" && (
        <section>
          <p className="muted">
            Unlocked · {view.info.secrets} secret{view.info.secrets === 1 ? "" : "s"}
            {view.info.expires_in_secs !== null && ` · locks in ${duration(view.info.expires_in_secs)}`}
          </p>
          <h2>{host ?? "This tab"}</h2>
          {host === null ? (
            <p className="muted">Not a web page.</p>
          ) : matches.length === 0 ? (
            <p className="muted">
              No login saved for this site. Add one:
              <br />
              <code>silo add login dev/{host.split(":")[0]} -u USER --url {host}</code>
            </p>
          ) : (
            <ul className="matches">
              {matches.map((m) => (
                <li key={m.id}>
                  <span>
                    {secretPath(m.meta)}
                    {isBasicAuth(m.meta) && <em>Basic Auth</em>}
                    {refused.includes(m.id) && <em className="refused">refused</em>}
                  </span>
                  <button onClick={() => void fill(m.id)}>Fill</button>
                </li>
              ))}
            </ul>
          )}
          <button onClick={() => void lock()} disabled={busy}>
            Lock
          </button>
          {error && <p className="error">{error}</p>}
        </section>
      )}

      {events.length > 0 && (
        <section>
          <h2>Recent activity</h2>
          <ul className="events">
            {events.slice(0, 6).map((e) => (
              <li key={e.at + e.origin}>
                <time>{new Date(e.at).toLocaleTimeString()}</time>
                <span className={`outcome ${e.outcome}`}>{label(e.outcome)}</span>
                <span className="origin" title={e.detail ?? e.origin}>
                  {e.origin}
                  {e.detail && e.outcome !== "error" ? ` → ${e.detail}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}

function label(outcome: AuthEvent["outcome"]): string {
  switch (outcome) {
    case "filled":
      return "filled";
    case "saved":
      return "saved";
    case "asked":
      return "asked you";
    case "no_match":
      return "no login";
    case "locked":
      return "locked";
    case "rejected":
      return "rejected";
    case "error":
      return "error";
  }
}

function duration(secs: number): string {
  if (secs < 60) return "under a minute";
  const hours = Math.floor(secs / 3600);
  const minutes = Math.round((secs % 3600) / 60);
  if (hours === 0) return `${minutes}m`;
  return minutes === 0 ? `${hours}h` : `${hours}h ${minutes}m`;
}
