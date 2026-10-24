import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { browser } from "wxt/browser";
import { Icon, Logo } from "@/components/Icon";
import { call, send } from "@/lib/client";
import type { AuthEvent } from "@/lib/messages";
import type { SecretSummary, SecretView, StatusInfo } from "@/lib/protocol";
import { errorText } from "@/lib/util";
import { Detail } from "./Detail";
import { Editor } from "./Editor";
import { VaultList } from "./VaultList";

type Connection =
  | { state: "loading" }
  | { state: "bridge_error"; message: string }
  | { state: "no_account"; home: string }
  | { state: "locked"; info: StatusInfo }
  | { state: "unlocked"; info: StatusInfo };

/** `id: null` adds a login. */
type Screen = { name: "list" } | { name: "detail"; id: string } | { name: "edit"; id: string | null };

export interface Tab {
  id: number;
  url: string;
  /** `host` of a web page; null for anything else. */
  host: string | null;
}

/** Copies `value` and says so; shared by every screen. */
export type Copy = (value: string, what: string) => void;

export default function App() {
  const [connection, setConnection] = useState<Connection>({ state: "loading" });
  const [screen, setScreen] = useState<Screen>({ name: "list" });
  const [tab, setTab] = useState<Tab | null>(null);
  const [secrets, setSecrets] = useState<SecretSummary[]>([]);
  const [matches, setMatches] = useState<SecretSummary[]>([]);
  const [refused, setRefused] = useState<string[]>([]);
  const [events, setEvents] = useState<AuthEvent[]>([]);
  const [query, setQuery] = useState("");
  const [toast, setToast] = useState<{ text: string; error?: boolean } | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const notify = useCallback((text: string, error = false) => {
    setToast({ text, error });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), error ? 4000 : 1800);
  }, []);

  const copy = useCallback<Copy>(
    (value, what) => {
      navigator.clipboard.writeText(value).then(
        () => notify(`${what} copied`),
        (err: unknown) => notify(`Could not copy: ${errorText(err)}`, true),
      );
    },
    [notify],
  );

  const refresh = useCallback(async () => {
    try {
      const reply = await call({ method: "status" });
      if (typeof reply !== "object" || !("status" in reply)) throw new Error("bad status reply");
      const info = reply.status;
      if (!info.has_account) setConnection({ state: "no_account", home: info.home });
      else setConnection({ state: info.unlocked ? "unlocked" : "locked", info });
    } catch (err) {
      setConnection({ state: "bridge_error", message: errorText(err) });
    }
    const response = await send({ kind: "events" }).catch(() => null);
    if (response?.kind === "events") setEvents(response.events);
  }, []);

  useEffect(() => {
    void refresh();
    browser.tabs
      .query({ active: true, currentWindow: true })
      .then(([active]) => {
        if (active?.id === undefined || !active.url) return setTab(null);
        const web = /^https?:/.test(active.url);
        setTab({ id: active.id, url: active.url, host: web ? new URL(active.url).host : null });
      })
      .catch(() => setTab(null));
  }, [refresh]);

  const unlocked = connection.state === "unlocked";
  const tabUrl = tab?.host ? tab.url : null;

  /** Everything in the vault and what matches the tab, again after a change. */
  const loadVault = useCallback(async () => {
    try {
      const reply = await call({ method: "list", params: {} });
      if (typeof reply === "object" && "list" in reply) setSecrets(reply.list);
    } catch (err) {
      notify(errorText(err), true);
      void refresh();
    }
    if (!tabUrl) return setMatches([]);
    call({ method: "match", params: { url: tabUrl } })
      .then((reply) => setMatches(typeof reply === "object" && "matches" in reply ? reply.matches : []))
      .catch(() => setMatches([]));
    send({ kind: "basic_auth", origin: new URL(tabUrl).origin })
      .then((response) => response.kind === "basic_auth" && setRefused(response.refused))
      .catch(() => undefined);
  }, [tabUrl, notify, refresh]);

  useEffect(() => {
    if (unlocked) void loadVault();
    else {
      setSecrets([]);
      setMatches([]);
      setScreen({ name: "list" });
    }
  }, [unlocked, loadVault]);

  async function lock() {
    try {
      await call({ method: "lock" });
    } catch (err) {
      notify(errorText(err), true);
    }
    setQuery("");
    await refresh();
  }

  /** Asks the page's login form to fill `id`; closes the popup when it did. */
  async function fill(id: string) {
    if (!tab) return;
    const response = await send({ kind: "fill_tab", tabId: tab.id, id });
    if (response.kind === "filled") window.close();
    else if (response.kind === "error") notify(response.message, true);
  }

  /** One field of a login, for the copy buttons in the list. */
  async function copyField(id: string, field: "username" | "password") {
    const what = field === "username" ? "Username" : "Password";
    const value = call({ method: "get", params: { selector: id } }).then((reply) => {
      if (typeof reply !== "object" || !("secret" in reply)) throw new Error("bad reply");
      const { body } = reply.secret;
      if (!("login" in body)) throw new Error("Not a login");
      return body.login[field];
    });
    if (import.meta.env.SAFARI && typeof ClipboardItem !== "undefined") {
      // WebKit only lets the click itself write: hand it the value still on its way from the agent.
      const blob = value.then((text) => new Blob([text], { type: "text/plain" }));
      navigator.clipboard.write([new ClipboardItem({ "text/plain": blob })]).then(
        () => notify(`${what} copied`),
        (err: unknown) => notify(`Could not copy: ${errorText(err)}`, true),
      );
      return;
    }
    try {
      copy(await value, what);
    } catch (err) {
      notify(errorText(err), true);
    }
  }

  async function saved(view: SecretView | SecretSummary) {
    await loadVault();
    setScreen({ name: "detail", id: view.id });
    notify("Saved");
  }

  const matchIds = new Set(matches.map((m) => m.id));

  return (
    <div className="app">
      <header className="bar">
        <Logo />
        <span className="brand">Silo</span>
        <Status connection={connection} />
        <span className="spacer" />
        {unlocked && (
          <button className="icon-button" title="Add a login" onClick={() => setScreen({ name: "edit", id: null })}>
            <Icon name="plus" />
          </button>
        )}
        {unlocked && (
          <button className="icon-button" title="Lock" onClick={() => void lock()}>
            <Icon name="lock" />
          </button>
        )}
        <button
          className="icon-button"
          title="Settings"
          onClick={() => {
            void browser.runtime.openOptionsPage();
            window.close();
          }}
        >
          <Icon name="settings" />
        </button>
      </header>

      {connection.state === "loading" && <div className="center muted">Connecting to the agent…</div>}
      {connection.state === "bridge_error" && <Offline message={connection.message} retry={() => void refresh()} />}
      {connection.state === "no_account" && (
        <div className="center">
          <Logo size={44} />
          <h2>No vault yet</h2>
          <p className="muted">
            Run <code>silo init</code> in a terminal, then try again.
          </p>
          <button onClick={() => void refresh()}>Try again</button>
        </div>
      )}
      {connection.state === "locked" && <Unlock onUnlocked={() => void refresh()} />}

      {unlocked && screen.name === "list" && (
        <VaultList
          secrets={secrets}
          matches={matches}
          refused={refused}
          tab={tab}
          query={query}
          setQuery={setQuery}
          events={events}
          open={(id) => setScreen({ name: "detail", id })}
          add={() => setScreen({ name: "edit", id: null })}
          fill={(id) => void fill(id)}
          copyField={(id, field) => void copyField(id, field)}
        />
      )}
      {unlocked && screen.name === "detail" && (
        <Detail
          id={screen.id}
          summary={secrets.find((s) => s.id === screen.id) ?? null}
          canFill={matchIds.has(screen.id)}
          copy={copy}
          back={() => setScreen({ name: "list" })}
          edit={() => setScreen({ name: "edit", id: screen.id })}
          fill={() => void fill(screen.id)}
        />
      )}
      {unlocked && screen.name === "edit" && (
        <Editor
          id={screen.id}
          tab={tab}
          folders={[...new Set(secrets.map((s) => s.meta.folder).filter(Boolean))].sort()}
          cancel={() => setScreen(screen.id ? { name: "detail", id: screen.id } : { name: "list" })}
          saved={(summary) => void saved(summary)}
        />
      )}

      {toast && (
        <div className={toast.error ? "toast error" : "toast"} role="status">
          <Icon name={toast.error ? "alert" : "check"} size={14} />
          {toast.text}
        </div>
      )}
    </div>
  );
}

function Status({ connection }: { connection: Connection }) {
  switch (connection.state) {
    case "loading":
      return null;
    case "unlocked": {
      const left = connection.info.expires_in_secs;
      return (
        <span className="status ok" title={`${connection.info.secrets} items`}>
          <i />
          {left === null ? "Unlocked" : `Locks in ${duration(left)}`}
        </span>
      );
    }
    case "locked":
      return (
        <span className="status warn">
          <i />
          Locked
        </span>
      );
    default:
      return (
        <span className="status error">
          <i />
          Offline
        </span>
      );
  }
}

function Unlock({ onUnlocked }: { onUnlocked: () => void }) {
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
      setPassword("");
      onUnlocked();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <form className="center unlock" onSubmit={(e) => void unlock(e)}>
      <Logo size={44} />
      <h2>Unlock Silo</h2>
      <p className="muted">Your master password unlocks the vault on this computer.</p>
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
        <button
          type="button"
          className="icon-button"
          title={shown ? "Hide" : "Show"}
          onClick={() => setShown(!shown)}
        >
          <Icon name={shown ? "eyeOff" : "eye"} />
        </button>
      </div>
      <button type="submit" className="primary wide" disabled={busy || password.length === 0}>
        {busy ? "Unlocking…" : "Unlock"}
      </button>
      {error && <p className="error">{error}</p>}
    </form>
  );
}

function Offline({ message, retry }: { message: string; retry: () => void }) {
  return (
    <div className="center offline">
      <span className="big-icon">
        <Icon name="alert" size={22} />
      </span>
      <h2>Can't reach the Silo agent</h2>
      <pre className="error">{message}</pre>
      <ol>
        <li>
          Install the CLI: <code>cargo install --path crates/cli --locked</code>
        </li>
        {import.meta.env.SAFARI ? (
          <li>
            Start the agent: <code>silo unlock</code>
          </li>
        ) : (
          <>
            <li>
              Connect this browser: <code>silo browser install</code>
            </li>
            <li>Reload the extension.</li>
          </>
        )}
      </ol>
      <button onClick={retry}>
        <Icon name="refresh" size={14} />
        Try again
      </button>
    </div>
  );
}

export function duration(secs: number): string {
  if (secs < 60) return "<1m";
  const hours = Math.floor(secs / 3600);
  const minutes = Math.round((secs % 3600) / 60);
  if (hours === 0) return `${minutes}m`;
  return minutes === 0 ? `${hours}h` : `${hours}h ${minutes}m`;
}
