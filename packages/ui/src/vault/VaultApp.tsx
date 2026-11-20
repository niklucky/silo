import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { SyncInfo, VaultClient, VaultSetup } from "../client";
import { createFaviconLoader, FaviconContext, type SiteFetcher } from "../favicon";
import { Icon, Logo } from "../icons";
import { KIND_LABEL, type SecretKind, type SecretSummary, type SecretView } from "../protocol";
import { search } from "../search";
import { createUsernameLoader, usernameKey, useUsernames } from "../usernames";
import { type Copy, Detail } from "./Detail";
import { type Draft, draftOf, Editor, newDraft } from "./Editor";
import { ItemList } from "./ItemList";
import { allFolders, inScope, type Scope } from "./scope";
import { Sidebar } from "./Sidebar";
import { VaultOnboarding } from "./VaultOnboarding";

export interface VaultAppProps {
  client: VaultClient;
  setup?: VaultSetup;
  /** Shown on the unlock screen; also lets hosts tweak layout via `data-host`. */
  host: "desktop" | "web";
  /** Lets login avatars show website favicons; letters only without it. */
  fetchSite?: SiteFetcher;
}

/** `session` is unique per opened editor: its React key, so a new editor never inherits one still saving. */
type Mode = { type: "view" } | { type: "edit"; view: SecretView; session: number } | { type: "new"; kind: SecretKind; session: number };

let editorSessions = 0;

/** The whole vault UI: unlock, browse, search, preview and edit. Hosts only supply the client. */
export function VaultApp({ client, setup, host, fetchSite }: VaultAppProps) {
  const [state, setState] = useState<"loading" | "locked" | "open">("loading");
  const [items, setItems] = useState<SecretSummary[]>([]);
  const [scope, setScopeRaw] = useState<Scope>({ type: "all" });
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>({ type: "view" });
  const [toast, setToast] = useState<string | null>(null);
  const [sync, setSync] = useState<SyncInfo | null | undefined>(undefined);
  const [syncing, setSyncing] = useState(false);
  const [noAccount, setNoAccount] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const favicons = useMemo(() => (fetchSite ? createFaviconLoader(fetchSite) : null), [fetchSite]);

  // A fresh cache per unlocked session (`session` is only there to force one), so no username outlives a lock.
  const [session, setSession] = useState(0);
  const username = useMemo(
    () => createUsernameLoader((id) => client.get(id).then((view) => ("login" in view.body ? view.body.login.username : null))),
    [client, session],
  );
  useEffect(() => {
    if (state === "locked") setSession((n) => n + 1);
  }, [state]);
  // Drop reads still queued from the session that just ended.
  useEffect(() => () => username.stop(), [username]);

  /**
   * Back to the unlock screen, forgetting everything read while unlocked: the
   * list, the selection and any open editor (which holds a decrypted secret).
   * Every path that notices a lock goes through here, whoever locked.
   */
  const locked = useCallback(() => {
    setItems([]);
    setSelected(null);
    setMode({ type: "view" });
    setState("locked");
  }, []);

  const refresh = useCallback(async () => {
    setItems(await client.list());
    client.syncStatus().then(setSync, () => setSync(null));
  }, [client]);

  /** Re-reads status and items: on start, and whenever the window comes back, since the CLI, browsers and sync change the vault too. */
  const reload = useCallback(async () => {
    try {
      const status = await client.status();
      setNoAccount(!status.has_account);
      if (!status.unlocked) {
        locked();
        return;
      }
      await refresh();
      setState("open");
    } catch (err) {
      if (isLocked(err)) locked();
      else setState((s) => (s === "loading" ? "locked" : s));
    }
  }, [client, refresh, locked]);

  useEffect(() => {
    void reload();
    const onFocus = () => void reload();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [reload]);

  // The agent locks on its own (timeout, `silo lock`) without telling clients,
  // and a window can stay in front for hours: ask now and then.
  useEffect(() => {
    if (state !== "open") return;
    const timer = setInterval(() => {
      client.status().then(
        (status) => !status.unlocked && locked(),
        (err: unknown) => isLocked(err) && locked(),
      );
    }, 30_000);
    return () => clearInterval(timer);
  }, [state, client, locked]);

  async function syncNow() {
    setSyncing(true);
    try {
      await client.sync();
      await refresh();
    } catch (err) {
      if (isLocked(err)) return locked();
      setToast(err instanceof Error ? err.message : String(err));
      client.syncStatus().then(setSync, () => undefined);
    } finally {
      setSyncing(false);
    }
  }

  const usernames = useUsernames(items, username);
  // In display order: inside a folder (not searching) the list groups rows by
  // subfolder, so sort by folder too; arrow keys and auto-select follow this.
  const visible = useMemo(() => {
    const found = search(
      items.filter((i) => inScope(i, scope)),
      query,
      (i) => usernames.get(usernameKey(i)) ?? null,
    );
    if (scope.type !== "folder" || query.trim()) return found;
    return found.sort((a, b) => (a.meta.folder < b.meta.folder ? -1 : a.meta.folder > b.meta.folder ? 1 : 0));
  }, [items, scope, query, usernames]);
  const current = items.find((i) => i.id === selected) ?? null;
  const folders = useMemo(() => allFolders(items), [items]);

  const setScope = (next: Scope) => {
    setScopeRaw(next);
    setMode({ type: "view" });
  };

  // Keep a selection while browsing so the right pane is never empty for no reason.
  useEffect(() => {
    if (mode.type !== "view") return;
    if (!selected || !visible.some((i) => i.id === selected)) setSelected(visible[0]?.id ?? null);
  }, [visible, selected, mode.type]);

  const copy: Copy = useCallback((text, what) => {
    void navigator.clipboard.writeText(text).then(
      () => setToast(`Copied ${what.toLowerCase()}`),
      () => setToast("Could not copy"),
    );
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 1600);
    return () => clearTimeout(timer);
  }, [toast]);

  const lock = useCallback(async () => {
    await client.lock();
    locked();
  }, [client, locked]);

  useEffect(() => {
    if (state !== "open") return;
    const onKey = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
      if (mod && e.key === "k") {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      } else if (e.key === "/" && !typing) {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (mod && e.key === "l") {
        e.preventDefault();
        void lock();
      } else if (mod && e.key === "n" && mode.type === "view") {
        e.preventDefault();
        setMode({ type: "new", kind: scope.type === "kind" ? scope.kind : "login", session: ++editorSessions });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [state, lock, mode.type, scope]);

  // The editor on screen now; a save that finishes after the user moved on
  // must not close whatever they opened since.
  const modeRef = useRef(mode);
  modeRef.current = mode;

  async function save(draft: Draft) {
    const editing = mode;
    const fields = {
      title: draft.title,
      folder: draft.folder,
      tags: draft.tags,
      urls: draft.urls.map((u) => u.trim()).filter(Boolean),
      basic_auth: "login" in draft.body ? draft.basicAuth : undefined,
      body: draft.body,
    };
    let saved: SecretSummary;
    try {
      saved =
        editing.type === "edit"
          ? await client.update({ selector: editing.view.id, revision: editing.view.revision, ...fields })
          : await client.add(fields);
    } catch (err) {
      if (isLocked(err)) locked();
      throw err;
    }
    // Saved. From here on nothing may send the user back to the editor: a
    // retry would add a duplicate or fail as stale.
    let note = editing.type === "edit" ? "Saved" : `${KIND_LABEL[saved.meta.kind]} added`;
    try {
      await refresh();
    } catch (err) {
      if (isLocked(err)) return locked();
      note += `, but the list did not reload: ${err instanceof Error ? err.message : String(err)}`;
    }
    if (modeRef.current === editing) {
      setSelected(saved.id);
      setMode({ type: "view" });
    }
    setToast(note);
  }

  if (state === "loading") return <div className="vault" data-host={host} />;
  if (state === "locked") {
    if (noAccount && setup) {
      return (
        <VaultOnboarding
          host={host}
          createVault={async (password) => {
            try {
              await setup.createVault(password);
            } finally {
              await reload();
            }
          }}
          signIn={async (server, username, password) => {
            await setup.signIn(server, username, password);
            try {
              await client.sync();
            } catch (err) {
              setToast(`Signed in. Initial sync failed: ${err instanceof Error ? err.message : String(err)}`);
            }
            await reload();
          }}
        />
      );
    }
    return (
      <Unlock
        host={host}
        noAccount={noAccount}
        unlock={async (password) => {
          await client.unlock(password);
          await refresh();
          setState("open");
        }}
      />
    );
  }

  const newFolder = scope.type === "folder" ? scope.path : "";

  return (
    <FaviconContext.Provider value={favicons}>
      <div className="vault" data-host={host}>
        <Sidebar
          items={items}
          scope={scope}
          setScope={setScope}
          lock={() => void lock()}
          sync={sync}
          syncing={syncing}
          syncNow={() => void syncNow()}
        />
        <ItemList
          scope={scope}
          items={visible}
          query={query}
          setQuery={setQuery}
          searchRef={searchRef}
          selected={mode.type === "new" ? null : selected}
          select={(id) => {
            setSelected(id);
            setMode({ type: "view" });
          }}
          create={(kind) => setMode({ type: "new", kind, session: ++editorSessions })}
          usernames={usernames}
        />
        <main className="pane">
          {mode.type === "edit" && (
            <Editor
              key={mode.session}
              kind={mode.view.meta.kind}
              initial={draftOf(mode.view)}
              isNew={false}
              folders={folders}
              save={save}
              cancel={() => setMode({ type: "view" })}
            />
          )}
          {mode.type === "new" && (
            <Editor
              key={mode.session}
              kind={mode.kind}
              initial={newDraft(mode.kind, newFolder)}
              isNew
              folders={folders}
              save={save}
              cancel={() => setMode({ type: "view" })}
            />
          )}
          {mode.type === "view" && current && (
            <Detail
              client={client}
              summary={current}
              copy={copy}
              edit={(view) => setMode({ type: "edit", view, session: ++editorSessions })}
              remove={async () => {
                try {
                  await client.remove(current.id);
                  await refresh();
                  setToast("Deleted");
                } catch (err) {
                  if (isLocked(err)) locked();
                  else setToast(err instanceof Error ? err.message : String(err));
                }
              }}
              openFolder={(path) => setScope({ type: "folder", path })}
              openTag={(tag) => setScope({ type: "tag", tag })}
              locked={locked}
            />
          )}
          {mode.type === "view" && !current && (
            <div className="pane-empty">
              <Icon name="key" size={28} />
              <p>Select an item, or press ⌘N to add one.</p>
            </div>
          )}
        </main>
        {toast && (
          <div className="toast" role="status">
            <Icon name="check" size={14} /> {toast}
          </div>
        )}
      </div>
    </FaviconContext.Provider>
  );
}

function isLocked(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "locked";
}

function Unlock({ host, noAccount, unlock }: { host: string; noAccount: boolean; unlock: (password: string) => Promise<void> }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="unlock" data-host={host} data-tauri-drag-region>
      <form
        className="unlock-card"
        onSubmit={(e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          unlock(password).catch((err: unknown) => {
            setError(err instanceof Error ? err.message : String(err));
            setBusy(false);
          });
        }}
      >
        <Logo size={64} />
        <h1>{noAccount ? "No vault on this machine" : "Silo is locked"}</h1>
        {noAccount ? (
          <p className="muted center">
            Create one with <code>silo init</code>, or sign in to your server with <code>silo sync login</code>, then come back.
          </p>
        ) : (
          <input type="password" autoFocus placeholder="Master password" value={password} onChange={(e) => setPassword(e.target.value)} />
        )}
        {error && <p className="error">{error}</p>}
        {!noAccount && (
          <button className="btn primary wide" disabled={busy}>
            Unlock
          </button>
        )}
      </form>
    </div>
  );
}
