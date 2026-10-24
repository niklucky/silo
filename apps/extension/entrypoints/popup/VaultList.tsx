import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { Avatar } from "@/components/Avatar";
import { Icon } from "@/components/Icon";
import { call } from "@/lib/client";
import type { IconName } from "@/lib/icons";
import type { AuthEvent } from "@/lib/messages";
import type { SecretKind, SecretSummary } from "@/lib/protocol";
import { isBasicAuth } from "@/lib/protocol";
import { hostsOf, search } from "@/lib/search";
import type { Tab } from "./App";

interface Props {
  secrets: SecretSummary[];
  /** Logins for the tab's URL, best first. */
  matches: SecretSummary[];
  /** Logins the tab's site refused as Basic Auth. */
  refused: string[];
  tab: Tab | null;
  query: string;
  setQuery: (query: string) => void;
  events: AuthEvent[];
  open: (id: string) => void;
  add: () => void;
  fill: (id: string) => void;
  copyField: (id: string, field: "username" | "password") => void;
}

export const KIND_ICON: Record<SecretKind, IconName> = {
  login: "key",
  card: "card",
  env_set: "terminal",
  file: "file",
  note: "note",
};

export const KIND_LABEL: Record<SecretKind, string> = {
  login: "Login",
  card: "Card",
  env_set: "Env vars",
  file: "File",
  note: "Note",
};

/** Looks like a URL or a host name: the agent also knows the site's other hosts. */
function siteQuery(query: string): string | null {
  const q = query.trim();
  if (/\s/.test(q) || !q.includes(".")) return null;
  const url = q.includes("://") ? q : `https://${q}`;
  try {
    return new URL(url).hostname.includes(".") ? url : null;
  } catch {
    return null;
  }
}

export function VaultList(props: Props) {
  const { secrets, matches, refused, tab, query, setQuery, events, open, add, fill, copyField } = props;
  const [active, setActive] = useState(0);
  const [usernames, setUsernames] = useState<Record<string, string>>({});
  const [siteHits, setSiteHits] = useState<SecretSummary[]>([]);
  const list = useRef<HTMLDivElement>(null);
  const searching = query.trim() !== "";

  // Usernames tell the tab's logins apart; there are few of them.
  useEffect(() => {
    let live = true;
    void Promise.all(
      matches.slice(0, 8).map(async (m) => {
        const reply = await call({ method: "get", params: { selector: m.id } }).catch(() => null);
        const body = reply && typeof reply === "object" && "secret" in reply ? reply.secret.body : null;
        return [m.id, body && "login" in body ? body.login.username : ""] as const;
      }),
    ).then((pairs) => live && setUsernames(Object.fromEntries(pairs)));
    return () => {
      live = false;
    };
  }, [matches]);

  // A pasted URL also finds logins for the rest of its site, with the agent's public suffix list.
  useEffect(() => {
    const url = siteQuery(query);
    if (!url) return setSiteHits([]);
    const timer = setTimeout(() => {
      call({ method: "match", params: { url, site: true } })
        .then((reply) => setSiteHits(typeof reply === "object" && "matches" in reply ? reply.matches : []))
        .catch(() => setSiteHits([]));
    }, 150);
    return () => clearTimeout(timer);
  }, [query]);

  const results = useMemo(() => {
    if (!searching) return [];
    const found = search(secrets, query);
    const seen = new Set(found.map((s) => s.id));
    return [...found, ...siteHits.filter((s) => !seen.has(s.id))];
  }, [secrets, query, searching, siteHits]);

  const rows: SecretSummary[] = searching ? results : [...matches, ...search(secrets, "")];
  const matchIds = new Set(matches.map((m) => m.id));

  useEffect(() => setActive(0), [query]);
  useEffect(() => {
    list.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  function onKey(event: KeyboardEvent) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActive((i) => Math.max(0, Math.min(rows.length - 1, i + step)));
    } else if (event.key === "Enter") {
      const row = rows[active];
      if (!row) return;
      event.preventDefault();
      // ⌘/Ctrl+Enter fills a login for this page; Enter opens it.
      if ((event.metaKey || event.ctrlKey) && matchIds.has(row.id)) fill(row.id);
      else open(row.id);
    } else if (event.key === "Escape" && query) {
      event.preventDefault();
      setQuery("");
    }
  }

  const row = (secret: SecretSummary, index: number, site: boolean) => (
    <Row
      key={`${site ? "site" : "all"}-${secret.id}`}
      index={index}
      secret={secret}
      active={index === active}
      subtitle={site ? usernames[secret.id] || "(no username)" : subtitleOf(secret)}
      refused={refused.includes(secret.id)}
      canFill={matchIds.has(secret.id)}
      open={() => open(secret.id)}
      fill={() => fill(secret.id)}
      copyField={(field) => copyField(secret.id, field)}
      hover={() => setActive(index)}
    />
  );

  return (
    <>
      <div className="search">
        <Icon name="search" />
        <input
          type="search"
          placeholder="Search by name, site, folder or tag"
          aria-label="Search the vault"
          autoFocus
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKey}
          spellCheck={false}
        />
      </div>

      <div className="list" ref={list}>
        {searching ? (
          <>
            <h3 className="section">
              {results.length === 0 ? "No results" : `${results.length} result${results.length === 1 ? "" : "s"}`}
            </h3>
            {results.map((s, i) => row(s, i, false))}
            {results.length === 0 && (
              <div className="empty">
                <p className="muted">Nothing matches “{query.trim()}”.</p>
              </div>
            )}
          </>
        ) : (
          <>
            {tab?.host && (
              <>
                <h3 className="section">
                  <Icon name="globe" size={12} />
                  {tab.host}
                </h3>
                {matches.map((s, i) => row(s, i, true))}
                {matches.length === 0 && (
                  <div className="empty site">
                    <span className="muted">No login saved for this site.</span>
                    <button className="ghost small" onClick={add}>
                      <Icon name="plus" size={14} />
                      Add
                    </button>
                  </div>
                )}
              </>
            )}
            <h3 className="section">All items · {secrets.length}</h3>
            {search(secrets, "").map((s, i) => row(s, matches.length + i, false))}
            {secrets.length === 0 && (
              <div className="empty">
                <p className="muted">Your vault is empty.</p>
                <button className="primary" onClick={add}>
                  <Icon name="plus" size={14} />
                  Add a login
                </button>
              </div>
            )}
            {events.length > 0 && <Activity events={events} />}
          </>
        )}
      </div>
    </>
  );
}

interface RowProps {
  index: number;
  secret: SecretSummary;
  active: boolean;
  subtitle: string;
  refused: boolean;
  canFill: boolean;
  open: () => void;
  fill: () => void;
  copyField: (field: "username" | "password") => void;
  hover: () => void;
}

function Row({ index, secret, active, subtitle, refused, canFill, open, fill, copyField, hover }: RowProps) {
  const { meta } = secret;
  const login = meta.kind === "login";
  return (
    <div
      className={active ? "row active" : "row"}
      data-index={index}
      role="button"
      tabIndex={-1}
      onClick={open}
      onMouseMove={hover}
    >
      {login ? <Avatar label={hostsOf(meta)[0] ?? meta.title} /> : <KindIcon kind={meta.kind} />}
      <span className="row-text">
        <span className="row-title">
          {meta.title}
          {isBasicAuth(meta) && <span className="badge accent">Basic Auth</span>}
          {refused && <span className="badge error">refused</span>}
        </span>
        <span className="row-sub">{subtitle}</span>
      </span>
      <span className="row-actions" onClick={(e) => e.stopPropagation()}>
        {login && (
          <>
            <button className="icon-button" title="Copy username" onClick={() => copyField("username")}>
              <Icon name="user" size={15} />
            </button>
            <button className="icon-button" title="Copy password" onClick={() => copyField("password")}>
              <Icon name="copy" size={15} />
            </button>
          </>
        )}
        {canFill && (
          <button className="primary small" title="Fill on this page (⌘/Ctrl+Enter)" onClick={fill}>
            Fill
          </button>
        )}
      </span>
    </div>
  );
}

export function KindIcon({ kind, large = false }: { kind: SecretKind; large?: boolean }) {
  return (
    <span className={large ? "avatar large kind" : "avatar kind"} title={KIND_LABEL[kind]}>
      <Icon name={KIND_ICON[kind]} size={large ? 22 : 16} />
    </span>
  );
}

function subtitleOf({ meta }: SecretSummary): string {
  const parts = [meta.folder, hostsOf(meta)[0]].filter(Boolean);
  if (meta.kind !== "login") parts.unshift(KIND_LABEL[meta.kind]);
  return parts.join(" · ") || "—";
}

function Activity({ events }: { events: AuthEvent[] }) {
  return (
    <details className="activity">
      <summary>
        <Icon name="clock" size={12} />
        Recent activity
      </summary>
      <ul>
        {events.slice(0, 8).map((e) => (
          <li key={e.at + e.origin + e.outcome}>
            <time>{new Date(e.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time>
            <span className={`outcome ${e.outcome}`}>{OUTCOME[e.outcome]}</span>
            <span className="origin" title={e.detail ?? e.origin}>
              {e.origin.replace(/^https?:\/\//, "")}
              {e.detail && e.outcome !== "error" ? ` → ${e.detail}` : ""}
            </span>
          </li>
        ))}
      </ul>
    </details>
  );
}

const OUTCOME: Record<AuthEvent["outcome"], string> = {
  filled: "filled",
  saved: "saved",
  asked: "asked you",
  no_match: "no login",
  locked: "locked",
  rejected: "rejected",
  error: "error",
};
