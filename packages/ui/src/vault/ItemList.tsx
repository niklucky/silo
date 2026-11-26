import { type KeyboardEvent as ReactKeyboardEvent, type RefObject, useEffect, useRef, useState } from "react";
import { firstWebsite, useFavicon } from "../favicon";
import { avatarFor } from "../format";
import { Icon } from "../icons";
import { KIND_LABEL, KINDS, type SecretKind, type SecretSummary } from "../protocol";
import { hostsOf } from "../search";
import { usernameKey } from "../usernames";
import { type Scope, scopeTitle } from "./scope";
import { KIND_ICON } from "./Sidebar";

interface Props {
  scope: Scope;
  openTokens?: () => void;
  /** Already filtered and ordered. */
  items: readonly SecretSummary[];
  query: string;
  setQuery: (query: string) => void;
  searchRef: RefObject<HTMLInputElement | null>;
  selected: string | null;
  select: (id: string) => void;
  create: (kind: SecretKind) => void;
  /** Login usernames read so far, by `usernameKey`. */
  usernames: ReadonlyMap<string, string | null>;
}

export function ItemList({ scope, items, query, setQuery, searchRef, selected, select, create, usernames, openTokens }: Props) {
  const [menu, setMenu] = useState(false);
  const groups = group(items, scope, query);
  const grouped = scope.type === "folder" && !query.trim() ? scope.path : null;
  const prefixes = new Map(groups.flatMap((g) => [...disambiguate(g.items)]));

  function onSearchKey(event: ReactKeyboardEvent) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Enter") {
      event.preventDefault();
      if (items.length === 0) return;
      const index = items.findIndex((i) => i.id === selected);
      const step = event.key === "ArrowUp" ? -1 : 1;
      const next = event.key === "Enter" && index < 0 ? 0 : Math.min(items.length - 1, Math.max(0, index + step));
      select(items[next]!.id);
    } else if (event.key === "Escape" && query) {
      event.preventDefault();
      setQuery("");
    }
  }

  return (
    <section className="list">
      <div className="list-head" data-tauri-drag-region>
        <h2>{scopeTitle(scope)}</h2>
        <span className="list-count">{items.length}</span>
        <span className="spacer" />
        {openTokens && (
          <button className="icon-btn" title={scope.type === "folder" ? "Folder access tokens" : "All access tokens"} onClick={openTokens}>
            <Icon name="key" size={16} />
          </button>
        )}
        <div className="menu-anchor">
          <button className="icon-btn accent" title="New item (⌘N)" onClick={() => setMenu(!menu)}>
            <Icon name="plus" size={16} />
          </button>
          {menu && (
            <NewMenu
              close={() => setMenu(false)}
              pick={(kind) => {
                setMenu(false);
                create(kind);
              }}
            />
          )}
        </div>
      </div>
      <label className="search">
        <Icon name="search" size={15} />
        <input
          ref={searchRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onSearchKey}
          placeholder="Search"
          spellCheck={false}
          autoComplete="off"
        />
        {query ? (
          <button className="icon-btn small" onClick={() => setQuery("")} aria-label="Clear">
            <Icon name="close" size={13} />
          </button>
        ) : (
          <kbd>⌘K</kbd>
        )}
      </label>
      <div className="list-scroll">
        {items.length === 0 && <p className="empty">{query ? "Nothing matches." : "Nothing here yet."}</p>}
        {groups.map(({ label, items: rows }) => (
          <div key={label}>
            {label && <div className="list-group">{label}</div>}
            {rows.map((item) => (
              <Row
                key={item.id}
                item={item}
                prefix={prefixes.get(item.id)}
                login={usernames.get(usernameKey(item))}
                active={item.id === selected}
                showFolder={grouped === null}
                onClick={() => select(item.id)}
              />
            ))}
          </div>
        ))}
      </div>
    </section>
  );
}

function Row({
  item,
  prefix,
  login,
  active,
  showFolder,
  onClick,
}: {
  item: SecretSummary;
  /** Folder segments that tell this item from others with the same title. */
  prefix: string | undefined;
  /** The username; undefined while unknown. */
  login: string | null | undefined;
  active: boolean;
  showFolder: boolean;
  onClick: () => void;
}) {
  const ref = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (active) ref.current?.scrollIntoView({ block: "nearest" });
  }, [active]);
  const host = hostsOf(item.meta)[0];
  // Logins: who you sign in as, which is what tells accounts on one site apart.
  // The website only while the username is unknown or empty.
  const first =
    item.meta.kind !== "login" ? KIND_LABEL[item.meta.kind] : login === undefined ? null : login || host || KIND_LABEL.login;
  const sub = [first, showFolder ? item.meta.folder : null].filter(Boolean).join(" · ") || "\u00a0";
  return (
    <button ref={ref} className={`row${active ? " active" : ""}`} onClick={onClick}>
      <ItemAvatar item={item} />
      <span className="row-text">
        <span className="row-title">
          {prefix && <span className="row-prefix">{prefix} / </span>}
          {item.meta.title}
        </span>
        <span className="row-sub">{sub}</span>
      </span>
      {item.meta.basic_auth && <span className="badge">Basic</span>}
    </button>
  );
}

export function ItemAvatar({ item, large = false }: { item: SecretSummary; large?: boolean }) {
  const cls = large ? "avatar large" : "avatar";
  const login = item.meta.kind === "login";
  const favicon = useFavicon(login ? firstWebsite(item.meta.urls) : null);
  const [broken, setBroken] = useState<string | null>(null);
  if (login) {
    if (favicon && broken !== favicon) {
      return (
        <span className={`${cls} favicon`} aria-hidden="true">
          <img src={favicon} alt="" onError={() => setBroken(favicon)} />
        </span>
      );
    }
    const { letter, color } = avatarFor(hostsOf(item.meta)[0] ?? item.meta.title);
    return (
      <span className={cls} style={{ background: color }} aria-hidden="true">
        {letter}
      </span>
    );
  }
  return (
    <span className={`${cls} kind kind-${item.meta.kind}`} aria-hidden="true">
      <Icon name={KIND_ICON[item.meta.kind]} size={large ? 20 : 15} />
    </span>
  );
}

function NewMenu({ close, pick }: { close: () => void; pick: (kind: SecretKind) => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    const onClick = (e: MouseEvent) => !(e.target as Element).closest(".menu-anchor") && close();
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onClick);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onClick);
    };
  }, [close]);
  return (
    <div className="menu" role="menu">
      {KINDS.map((kind) => (
        <button key={kind} role="menuitem" onClick={() => pick(kind)}>
          <Icon name={KIND_ICON[kind]} size={15} />
          {KIND_LABEL[kind]}
        </button>
      ))}
    </div>
  );
}

/** Flat by title outside folders and while searching; grouped by subfolder inside a folder. */
function group(items: readonly SecretSummary[], scope: Scope, query: string) {
  if (scope.type !== "folder" || query.trim()) return [{ label: "", items: [...items] }];
  const groups = new Map<string, SecretSummary[]>();
  for (const item of items) {
    const rest = item.meta.folder === scope.path ? "" : item.meta.folder.slice(scope.path.length + 1);
    groups.set(rest, [...(groups.get(rest) ?? []), item]);
  }
  // Same order as VaultApp sorts folders in (code units), so rows and arrow keys agree.
  const keys = [...groups.keys()].sort();
  return keys.map((key) => ({ label: key, items: groups.get(key)! }));
}

/**
 * For titles that occur more than once in `items`, the shortest tail of each
 * one's folder that tells them apart: `api` and `wallet` for two `dev` env sets
 * in projects/api and projects/wallet.
 */
function disambiguate(items: readonly SecretSummary[]): Map<string, string> {
  const byTitle = new Map<string, SecretSummary[]>();
  for (const item of items) {
    const key = item.meta.title.toLowerCase();
    byTitle.set(key, [...(byTitle.get(key) ?? []), item]);
  }
  const out = new Map<string, string>();
  for (const same of byTitle.values()) {
    // Same folder: the folder tells them apart no better than the title.
    if (same.length < 2 || new Set(same.map((i) => i.meta.folder)).size < 2) continue;
    const paths = same.map((i) => (i.meta.folder ? i.meta.folder.split("/") : []));
    const deepest = Math.max(...paths.map((p) => p.length));
    let depth = 1;
    for (; depth < deepest; depth++) {
      const tails = paths.map((p) => p.slice(-depth).join("/"));
      if (new Set(tails).size === tails.length) break;
    }
    same.forEach((item, i) => {
      const tail = paths[i]!.slice(-depth).join(" / ");
      out.set(item.id, tail || "root");
    });
  }
  return out;
}
