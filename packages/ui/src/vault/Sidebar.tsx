import { type ReactNode, useMemo, useState } from "react";
import type { SyncInfo } from "../client";
import { timeAgo } from "../format";
import { Icon, type IconName, Logo } from "../icons";
import { KIND_PLURAL, KINDS, type SecretKind, type SecretSummary } from "../protocol";
import { allTags, type FolderNode, folderTree, type Scope, sameScope } from "./scope";

export const KIND_ICON: Record<SecretKind, IconName> = {
  login: "key",
  card: "card",
  env_set: "terminal",
  file: "file",
  note: "note",
};

interface Props {
  items: readonly SecretSummary[];
  scope: Scope;
  setScope: (scope: Scope) => void;
  lock: () => void;
  /** Undefined until known; null when the vault does not sync. */
  sync: SyncInfo | null | undefined;
  syncing: boolean;
  syncNow: () => void;
  biometric?: {
    enabled: boolean;
    busy: boolean;
    label: string;
    toggle: () => void;
  };
}

export function Sidebar({ items, scope, setScope, lock, sync, syncing, syncNow, biometric }: Props) {
  const folders = useMemo(() => folderTree(items), [items]);
  const tags = useMemo(() => allTags(items), [items]);
  const kindCount = (kind: SecretKind) => items.filter((i) => i.meta.kind === kind).length;

  const row = (target: Scope, icon: IconName, label: string, count: number) => (
    <button key={JSON.stringify(target)} className={`nav-row${sameScope(scope, target) ? " active" : ""}`} onClick={() => setScope(target)}>
      <Icon name={icon} size={15} />
      <span className="nav-label">{label}</span>
      <span className="nav-count">{count}</span>
    </button>
  );

  return (
    <nav className="sidebar">
      <div className="sidebar-head" data-tauri-drag-region>
        <Logo />
        <span className="brand">Silo</span>
      </div>
      <div className="sidebar-scroll">
        <div className="nav-group">{row({ type: "all" }, "grid", "All items", items.length)}</div>

        {folders.length > 0 && (
          <Section id="folders" title="Folders">
            {folders.map((f) => (
              <FolderRows key={f.path} node={f} scope={scope} setScope={setScope} depth={0} />
            ))}
          </Section>
        )}

        <Section id="types" title="Types">
          {KINDS.map((kind) => {
            const count = kindCount(kind);
            return count > 0 ? row({ type: "kind", kind }, KIND_ICON[kind], KIND_PLURAL[kind], count) : null;
          })}
        </Section>

        {tags.length > 0 && (
          <Section id="tags" title="Tags">
            <div className="tag-cloud">
              {tags.map(({ tag }) => {
                const target: Scope = { type: "tag", tag };
                return (
                  <button key={tag} className={`chip${sameScope(scope, target) ? " active" : ""}`} onClick={() => setScope(target)}>
                    {tag}
                  </button>
                );
              })}
            </div>
          </Section>
        )}
      </div>
      <div className="sidebar-foot">
        <SyncState sync={sync} syncing={syncing} syncNow={syncNow} />
        {biometric && (
          <button
            className={`icon-btn${biometric.enabled ? " active" : ""}`}
            title={
              biometric.enabled
                ? `${biometric.label} unlock enabled — click to disable`
                : `Enable ${biometric.label} unlock`
            }
            aria-label={biometric.enabled ? `Disable ${biometric.label} unlock` : `Enable ${biometric.label} unlock`}
            aria-pressed={biometric.enabled}
            disabled={biometric.busy}
            onClick={biometric.toggle}
          >
            <Icon name="fingerprint" size={15} />
          </button>
        )}
        <button className="icon-btn" title="Lock (⌘L)" onClick={lock}>
          <Icon name="lock" size={15} />
        </button>
      </div>
    </nav>
  );
}

function SyncState({ sync, syncing, syncNow }: Pick<Props, "sync" | "syncing" | "syncNow">) {
  if (sync === undefined) return <span className="sync-state" />;
  if (sync === null) {
    return (
      <span className="sync-state off" title="Set up with `silo sync login` in a terminal">
        <i /> Not syncing
      </span>
    );
  }
  const state = syncing ? "busy" : sync.last_error ? "error" : "ok";
  const label = syncing
    ? "Syncing…"
    : sync.last_error
      ? "Sync failed"
      : sync.last_sync
        ? `Synced ${timeAgo(sync.last_sync)}`
        : "Not synced yet";
  const title = [sync.last_error, `${sync.username} on ${sync.server}`, "Click to sync now"].filter(Boolean).join("\n");
  return (
    <button className={`sync-state ${state}`} title={title} onClick={syncNow} disabled={syncing}>
      <i /> {label}
      {!!sync.pending && <span className="nav-count">· {sync.pending} pending</span>}
    </button>
  );
}

/** A sidebar group whose open state is remembered across launches. */
function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  const key = `silo.sidebar.${id}`;
  const [open, setOpenRaw] = useState(() => {
    try {
      return localStorage.getItem(key) !== "closed";
    } catch {
      return true;
    }
  });
  const setOpen = (next: boolean) => {
    setOpenRaw(next);
    try {
      localStorage.setItem(key, next ? "open" : "closed");
    } catch {
      // Remembering is a convenience.
    }
  };
  return (
    <div className="nav-group">
      <button className="nav-title" onClick={() => setOpen(!open)}>
        {title}
        <Icon name={open ? "chevronDown" : "chevron"} size={12} />
      </button>
      {open && children}
    </div>
  );
}

function FolderRows({ node, scope, setScope, depth }: { node: FolderNode; scope: Scope; setScope: (scope: Scope) => void; depth: number }) {
  const inside = scope.type === "folder" && scope.path.startsWith(`${node.path}/`);
  const [open, setOpen] = useState(false);
  const expanded = open || inside;
  const active = scope.type === "folder" && scope.path === node.path;
  return (
    <>
      <div className={`nav-row folder${active ? " active" : ""}`} style={{ paddingLeft: 4 + depth * 14 }}>
        <button
          className={`twisty${node.children.length ? "" : " hidden"}`}
          onClick={() => setOpen(!expanded)}
          aria-label={expanded ? "Collapse" : "Expand"}
        >
          <Icon name={expanded ? "chevronDown" : "chevron"} size={11} />
        </button>
        <button
          className="nav-hit"
          onClick={() => {
            setScope({ type: "folder", path: node.path });
            setOpen(true);
          }}
        >
          <Icon name="folder" size={15} />
          <span className="nav-label">{node.name}</span>
          <span className="nav-count">{node.count}</span>
        </button>
      </div>
      {expanded &&
        node.children.map((child) => <FolderRows key={child.path} node={child} scope={scope} setScope={setScope} depth={depth + 1} />)}
    </>
  );
}
