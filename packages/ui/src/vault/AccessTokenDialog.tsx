import { useEffect, useRef, useState } from "react";
import type { AccessTokenInfo, AccessTokens, TokenScope } from "../client";
import { Icon } from "../icons";
import type { SecretSummary } from "../protocol";
import { inScope } from "./scope";
import { Field } from "./Detail";

export interface TokenContext {
  scope: TokenScope | null;
  label: string;
}

type TokenAction = { type: "rotate" | "revoke"; name: string };
type Change = TokenAction | { type: "issue"; name: string; scope: TokenScope };

interface Props {
  api: AccessTokens;
  context: TokenContext;
  items: readonly SecretSummary[];
  close: () => void;
  locked: () => void;
}

export function AccessTokenDialog({ api, context, items, close, locked }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [rows, setRows] = useState<AccessTokenInfo[] | null>(null);
  const [revision, setRevision] = useState(0);
  const [name, setName] = useState("");
  const [confirm, setConfirm] = useState<TokenAction | null>(null);
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<{ name: string; value: string } | null>(null);
  const [error, setError] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const { scope, label } = context;
  const folderItems =
    scope && "folder" in scope
      ? items.filter((item) => item.meta.kind === "env_set" && inScope(item, { type: "folder", path: scope.folder }))
      : null;

  useEffect(() => {
    const element = dialog.current!;
    element.showModal();
    return () => element.close();
  }, []);

  useEffect(() => {
    let active = true;
    setRows(null);
    setError("");
    api.list(scope).then(
      (list) => active && setRows(list),
      (err: unknown) => {
        if (!active) return;
        if (isLockError(err)) locked();
        else setError(message(err));
      },
    );
    return () => {
      active = false;
    };
  }, [api, scope, revision, locked]);

  async function copyCredential(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopyStatus("Copied to clipboard.");
    } catch {
      setCopyStatus("Could not copy. Reveal the token and copy it manually.");
    }
  }

  async function apply(change: Change) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      if (change.type === "revoke") {
        await api.revoke(change.name);
        setRevision((n) => n + 1);
      } else {
        const value = change.type === "issue" ? await api.issue(change.name, change.scope) : await api.rotate(change.name);
        setIssued({ name: change.name, value });
        setCopyStatus("");
        setName("");
      }
      setConfirm(null);
    } catch (err) {
      if (isLockError(err)) locked();
      else setError(message(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog
      className="token-dialog"
      ref={dialog}
      aria-labelledby="token-heading"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) close();
      }}
      onKeyDown={(event) => {
        if (!((event.metaKey || event.ctrlKey) && event.key === "l")) event.stopPropagation();
      }}
    >
      <header>
        <div>
          <h2 id="token-heading">{issued ? "Save your access token" : "Access tokens"}</h2>
          <p className="muted token-path">{issued?.name ?? label}</p>
        </div>
        <button className="icon-btn" aria-label="Close access tokens" onClick={close} disabled={busy}>
          <Icon name="close" />
        </button>
      </header>
      {issued ? (
        <>
          <p>Save this credential in your CI secrets now. You can view it once.</p>
          <div className="fields">
            <Field label="Access token" value={issued.value} secret copy={copyCredential} />
          </div>
          <div className="token-actions">
            <span role="status" className="muted">
              {copyStatus}
            </span>
            <button
              className="btn primary"
              onClick={() => {
                setIssued(null);
                setRevision((n) => n + 1);
              }}
            >
              Done
            </button>
          </div>
        </>
      ) : (
        <>
          {scope && (
            <form
              className="token-create"
              onSubmit={(event) => {
                event.preventDefault();
                void apply({ type: "issue", name, scope });
              }}
            >
              <label className="form-field">
                <span>Token name</span>
                <input
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  required
                  pattern="[A-Za-z0-9_\-]+"
                  maxLength={128}
                  title="Letters, digits, underscores and hyphens"
                  placeholder="api-deploy"
                  spellCheck={false}
                  autoComplete="off"
                  disabled={busy}
                />
              </label>
              {folderItems ? (
                folderItems.length ? (
                  <details>
                    <summary>
                      {folderItems.length} env {folderItems.length === 1 ? "set" : "sets"} currently in this folder and its
                      subfolders
                    </summary>
                    <ul>
                      {folderItems.map((item) => (
                        <li key={item.id}>
                          {item.meta.folder}/{item.meta.title}
                        </li>
                      ))}
                    </ul>
                  </details>
                ) : (
                  <p className="muted">This folder contains no env sets.</p>
                )
              ) : (
                <p className="muted">Grants read access to every variable in this env set.</p>
              )}
              <button className="btn primary" disabled={busy || !name || !rows || confirm !== null || folderItems?.length === 0}>
                Issue token
              </button>
            </form>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          {rows === null && !error && (
            <p role="status" className="muted">
              Loading tokens…
            </p>
          )}
          {rows?.length === 0 && <p className="muted">No access tokens {scope ? "cover this selection" : "have been issued"}.</p>}
          {rows?.map((row) => (
            <section className="token-entry" key={row.name}>
              <h3>
                <Icon name="key" size={15} />
                {row.name}
              </h3>
              <details>
                <summary>
                  Read access to {row.paths.length} env {row.paths.length === 1 ? "set" : "sets"}
                </summary>
                <ul>
                  {row.paths.map((path, index) => (
                    <li key={index}>{path}</li>
                  ))}
                </ul>
              </details>
              {confirm?.name === row.name ? (
                <>
                  <p>
                    {confirm.type === "rotate"
                      ? "Rotate this token? Its current credential will stop working immediately."
                      : "Revoke this token? Pipelines using it will lose access to every env set listed here."}
                  </p>
                  <div className="token-actions">
                    <button className="btn" disabled={busy} onClick={() => setConfirm(null)}>
                      Cancel
                    </button>
                    <button
                      className={`btn ${confirm.type === "rotate" ? "primary" : "danger"}`}
                      disabled={busy}
                      onClick={() => void apply(confirm)}
                    >
                      {confirm.type === "rotate" ? "Confirm rotation" : "Confirm revocation"}
                    </button>
                  </div>
                </>
              ) : (
                <div className="token-actions">
                  <button className="btn" disabled={busy} onClick={() => setConfirm({ type: "rotate", name: row.name })}>
                    Rotate
                  </button>
                  <button className="btn" disabled={busy} onClick={() => setConfirm({ type: "revoke", name: row.name })}>
                    Revoke
                  </button>
                </div>
              )}
            </section>
          ))}
          {error && (
            <button
              className="btn"
              disabled={busy}
              onClick={() => {
                setConfirm(null);
                setRevision((n) => n + 1);
              }}
            >
              Reload tokens
            </button>
          )}
          {busy && (
            <p role="status" className="muted">
              Updating token…
            </p>
          )}
        </>
      )}
    </dialog>
  );
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isLockError(err: unknown): boolean {
  return (err as { code?: unknown } | null)?.code === "locked";
}
