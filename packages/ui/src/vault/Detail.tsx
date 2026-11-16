import { type ReactNode, useEffect, useMemo, useState } from "react";
import type { VaultClient } from "../client";
import {
  asText,
  cardBrand,
  decodeBase64,
  formatBytes,
  groupCardNumber,
  maskCardNumber,
  timeAgo,
  toDotenv,
  totp,
} from "../format";
import { Icon } from "../icons";
import type { Card, EnvVar, FileBody, Login, SecretSummary, SecretView } from "../protocol";
import { ItemAvatar } from "./ItemList";

export type Copy = (text: string, what: string) => void;

interface Props {
  client: VaultClient;
  summary: SecretSummary;
  copy: Copy;
  edit: (view: SecretView) => void;
  remove: () => void;
  openFolder: (path: string) => void;
  openTag: (tag: string) => void;
  /** The agent locked itself (timeout, `silo lock`). */
  locked: () => void;
}

export function Detail({ client, summary, copy, edit, remove, openFolder, openTag, locked }: Props) {
  const [view, setView] = useState<SecretView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [history, setHistory] = useState<SecretView[] | null>(null);

  useEffect(() => {
    let live = true;
    setView(null);
    setError(null);
    setConfirm(false);
    setHistory(null);
    client.get(summary.id).then(
      (v) => live && setView(v),
      (e: unknown) => {
        if (!live) return;
        if ((e as { code?: unknown }).code === "locked") locked();
        else setError(e instanceof Error ? e.message : String(e));
      },
    );
    return () => {
      live = false;
    };
  }, [client, summary.id, summary.revision, locked]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "e" && view) {
        e.preventDefault();
        edit(view);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [view, edit]);

  const meta = view?.meta ?? summary.meta;
  const segments = meta.folder ? meta.folder.split("/") : [];

  return (
    <article className="detail">
      <header className="detail-head" data-tauri-drag-region>
        <ItemAvatar item={summary} large />
        <div className="detail-titles">
          <h1>{meta.title}</h1>
          <div className="crumbs">
            {segments.length === 0 && <span className="muted">No folder</span>}
            {segments.map((segment, i) => (
              <span key={i}>
                {i > 0 && <span className="crumb-sep">/</span>}
                <button className="crumb" onClick={() => openFolder(segments.slice(0, i + 1).join("/"))}>
                  {segment}
                </button>
              </span>
            ))}
            {(meta.tags ?? []).map((tag) => (
              <button key={tag} className="chip small" onClick={() => openTag(tag)}>
                {tag}
              </button>
            ))}
          </div>
        </div>
        <div className="detail-actions">
          {confirm ? (
            <>
              <span className="muted">Delete?</span>
              <button className="btn" onClick={() => setConfirm(false)}>
                Cancel
              </button>
              <button className="btn danger" onClick={remove}>
                Delete
              </button>
            </>
          ) : (
            <>
              <button className="icon-btn" title="Delete" onClick={() => setConfirm(true)}>
                <Icon name="trash" size={15} />
              </button>
              <button className="btn" disabled={!view} onClick={() => view && edit(view)} title="Edit (⌘E)">
                <Icon name="edit" size={14} /> Edit
              </button>
            </>
          )}
        </div>
      </header>

      <div className="detail-scroll">
        {error && <p className="error">{error}</p>}
        {!view && !error && <div className="skeleton" />}
        {view && <Body view={view} copy={copy} />}

        {view && (
          <footer className="detail-foot">
            <span>
              Revision {view.revision} · edited {timeAgo(view.meta.updated_at)}
            </span>
            {view.revision > 1 && (
              <button
                className="link"
                onClick={() => (history ? setHistory(null) : client.history(view.id).then(setHistory, () => setHistory([])))}
              >
                <Icon name="history" size={13} /> {history ? "Hide history" : "History"}
              </button>
            )}
          </footer>
        )}
        {history && (
          <ul className="history">
            {history.length === 0 && <li className="muted">No earlier revisions.</li>}
            {history.map((rev) => (
              <li key={rev.revision}>
                <span>Revision {rev.revision}</span>
                <span className="muted">{timeAgo(rev.meta.updated_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </article>
  );
}

function Body({ view, copy }: { view: SecretView; copy: Copy }) {
  const { body } = view;
  if ("login" in body) return <LoginView login={body.login} urls={view.meta.urls ?? []} basicAuth={!!view.meta.basic_auth} copy={copy} />;
  if ("card" in body) return <CardView card={body.card} copy={copy} />;
  if ("env_set" in body) return <EnvView vars={body.env_set.vars} path={view.meta.folder ? `${view.meta.folder}/${view.meta.title}` : view.meta.title} copy={copy} />;
  if ("file" in body) return <FileView file={body.file} copy={copy} />;
  return <NoteView text={body.note.text} copy={copy} />;
}

/* ---------- fields ---------- */

export function Field({
  label,
  value,
  secret = false,
  mono = false,
  copy,
  display,
  extra,
}: {
  label: string;
  value: string;
  secret?: boolean;
  mono?: boolean;
  copy?: Copy;
  /** Shown instead of `value` while hidden or always, e.g. a grouped card number. */
  display?: string;
  extra?: ReactNode;
}) {
  const [shown, setShown] = useState(false);
  useEffect(() => setShown(false), [value]);
  if (!value) return null;
  const text = secret && !shown ? "•".repeat(Math.min(16, Math.max(8, value.length))) : (display ?? value);
  return (
    <div className="field">
      <div className="field-label">{label}</div>
      <div className="field-row">
        <span className={`field-value${mono || secret ? " mono" : ""}${secret && !shown ? " masked" : ""}`}>{text}</span>
        {extra}
        {secret && (
          <button className="icon-btn small" title={shown ? "Hide" : "Reveal"} onClick={() => setShown(!shown)}>
            <Icon name={shown ? "eyeOff" : "eye"} size={14} />
          </button>
        )}
        {copy && (
          <button className="icon-btn small" title={`Copy ${label.toLowerCase()}`} onClick={() => copy(value, label)}>
            <Icon name="copy" size={14} />
          </button>
        )}
      </div>
    </div>
  );
}

function Fields({ children }: { children: ReactNode }) {
  return <div className="fields">{children}</div>;
}

/* ---------- kinds ---------- */

function LoginView({ login, urls, basicAuth, copy }: { login: Login; urls: string[]; basicAuth: boolean; copy: Copy }) {
  return (
    <>
      <Fields>
        <Field label="Username" value={login.username} copy={copy} />
        <Field label="Password" value={login.password} secret copy={copy} />
        {login.totp && <TotpField seed={login.totp} copy={copy} />}
      </Fields>
      {urls.length > 0 && (
        <Fields>
          <div className="field">
            <div className="field-label">
              Websites {basicAuth && <span className="badge">Basic Auth</span>}
            </div>
            {urls.map((url) => (
              <div className="field-row" key={url}>
                <span className="field-value">{url}</span>
                {!url.includes("*") && (
                  <a className="icon-btn small" href={url.includes("://") ? url : `https://${url}`} target="_blank" rel="noreferrer" title="Open">
                    <Icon name="external" size={14} />
                  </a>
                )}
              </div>
            ))}
          </div>
        </Fields>
      )}
      {login.notes && <NoteView text={login.notes} label="Notes" />}
    </>
  );
}

function TotpField({ seed, copy }: { seed: string; copy: Copy }) {
  const [now, setNow] = useState(Date.now());
  const [code, setCode] = useState<Awaited<ReturnType<typeof totp>>>(null);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    void totp(seed, now).then(setCode);
  }, [seed, now]);
  if (!code) return <Field label="One-time code" value="Invalid seed" />;
  const half = Math.ceil(code.code.length / 2);
  const pretty = `${code.code.slice(0, half)} ${code.code.slice(half)}`;
  return (
    <Field
      label="One-time code"
      value={code.code}
      display={pretty}
      mono
      copy={copy}
      extra={
        <span className={`totp-timer${code.remaining <= 5 ? " low" : ""}`} title={`${code.remaining}s left`}>
          <svg viewBox="0 0 20 20" width="18" height="18">
            <circle cx="10" cy="10" r="8" className="track" />
            <circle cx="10" cy="10" r="8" className="arc" strokeDasharray={`${(code.remaining / code.period) * 50.3} 50.3`} />
          </svg>
          {code.remaining}
        </span>
      }
    />
  );
}

function CardView({ card, copy }: { card: Card; copy: Copy }) {
  const [shown, setShown] = useState(false);
  const brand = cardBrand(card.number);
  const expiry = card.expiry_month ? `${String(card.expiry_month).padStart(2, "0")}/${String(card.expiry_year).slice(-2)}` : "";
  return (
    <>
      <button className={`card-visual${shown ? " shown" : ""}`} onClick={() => setShown(!shown)} title={shown ? "Hide" : "Reveal"}>
        <span className="card-brand">{brand ?? "Card"}</span>
        <span className="card-number">{shown ? groupCardNumber(card.number) : maskCardNumber(card.number)}</span>
        <span className="card-bottom">
          <span>{card.holder}</span>
          <span>{expiry}</span>
        </span>
      </button>
      <Fields>
        <Field label="Number" value={card.number.replace(/\D/g, "")} display={groupCardNumber(card.number)} secret copy={copy} />
        <Field label="Expiry" value={expiry} mono copy={copy} />
        <Field label="Security code" value={card.cvv} secret copy={copy} />
        <Field label="Holder" value={card.holder} copy={copy} />
      </Fields>
      {card.notes && <NoteView text={card.notes} label="Notes" />}
    </>
  );
}

function EnvView({ vars, path, copy }: { vars: EnvVar[]; path: string; copy: Copy }) {
  const [shown, setShown] = useState(false);
  const run = `silo run ${path} -- `;
  return (
    <>
      <div className="env-toolbar">
        <span className="muted">{vars.length} variables</span>
        <span className="spacer" />
        <button className="btn ghost" onClick={() => setShown(!shown)}>
          <Icon name={shown ? "eyeOff" : "eye"} size={14} /> {shown ? "Hide" : "Reveal"}
        </button>
        <button className="btn ghost" onClick={() => copy(toDotenv(vars), ".env")}>
          <Icon name="copy" size={14} /> Copy .env
        </button>
      </div>
      <div className="env-table">
        {vars.map((v, i) => (
          <div className="env-row" key={`${v.key}-${i}`}>
            <span className="env-key">{v.key}</span>
            <span className={`env-value mono${shown ? "" : " masked"}`}>{shown ? v.value : "••••••••••••"}</span>
            <button className="icon-btn small" title={`Copy ${v.key}`} onClick={() => copy(v.value, v.key)}>
              <Icon name="copy" size={14} />
            </button>
          </div>
        ))}
      </div>
      <button className="cli-hint" onClick={() => copy(run, "command")} title="Copy command">
        <Icon name="terminal" size={14} />
        <code>{run}&lt;command&gt;</code>
      </button>
    </>
  );
}

function FileView({ file, copy }: { file: FileBody; copy: Copy }) {
  const bytes = useMemo(() => decodeBase64(file.data), [file.data]);
  const isImage = (file.mime ?? "").startsWith("image/");
  const text = useMemo(() => (isImage ? null : asText(bytes)), [bytes, isImage]);
  const [url, setUrl] = useState<string | null>(null);

  useEffect(() => {
    const blob = new Blob([bytes as Uint8Array<ArrayBuffer>], { type: file.mime ?? "application/octet-stream" });
    const next = URL.createObjectURL(blob);
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [bytes, file.mime]);

  return (
    <>
      <div className="file-meta">
        <Icon name="file" size={16} />
        <span className="file-name">{file.name}</span>
        <span className="muted">
          {file.mime ?? (text !== null ? "text" : "binary")} · {formatBytes(bytes.length)}
        </span>
        <span className="spacer" />
        {text !== null && (
          <button className="btn ghost" onClick={() => copy(text, "contents")}>
            <Icon name="copy" size={14} /> Copy
          </button>
        )}
        {url && (
          <a className="btn ghost" href={url} download={file.name}>
            <Icon name="download" size={14} /> Download
          </a>
        )}
      </div>
      <div className="file-preview">
        {isImage && url && <img src={url} alt={file.name} />}
        {!isImage && text !== null && <pre>{text}</pre>}
        {!isImage && text === null && <p className="muted">Binary file, no preview.</p>}
      </div>
    </>
  );
}

function NoteView({ text, label, copy }: { text: string; label?: string; copy?: Copy }) {
  return (
    <div className="note">
      {(label || copy) && (
        <div className="field-label note-head">
          {label ?? ""}
          {copy && (
            <button className="icon-btn small" title="Copy note" onClick={() => copy(text, "note")}>
              <Icon name="copy" size={14} />
            </button>
          )}
        </div>
      )}
      <div className="note-text">{text}</div>
    </div>
  );
}
