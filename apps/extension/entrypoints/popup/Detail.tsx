import { type ReactNode, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Avatar } from "@/components/Avatar";
import { Icon } from "@/components/Icon";
import { call } from "@/lib/client";
import type { SecretSummary, SecretView } from "@/lib/protocol";
import { isBasicAuth, secretPath } from "@/lib/protocol";
import { hostsOf } from "@/lib/search";
import { errorText } from "@/lib/util";
import type { Copy } from "./App";
import { KIND_LABEL, KindIcon } from "./VaultList";

interface Props {
  id: string;
  /** The item as the list knows it: shown while loading, and if its body cannot be. */
  summary: SecretSummary | null;
  /** The login matches the tab, so the page can fill it. */
  canFill: boolean;
  copy: Copy;
  back: () => void;
  edit: () => void;
  fill: () => void;
}

export function Detail({ id, summary, canFill, copy, back, edit, fill }: Props) {
  const [view, setView] = useState<SecretView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setView(null);
    setError(null);
    call({ method: "get", params: { selector: id } })
      .then((reply) => {
        if (typeof reply === "object" && "secret" in reply) setView(reply.secret);
        else setError("Unexpected reply from the agent.");
      })
      .catch((err: unknown) => {
        const message = errorText(err);
        // The native host refuses replies over 1 MiB: a big file, say.
        setError(
          message.includes("native messaging limit")
            ? "Too large to open in the browser. Use the silo CLI, e.g. silo file pull."
            : message,
        );
      });
  }, [id]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" || (event.key === "Backspace" && !(event.target instanceof HTMLInputElement))) {
        event.preventDefault();
        back();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [back]);

  const editable = view?.meta.kind === "login";
  const item = view ?? summary;

  return (
    <div className="screen">
      <div className="subbar">
        <button className="icon-button" title="Back (Esc)" onClick={back}>
          <Icon name="back" />
        </button>
        <span className="spacer" />
        {editable && (
          <button className="ghost small" onClick={edit}>
            <Icon name="edit" size={14} />
            Edit
          </button>
        )}
      </div>
      {!item && error && <p className="notice error">{error}</p>}
      {item && (
        <div className="detail">
          <div className="detail-head">
            {item.meta.kind === "login" ? (
              <Avatar large label={hostsOf(item.meta)[0] ?? item.meta.title} />
            ) : (
              <KindIcon large kind={item.meta.kind} />
            )}
            <div className="detail-title">
              <h2>{item.meta.title}</h2>
              <span className="muted">
                {item.meta.folder ? (
                  <>
                    <Icon name="folder" size={12} /> {item.meta.folder}
                  </>
                ) : (
                  KIND_LABEL[item.meta.kind]
                )}
              </span>
            </div>
          </div>
          {view ? (
            <Body view={view} copy={copy} />
          ) : error ? (
            <p className="notice error">{error}</p>
          ) : (
            <p className="muted">Loading…</p>
          )}
          <Meta item={item} />
        </div>
      )}
      {view && canFill && (
        <div className="footer">
          <button className="primary wide" onClick={fill}>
            <Icon name="fill" size={15} />
            Fill on this page
          </button>
        </div>
      )}
    </div>
  );
}

function Body({ view, copy }: { view: SecretView; copy: Copy }) {
  const { body } = view;
  if ("login" in body) {
    const { username, password, totp, notes } = body.login;
    return (
      <div className="fields">
        <Field label="Username" value={username} copy={copy} />
        <Field label="Password" value={password} secret mono copy={copy} />
        {totp && <Field label="One-time code secret" value={totp} secret mono copy={copy} />}
        <Websites urls={view.meta.urls ?? []} />
        {notes && <Field label="Notes" value={notes} multiline copy={copy} />}
      </div>
    );
  }
  if ("card" in body) {
    const card = body.card;
    const expiry = `${String(card.expiry_month).padStart(2, "0")}/${String(card.expiry_year).slice(-2)}`;
    return (
      <div className="fields">
        <Field label="Cardholder" value={card.holder} copy={copy} />
        <Field label="Number" value={card.number} secret mono copy={copy} hint={`•••• ${card.number.slice(-4)}`} />
        <Field label="Expires" value={expiry} copy={copy} />
        <Field label="Security code" value={card.cvv} secret mono copy={copy} />
        {card.notes && <Field label="Notes" value={card.notes} multiline copy={copy} />}
      </div>
    );
  }
  if ("env_set" in body) {
    const dotenv = body.env_set.vars.map((v) => `${v.key}=${v.value}`).join("\n");
    return (
      <div className="fields">
        {body.env_set.vars.map((v) => (
          <Field key={v.key} label={v.key} value={v.value} secret mono copy={copy} />
        ))}
        <button className="small" onClick={() => copy(dotenv, ".env")}>
          <Icon name="copy" size={14} />
          Copy all as .env
        </button>
      </div>
    );
  }
  if ("note" in body) {
    return (
      <div className="fields">
        <Field label="Note" value={body.note.text} secret multiline copy={copy} />
      </div>
    );
  }
  const { file } = body;
  return (
    <div className="fields">
      <Field label="File name" value={file.name} copy={copy} />
      <div className="field-row">
        <span className="field-label">Size</span>
        <span>{size(file.data)}</span>
        <button className="small" onClick={() => download(file.name, file.mime, file.data)}>
          Download
        </button>
      </div>
    </div>
  );
}

interface FieldProps {
  label: string;
  value: string;
  copy: Copy;
  secret?: boolean;
  mono?: boolean;
  multiline?: boolean;
  /** Shown instead of dots while hidden. */
  hint?: string;
}

function Field({ label, value, copy, secret = false, mono = false, multiline = false, hint }: FieldProps) {
  const [shown, setShown] = useState(!secret);
  const display = shown ? value || "—" : (hint ?? "••••••••••••");
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      <span
        className={["field-value", mono && shown ? "mono" : "", multiline ? "multiline" : "", value ? "" : "muted"].join(" ")}
        title={shown ? undefined : "Hidden"}
      >
        {display}
      </span>
      <span className="field-actions">
        {secret && (
          <button className="icon-button" title={shown ? "Hide" : "Show"} onClick={() => setShown(!shown)}>
            <Icon name={shown ? "eyeOff" : "eye"} size={15} />
          </button>
        )}
        {value && (
          <button className="icon-button" title={`Copy ${label.toLowerCase()}`} onClick={() => copy(value, label)}>
            <Icon name="copy" size={15} />
          </button>
        )}
      </span>
    </div>
  );
}

function Websites({ urls }: { urls: string[] }) {
  if (urls.length === 0) return null;
  return (
    <div className="field-row">
      <span className="field-label">{urls.length === 1 ? "Website" : "Websites"}</span>
      <span className="field-value">
        {urls.map((url) => (
          <Website key={url} pattern={url} />
        ))}
      </span>
    </div>
  );
}

/** A URL pattern, as a link when it names one page (no wildcard). */
function Website({ pattern }: { pattern: string }) {
  const href = pattern.includes("*") ? null : pattern.includes("://") ? pattern : `https://${pattern}`;
  const label = pattern.replace(/^https:\/\//, "").replace(/\/$/, "");
  if (!href || !/^https?:/.test(href)) return <span className="url">{label}</span>;
  return (
    <a
      className="url"
      href={href}
      onClick={(e) => {
        e.preventDefault();
        void browser.tabs.create({ url: href });
        window.close();
      }}
    >
      {label}
      <Icon name="external" size={12} />
    </a>
  );
}

function Meta({ item }: { item: SecretSummary }) {
  const items: ReactNode[] = [];
  for (const tag of item.meta.tags ?? []) items.push(<span key={`t-${tag}`} className="badge">#{tag}</span>);
  if (isBasicAuth(item.meta)) items.push(<span key="basic" className="badge accent">Basic Auth</span>);
  return (
    <div className="meta">
      {items.length > 0 && <div className="tags">{items}</div>}
      <span className="muted" title={secretPath(item.meta)}>
        Updated {new Date(item.meta.updated_at * 1000).toLocaleString()} · revision {item.revision}
      </span>
    </div>
  );
}

function size(base64: string): string {
  const bytes = Math.floor((base64.length * 3) / 4) - (base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function download(name: string, mime: string | null, base64: string) {
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: mime ?? "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
