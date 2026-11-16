import { createContext, type KeyboardEvent as ReactKeyboardEvent, useCallback, useContext, useEffect, useRef, useState } from "react";
import { encodeBase64, formatBytes, parseDotenv, toDotenv } from "../format";
import { Icon } from "../icons";
import { emptyBody, KIND_LABEL, type SecretBody, type SecretKind, type SecretView } from "../protocol";

export interface Draft {
  title: string;
  folder: string;
  tags: string[];
  urls: string[];
  basicAuth: boolean;
  body: SecretBody;
}

export function draftOf(view: SecretView): Draft {
  return {
    title: view.meta.title,
    folder: view.meta.folder,
    tags: view.meta.tags ?? [],
    urls: view.meta.urls ?? [],
    basicAuth: !!view.meta.basic_auth,
    body: structuredClone(view.body),
  };
}

export function newDraft(kind: SecretKind, folder: string): Draft {
  return { title: "", folder, tags: [], urls: [], basicAuth: false, body: emptyBody(kind) };
}

interface Props {
  kind: SecretKind;
  initial: Draft;
  isNew: boolean;
  folders: string[];
  save: (draft: Draft) => Promise<void>;
  cancel: () => void;
}

/**
 * Fields tell the editor what stops the draft from being saved as shown: a
 * half-typed date, a line that is not KEY=value, a file still being read.
 * Save then explains instead of storing something other than what is on screen.
 */
type Report = (field: string, problem: string | null) => void;
const Problems = createContext<Report>(() => undefined);

function useProblem(field: string, problem: string | null) {
  const report = useContext(Problems);
  useEffect(() => {
    report(field, problem);
    return () => report(field, null);
  }, [report, field, problem]);
}

export function Editor({ kind, initial, isNew, folders, save, cancel }: Props) {
  const [problems, setProblems] = useState<Record<string, string>>({});
  const report = useCallback<Report>((field, problem) => {
    setProblems((old) => {
      if ((old[field] ?? null) === problem) return old;
      const next = { ...old };
      if (problem) next[field] = problem;
      else delete next[field];
      return next;
    });
  }, []);
  const [draft, setDraft] = useState(initial);
  const [saving, setSaving] = useState(false);
  // Set at once, unlike state, so a second ⌘S during a save is ignored.
  const inFlight = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const titleRef = useRef<HTMLInputElement>(null);
  const set: SetDraft = (patch) => setDraft((d) => ({ ...d, ...(typeof patch === "function" ? patch(d) : patch) }));

  useEffect(() => {
    if (isNew) titleRef.current?.focus();
  }, [isNew]);

  async function submit() {
    if (inFlight.current) return;
    const problem = Object.values(problems)[0];
    if (problem) {
      setError(problem);
      return;
    }
    if (!draft.title.trim()) {
      setError("Give it a title.");
      titleRef.current?.focus();
      return;
    }
    inFlight.current = true;
    setSaving(true);
    setError(null);
    try {
      await save({ ...draft, title: draft.title.trim(), folder: draft.folder.trim().replace(/^\/+|\/+$/g, "") });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setSaving(false);
      inFlight.current = false;
    }
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        cancel();
      } else if ((e.metaKey || e.ctrlKey) && (e.key === "s" || e.key === "Enter")) {
        e.preventDefault();
        void submit();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  return (
    <article className="detail editing">
      <header className="detail-head" data-tauri-drag-region>
        <div className="detail-titles">
          <div className="eyebrow">{isNew ? `New ${KIND_LABEL[kind].toLowerCase()}` : `Editing ${KIND_LABEL[kind].toLowerCase()}`}</div>
          <input
            ref={titleRef}
            className="title-input"
            value={draft.title}
            placeholder="Title"
            onChange={(e) => set({ title: e.target.value })}
          />
        </div>
        <div className="detail-actions">
          <button className="btn" onClick={cancel}>
            Cancel
          </button>
          <button className="btn primary" disabled={saving} onClick={() => void submit()} title="Save (⌘S)">
            <Icon name="check" size={14} /> Save
          </button>
        </div>
      </header>
      <div className="detail-scroll">
        {error && <p className="error">{error}</p>}
        <div className="form-grid">
          <label className="form-field">
            <span>Folder</span>
            <input list="silo-folders" value={draft.folder} placeholder="e.g. projects/wallet" onChange={(e) => set({ folder: e.target.value })} />
            <datalist id="silo-folders">
              {folders.map((f) => (
                <option key={f} value={f} />
              ))}
            </datalist>
          </label>
          <div className="form-field">
            <span>Tags</span>
            <TagInput tags={draft.tags} onChange={(tags) => set({ tags })} />
          </div>
        </div>

        <Problems.Provider value={report}>
          <BodyEditor draft={draft} set={set} />
        </Problems.Provider>
      </div>
    </article>
  );
}

/** A patch, or a function of the latest draft for changes that land later (a file read). */
type SetDraft = (patch: Partial<Draft> | ((draft: Draft) => Partial<Draft>)) => void;

function BodyEditor({ draft, set }: { draft: Draft; set: SetDraft }) {
  const { body } = draft;
  if ("login" in body) {
    const login = body.login;
    const put = (patch: Partial<typeof login>) => set({ body: { login: { ...login, ...patch } } });
    return (
      <>
        <div className="form-grid">
          <TextField label="Username" value={login.username} onChange={(username) => put({ username })} />
          <PasswordField value={login.password} onChange={(password) => put({ password })} />
          <TextField label="One-time code seed" value={login.totp ?? ""} placeholder="Base32 or otpauth://" mono onChange={(v) => put({ totp: v || null })} />
        </div>
        <label className="form-field">
          <span>Websites, one per line</span>
          <textarea
            rows={Math.max(2, draft.urls.length + 1)}
            className="mono"
            value={draft.urls.join("\n")}
            placeholder="https://example.com or https://*.staging.example.com"
            onChange={(e) => set({ urls: e.target.value.split("\n") })}
            onBlur={() => set({ urls: draft.urls.map((u) => u.trim()).filter(Boolean) })}
          />
        </label>
        <label className="check">
          <input type="checkbox" checked={draft.basicAuth} onChange={(e) => set({ basicAuth: e.target.checked })} />
          Answer HTTP Basic Auth on these websites
        </label>
        <TextArea label="Notes" value={login.notes} onChange={(notes) => put({ notes })} />
      </>
    );
  }
  if ("card" in body) {
    const card = body.card;
    const put = (patch: Partial<typeof card>) => set({ body: { card: { ...card, ...patch } } });
    return (
      <>
        <div className="form-grid">
          <TextField label="Number" value={card.number} mono onChange={(number) => put({ number: number.replace(/[^\d ]/g, "") })} />
          <TextField label="Holder" value={card.holder} onChange={(holder) => put({ holder })} />
          <ExpiryField month={card.expiry_month} year={card.expiry_year} onChange={(expiry_month, expiry_year) => put({ expiry_month, expiry_year })} />
          <TextField label="Security code" value={card.cvv} mono onChange={(cvv) => put({ cvv: cvv.replace(/\D/g, "") })} />
        </div>
        <TextArea label="Notes" value={card.notes} onChange={(notes) => put({ notes })} />
      </>
    );
  }
  if ("env_set" in body) return <EnvEditor vars={body.env_set.vars} onChange={(vars) => set({ body: { env_set: { vars } } })} />;
  if ("file" in body) return <FileEditor file={body.file} onChange={(file) => set((d) => ({ body: { file }, title: d.title || file.name }))} />;
  return <TextArea label="Text" value={body.note.text} rows={14} onChange={(text) => set({ body: { note: { text } } })} />;
}

/* ---------- inputs ---------- */

function TextField({
  label,
  value,
  onChange,
  placeholder,
  mono,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  mono?: boolean;
}) {
  return (
    <label className="form-field">
      <span>{label}</span>
      <input className={mono ? "mono" : undefined} value={value} placeholder={placeholder} spellCheck={false} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

/**
 * MM/YY typed freely: the text stays as typed, and the card only changes once
 * it reads as a full date (or is cleared), so partial input is never rewritten.
 */
function ExpiryField({ month, year, onChange }: { month: number; year: number; onChange: (month: number, year: number) => void }) {
  const [text, setText] = useState(month ? `${String(month).padStart(2, "0")}/${String(year).slice(-2)}` : "");
  const parsed = parseExpiry(text);
  useProblem("expiry", parsed ? null : "Expiry must be MM/YY, or left empty.");
  return (
    <label className="form-field">
      <span>Expiry (MM/YY)</span>
      <input
        className={`mono${parsed ? "" : " invalid"}`}
        value={text}
        placeholder="08/29"
        spellCheck={false}
        onChange={(e) => {
          setText(e.target.value);
          const next = parseExpiry(e.target.value);
          if (next) onChange(next.month, next.year);
        }}
      />
    </label>
  );
}

/** `{0, 0}` for an empty field, null while it is not a date yet. */
function parseExpiry(text: string): { month: number; year: number } | null {
  if (!text.trim()) return { month: 0, year: 0 };
  const match = /^\s*(\d{1,2})\s*\/\s*(\d{2}|\d{4})\s*$/.exec(text);
  if (!match) return null;
  const month = Number(match[1]);
  const year = Number(match[2]);
  if (month < 1 || month > 12) return null;
  return { month, year: year < 100 ? 2000 + year : year };
}

function TextArea({ label, value, onChange, rows = 4 }: { label: string; value: string; onChange: (value: string) => void; rows?: number }) {
  return (
    <label className="form-field">
      <span>{label}</span>
      <textarea rows={rows} value={value} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

function PasswordField({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const [shown, setShown] = useState(false);
  return (
    <label className="form-field">
      <span>Password</span>
      <span className="input-with-actions">
        <input className="mono" type={shown ? "text" : "password"} value={value} spellCheck={false} onChange={(e) => onChange(e.target.value)} />
        <button type="button" className="icon-btn small" title={shown ? "Hide" : "Reveal"} onClick={() => setShown(!shown)}>
          <Icon name={shown ? "eyeOff" : "eye"} size={14} />
        </button>
        <button
          type="button"
          className="icon-btn small"
          title="Generate"
          onClick={() => {
            onChange(randomPassword());
            setShown(true);
          }}
        >
          <Icon name="sparkle" size={14} />
        </button>
      </span>
    </label>
  );
}

function TagInput({ tags, onChange }: { tags: string[]; onChange: (tags: string[]) => void }) {
  const [text, setText] = useState("");
  const commit = () => {
    const tag = text.trim().replace(/^#/, "");
    if (tag && !tags.includes(tag)) onChange([...tags, tag]);
    setText("");
  };
  const onKey = (e: ReactKeyboardEvent) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit();
    } else if (e.key === "Backspace" && !text && tags.length) {
      onChange(tags.slice(0, -1));
    }
  };
  return (
    <span className="tag-input">
      {tags.map((tag) => (
        <span key={tag} className="chip small">
          {tag}
          <button type="button" onClick={() => onChange(tags.filter((t) => t !== tag))} aria-label={`Remove ${tag}`}>
            <Icon name="close" size={10} />
          </button>
        </span>
      ))}
      <input value={text} placeholder={tags.length ? "" : "Add tag"} onChange={(e) => setText(e.target.value)} onKeyDown={onKey} onBlur={commit} />
    </span>
  );
}

function EnvEditor({ vars, onChange }: { vars: { key: string; value: string }[]; onChange: (vars: { key: string; value: string }[]) => void }) {
  const [asText, setAsText] = useState(false);
  const [text, setText] = useState("");
  const bad = asText ? parseDotenv(text).bad : [];
  const unnamed = asText ? -1 : vars.findIndex((v) => !v.key.trim() && v.value);
  const problem = bad.length
    ? `.env line ${bad.join(", ")} is not KEY=value.`
    : unnamed >= 0
      ? `Variable ${unnamed + 1} has a value but no name.`
      : null;
  useProblem("env", problem);
  const put = (i: number, patch: Partial<{ key: string; value: string }>) => onChange(vars.map((v, j) => (j === i ? { ...v, ...patch } : v)));

  return (
    <div className="form-field">
      <span className="env-editor-head">
        Variables
        <span className="segmented">
          <button
            type="button"
            className={asText ? "" : "on"}
            disabled={bad.length > 0}
            title={bad.length ? (problem ?? undefined) : undefined}
            onClick={() => asText && (onChange(parseDotenv(text).vars), setAsText(false))}
          >
            <Icon name="table" size={13} /> Table
          </button>
          <button
            type="button"
            className={asText ? "on" : ""}
            disabled={unnamed >= 0}
            title={unnamed >= 0 ? (problem ?? undefined) : undefined}
            onClick={() => !asText && (setText(toDotenv(vars)), setAsText(true))}
          >
            <Icon name="text" size={13} /> .env
          </button>
        </span>
      </span>
      {asText ? (
        <textarea
          className="mono"
          rows={Math.max(8, text.split("\n").length + 1)}
          value={text}
          placeholder={"KEY=value\nOTHER=\"with spaces\""}
          spellCheck={false}
          onChange={(e) => {
            setText(e.target.value);
            onChange(parseDotenv(e.target.value).vars);
          }}
        />
      ) : (
        <div className="env-table editing">
          {vars.map((v, i) => (
            <div className="env-row" key={i}>
              <input className="env-key mono" value={v.key} placeholder="KEY" spellCheck={false} onChange={(e) => put(i, { key: e.target.value })} />
              <input
                className="env-value mono"
                value={v.value}
                placeholder="value"
                spellCheck={false}
                onChange={(e) => put(i, { value: e.target.value })}
                onPaste={(e) => {
                  const pasted = e.clipboardData.getData("text");
                  const { vars: parsed, bad: unparsed } = parseDotenv(pasted);
                  // Split only a paste that is wholly .env; anything else goes in as typed.
                  if (parsed.length > 1 && unparsed.length === 0) {
                    e.preventDefault();
                    onChange([...vars.slice(0, i), ...parsed, ...vars.slice(i + 1)].filter((x) => x.key || x.value));
                  }
                }}
              />
              <button type="button" className="icon-btn small" title="Remove" onClick={() => onChange(vars.filter((_, j) => j !== i))}>
                <Icon name="close" size={13} />
              </button>
            </div>
          ))}
          <button type="button" className="btn ghost add-row" onClick={() => onChange([...vars, { key: "", value: "" }])}>
            <Icon name="plus" size={14} /> Add variable
          </button>
        </div>
      )}
      {problem ? <span className="hint warn">{problem}</span> : <span className="hint">Paste a whole .env into any value to split it into rows.</span>}
    </div>
  );
}

function FileEditor({ file, onChange }: { file: { name: string; mime: string | null; data: string }; onChange: (file: { name: string; mime: string | null; data: string }) => void }) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const size = file.data ? Math.floor((file.data.length * 3) / 4) : 0;
  const [reading, setReading] = useState<string | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  // Only the latest pick may land; an earlier, slower read is dropped.
  const latest = useRef(0);
  useProblem("file", reading ? `Still reading ${reading}…` : failed);

  async function take(f: File | undefined) {
    if (!f) return;
    const pick = ++latest.current;
    setReading(f.name);
    setFailed(null);
    try {
      const data = encodeBase64(new Uint8Array(await f.arrayBuffer()));
      if (pick === latest.current) onChange({ name: f.name, mime: f.type || null, data });
    } catch (err) {
      if (pick === latest.current) setFailed(`Could not read ${f.name}: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      if (pick === latest.current) setReading(null);
    }
  }

  return (
    <div
      className={`drop${over ? " over" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        void take(e.dataTransfer.files[0]);
      }}
      onClick={() => input.current?.click()}
    >
      <Icon name="upload" size={20} />
      {reading ? (
        <span>Reading {reading}…</span>
      ) : failed ? (
        <span className="warn">{failed}</span>
      ) : file.data ? (
        <span>
          <strong>{file.name}</strong> · {formatBytes(size)}
          <br />
          <span className="muted">Drop or click to replace</span>
        </span>
      ) : (
        <span>Drop a file here or click to choose</span>
      )}
      <input ref={input} type="file" hidden onChange={(e) => void take(e.target.files?.[0])} />
    </div>
  );
}

function randomPassword(): string {
  const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@#$%*+=?";
  const out: string[] = [];
  const buf = new Uint32Array(1);
  while (out.length < 20) {
    crypto.getRandomValues(buf);
    const n = buf[0]!;
    if (n < Math.floor(0x1_0000_0000 / alphabet.length) * alphabet.length) out.push(alphabet[n % alphabet.length]!);
  }
  return out.join("");
}
