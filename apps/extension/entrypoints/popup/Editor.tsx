import { type FormEvent, useEffect, useState } from "react";
import { Icon } from "@/components/Icon";
import { AgentFailure, call } from "@/lib/client";
import { type GeneratorStyle, generate, strength } from "@/lib/generate";
import type { SecretSummary, SecretView } from "@/lib/protocol";
import { errorText } from "@/lib/util";
import type { Tab } from "./App";

interface Props {
  /** The login to edit; null adds one, for the tab's site when there is one. */
  id: string | null;
  tab: Tab | null;
  /** Existing folders, offered as suggestions. */
  folders: string[];
  cancel: () => void;
  saved: (summary: SecretSummary) => void;
}

interface Draft {
  title: string;
  folder: string;
  username: string;
  password: string;
  /** One URL pattern per line. */
  urls: string;
  notes: string;
  /** Comma or space separated. */
  tags: string;
  basicAuth: boolean;
}

function draftFor(view: SecretView): Draft {
  const login = "login" in view.body ? view.body.login : null;
  return {
    title: view.meta.title,
    folder: view.meta.folder,
    username: login?.username ?? "",
    password: login?.password ?? "",
    urls: (view.meta.urls ?? []).join("\n"),
    notes: login?.notes ?? "",
    tags: (view.meta.tags ?? []).join(", "),
    basicAuth: view.meta.basic_auth === true,
  };
}

function newDraft(tab: Tab | null): Draft {
  const host = tab?.host ?? "";
  return {
    title: host,
    folder: "web",
    username: "",
    password: "",
    urls: host && tab ? new URL(tab.url).origin : "",
    notes: "",
    tags: "",
    basicAuth: false,
  };
}

export function Editor({ id, tab, folders, cancel, saved }: Props) {
  const [view, setView] = useState<SecretView | null>(null);
  const [draft, setDraft] = useState<Draft | null>(id ? null : newDraft(tab));
  const [shown, setShown] = useState(false);
  const [bits, setBits] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!id) return;
    call({ method: "get", params: { selector: id } })
      .then((reply) => {
        if (typeof reply !== "object" || !("secret" in reply)) throw new Error("Unexpected reply from the agent.");
        setView(reply.secret);
        setDraft(draftFor(reply.secret));
      })
      .catch((err: unknown) => setError(errorText(err)));
  }, [id]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        cancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [cancel]);

  if (!draft) {
    return (
      <div className="screen">
        <EditorBar title="Edit login" cancel={cancel} />
        {error ? <p className="notice error">{error}</p> : <p className="center muted">Loading…</p>}
      </div>
    );
  }

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft({ ...draft, [key]: value });

  function suggest(style: GeneratorStyle) {
    const generated = generate(style);
    setDraft((d) => d && { ...d, password: generated.password });
    setBits(generated.bits);
    setShown(true);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!draft) return;
    setBusy(true);
    setError(null);
    const urls = draft.urls
      .split(/[\n,]/)
      .map((u) => u.trim())
      .filter(Boolean);
    const tags = draft.tags
      .split(/[\s,]+/)
      .map((t) => t.replace(/^#/, "").trim())
      .filter(Boolean);
    const folder = draft.folder.trim().replace(/^\/+|\/+$/g, "");
    const login = {
      username: draft.username.trim(),
      password: draft.password,
      totp: view && "login" in view.body ? view.body.login.totp : null,
      notes: draft.notes,
    };
    try {
      const reply = view
        ? await call({
            method: "update",
            params: {
              selector: view.id,
              revision: view.revision,
              title: draft.title.trim(),
              folder,
              urls,
              tags,
              basic_auth: draft.basicAuth,
              body: { login },
            },
          })
        : await call({
            method: "add",
            params: { title: draft.title.trim(), folder, urls, tags, basic_auth: draft.basicAuth, body: { login } },
          });
      if (typeof reply === "object" && "updated" in reply) saved(reply.updated);
      else if (typeof reply === "object" && "added" in reply) saved(reply.added);
      else throw new Error("Unexpected reply from the agent.");
    } catch (err) {
      setError(
        err instanceof AgentFailure && err.info.code === "stale"
          ? "This login changed elsewhere since you opened it. Go back and edit it again."
          : errorText(err),
      );
      setBusy(false);
    }
  }

  const meter = draft.password ? strength(bits ?? guessBits(draft.password)) : null;

  return (
    <form className="screen editor" onSubmit={(e) => void submit(e)}>
      <EditorBar title={view ? "Edit login" : "New login"} cancel={cancel} />
      <div className="form-body">
        <div className="field">
          <label htmlFor="title">Name</label>
          <input
            id="title"
            autoFocus
            required
            value={draft.title}
            onChange={(e) => set("title", e.target.value)}
            placeholder="github.com"
          />
        </div>
        <div className="field">
          <label htmlFor="folder">Folder</label>
          <input
            id="folder"
            list="folders"
            value={draft.folder}
            onChange={(e) => set("folder", e.target.value)}
            placeholder="web"
          />
          <datalist id="folders">
            {folders.map((f) => (
              <option key={f} value={f} />
            ))}
          </datalist>
        </div>
        <div className="field">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            autoComplete="off"
            value={draft.username}
            onChange={(e) => set("username", e.target.value)}
            placeholder="you@example.com"
          />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <div className="input-group">
            <input
              id="password"
              className={shown ? "mono" : undefined}
              type={shown ? "text" : "password"}
              autoComplete="new-password"
              value={draft.password}
              onChange={(e) => {
                set("password", e.target.value);
                setBits(null);
              }}
            />
            <button type="button" className="icon-button" title={shown ? "Hide" : "Show"} onClick={() => setShown(!shown)}>
              <Icon name={shown ? "eyeOff" : "eye"} size={15} />
            </button>
          </div>
          <div className="generator">
            <button type="button" className="ghost small" onClick={() => suggest("random")} title="20 random characters">
              <Icon name="sparkle" size={13} />
              Random
            </button>
            <button type="button" className="ghost small" onClick={() => suggest("easy")} title="Syllables, easy to type">
              <Icon name="sparkle" size={13} />
              Easy to type
            </button>
            {meter && (
              <span className={`meter l${meter.level}`}>
                <span className="bars">
                  {[1, 2, 3, 4].map((i) => (
                    <i key={i} className={i <= meter.level ? "on" : undefined} />
                  ))}
                </span>
                {meter.label}
              </span>
            )}
          </div>
        </div>
        <div className="field">
          <label htmlFor="urls">Websites</label>
          <textarea
            id="urls"
            rows={2}
            value={draft.urls}
            onChange={(e) => set("urls", e.target.value)}
            placeholder={"https://example.com\none per line; https://*.example.com for all subdomains"}
            spellCheck={false}
          />
        </div>
        <div className="field">
          <label htmlFor="notes">Notes</label>
          <textarea id="notes" rows={2} value={draft.notes} onChange={(e) => set("notes", e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="tags">Tags</label>
          <input id="tags" value={draft.tags} onChange={(e) => set("tags", e.target.value)} placeholder="dev, work" />
        </div>
        <label className="check">
          <input type="checkbox" checked={draft.basicAuth} onChange={(e) => set("basicAuth", e.target.checked)} />
          <span>
            Use for HTTP Basic Auth
            <span className="muted"> — answers the browser's sign-in prompt on these websites</span>
          </span>
        </label>
        {error && <p className="notice error">{error}</p>}
      </div>
      <div className="footer">
        <button type="button" onClick={cancel} disabled={busy}>
          Cancel
        </button>
        <button type="submit" className="primary wide" disabled={busy || !draft.title.trim()}>
          {busy ? "Saving…" : view ? "Save changes" : "Add login"}
        </button>
      </div>
    </form>
  );
}

function EditorBar({ title, cancel }: { title: string; cancel: () => void }) {
  return (
    <div className="subbar">
      <button type="button" className="icon-button" title="Back (Esc)" onClick={cancel}>
        <Icon name="back" />
      </button>
      <h2>{title}</h2>
    </div>
  );
}

/** Rough entropy of a typed password: length × log2(alphabet of the classes it uses). */
function guessBits(password: string): number {
  let alphabet = 0;
  if (/[a-z]/.test(password)) alphabet += 26;
  if (/[A-Z]/.test(password)) alphabet += 26;
  if (/\d/.test(password)) alphabet += 10;
  if (/[^a-zA-Z\d]/.test(password)) alphabet += 32;
  return Math.round([...password].length * Math.log2(Math.max(alphabet, 2)) * 0.8);
}
