/**
 * Wire types of the agent protocol as serde renders them in JSON. The Rust
 * side (crates/agent/src/protocol.rs) is the source of truth; keep this in sync
 * by hand until bindings are generated.
 */

export type SecretKind = "login" | "card" | "env_set" | "file" | "note";

export interface SecretMeta {
  title: string;
  kind: SecretKind;
  /** Folder path such as "projects/wallet"; "" at the root. */
  folder: string;
  tags?: string[];
  urls?: string[];
  /** A login that answers HTTP Basic Auth: tried first there, offered last in sign-in forms. */
  basic_auth?: boolean;
  created_at: number;
  updated_at: number;
}

export interface SecretSummary {
  id: string;
  revision: number;
  meta: SecretMeta;
}

export interface Login {
  username: string;
  password: string;
  totp: string | null;
  notes: string;
}

export type SecretBody =
  | { login: Login }
  | {
      card: {
        holder: string;
        number: string;
        expiry_month: number;
        expiry_year: number;
        cvv: string;
        notes: string;
      };
    }
  | { env_set: { vars: { key: string; value: string }[] } }
  | { file: { name: string; mime: string | null; data: string } }
  | { note: { text: string } };

export interface SecretView extends SecretSummary {
  body: SecretBody;
}

export interface StatusInfo {
  agent_version: string;
  core_version: string;
  home: string;
  has_account: boolean;
  unlocked: boolean;
  fingerprint: string | null;
  public_key: string | null;
  secrets: number;
  expires_in_secs: number | null;
}

/** Input for `add`; the agent assigns id, revision and timestamps. */
export interface NewSecret {
  title: string;
  folder?: string;
  tags?: string[];
  urls?: string[];
  basic_auth?: boolean;
  body: SecretBody;
}

/** Input for `update`: absent fields keep their value. */
export interface SecretUpdate {
  selector: string;
  /** Fail with `stale` instead of overwriting if the secret moved past this revision. */
  revision?: number;
  title?: string;
  folder?: string;
  tags?: string[];
  urls?: string[];
  basic_auth?: boolean;
  body?: SecretBody;
}

export interface ListFilter {
  folder?: string;
  exact_folder?: boolean;
  tag?: string;
  kind?: SecretKind;
}

/** Methods the bridge lets a browser use. `shutdown` and `history` are refused. */
export type Request =
  | { method: "status" }
  | { method: "unlock"; params: { password: string; ttl_secs?: number } }
  | { method: "lock" }
  | { method: "list"; params: ListFilter }
  | { method: "get"; params: { selector: string } }
  | { method: "add"; params: NewSecret }
  | { method: "update"; params: SecretUpdate }
  | { method: "remove"; params: { selector: string } }
  /** `site` adds logins for other hosts of the same site, after the matching ones. */
  | { method: "match"; params: { url: string; site?: boolean } }
  /** The registrable domain of the URL's host; null for an address or a public suffix. */
  | { method: "site"; params: { url: string } };

export type Reply =
  | { status: StatusInfo }
  | { unlocked: StatusInfo }
  | "locked"
  | { list: SecretSummary[] }
  | { secret: SecretView }
  | { added: SecretSummary }
  | { updated: SecretSummary }
  | { removed: SecretSummary }
  | { matches: SecretSummary[] }
  | { site: string | null };

export type AgentError =
  | { code: "locked" }
  | { code: "wrong_password" }
  | { code: "no_account"; home: string }
  | { code: "not_found"; selector: string }
  | { code: "ambiguous"; selector: string; matches: string[] }
  | { code: "stale"; selector: string; expected: number; current: number }
  | { code: "invalid" | "core" | "storage" | "internal"; message: string };

export type Response = { ok: Reply } | { err: AgentError };

export function describe(error: AgentError): string {
  switch (error.code) {
    case "locked":
      return "The vault is locked.";
    case "wrong_password":
      return "Wrong password.";
    case "no_account":
      return `No account in ${error.home}. Run \`silo init\` in a terminal.`;
    case "not_found":
      return `No secret matches ${error.selector}.`;
    case "ambiguous":
      return `${error.selector} is ambiguous: ${error.matches.join(", ")}`;
    case "stale":
      return `${error.selector} changed in the meantime; try again.`;
    default:
      return error.message;
  }
}

export function isBasicAuth(meta: SecretMeta): boolean {
  return meta.basic_auth === true;
}

/** `folder/title`, or just the title at the root. */
export function secretPath(meta: SecretMeta): string {
  return meta.folder ? `${meta.folder}/${meta.title}` : meta.title;
}
