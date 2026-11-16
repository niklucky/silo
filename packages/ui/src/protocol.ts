/**
 * Vault types as the agent protocol renders them in JSON
 * (crates/agent/src/protocol.rs is the source of truth). The extension keeps
 * its own copy in apps/extension/lib/protocol.ts; both go away once the
 * bindings are generated.
 */

export type SecretKind = "login" | "card" | "env_set" | "file" | "note";

export interface SecretMeta {
  title: string;
  kind: SecretKind;
  /** Folder path such as "projects/wallet"; "" at the root. */
  folder: string;
  tags?: string[];
  urls?: string[];
  /** A login that answers HTTP Basic Auth on its URLs. */
  basic_auth?: boolean;
  /** Unix seconds. */
  created_at: number;
  /** Unix seconds. */
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

export interface Card {
  holder: string;
  number: string;
  expiry_month: number;
  expiry_year: number;
  cvv: string;
  notes: string;
}

export interface EnvVar {
  key: string;
  value: string;
}

export interface FileBody {
  name: string;
  mime: string | null;
  /** Base64. */
  data: string;
}

export type SecretBody =
  | { login: Login }
  | { card: Card }
  | { env_set: { vars: EnvVar[] } }
  | { file: FileBody }
  | { note: { text: string } };

export interface SecretView extends SecretSummary {
  body: SecretBody;
}

export interface NewSecret {
  title: string;
  folder?: string;
  tags?: string[];
  urls?: string[];
  basic_auth?: boolean;
  body: SecretBody;
}

export interface SecretUpdate {
  selector: string;
  revision?: number;
  title?: string;
  folder?: string;
  tags?: string[];
  urls?: string[];
  basic_auth?: boolean;
  body?: SecretBody;
}

export interface StatusInfo {
  has_account: boolean;
  unlocked: boolean;
  fingerprint: string | null;
  secrets: number;
  expires_in_secs: number | null;
}

export const KIND_LABEL: Record<SecretKind, string> = {
  login: "Login",
  card: "Card",
  env_set: "Environment",
  file: "File",
  note: "Note",
};

export const KIND_PLURAL: Record<SecretKind, string> = {
  login: "Logins",
  card: "Cards",
  env_set: "Environments",
  file: "Files",
  note: "Notes",
};

export const KINDS: SecretKind[] = ["login", "card", "env_set", "file", "note"];

export function emptyBody(kind: SecretKind): SecretBody {
  switch (kind) {
    case "login":
      return { login: { username: "", password: "", totp: null, notes: "" } };
    case "card":
      return { card: { holder: "", number: "", expiry_month: 0, expiry_year: 0, cvv: "", notes: "" } };
    case "env_set":
      return { env_set: { vars: [{ key: "", value: "" }] } };
    case "file":
      return { file: { name: "", mime: null, data: "" } };
    case "note":
      return { note: { text: "" } };
  }
}
