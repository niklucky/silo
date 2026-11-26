import type { NewSecret, SecretSummary, SecretUpdate, SecretView, StatusInfo } from "./protocol";

export type TokenScope = { env_set: string } | { folder: string };
export interface AccessTokenInfo {
  name: string;
  paths: string[];
}
export interface AccessTokens {
  list(scope: TokenScope | null): Promise<AccessTokenInfo[]>;
  issue(name: string, scope: TokenScope): Promise<string>;
  rotate(name: string): Promise<string>;
  revoke(name: string): Promise<void>;
}

/** Where the vault syncs and how the last run went. */
export interface SyncInfo {
  server: string;
  username: string;
  /** Unix seconds. */
  last_sync: number | null;
  last_error: string | null;
  /** Local changes not on the server yet; null while locked. */
  pending: number | null;
}

/**
 * What the vault UI needs from its host. Desktop implements it over the local
 * agent (Tauri command → agent socket); the web app will implement it over the
 * WASM core and the sync server. Both decrypt on the device, never on a server.
 *
 * Errors are thrown as `Error`; one with `code === "locked"` sends the UI back
 * to the unlock screen.
 */
export interface VaultClient {
  tokens?: AccessTokens;
  status(): Promise<StatusInfo>;
  unlock(password: string): Promise<StatusInfo>;
  /** Unlocks using OS biometrics (Touch ID) when supported by the host. */
  unlockBiometric?(): Promise<StatusInfo>;
  enableBiometric?(): Promise<StatusInfo>;
  disableBiometric?(): Promise<StatusInfo>;
  lock(): Promise<void>;
  /** Every secret, without bodies. */
  list(): Promise<SecretSummary[]>;
  get(id: string): Promise<SecretView>;
  add(secret: NewSecret): Promise<SecretSummary>;
  update(update: SecretUpdate): Promise<SecretSummary>;
  remove(id: string): Promise<void>;
  /** Earlier revisions, newest first. */
  history(id: string): Promise<SecretView[]>;
  /** Null when this vault does not sync. */
  syncStatus(): Promise<SyncInfo | null>;
  /** Pull and push now. */
  sync(): Promise<void>;
}

/** Account setup offered by hosts that can provision a fresh vault. */
export interface VaultSetup {
  createVault(password: string): Promise<StatusInfo>;
  signIn(server: string, username: string, password: string): Promise<SyncInfo | null>;
}
