/**
 * VaultClient over the agent protocol (crates/agent/src/protocol.rs). The
 * host supplies the transport: desktop sends JSON lines through a Tauri
 * command to the agent socket.
 */

import type { SyncInfo, VaultClient, VaultSetup } from "./client";
import type { NewSecret, SecretSummary, SecretUpdate, SecretView, StatusInfo } from "./protocol";

/** Sends one request as JSON and resolves with the response JSON. */
export type AgentTransport = (request: string) => Promise<string>;

type AgentErrorBody =
  | { code: "locked" }
  | { code: "wrong_password" }
  | { code: "no_account"; home: string }
  | { code: "not_found"; selector: string }
  | { code: "ambiguous"; selector: string; matches: string[] }
  | { code: "stale"; selector: string; expected: number; current: number }
  | { code: "invalid" | "core" | "storage" | "sync" | "internal"; message: string };

/** An error the agent answered with. `code` is the protocol's error code. */
export class AgentError extends Error {
  readonly code: AgentErrorBody["code"];
  constructor(body: AgentErrorBody) {
    super(describe(body));
    this.code = body.code;
  }
}

function describe(error: AgentErrorBody): string {
  switch (error.code) {
    case "locked":
      return "The vault is locked.";
    case "wrong_password":
      return "Wrong password.";
    case "no_account":
      return `No vault in ${error.home}. Run \`silo init\` in a terminal.`;
    case "not_found":
      return `No secret matches ${error.selector}.`;
    case "ambiguous":
      return `${error.selector} is ambiguous: ${error.matches.join(", ")}`;
    case "stale":
      return "It changed in the meantime (another device or the CLI). Reopen it and try again.";
    default:
      return error.message;
  }
}

export function createAgentClient(send: AgentTransport): VaultClient & VaultSetup {
  async function call<T>(method: string, params: unknown, key: string): Promise<T> {
    const request = params === undefined ? { method } : { method, params };
    const response = JSON.parse(await send(JSON.stringify(request))) as { ok: unknown } | { err: AgentErrorBody };
    if ("err" in response) throw new AgentError(response.err);
    const reply = response.ok;
    if (reply === key) return undefined as T;
    if (typeof reply === "object" && reply !== null && key in reply) return (reply as Record<string, T>)[key] as T;
    throw new Error(`Unexpected reply from the agent to ${method}.`);
  }

  return {
    status: () => call<StatusInfo>("status", undefined, "status"),
    createVault: (password) => call<StatusInfo>("init", { password }, "unlocked"),
    signIn: (server, username, password) => call<SyncInfo | null>("sync_login", { server, username, password }, "sync_status"),
    unlock: (password) => call<StatusInfo>("unlock", { password }, "unlocked"),
    lock: () => call<void>("lock", undefined, "locked"),
    list: () => call<SecretSummary[]>("list", {}, "list"),
    get: (id) => call<SecretView>("get", { selector: id }, "secret"),
    add: (secret: NewSecret) => call<SecretSummary>("add", secret, "added"),
    update: (update: SecretUpdate) => call<SecretSummary>("update", update, "updated"),
    remove: async (id) => {
      await call<SecretSummary>("remove", { selector: id }, "removed");
    },
    history: (id) => call<SecretView[]>("history", { selector: id }, "history"),
    syncStatus: () => call<SyncInfo | null>("sync_status", undefined, "sync_status"),
    sync: async () => {
      await call<unknown>("sync", undefined, "synced");
    },
  };
}
