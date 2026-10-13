import { browser, type Browser } from "wxt/browser";
import type {
  AgentError as AgentErrorInfo,
  ListFilter,
  NewSecret,
  Reply,
  Request,
  Response,
  SecretSummary,
  SecretUpdate,
  SecretView,
  StatusInfo,
} from "./protocol";
import { describe, isBasicAuth, secretPath } from "./protocol";

/** Name of the native messaging host; must match `silo browser install`. */
export const HOST_NAME = "dev.silo.agent";

/** The agent answered, with an error. */
export class AgentError extends Error {
  constructor(readonly info: AgentErrorInfo) {
    super(describe(info));
    this.name = "AgentError";
  }

  get code(): AgentErrorInfo["code"] {
    return this.info.code;
  }
}

/** The native host could not be reached: not installed, stale manifest, or it crashed. */
export class BridgeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BridgeError";
  }
}

interface Pending {
  resolve: (response: Response) => void;
  reject: (error: Error) => void;
}

export interface Credentials {
  username: string;
  password: string;
  /** `folder/title` of the login used, for the activity log. */
  path: string;
  /** The login's id; absent for "use once" credentials. */
  id?: string;
  /** The login answers Basic Auth. */
  basicAuth?: boolean;
}

/**
 * One native messaging port to `silo-native-host`, opened on first use and
 * reopened after a disconnect. The host answers strictly in order, so a FIFO
 * pairs replies with requests. Safari sends single messages instead.
 */
export class Agent {
  private port: Browser.runtime.Port | null = null;
  private pending: Pending[] = [];

  private connect(): Browser.runtime.Port {
    const port = browser.runtime.connectNative(HOST_NAME);
    port.onMessage.addListener((message: unknown) => {
      this.pending.shift()?.resolve(message as Response);
    });
    port.onDisconnect.addListener(() => {
      const reason =
        (port as { error?: { message?: string } }).error?.message ??
        browser.runtime.lastError?.message ??
        "native host disconnected";
      if (this.port === port) this.port = null;
      for (const waiting of this.pending.splice(0)) {
        waiting.reject(new BridgeError(reason));
      }
    });
    this.port = port;
    return port;
  }

  async call(request: Request): Promise<Reply> {
    const response = import.meta.env.SAFARI ? await this.send(request) : await this.post(request);
    if ("err" in response) throw new AgentError(response.err);
    return response.ok;
  }

  /**
   * Safari has no native messaging hosts: each message goes to the containing
   * app's extension (apps/safari), which forwards it to the agent socket.
   */
  private async send(request: Request): Promise<Response> {
    let reply: Response | { bridge_error: string } | undefined;
    try {
      reply = (await browser.runtime.sendNativeMessage(HOST_NAME, request)) as typeof reply;
    } catch (err) {
      throw new BridgeError(err instanceof Error ? err.message : String(err));
    }
    if (!reply) throw new BridgeError("no reply from the Silo for Safari app");
    if ("bridge_error" in reply) throw new BridgeError(reply.bridge_error);
    return reply;
  }

  private post(request: Request): Promise<Response> {
    const port = this.port ?? this.connect();
    return new Promise<Response>((resolve, reject) => {
      this.pending.push({ resolve, reject });
      try {
        port.postMessage(request);
      } catch (err) {
        this.pending.pop();
        reject(new BridgeError(err instanceof Error ? err.message : String(err)));
      }
    });
  }

  async status(): Promise<StatusInfo> {
    const reply = await this.call({ method: "status" });
    if (typeof reply === "object" && "status" in reply) return reply.status;
    throw unexpected(reply);
  }

  async unlock(password: string, ttlSecs?: number): Promise<StatusInfo> {
    const reply = await this.call({ method: "unlock", params: { password, ttl_secs: ttlSecs } });
    if (typeof reply === "object" && "unlocked" in reply) return reply.unlocked;
    throw unexpected(reply);
  }

  async lock(): Promise<void> {
    await this.call({ method: "lock" });
  }

  async list(filter: ListFilter = {}): Promise<SecretSummary[]> {
    const reply = await this.call({ method: "list", params: filter });
    if (typeof reply === "object" && "list" in reply) return reply.list;
    throw unexpected(reply);
  }

  /**
   * Logins whose URL patterns cover `url`, best first. With `site`, followed by
   * logins for other hosts of the same site (`example.com` for `dev.example.com`).
   */
  async matches(url: string, { site = false } = {}): Promise<SecretSummary[]> {
    const reply = await this.call({ method: "match", params: site ? { url, site } : { url } });
    if (typeof reply === "object" && "matches" in reply) return reply.matches;
    throw unexpected(reply);
  }

  async add(secret: NewSecret): Promise<SecretSummary> {
    const reply = await this.call({ method: "add", params: secret });
    if (typeof reply === "object" && "added" in reply) return reply.added;
    throw unexpected(reply);
  }

  /** Makes a new revision; the agent keeps the old one in the secret's history. */
  async update(update: SecretUpdate): Promise<SecretSummary> {
    const reply = await this.call({ method: "update", params: update });
    if (typeof reply === "object" && "updated" in reply) return reply.updated;
    throw unexpected(reply);
  }

  async get(selector: string): Promise<SecretView> {
    const reply = await this.call({ method: "get", params: { selector } });
    if (typeof reply === "object" && "secret" in reply) return reply.secret;
    throw unexpected(reply);
  }

  /** Username and password of the login `id`, or null when it is not a login. */
  async credentials(id: string): Promise<Credentials | null> {
    const view = await this.get(id);
    if (!("login" in view.body)) return null;
    return {
      username: view.body.login.username,
      password: view.body.login.password,
      path: secretPath(view.meta),
      id: view.id,
      basicAuth: isBasicAuth(view.meta),
    };
  }

  /** Marks login `id` as answering Basic Auth, unless it already does. */
  async markBasicAuth(id: string): Promise<void> {
    const view = await this.get(id);
    if (isBasicAuth(view.meta)) return;
    await this.update({ selector: view.id, revision: view.revision, basic_auth: true });
  }
}

function unexpected(reply: Reply): Error {
  return new Error(`unexpected reply from agent: ${JSON.stringify(reply)}`);
}
