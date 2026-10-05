import { browser, type Browser } from "wxt/browser";
import type {
  AgentError as AgentErrorInfo,
  Reply,
  Request,
  Response,
  SecretSummary,
  SecretView,
  StatusInfo,
} from "./protocol";
import { describe, secretPath } from "./protocol";

/** Name of the native messaging host; must match `secret browser install`. */
export const HOST_NAME = "dev.secret.agent";

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
}

/**
 * One native messaging port to `secret-native-host`, opened on first use and
 * reopened after a disconnect. The host answers strictly in order, so a FIFO
 * pairs replies with requests.
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
    const port = this.port ?? this.connect();
    const response = await new Promise<Response>((resolve, reject) => {
      this.pending.push({ resolve, reject });
      try {
        port.postMessage(request);
      } catch (err) {
        this.pending.pop();
        reject(new BridgeError(err instanceof Error ? err.message : String(err)));
      }
    });
    if ("err" in response) throw new AgentError(response.err);
    return response.ok;
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

  /** Logins whose URL patterns cover `url`, best first. */
  async matches(url: string): Promise<SecretSummary[]> {
    const reply = await this.call({ method: "match", params: { url } });
    if (typeof reply === "object" && "matches" in reply) return reply.matches;
    throw unexpected(reply);
  }

  async get(selector: string): Promise<SecretView> {
    const reply = await this.call({ method: "get", params: { selector } });
    if (typeof reply === "object" && "secret" in reply) return reply.secret;
    throw unexpected(reply);
  }

  /** Username and password of the best login for `url`, or null when none is saved. */
  async credentialsFor(url: string): Promise<Credentials | null> {
    const [best] = await this.matches(url);
    if (!best) return null;
    const view = await this.get(best.id);
    if (!("login" in view.body)) return null;
    return {
      username: view.body.login.username,
      password: view.body.login.password,
      path: secretPath(view.meta),
    };
  }
}

function unexpected(reply: Reply): Error {
  return new Error(`unexpected reply from agent: ${JSON.stringify(reply)}`);
}
