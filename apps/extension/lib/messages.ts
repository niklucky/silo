/** Messages between the popup and the background script, which owns the native port. */

import type { Request, Response } from "./protocol";

export interface AuthEvent {
  at: number;
  origin: string;
  outcome: "filled" | "no_match" | "locked" | "rejected" | "error";
  /** Login path for `filled`, error text for `error`. */
  detail?: string;
}

export type PopupRequest = { kind: "agent"; request: Request } | { kind: "events" };

export type PopupResponse =
  | { kind: "agent"; response: Response }
  | { kind: "bridge_error"; message: string }
  | { kind: "events"; events: AuthEvent[] };
