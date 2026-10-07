/** Messages between the extension's pages (popup, auth page) and the background script, which owns the native port. */

import type { Request, Response } from "./protocol";

export interface AuthEvent {
  at: number;
  origin: string;
  outcome: "filled" | "asked" | "no_match" | "locked" | "rejected" | "error";
  /** Login path for `filled`, error text for `error`. */
  detail?: string;
}

/** A 401 the extension took over from the browser; the auth page resolves it. */
export interface ChallengeView {
  id: string;
  url: string;
  origin: string;
  host: string;
  realm: string | null;
  state: "locked" | "no_match";
}

export type UiRequest =
  | { kind: "agent"; request: Request }
  | { kind: "events" }
  | { kind: "challenge"; id: string }
  /** After an unlock: look again, then either continue or ask to save. */
  | { kind: "challenge_retry"; id: string }
  | {
      kind: "challenge_save";
      id: string;
      username: string;
      password: string;
      folder: string;
      title: string;
      /** false = use for this browser session only, do not store. */
      remember: boolean;
    }
  | { kind: "challenge_cancel"; id: string };

export type UiResponse =
  | { kind: "agent"; response: Response }
  | { kind: "bridge_error"; message: string }
  | { kind: "events"; events: AuthEvent[] }
  | { kind: "challenge"; challenge: ChallengeView }
  | { kind: "unknown_challenge" }
  /** Navigate the tab to `url`; the request will carry credentials. */
  | { kind: "continue"; url: string }
  /** Still nothing saved for the site: show the save form. */
  | { kind: "save" }
  | { kind: "error"; message: string };
