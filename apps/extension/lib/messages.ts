/**
 * Messages to the background script, which owns the native port: from the
 * extension's own pages (popup, auth and unlock pages) and, with a much smaller
 * vocabulary, from the login content script running in web pages.
 */

import type { Request, Response } from "./protocol";

export interface AuthEvent {
  at: number;
  origin: string;
  outcome: "filled" | "saved" | "asked" | "no_match" | "locked" | "rejected" | "error";
  /** Login path for `filled` and `saved`, error text for `error`. */
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
  /** Paths of the saved logins the site refused. */
  refused: string[];
}

/**
 * A login saved for this site under the same username, which a save could
 * overwrite instead of adding another login.
 */
export interface SameSiteLogin {
  id: string;
  path: string;
  username: string;
  /** Already fills on the page being saved for; otherwise it is for another host of the site. */
  here: boolean;
  /**
   * Auth page only: the other hosts it fills on, which a new password changes
   * too. Never sent to web pages.
   */
  elsewhere?: string[];
}

/** A same-site login the auth page offers to use on the challenged host instead of typing one. */
export interface LinkOption {
  id: string;
  path: string;
  username: string;
  /** Hosts it fills on now. */
  hosts: string[];
  /** A pattern that would cover this host and the login's sibling hosts in place of theirs. */
  wildcard: string | null;
}

/** The user's answer when a save finds a same-site login with the same username. */
export type SaveChoice = { kind: "new" } | { kind: "overwrite"; id: string };

/** A same-site login that a login the user signed in with could update instead of being added. */
export interface UpdateTarget extends SameSiteLogin {
  /** It already has the password: updating only adds the username or this host. */
  samePassword: boolean;
}

/**
 * Shown in the tab's top frame after the user signed in with a login that
 * Silo does not have. The password stays in the background.
 */
export interface SaveOffer {
  id: string;
  /** Host of the page the login was sent from. */
  host: string;
  username: string;
  /** Unlock first; the background works the offer out again afterwards. */
  locked: boolean;
  /** Logins to update instead of adding one; empty means a plain save. */
  logins: UpdateTarget[];
}

export type OfferAnswer = SaveChoice | { kind: "dismiss" } | { kind: "never" };

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
      /** Absent on the first try; the answer to a `conflict` reply on the second. */
      choice?: SaveChoice;
    }
  | { kind: "challenge_cancel"; id: string }
  /** Same-site logins the challenged host could use. */
  | { kind: "challenge_logins"; id: string }
  /**
   * Use `login` on the challenged host from now on, by its origin or, with
   * `wildcard`, by the wildcard its `LinkOption` offered. Undone if the site refuses it.
   */
  | { kind: "challenge_link"; id: string; login: string; wildcard: boolean }
  /** Popup: the logins `origin` refused as Basic Auth. */
  | { kind: "basic_auth"; origin: string }
  /** Popup "Fill": ask the content scripts in a tab to fill this login. */
  | { kind: "fill_tab"; tabId: number; id: string };

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
  /** The same username is already saved for this site: ask, then save again with a choice. */
  | { kind: "conflict"; logins: SameSiteLogin[] }
  /** Answer to `challenge_logins`. */
  | { kind: "link_options"; logins: LinkOption[] }
  /** Answer to `basic_auth`: login ids. */
  | { kind: "basic_auth"; refused: string[] }
  /** Answer to `fill_tab`. */
  | { kind: "filled" }
  | { kind: "error"; message: string };

/** A matching login as the content script may see it: no password. */
export interface LoginOption {
  id: string;
  title: string;
  path: string;
  username: string;
}

/**
 * Content script to background. The background answers for the URL of the
 * frame that sent the message, as reported by the browser, never for a URL in
 * the message, so a page only ever gets logins saved for itself.
 */
export type PageRequest =
  | { kind: "page_logins" }
  | { kind: "page_fill"; id: string }
  | { kind: "page_unlock" }
  /**
   * A generated password the user chose: stored before the page gets it, as a
   * new login or, when `choice` says so, over a same-site login.
   */
  | { kind: "page_save_generated"; username: string; password: string; choice?: SaveChoice }
  /** The user sent a login form; the background decides whether to offer saving it. */
  | { kind: "page_submitted"; username: string; password: string; previous?: string }
  /** Top frame only: the offer pending for this tab, if any. */
  | { kind: "page_offer" }
  | { kind: "page_offer_answer"; id: string; answer: OfferAnswer };

export type PageResponse =
  | { kind: "logins"; logins: LoginOption[] }
  | { kind: "locked" }
  /** No agent, no account, or not a web page: stay out of the way. */
  | { kind: "unavailable" }
  | { kind: "credentials"; username: string; password: string }
  /** `updated`: an existing login got the new password; its old one is in its history. */
  | { kind: "saved"; path: string; updated: boolean }
  | { kind: "conflict"; logins: SameSiteLogin[] }
  | { kind: "failed"; message: string }
  | { kind: "offer"; offer: SaveOffer | null }
  | { kind: "ok" };

/** Background to the content scripts of one tab. */
export type TabMessage =
  | { kind: "fill"; id: string }
  /** A save offer is pending for the tab: the top frame should ask for it. */
  | { kind: "offer_save" };

export const PAGE_KINDS: ReadonlySet<string> = new Set<PageRequest["kind"]>([
  "page_logins",
  "page_fill",
  "page_unlock",
  "page_save_generated",
  "page_submitted",
  "page_offer",
  "page_offer_answer",
]);
