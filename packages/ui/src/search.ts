/**
 * Vault search over summaries: title, folder, website and tag. Same scoring as
 * the extension popup (apps/extension/lib/search.ts); merge once the extension
 * moves onto @silo/ui.
 */

import type { SecretMeta } from "./protocol";

export interface Searchable {
  meta: SecretMeta;
}

/** A login's username, when the caller knows it; summaries do not carry it. */
export type UsernameOf<T> = (secret: T) => string | null;

interface Term {
  text: string;
  host: string | null;
}

/** Host names of URL patterns, without a leading `*.` or `www.`. */
export function hostsOf(meta: SecretMeta): string[] {
  const hosts = new Set<string>();
  for (const pattern of meta.urls ?? []) {
    try {
      const raw = pattern.trim().replace("://*.", "://");
      hosts.add(bareHost(new URL(raw.includes("://") ? raw : `https://${raw}`).hostname));
    } catch {
      // Not a pattern the core would match either.
    }
  }
  return [...hosts];
}

/** `secrets` matching every word of `query`, best first; all of them by title when it is empty. */
export function search<T extends Searchable>(secrets: readonly T[], query: string, usernameOf?: UsernameOf<T>): T[] {
  const terms = parse(query);
  if (terms.length === 0) return [...secrets].sort(byTitle);
  const scored: { secret: T; score: number }[] = [];
  for (const secret of secrets) {
    let total = 0;
    for (const term of terms) {
      const score = scoreTerm(secret.meta, usernameOf?.(secret) ?? null, term);
      if (score === 0) {
        total = 0;
        break;
      }
      total += score;
    }
    if (total > 0) scored.push({ secret, score: total });
  }
  return scored.sort((a, b) => b.score - a.score || byTitle(a.secret, b.secret)).map((s) => s.secret);
}

function parse(query: string): Term[] {
  return query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .map((text) => {
      const host = hostIn(text);
      return { text: host ?? text, host };
    });
}

function hostIn(word: string): string | null {
  if (word.includes("://")) {
    try {
      return bareHost(new URL(word).hostname);
    } catch {
      return null;
    }
  }
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(\/.*)?$/.test(word) ? bareHost(word.split(/[:/]/)[0] ?? word) : null;
}

function bareHost(host: string): string {
  return host.toLowerCase().replace(/^\*\./, "").replace(/^www\./, "");
}

function scoreTerm(meta: SecretMeta, username: string | null, term: Term): number {
  const { text, host } = term;
  let best = 0;
  const take = (score: number) => {
    if (score > best) best = score;
  };
  for (const h of hostsOf(meta)) {
    if (h === text) take(100);
    else if (host && (h.endsWith(`.${host}`) || host.endsWith(`.${h}`))) take(85);
    else if (h.split(".").some((label) => label.startsWith(text))) take(70);
    else if (h.includes(text)) take(45);
  }
  const title = meta.title.toLowerCase();
  if (title === text) take(95);
  else if (title.startsWith(text)) take(75);
  else if (title.split(/[\s._\-/@()]+/).some((word) => word.startsWith(text))) take(60);
  else if (title.includes(text)) take(40);
  if (username) {
    const name = username.toLowerCase();
    if (name === text) take(90);
    else if (name.startsWith(text)) take(65);
    else if (name.split(/[\s._\-@+]+/).some((word) => word.startsWith(text))) take(55);
    else if (name.includes(text)) take(35);
  }
  for (const tag of meta.tags ?? []) {
    if (tag.toLowerCase() === text) take(50);
    else if (tag.toLowerCase().startsWith(text)) take(30);
  }
  const folder = meta.folder.toLowerCase();
  if (folder.split("/").some((segment) => segment.startsWith(text))) take(25);
  else if (folder.includes(text)) take(15);
  return best;
}

export function byTitle(a: Searchable, b: Searchable): number {
  return a.meta.title.localeCompare(b.meta.title, undefined, { sensitivity: "base" }) || a.meta.folder.localeCompare(b.meta.folder);
}
