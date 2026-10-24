/**
 * Vault search for the popup: by title, folder, website and tag. Works on
 * summaries only, so it never needs a secret's body. A query that looks like
 * a URL or a host name also finds logins of the same site's other hosts.
 */

import type { SecretMeta } from "./protocol";
import { patternHosts } from "./site";

export interface Searchable {
  meta: SecretMeta;
}

/** A query term: what the user typed, and the host name when it reads as one. */
interface Term {
  text: string;
  host: string | null;
}

/** Hosts a secret fills on, without a leading `*.` or `www.`. */
export function hostsOf(meta: SecretMeta): string[] {
  return [...new Set(patternHosts(meta.urls ?? []).map(bareHost))];
}

/** `secrets` matching every word of `query`, best first; all of them by title when it is empty. */
export function search<T extends Searchable>(secrets: readonly T[], query: string): T[] {
  const terms = parse(query);
  if (terms.length === 0) return [...secrets].sort(byTitle);
  const scored: { secret: T; score: number }[] = [];
  for (const secret of secrets) {
    let total = 0;
    for (const term of terms) {
      const score = scoreTerm(secret.meta, term);
      if (score === 0) {
        total = 0;
        break;
      }
      total += score;
    }
    if (total > 0) scored.push({ secret, score: total + (secret.meta.kind === "login" ? 1 : 0) });
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

/** The host of a pasted URL, or the word itself when it looks like a host name (`github.com`). */
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

function scoreTerm(meta: SecretMeta, term: Term): number {
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
  for (const tag of meta.tags ?? []) {
    if (tag.toLowerCase() === text) take(50);
    else if (tag.toLowerCase().startsWith(text)) take(30);
  }
  const folder = meta.folder.toLowerCase();
  if (folder.split("/").some((segment) => segment.startsWith(text))) take(25);
  else if (folder.includes(text)) take(15);
  return best;
}

function byTitle(a: Searchable, b: Searchable): number {
  return a.meta.title.localeCompare(b.meta.title, undefined, { sensitivity: "base" }) ||
    a.meta.folder.localeCompare(b.meta.folder);
}
