/**
 * Widening one login's URL patterns to a wildcard when it already serves
 * several hosts under one parent domain: `https://admin.dev.example.com` and
 * `https://test.dev.example.com`, about to be used on `id.dev.example.com`,
 * become `https://*.dev.example.com`. Patterns are matched by the core
 * (crates/core/src/vault/urls.rs); this only proposes them.
 */

/** A wildcard covering the target and the login's sibling hosts, and the patterns it replaces. */
export interface Widening {
  wildcard: string;
  replaces: string[];
}

/**
 * Last labels like `co.uk` or `com.au`: a public suffix rather than a site,
 * never worth a wildcard. A rough check; the agent only offers same-site
 * logins, so their hosts rarely share nothing but a suffix.
 */
const SUFFIX_LIKE = /^(ac|co|com|edu|go|gov|ne|net|or|org)\.[a-z]{2}$/;

/**
 * The wildcard to offer when `patterns` already cover at least two hosts that
 * share a parent domain with `target`, or null. The wildcard keeps the
 * target's scheme and port, and replaces only patterns it covers entirely:
 * same scheme and port, host at or under the parent. Bare hosts (any scheme)
 * stay as they are.
 */
export function widening(patterns: readonly string[], target: string): Widening | null {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  if (!host.includes(".") || host.startsWith("[") || /^[\d.]+$/.test(host)) return null;

  const eligible: { pattern: string; host: string }[] = [];
  for (const pattern of patterns) {
    if (!pattern.includes("://")) continue;
    let parsed: URL;
    try {
      parsed = new URL(pattern.trim());
    } catch {
      continue;
    }
    if (parsed.protocol !== url.protocol || parsed.port !== url.port) continue;
    const patternHost = parsed.hostname.toLowerCase().replace(/^\*\./, "");
    if (patternHost && patternHost !== host) eligible.push({ pattern, host: patternHost });
  }

  // The most specific parent shared with the target that covers two hosts or more.
  const parents = new Set(eligible.map((e) => commonSuffix(e.host, host)));
  let best: string | null = null;
  for (const parent of parents) {
    if (!parent.includes(".") || SUFFIX_LIKE.test(parent)) continue;
    const covered = new Set(eligible.filter((e) => under(e.host, parent)).map((e) => e.host));
    if (covered.size < 2) continue;
    if (!best || parent.split(".").length > best.split(".").length) best = parent;
  }
  if (!best) return null;
  const parent = best;
  return {
    wildcard: `${url.protocol}//*.${parent}${url.port ? `:${url.port}` : ""}`,
    replaces: eligible.filter((e) => under(e.host, parent)).map((e) => e.pattern),
  };
}

/** Host names of `patterns`, for showing where a login is used. */
export function patternHosts(patterns: readonly string[]): string[] {
  const hosts = new Set<string>();
  for (const pattern of patterns) {
    try {
      const raw = pattern.trim();
      hosts.add(new URL(raw.includes("://") ? raw : `https://${raw}`).hostname.toLowerCase());
    } catch {
      // Not a pattern the core would match either.
    }
  }
  return [...hosts];
}

/** The labels `a` and `b` end with in common: `dev.example.com` for `x.dev.example.com` and `y.dev.example.com`. */
function commonSuffix(a: string, b: string): string {
  const left = a.split(".").reverse();
  const right = b.split(".").reverse();
  let n = 0;
  while (n < left.length && n < right.length && left[n] === right[n]) n++;
  return left.slice(0, n).reverse().join(".");
}

function under(host: string, parent: string): boolean {
  return host === parent || host.endsWith(`.${parent}`);
}
