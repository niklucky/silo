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
 * The wildcard to offer when `patterns` already cover at least two hosts that
 * share a parent domain with `target`, or null. `site` is the target's
 * registrable domain (`Agent.site`): the parent stays at or under it, and
 * patterns of other sites do not count, so `bob.github.io` never widens
 * `alice.github.io` to `*.github.io`. No site, no wildcard. The wildcard keeps
 * the target's scheme and port, and replaces only patterns it covers
 * entirely: same scheme and port, host at or under the parent. Bare hosts
 * (any scheme) stay as they are.
 */
export function widening(patterns: readonly string[], target: string, site: string | null): Widening | null {
  if (!site) return null;
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  if (!host.includes(".") || !under(host, site)) return null;

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
    if (patternHost && patternHost !== host && under(patternHost, site)) eligible.push({ pattern, host: patternHost });
  }

  // The most specific parent shared with the target that covers two hosts or more.
  // Both hosts are under `site`, so their common parent is too.
  const parents = new Set(eligible.map((e) => commonSuffix(e.host, host)));
  let best: string | null = null;
  for (const parent of parents) {
    if (!parent.includes(".")) continue;
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
