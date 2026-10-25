/** An HTTP(S) destination for a saved pattern; a wildcard host opens its parent. */
export function websiteUrl(pattern: string): string | null {
  const raw = pattern.trim();
  if (!raw) return null;
  // A bare host may have a port, but other explicit schemes are never links.
  if (/^[a-z][a-z\d+.-]*:/i.test(raw) && !/^https?:\/\//i.test(raw) && !/^[^/:]+:\d+(?:[/?#]|$)/.test(raw)) return null;
  try {
    const url = new URL(raw.includes("://") ? raw : `https://${raw}`);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password) return null;
    url.hostname = url.hostname.replace(/^\*\./, "");
    if (!url.hostname || url.href.includes("*")) return null;
    return url.href;
  } catch {
    return null;
  }
}

export function firstWebsite(patterns: readonly string[]): string | null {
  for (const pattern of patterns) {
    const url = websiteUrl(pattern);
    if (url) return url;
  }
  return null;
}
