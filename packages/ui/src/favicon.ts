/**
 * Website favicons for login avatars. Same approach as the extension
 * (apps/extension/lib/favicon.ts): fetch straight from the site, once per
 * origin, without cookies, and keep only a 32 px PNG. The host does the
 * fetching, since a page cannot read other origins itself.
 */

import { createContext, useContext, useEffect, useState } from "react";

export interface SiteResponse {
  /** Where the request ended up after redirects. */
  url: string;
  contentType: string;
  body: Uint8Array;
}

/** A plain GET of `url`: null unless it answers 2xx within `limit` bytes. */
export type SiteFetcher = (url: string, limit: number) => Promise<SiteResponse | null>;

/** Favicon PNG data URL for a website, or null for a letter avatar. */
export type FaviconLoader = (website: string) => Promise<string | null>;

const CACHE_KEY = "silo.favicons.v1";
const WEEK = 7 * 24 * 60 * 60_000;
const HOUR = 60 * 60_000;
const MAX_ENTRIES = 1024;
const PNG_PREFIX = "data:image/png;base64,";

interface CachedIcon {
  png: string | null;
  at: number;
}

/** An HTTP(S) URL for a saved pattern; a wildcard host opens its parent. */
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

export function firstWebsite(patterns: readonly string[] | undefined): string | null {
  for (const pattern of patterns ?? []) {
    const url = websiteUrl(pattern);
    if (url) return url;
  }
  return null;
}

export function createFaviconLoader(fetchSite: SiteFetcher): FaviconLoader {
  const entries = readCache();
  const pending = new Map<string, Promise<string | null>>();
  const queue: (() => void)[] = [];
  let running = 0;
  let saveTimer: ReturnType<typeof setTimeout> | null = null;

  const save = () => {
    saveTimer = null;
    const stale = Object.entries(entries)
      .sort((a, b) => b[1].at - a[1].at)
      .slice(MAX_ENTRIES);
    for (const [key] of stale) delete entries[key];
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify(entries));
    } catch {
      // Remembering icons is a convenience; they are fetched again next time.
    }
  };

  const load = async (origin: string): Promise<string | null> => {
    const hit = entries[origin];
    if (hit && Date.now() - hit.at < (hit.png ? WEEK : HOUR)) return hit.png;
    // A vault can have hundreds of sites; bound the fetches even when every row mounts at once.
    if (running >= 4) await new Promise<void>((resolve) => queue.push(resolve));
    else running++;
    let png: string | null;
    try {
      png = await fetchIcon(fetchSite, origin).catch(() => null);
    } finally {
      const next = queue.shift();
      if (next) next();
      else running--;
    }
    entries[origin] = { png, at: Date.now() };
    saveTimer ??= setTimeout(save, 500);
    return png;
  };

  return (website) => {
    const url = websiteUrl(website);
    if (!url) return Promise.resolve(null);
    const origin = new URL(url).origin;
    const existing = pending.get(origin);
    if (existing) return existing;
    const result = load(origin);
    pending.set(origin, result);
    void result.finally(() => pending.delete(origin));
    return result;
  };
}

function readCache(): Record<string, CachedIcon> {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(CACHE_KEY) ?? "{}");
    if (!parsed || typeof parsed !== "object") return {};
    return Object.fromEntries(
      Object.entries(parsed).filter((pair): pair is [string, CachedIcon] => {
        const item = pair[1] as CachedIcon | null;
        return (
          !!item &&
          typeof item.at === "number" &&
          (item.png === null || (typeof item.png === "string" && item.png.startsWith(PNG_PREFIX) && item.png.length < 32_768))
        );
      }),
    );
  } catch {
    return {};
  }
}

async function fetchIcon(fetchSite: SiteFetcher, origin: string): Promise<string | null> {
  const candidates: string[] = [];
  const page = await fetchSite(`${origin}/`, 512 * 1024).catch(() => null);
  if (page?.contentType.includes("text/html")) {
    const doc = new DOMParser().parseFromString(new TextDecoder().decode(page.body), "text/html");
    for (const link of doc.querySelectorAll<HTMLLinkElement>('link[rel~="icon"], link[rel="apple-touch-icon"]')) {
      const href = link.getAttribute("href");
      if (!href) continue;
      try {
        const icon = websiteUrl(new URL(href, page.url || `${origin}/`).href);
        if (icon) candidates.push(icon);
      } catch {
        // Invalid icon URLs are skipped.
      }
    }
  }
  const fallback = `${origin}/favicon.ico`;
  const attempts = [...new Set(candidates)].slice(0, 3);
  // Keep the conventional icon reachable even when the page declares many alternatives.
  if (!attempts.includes(fallback)) attempts.push(fallback);
  for (const candidate of attempts) {
    const icon = await fetchSite(candidate, 256 * 1024).catch(() => null);
    if (!icon) continue;
    try {
      return await smallPng(new Blob([icon.body as Uint8Array<ArrayBuffer>], { type: imageType(icon) }));
    } catch {
      // A missing or undecodable image keeps the letter avatar.
    }
  }
  return null;
}

/** Servers often send icons as octet-stream; an SVG only renders with its own type. */
function imageType(icon: SiteResponse): string {
  const type = icon.contentType.split(";")[0]?.trim() ?? "";
  if (type.startsWith("image/")) return type;
  const head = new TextDecoder().decode(icon.body.subarray(0, 256)).trimStart();
  return head.startsWith("<svg") || head.startsWith("<?xml") ? "image/svg+xml" : type || "application/octet-stream";
}

async function smallPng(blob: Blob): Promise<string> {
  const image = new Image();
  const objectUrl = URL.createObjectURL(blob);
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Icon load timed out")), 6000);
      image.onload = () => {
        clearTimeout(timer);
        resolve();
      };
      image.onerror = () => {
        clearTimeout(timer);
        reject(new Error("Invalid icon"));
      };
      image.src = objectUrl;
    });
    if (!image.naturalWidth || !image.naturalHeight) throw new Error("Empty icon");
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 32;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Canvas unavailable");
    const scale = 32 / Math.max(image.naturalWidth, image.naturalHeight);
    const width = image.naturalWidth * scale;
    const height = image.naturalHeight * scale;
    context.drawImage(image, (32 - width) / 2, (32 - height) / 2, width, height);
    return canvas.toDataURL("image/png");
  } finally {
    image.onload = image.onerror = null;
    image.src = "";
    URL.revokeObjectURL(objectUrl);
  }
}

/** The loader rows use; null when the host cannot fetch sites. */
export const FaviconContext = createContext<FaviconLoader | null>(null);

/** The favicon for `website`, once loaded; null until then or when there is none. */
export function useFavicon(website: string | null): string | null {
  const load = useContext(FaviconContext);
  const [icon, setIcon] = useState<{ website: string; png: string | null } | null>(null);
  useEffect(() => {
    if (!website || !load) return;
    let live = true;
    void load(website).then((png) => {
      if (live) setIcon({ website, png });
    });
    return () => {
      live = false;
    };
  }, [website, load]);
  return icon && icon.website === website ? icon.png : null;
}
