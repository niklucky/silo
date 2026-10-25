import { browser } from "wxt/browser";
import { websiteUrl } from "./website";

const CACHE_KEY = "website-favicons-v1";
const WEEK = 7 * 24 * 60 * 60_000;
const HOUR = 60 * 60_000;
const MAX_ENTRIES = 128;
const PNG_PREFIX = "data:image/png;base64,";

interface CachedIcon {
  png: string | null;
  at: number;
}

let cache: Promise<Record<string, CachedIcon>> | undefined;
let writes = Promise.resolve();
const pending = new Map<string, Promise<string | null>>();
let running = 0;
const queue: (() => void)[] = [];

/** Fetch directly from the site, once per origin, and keep only a small PNG locally. */
export function faviconFor(website: string): Promise<string | null> {
  const url = websiteUrl(website);
  if (!url) return Promise.resolve(null);
  const origin = new URL(url).origin;
  const existing = pending.get(origin);
  if (existing) return existing;
  const result = load(origin).catch(() => null);
  pending.set(origin, result);
  void result.finally(() => pending.delete(origin));
  return result;
}

async function load(origin: string): Promise<string | null> {
  cache ??= browser.storage.local.get(CACHE_KEY).then((stored) => {
    const entries = stored[CACHE_KEY];
    if (!entries || typeof entries !== "object") return {};
    return Object.fromEntries(Object.entries(entries).filter((pair): pair is [string, CachedIcon] => {
      const item = pair[1] as CachedIcon | null;
      return !!item && typeof item.at === "number" &&
        (item.png === null || (typeof item.png === "string" && item.png.startsWith(PNG_PREFIX) && item.png.length < 32_768));
    }));
  }).catch(() => ({}));
  const entries = await cache;
  const hit = entries[origin];
  if (hit && Date.now() - hit.at < (hit.png ? WEEK : HOUR)) return hit.png;

  // A vault can have many sites. Bound concurrent fetches even when every row mounts at once.
  if (running >= 4) await new Promise<void>((resolve) => queue.push(resolve));
  else running++;
  let png: string | null;
  try {
    png = await fetchIcon(origin);
  } finally {
    const next = queue.shift();
    if (next) next();
    else running--;
  }
  entries[origin] = { png, at: Date.now() };
  const newest = Object.fromEntries(Object.entries(entries).sort((a, b) => b[1].at - a[1].at).slice(0, MAX_ENTRIES));
  for (const key of Object.keys(entries)) if (!(key in newest)) delete entries[key];
  writes = writes.catch(() => undefined).then(() => browser.storage.local.set({ [CACHE_KEY]: { ...entries } }));
  await writes.catch(() => undefined);
  return png;
}

async function fetchIcon(origin: string): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const candidates: string[] = [];
    try {
      const page = await fetch(`${origin}/`, { credentials: "omit", referrerPolicy: "no-referrer", signal: controller.signal });
      if (page.ok && page.headers.get("content-type")?.includes("text/html")) {
        const html = await limitedBlob(page, 512 * 1024);
        const doc = new DOMParser().parseFromString(await html.text(), "text/html");
        const base = page.url || `${origin}/`;
        for (const link of doc.querySelectorAll<HTMLLinkElement>('link[rel~="icon"], link[rel="apple-touch-icon"]')) {
          const href = link.getAttribute("href");
          if (!href) continue;
          try {
            const icon = websiteUrl(new URL(href, base).href);
            if (icon) candidates.push(icon);
          } catch { /* Invalid icon URLs are skipped. */ }
        }
      } else {
        await page.body?.cancel();
      }
    } catch { /* Try /favicon.ico even when the home page is unavailable. */ }
    const fallback = `${origin}/favicon.ico`;
    const attempts = [...new Set(candidates)].slice(0, 3);
    // Keep the conventional icon reachable even when the page declares many alternatives.
    if (!attempts.includes(fallback)) attempts.push(fallback);
    for (const candidate of attempts) {
      try {
        const response = await fetch(candidate, { credentials: "omit", referrerPolicy: "no-referrer", signal: controller.signal });
        if (!response.ok) {
          await response.body?.cancel();
          continue;
        }
        return await smallPng(await limitedBlob(response, 256 * 1024), controller.signal);
      } catch { /* A missing, oversized or undecodable image keeps the letter avatar. */ }
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function limitedBlob(response: Response, limit: number): Promise<Blob> {
  if (!response.body) throw new Error("Empty response");
  const reader = response.body.getReader();
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error("Response too large");
      chunks.push(value);
    }
    return new Blob(chunks, { type: response.headers.get("content-type") ?? "application/octet-stream" });
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

async function smallPng(blob: Blob, signal: AbortSignal): Promise<string> {
  const image = new Image();
  const objectUrl = URL.createObjectURL(blob);
  try {
    await new Promise<void>((resolve, reject) => {
      const finish = (error?: Error) => {
        signal.removeEventListener("abort", abort);
        image.onload = image.onerror = null;
        if (error) reject(error);
        else resolve();
      };
      const abort = () => finish(new Error("Icon load timed out"));
      if (signal.aborted) return abort();
      signal.addEventListener("abort", abort, { once: true });
      image.onload = () => finish();
      image.onerror = () => finish(new Error("Invalid icon"));
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
    image.src = "";
    URL.revokeObjectURL(objectUrl);
  }
}
