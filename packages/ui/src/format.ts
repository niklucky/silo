/** Small display helpers shared by the vault views. */

/** A letter and a color for a secret, so rows are told apart at a glance. */
export function avatarFor(label: string): { letter: string; color: string } {
  const clean = label.trim().replace(/^(https?:\/\/)?(\*\.)?(www\.)?/i, "");
  const letter = [...clean].find((c) => /[\p{L}\p{N}]/u.test(c)) ?? "?";
  let hash = 0;
  for (const c of clean.toLowerCase()) hash = (hash * 31 + (c.codePointAt(0) ?? 0)) >>> 0;
  return { letter: letter.toUpperCase(), color: `hsl(${hash % 360} 45% 45%)` };
}

export function timeAgo(unixSeconds: number): string {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (seconds < 60) return "just now";
  const units: [number, string][] = [
    [365 * 86400, "year"],
    [30 * 86400, "month"],
    [7 * 86400, "week"],
    [86400, "day"],
    [3600, "hour"],
    [60, "minute"],
  ];
  for (const [size, name] of units) {
    if (seconds >= size) {
      const n = Math.floor(seconds / size);
      return `${n} ${name}${n === 1 ? "" : "s"} ago`;
    }
  }
  return "just now";
}

export function cardBrand(number: string): string | null {
  const n = number.replace(/\D/g, "");
  if (/^4/.test(n)) return "Visa";
  if (/^(5[1-5]|2[2-7])/.test(n)) return "Mastercard";
  if (/^3[47]/.test(n)) return "Amex";
  if (/^(6011|65|64[4-9])/.test(n)) return "Discover";
  if (/^220[0-4]/.test(n)) return "Mir";
  return null;
}

/** `4111 1111 1111 1111`, or Amex's `3782 822463 10005`. */
export function groupCardNumber(number: string): string {
  const n = number.replace(/\D/g, "");
  if (/^3[47]/.test(n)) return [n.slice(0, 4), n.slice(4, 10), n.slice(10)].filter(Boolean).join(" ");
  return n.replace(/(.{4})/g, "$1 ").trim();
}

export function maskCardNumber(number: string): string {
  const n = number.replace(/\D/g, "");
  return `•••• ${n.slice(-4)}`;
}

export function decodeBase64(data: string): Uint8Array {
  const raw = atob(data);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

export function encodeBase64(bytes: Uint8Array): string {
  let raw = "";
  for (let i = 0; i < bytes.length; i += 0x8000) raw += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(raw);
}

/** The bytes as text when they are valid UTF-8 without control characters, else null. */
export function asText(bytes: Uint8Array): string | null {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return /[\u0000-\u0008\u000e-\u001f]/.test(text) ? null : text;
  } catch {
    return null;
  }
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function toDotenv(vars: { key: string; value: string }[]): string {
  return vars
    .filter((v) => v.key)
    .map(({ key, value }) => `${key}=${/[\s#"'$`\\]/.test(value) ? JSON.stringify(value) : value}`)
    .join("\n");
}

export function fromDotenv(text: string): { key: string; value: string }[] {
  const vars: { key: string; value: string }[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    let value = (match[2] ?? "").trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      try {
        value = JSON.parse(value) as string;
      } catch {
        value = value.slice(1, -1);
      }
    } else if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
      value = value.slice(1, -1);
    }
    vars.push({ key: match[1] ?? "", value });
  }
  return vars;
}

/** Current TOTP code (RFC 6238, SHA-1, 6 digits, 30 s) for a base32 seed or `otpauth://` URI. */
export async function totp(seed: string, at = Date.now()): Promise<{ code: string; remaining: number } | null> {
  let secret = seed.trim();
  let digits = 6;
  let period = 30;
  if (secret.startsWith("otpauth://")) {
    try {
      const url = new URL(secret);
      secret = url.searchParams.get("secret") ?? "";
      digits = Number(url.searchParams.get("digits") ?? 6) || 6;
      period = Number(url.searchParams.get("period") ?? 30) || 30;
    } catch {
      return null;
    }
  }
  const key = base32(secret);
  if (!key || key.length === 0) return null;
  const counter = Math.floor(at / 1000 / period);
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, message));
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const binary =
    (((mac[offset] ?? 0) & 0x7f) << 24) | ((mac[offset + 1] ?? 0) << 16) | ((mac[offset + 2] ?? 0) << 8) | (mac[offset + 3] ?? 0);
  const code = String(binary % 10 ** digits).padStart(digits, "0");
  return { code, remaining: period - (Math.floor(at / 1000) % period) };
}

function base32(input: string): Uint8Array<ArrayBuffer> | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of clean) {
    const index = alphabet.indexOf(c);
    if (index < 0) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
