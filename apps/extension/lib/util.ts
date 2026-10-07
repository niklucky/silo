export function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** `scheme://host[:port]` of a URL, or the input when it does not parse. */
export function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}
