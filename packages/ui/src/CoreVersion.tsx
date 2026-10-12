export type CoreVersionProps = {
  /** Which host loaded the Rust core. */
  host: "desktop" | "extension";
  /** Version string from `silo_core::version()`, or null while loading. */
  version: string | null;
  error?: string | null;
};

/**
 * Shows the Rust core version. Used by every host as the bridge smoke test.
 */
export function CoreVersion({ host, version, error }: CoreVersionProps) {
  if (error) {
    return (
      <p role="alert">
        Core failed to load in {host}: {error}
      </p>
    );
  }
  return (
    <p>
      Core <strong>{version ?? "loading…"}</strong> via {host}
    </p>
  );
}
