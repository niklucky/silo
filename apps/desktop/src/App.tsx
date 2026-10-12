import { useEffect, useState } from "react";
import { commands } from "@silo/bindings/desktop";
import { CoreVersion } from "@silo/ui";

export default function App() {
  const [version, setVersion] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    commands
      .coreVersion()
      .then(setVersion)
      .catch((err: unknown) => setError(String(err)));
  }, []);

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: 24 }}>
      <h1>Silo</h1>
      <CoreVersion host="desktop" version={version} error={error} />
    </main>
  );
}
