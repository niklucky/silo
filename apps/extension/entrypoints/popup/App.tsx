import { useEffect, useState } from "react";
import { CoreVersion } from "@secret/ui";
import { loadCore } from "@/lib/core";

export default function App() {
  const [version, setVersion] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadCore()
      .then((core) => setVersion(core.version()))
      .catch((err: unknown) => setError(String(err)));
  }, []);

  return (
    <main>
      <h1>Secret</h1>
      <CoreVersion host="extension" version={version} error={error} />
    </main>
  );
}
