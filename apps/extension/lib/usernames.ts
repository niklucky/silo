import type { SecretSummary } from "./protocol";

/** Popup-local usernames, shared by duplicate rows; secret bodies are never cached. */
export function createUsernameLoader(read: (id: string) => Promise<string | null>) {
  const cache = new Map<string, Promise<string | null>>();
  const queue: (() => void)[] = [];
  let running = 0;

  return (secret: Pick<SecretSummary, "id" | "revision">): Promise<string | null> => {
    const key = `${secret.id}:${secret.revision}`;
    const cached = cache.get(key);
    if (cached) return cached;
    const result = new Promise<string | null>((resolve) => {
      const run = () => {
        running++;
        void Promise.resolve().then(() => read(secret.id)).then(resolve, () => {
          cache.delete(key);
          resolve(null);
        }).finally(() => {
          running--;
          queue.shift()?.();
        });
      };
      if (running < 4) run();
      else queue.push(run);
    });
    cache.set(key, result);
    return result;
  };
}
