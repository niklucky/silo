import { useEffect, useRef, useState } from "react";
import type { SecretSummary } from "./protocol";

export interface UsernameLoader {
  (secret: Pick<SecretSummary, "id" | "revision">): Promise<string | null>;
  /** Drops queued reads and answers null from now on; for when the vault locks. */
  stop(): void;
}

/**
 * Usernames for list rows, read from login bodies a few at a time and kept
 * per revision. Only the username is kept, never the rest of the body. Same
 * approach as apps/extension/lib/usernames.ts.
 */
export function createUsernameLoader(read: (id: string) => Promise<string | null>): UsernameLoader {
  const cache = new Map<string, Promise<string | null>>();
  const queue: (() => void)[] = [];
  let running = 0;
  let stopped = false;

  const load = (secret: Pick<SecretSummary, "id" | "revision">): Promise<string | null> => {
    if (stopped) return Promise.resolve(null);
    const key = `${secret.id}:${secret.revision}`;
    const cached = cache.get(key);
    if (cached) return cached;
    const result = new Promise<string | null>((resolve) => {
      const run = () => {
        running++;
        void Promise.resolve()
          .then(() => (stopped ? null : read(secret.id)))
          .then(resolve, () => {
            cache.delete(key);
            resolve(null);
          })
          .finally(() => {
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
  return Object.assign(load, {
    stop() {
      stopped = true;
      cache.clear();
      // Let queued reads settle as null without touching the agent.
      for (const run of queue.splice(0)) run();
    },
  });
}

/** `id:revision`, the key usernames are kept under. */
export function usernameKey(secret: Pick<SecretSummary, "id" | "revision">): string {
  return `${secret.id}:${secret.revision}`;
}

/**
 * Usernames of every login in `items`, filled in as they are read, keyed by
 * {@link usernameKey}. Updates are batched on a short timer (not animation
 * frames, which stop in a hidden window) so a big vault does not re-render
 * once per login.
 */
export function useUsernames(items: readonly SecretSummary[], load: UsernameLoader): ReadonlyMap<string, string | null> {
  const [names, setNames] = useState<ReadonlyMap<string, string | null>>(new Map());
  const pending = useRef(new Map<string, string | null>());
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    // A new loader means a new session: forget the old one's names.
    setNames(new Map());
    pending.current.clear();
  }, [load]);

  useEffect(() => {
    let live = true;
    const flush = () => {
      timer.current = null;
      const batch = new Map(pending.current);
      pending.current.clear();
      setNames((old) => new Map([...old, ...batch]));
    };
    for (const item of items) {
      if (item.meta.kind !== "login") continue;
      const key = usernameKey(item);
      void load(item).then((name) => {
        if (!live) return;
        pending.current.set(key, name);
        timer.current ??= setTimeout(flush, 30);
      });
    }
    return () => {
      live = false;
      if (timer.current !== null) clearTimeout(timer.current);
      timer.current = null;
    };
  }, [items, load]);

  return names;
}
