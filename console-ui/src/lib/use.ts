import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api, Refused } from "./api";

// Loads one API answer and reloads it after a change. A change shows its answer as a toast: the saved message, or
// the refusal, which names the cause and the fix. The refusal is also returned, for a dialog to show beside its form.
// `every`: reload that often (milliseconds) while `paused` is false, so the page keeps up with what the gateway sees.
export function useData<T>(path: string, every = 0, paused = false) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(() => {
    api
      .get<T>(path)
      .then((d) => {
        setData(d);
        setError("");
      })
      .catch((e: Error) => setError(e.message));
  }, [path]);
  useEffect(load, [load]);
  useEffect(() => {
    if (!every || paused) return;
    const timer = window.setInterval(load, every);
    return () => window.clearInterval(timer);
  }, [load, every, paused]);
  const change = useCallback(
    async (run: () => Promise<{ message: string }>) => {
      try {
        const done = await run();
        toast(done.message);
        load();
        return "";
      } catch (e) {
        if (e instanceof Refused) {
          toast.error(e.message, { duration: 10000 });
          return e.message;
        }
        throw e;
      }
    },
    [load],
  );
  return { data, error, change };
}

export const words = (text: string) =>
  text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
