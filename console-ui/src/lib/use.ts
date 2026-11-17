import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api, Refused } from "./api";

// Loads one API answer and reloads it after a change. A change shows its answer as a toast: the saved message, or
// the refusal, which names the cause and the fix. The refusal is also returned, for a dialog to show beside its form.
export function useData<T>(path: string) {
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
