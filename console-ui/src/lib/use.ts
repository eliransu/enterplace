import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api, Refused } from "./api";
import { useLiveFeed } from "./live";

// Loads one API answer and reloads it after a change. A change shows its answer as a toast: the saved message, or
// the refusal, which names the cause and the fix. The refusal is also returned, for a dialog to show beside its form.
// It reloads on each change from the live feed while `paused` is false (a dialog is open), so the page shows a request
// the moment it is recorded. `every`: the polling fallback (milliseconds), used only while the feed is down.
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
  const live = useLiveFeed();
  const first = useRef(live.version);
  useEffect(() => {
    // The first change event only says the stream opened: the page has just loaded.
    if (paused || live.version === first.current || live.version === 1) return;
    load();
  }, [live.version, paused, load]);
  useEffect(() => {
    if (!every || paused || live.state === "live") return;
    const timer = window.setInterval(load, every);
    return () => window.clearInterval(timer);
  }, [load, every, paused, live.state]);
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
