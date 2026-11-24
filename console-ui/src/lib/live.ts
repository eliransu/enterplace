import { createContext, useContext, useEffect, useState } from "react";

// The console's live feed: one /console/events stream (server-sent events) per tab. Each `change` event means a
// request was recorded or the policy or keys changed; `version` counts them, and every page's useData reloads when it
// moves. The browser reconnects by itself after a drop, and the server sends a change at once on reconnect, so a page
// catches up on what it missed.
export type Live = { state: "checking" | "live" | "paused"; last?: number | null; version: number };

export const LiveContext = createContext<Live>({ state: "checking", version: 0 });
export const useLiveFeed = () => useContext(LiveContext);

export function useLiveStream(): Live {
  const [live, setLive] = useState<Live>({ state: "checking", version: 0 });
  useEffect(() => {
    const source = new EventSource("/console/events", { withCredentials: true });
    source.addEventListener("change", (e) => {
      let last: number | null = null;
      try {
        last = (JSON.parse((e as MessageEvent<string>).data) as { last_request_ms: number | null }).last_request_ms;
      } catch {
        // A malformed event still means something changed.
      }
      setLive((l) => ({ state: "live", last, version: l.version + 1 }));
    });
    source.onerror = () => setLive((l) => ({ ...l, state: "paused" }));
    return () => source.close();
  }, []);
  return live;
}
