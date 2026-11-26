import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";

// Each provider's status from its last real connection test. Reading it makes the gateway test any provider never
// tested, changed or tested 10 minutes ago, so it is polled: a provider just added shows its test within seconds.
export type Status = Record<string, { ok: boolean; text: string }>;

export function useProviderStatus(onChange?: () => void, every = 3000) {
  const [status, setStatus] = useState<Status | null>(null);
  const seen = useRef("");
  const changed = useRef(onChange);
  changed.current = onChange;
  const load = useCallback(() => {
    api
      .get<{ status: Status }>("provider-status")
      .then((d) => {
        setStatus(d.status);
        const now = JSON.stringify(d.status);
        if (seen.current && now !== seen.current) changed.current?.();
        seen.current = now;
      })
      .catch(() => {});
  }, []);
  useEffect(() => {
    load();
    const timer = window.setInterval(load, every);
    return () => window.clearInterval(timer);
  }, [load, every]);
  return { status, reload: load };
}
