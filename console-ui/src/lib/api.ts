// The console's JSON API, signed in with the console's own session cookie. A refusal carries a message that names
// the cause and the fix: it is shown as it comes.
export class Refused extends Error {}

// ponytail: a flag read while `send` builds its request, before its first await, so only the call `preview` starts
// carries it. A per-call option if a change ever sends two requests.
let previewing = false;

/// Runs a change as a preview: the console drafts and checks it, answers with its diff, and saves nothing.
export function preview<T>(run: () => Promise<T>): Promise<T> {
  previewing = true;
  try {
    return run();
  } finally {
    previewing = false;
  }
}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = body === undefined ? {} : { "content-type": "application/json" };
  if (previewing) headers["x-enterplace-preview"] = "1";
  const response = await fetch(`/console/api/${path}`, {
    method,
    credentials: "same-origin",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) {
    // Back here once signed in: the console keeps the path and this page's # route.
    window.location.href = `/console/sign-in?next=${encodeURIComponent(location.pathname + location.hash)}`;
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Refused(data.error ?? `The gateway answered ${response.status}. Reload the page and try again.`);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => send<T>("GET", path),
  post: (path: string, body: unknown) => send<{ message: string }>("POST", path, body),
  put: (path: string, body: unknown) => send<{ message: string }>("PUT", path, body),
  del: (path: string, body?: unknown) => send<{ message: string }>("DELETE", path, body),
};

export const part = encodeURIComponent;

export type Me = {
  name: string;
  role: string;
  edit_policy: boolean;
  credentials: boolean;
  source: "file" | "store";
  policy: string;
  observe: boolean;
  tools: { href: string; label: string }[];
  /// Whether every request must name its person. Missing on an older gateway: the app then hides the control.
  names?: Names;
};

/// `required`: a request with no person token is refused. `passthrough`: a provider takes subscription logins, the
/// only place a request can come without a name; with none, `required` is true and there is nothing to switch.
export type Names = { required: boolean; passthrough: boolean };

/// The person the gateway records for a request that named nobody.
export const UNNAMED = "unknown";
