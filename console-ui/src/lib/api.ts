// The console's JSON API, signed in with the console's own session cookie. A refusal carries a message that names
// the cause and the fix: it is shown as it comes.
export class Refused extends Error {}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/console/api/${path}`, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) {
    window.location.href = "/console/sign-in";
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
  del: (path: string) => send<{ message: string }>("DELETE", path),
};

export const part = encodeURIComponent;

export type Me = { name: string; role: string; edit_policy: boolean; credentials: boolean; source: "file" | "store"; policy: string };
