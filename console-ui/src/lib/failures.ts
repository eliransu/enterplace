// A request the gateway let through and the provider failed, in words: the code or status the record keeps,
// never shown raw. Requests and Overview's live strip read the same map.
export type Failure = {
  code?: string;
  status?: number | null;
  provider?: string;
};

const CODES: Record<string, string> = {
  upstream_unreachable: "Provider unreachable",
  upstream_failed: "Provider did not answer",
  upstream_timeout: "Provider timed out",
  timeout: "Provider timed out",
  timeout_error: "Provider timed out",
  upstream_error: "Provider answered with an error",
  provider_error: "Provider answered with an error",
  overloaded_error: "Provider overloaded",
  api_error: "Provider answered with an error",
};

const STATUSES: Record<number, string> = {
  400: "Provider refused the request",
  401: "Provider refused the key",
  403: "Provider refused the key",
  404: "Model not found at the provider",
  408: "Provider timed out",
  413: "Request too large for the provider",
  429: "Provider rate limit",
  500: "Provider error",
  502: "Provider unreachable",
  503: "Provider overloaded",
  504: "Provider timed out",
  529: "Provider overloaded",
};

/// "Provider unreachable".
export function failureWords(f: Failure): string {
  return (
    (f.code && CODES[f.code]) ||
    (f.status && STATUSES[f.status]) ||
    (f.status ? `Provider error ${f.status}` : "Provider error")
  );
}

/// "Provider unreachable (openai)".
export function failureText(f: Failure): string {
  return f.provider ? `${failureWords(f)} (${f.provider})` : failureWords(f);
}
