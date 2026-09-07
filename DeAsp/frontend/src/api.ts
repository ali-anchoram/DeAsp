const BASE = "/api";

async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(err.detail ?? r.statusText);
  }
  return r.json();
}

export const api = {
  parseRequest: (raw_request: string) =>
    post("/parse-request", { raw_request }),

  fetchUrl: (url: string, verify_ssl: boolean, cookies?: string) =>
    post("/fetch-url", { url, verify_ssl, cookies }),

  login: (login_url: string, credentials: Record<string, string>, verify_ssl: boolean, extra_cookies?: string) =>
    post("/login", { login_url, credentials, verify_ssl, extra_cookies }),

  replay: (method: string, url: string, headers: Record<string, string>, body: string, verify_ssl: boolean, extra_cookies?: string) =>
    post("/replay", { method, url, headers, body, verify_ssl, extra_cookies }),

  decodeViewstate: (viewstate: string) =>
    post("/decode-viewstate", { viewstate }),

  checkMac: (method: string, url: string, headers: Record<string, string>, body: string, verify_ssl: boolean, extra_cookies?: string) =>
    post("/check-mac", { method, url, headers, body, verify_ssl, extra_cookies }),

  parseAjax: (body: string) =>
    post("/parse-ajax-response", { body }),
};
