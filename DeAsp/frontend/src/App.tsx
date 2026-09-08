import React, { useState, useCallback, useRef, useEffect } from "react";
import { api } from "./api";
import {
  TabId, ParsedRequest, Param, ReplayResponse,
  MacResult, ViewStateInfo, FetchResult, FetchedForm,
} from "./types";
import ParamEditor from "./components/ParamEditor";
import ViewStatePanel from "./components/ViewStatePanel";
import ResponsePanel from "./components/ResponsePanel";

// ── helpers ───────────────────────────────────────────────────────────────────

function rebuildBody(params: Param[]): string {
  return params.filter(p => p.source !== "query")
    .map(p => `${encodeURIComponent(p.name)}=${encodeURIComponent(p.value)}`).join("&");
}

function rebuildQueryString(params: Param[]): string {
  return params.filter(p => p.source === "query")
    .map(p => `${encodeURIComponent(p.name)}=${encodeURIComponent(p.value)}`).join("&");
}

/** Reconstruct the full request URL from a parsed request's url_base plus any
 *  edited query-string params (falls back to the original url if there's no
 *  url_base, e.g. requests parsed before this field existed). */
function rebuildUrl(parsed: { url: string; url_base?: string }, params: Param[]): string {
  if (!parsed.url_base) return parsed.url;
  const qs = rebuildQueryString(params);
  return qs ? `${parsed.url_base}?${qs}` : parsed.url_base;
}

function cookieDictToStr(d: Record<string, string>): string {
  return Object.entries(d).map(([k, v]) => `${k}=${v}`).join("; ");
}

// ── Cookie Manager ────────────────────────────────────────────────────────────

function CookieManager({
  cookies,
  onChange,
}: {
  cookies: Record<string, string>;
  onChange: (c: Record<string, string>) => void;
}) {
  const [open, setOpen] = useState(false);
  const [raw, setRaw] = useState(cookieDictToStr(cookies));
  const sessionId = cookies["ASP.NET_SessionId"];

  useEffect(() => {
    setRaw(cookieDictToStr(cookies));
  }, [cookies]);

  const apply = () => {
    const d: Record<string, string> = {};
    raw.split(";").forEach(c => {
      const [k, ...vs] = c.trim().split("=");
      if (k?.trim()) d[k.trim()] = vs.join("=").trim();
    });
    onChange(d);
  };

  const count = Object.keys(cookies).length;

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-2 px-3 py-1.5 rounded text-xs border transition"
        style={{
          borderColor: sessionId ? "#56d364" : "#30363d",
          color: sessionId ? "#56d364" : "#8b949e",
          background: sessionId ? "#0f2a16" : "#161b22",
        }}
      >
        🍪 {count} cookie{count !== 1 ? "s" : ""}
        {sessionId && <span className="text-[10px] text-[#56d364]">✓ session</span>}
        <span>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="absolute top-full mt-1 right-0 z-50 w-96 rounded border border-[#30363d] bg-[#161b22] shadow-xl p-3">
          <div className="text-[10px] text-[#8b949e] mb-1 uppercase tracking-wider">
            Cookies — edit then Apply
          </div>
          <textarea
            className="w-full bg-[#0d1117] border border-[#30363d] rounded px-2 py-1.5 text-[#c9d1d9] text-[11px] font-mono h-28 resize-none outline-none focus:border-[#58a6ff]"
            value={raw}
            onChange={e => setRaw(e.target.value)}
            spellCheck={false}
          />
          <div className="flex gap-2 mt-2">
            <button
              onClick={apply}
              className="px-3 py-1 rounded text-xs bg-[#56d364] text-black font-bold hover:bg-[#3fb950]"
            >
              Apply
            </button>
            <button
              onClick={() => { onChange({}); setRaw(""); }}
              className="px-3 py-1 rounded text-xs bg-[#2d0d0d] text-[#f85149] border border-[#f85149] hover:opacity-80"
            >
              Clear all
            </button>
            {sessionId && (
              <span className="ml-auto text-[10px] text-[#56d364] self-center">
                Session: {sessionId.slice(0, 16)}…
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Rendered Page Viewer ──────────────────────────────────────────────────────

function RenderedPage({ html, label }: { html: string; label: string }) {
  const [show, setShow] = useState(false);
  if (!html) return null;

  // Simple XSS reflection check
  const xssProbes = ["<script", "javascript:", "onerror=", "onload=", "alert(", "prompt(", "confirm("];
  const lc = html.toLowerCase();
  const xssFound = xssProbes.filter(p => lc.includes(p));

  return (
    <div className="mt-2 rounded border border-[#30363d]">
      <button
        onClick={() => setShow(v => !v)}
        className="w-full flex items-center justify-between px-3 py-2 text-xs hover:bg-[#1a1f2e] transition"
      >
        <span className="text-[#58a6ff] font-semibold">🖥 {label}</span>
        <div className="flex items-center gap-2">
          {xssFound.length > 0 && (
            <span className="text-[#f85149] font-bold text-[10px] bg-[#2d0d0d] px-2 py-0.5 rounded border border-[#f85149]">
              ⚡ POSSIBLE XSS: {xssFound[0]}
            </span>
          )}
          <span className="text-[#8b949e]">{show ? "▲ hide" : "▼ show"}</span>
        </div>
      </button>

      {show && (
        <div className="border-t border-[#30363d]">
          {/* Sandboxed iframe rendering */}
          <iframe
            title={label}
            sandbox="allow-same-origin"
            srcDoc={`<!doctype html><html><head>
              <style>body{background:#fff;font-family:sans-serif;font-size:14px;padding:12px;}</style>
              </head><body>${html}</body></html>`}
            className="w-full border-0 bg-white"
            style={{ height: "300px" }}
          />
          {/* Raw HTML */}
          <details className="border-t border-[#30363d]">
            <summary className="px-3 py-1 text-xs text-[#8b949e] cursor-pointer hover:text-[#c9d1d9]">
              Raw HTML source
            </summary>
            <pre className="px-3 py-2 text-[10px] text-[#8b949e] overflow-auto max-h-48 bg-[#0d1117] font-mono whitespace-pre-wrap break-all">
              {html}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}

// ── Mac Checker modal ─────────────────────────────────────────────────────────

function MacModal({ result, onClose }: { result: MacResult; onClose: () => void }) {
  const vuln = result.vulnerable;
  const color = vuln === undefined ? "#58a6ff" : vuln ? "#f85149" : "#56d364";
  const icon  = vuln === undefined ? "🔍" : vuln ? "🔓" : "🔒";
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
      <div className="rounded-lg border p-6 max-w-lg w-full mx-4 bg-[#161b22]" style={{ borderColor: color }}>
        <div className="flex items-start justify-between mb-4">
          <h3 className="text-lg font-bold" style={{ color }}>{icon} ViewState MAC Check</h3>
          <button onClick={onClose} className="text-[#8b949e] hover:text-white text-xl">✕</button>
        </div>
        <div className="rounded p-4 mb-4 border text-sm font-semibold"
             style={{ background: vuln ? "#2d0d0d" : vuln === false ? "#0a1f0c" : "#0d2244", borderColor: color, color }}>
          {result.message}
        </div>
        <div className="space-y-2 text-xs text-[#8b949e]">
          {result.mac_algorithm && <div className="flex gap-2"><span className="w-32">Algorithm</span><span className="text-[#c9d1d9]">{result.mac_algorithm}</span></div>}
          {result.mac_length !== undefined && <div className="flex gap-2"><span className="w-32">MAC length</span><span className="text-[#c9d1d9]">{result.mac_length}B</span></div>}
          {result.response_status !== undefined && <div className="flex gap-2"><span className="w-32">Response</span><span className="text-[#c9d1d9]">{result.response_status}</span></div>}
        </div>
        {result.stripped_viewstate && (
          <div className="mt-4">
            <div className="text-xs text-[#8b949e] mb-1">Stripped ViewState (no MAC):</div>
            <textarea readOnly className="w-full bg-[#0d1117] border border-[#30363d] rounded p-2 text-[#6e7681] text-[10px] font-mono h-16 resize-none" value={result.stripped_viewstate} />
          </div>
        )}
      </div>
    </div>
  );
}

// ── Login Tab ─────────────────────────────────────────────────────────────────

// Field-name substrings that hint at username vs. other text inputs, in
// priority order — checked case-insensitively against name/id.
const USERNAME_HINTS = ["username", "user", "email", "login", "signin", "logon", "userid", "uid"];
const CUSTOM_FIELD = "__custom__";

function scoreUsernameCandidate(name: string): number {
  const lc = name.toLowerCase();
  const idx = USERNAME_HINTS.findIndex(h => lc.includes(h));
  return idx === -1 ? USERNAME_HINTS.length : idx; // lower = better match
}

function LoginTab({ cookies, onCookies }: { cookies: Record<string, string>; onCookies: (c: Record<string, string>) => void }) {
  const [loginUrl, setLoginUrl]     = useState("");
  const [userField, setUserField]   = useState("");
  const [passField, setPassField]   = useState("");
  const [userFieldCustom, setUserFieldCustom] = useState("");
  const [passFieldCustom, setPassFieldCustom] = useState("");
  const [username, setUsername]     = useState("");
  const [password, setPassword]     = useState("");
  const [verifySsl, setVerifySsl]   = useState(false);
  const [loading, setLoading]       = useState(false);
  const [detecting, setDetecting]   = useState(false);
  const [detectError, setDetectError] = useState("");
  const [fields, setFields]         = useState<Param[] | null>(null);
  const [result, setResult]         = useState<null | {
    aspnet_session?: string; likely_success: boolean; final_url: string;
    response_status: number; cookies: Record<string, string>;
  }>(null);
  const [error, setError]           = useState("");

  const userCandidates = (fields ?? []).filter(f => ["text", "email", "tel", ""].includes(f.input_type ?? ""));
  const passCandidates = (fields ?? []).filter(f => f.input_type === "password");

  const detectFields = async () => {
    if (!loginUrl) return;
    setDetectError(""); setDetecting(true);
    try {
      const r = await api.fetchUrl(loginUrl, verifySsl) as FetchResult;
      // Prefer the form that actually has a password field — that's the login form.
      const withPassword = r.forms.find(f => f.all_params.some(p => p.input_type === "password"));
      const form = withPassword ?? r.forms[0];
      if (!form) {
        setDetectError("No form found on that page — check the URL, or enter field names manually below.");
        setFields([]);
        return;
      }
      setFields(form.all_params);

      const pwCandidates = form.all_params.filter(p => p.input_type === "password");
      const userCands = form.all_params.filter(p => ["text", "email", "tel", ""].includes(p.input_type ?? ""));

      if (pwCandidates.length > 0) {
        setPassField(pwCandidates[0].name);
      } else {
        setPassField(CUSTOM_FIELD);
      }

      if (userCands.length > 0) {
        const best = [...userCands].sort((a, b) => scoreUsernameCandidate(a.name) - scoreUsernameCandidate(b.name))[0];
        setUserField(best.name);
      } else {
        setUserField(CUSTOM_FIELD);
      }

      if (pwCandidates.length === 0 && userCands.length === 0) {
        setDetectError("Found a form but no obvious username/password inputs — pick fields manually below.");
      }
    } catch (e: unknown) {
      setDetectError((e as Error).message);
      setFields([]);
    } finally {
      setDetecting(false);
    }
  };

  const effectiveUserField = userField === CUSTOM_FIELD ? userFieldCustom : userField;
  const effectivePassField = passField === CUSTOM_FIELD ? passFieldCustom : passField;

  const login = async () => {
    setError(""); setLoading(true);
    try {
      const creds: Record<string, string> = {
        [effectiveUserField]: username,
        [effectivePassField]: password,
      };
      const r = await (api as unknown as { login: (a: string, c: Record<string, string>, v: boolean, ec: string) => Promise<unknown> }).login(
        loginUrl, creds, verifySsl, cookieDictToStr(cookies)
      ) as typeof result & { cookies: Record<string, string> };
      setResult(r);
      if (r && r.cookies) {
        onCookies({ ...cookies, ...r.cookies });
      }
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full p-4 gap-4 max-w-2xl mx-auto w-full overflow-auto">
      <div className="rounded border border-[#30363d] bg-[#161b22] p-4">
        <div className="text-xs text-[#8b949e] mb-3 uppercase tracking-wider font-semibold">Login to grab session cookie</div>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-[#8b949e] block mb-1">Login page URL</label>
            <div className="flex gap-2">
              <input type="url" className="flex-1 bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-sm outline-none focus:border-[#58a6ff]"
                placeholder="https://target.example/account/Login.aspx"
                value={loginUrl}
                onChange={e => { setLoginUrl(e.target.value); setFields(null); }}
                onBlur={detectFields}
                onKeyDown={e => { if (e.key === "Enter") detectFields(); }} />
              <button onClick={detectFields} disabled={detecting || !loginUrl}
                className="px-3 py-2 rounded text-xs font-bold bg-[#1a365d] text-[#58a6ff] border border-[#58a6ff] hover:bg-[#58a6ff] hover:text-black disabled:opacity-50 transition flex-shrink-0">
                {detecting ? "Detecting…" : "🔍 Detect Fields"}
              </button>
            </div>
            {detectError && <div className="text-[#f0883e] text-xs mt-1">{detectError}</div>}
            {fields && fields.length > 0 && !detectError && (
              <div className="text-[#56d364] text-xs mt-1">
                ✓ Found {fields.length} field{fields.length !== 1 ? "s" : ""} on the form — username/password guessed below, override if wrong.
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Username field</label>
              {userCandidates.length > 0 ? (
                <select value={userField} onChange={e => setUserField(e.target.value)}
                  className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-xs outline-none focus:border-[#58a6ff]">
                  {userCandidates.map(f => (
                    <option key={f.name} value={f.name}>{f.name} ({f.input_type || "text"})</option>
                  ))}
                  <option value={CUSTOM_FIELD}>Other (type manually)…</option>
                </select>
              ) : (
                <input type="text" className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-xs outline-none focus:border-[#58a6ff]"
                  placeholder="ctl00$cphMaster$txtUsername"
                  value={userField === CUSTOM_FIELD ? userFieldCustom : userField}
                  onChange={e => { setUserField(CUSTOM_FIELD); setUserFieldCustom(e.target.value); }} />
              )}
              {userCandidates.length > 0 && userField === CUSTOM_FIELD && (
                <input type="text" className="w-full mt-1 bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-xs outline-none focus:border-[#58a6ff]"
                  placeholder="ctl00$cphMaster$txtUsername"
                  value={userFieldCustom} onChange={e => setUserFieldCustom(e.target.value)} />
              )}
            </div>
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Password field</label>
              {passCandidates.length > 0 ? (
                <select value={passField} onChange={e => setPassField(e.target.value)}
                  className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-xs outline-none focus:border-[#58a6ff]">
                  {passCandidates.map(f => (
                    <option key={f.name} value={f.name}>{f.name}</option>
                  ))}
                  <option value={CUSTOM_FIELD}>Other (type manually)…</option>
                </select>
              ) : (
                <input type="text" className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-xs outline-none focus:border-[#58a6ff]"
                  placeholder="ctl00$cphMaster$txtPassword"
                  value={passField === CUSTOM_FIELD ? passFieldCustom : passField}
                  onChange={e => { setPassField(CUSTOM_FIELD); setPassFieldCustom(e.target.value); }} />
              )}
              {passCandidates.length > 0 && passField === CUSTOM_FIELD && (
                <input type="text" className="w-full mt-1 bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-xs outline-none focus:border-[#58a6ff]"
                  placeholder="ctl00$cphMaster$txtPassword"
                  value={passFieldCustom} onChange={e => setPassFieldCustom(e.target.value)} />
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Username</label>
              <input type="text" className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-sm outline-none focus:border-[#58a6ff]"
                value={username} onChange={e => setUsername(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-[#8b949e] block mb-1">Password</label>
              <input type="password" className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-sm outline-none focus:border-[#58a6ff]"
                value={password} onChange={e => setPassword(e.target.value)} />
            </div>
          </div>

          <div className="flex items-center justify-between">
            <label className="flex items-center gap-2 text-xs text-[#8b949e] cursor-pointer">
              <input type="checkbox" checked={verifySsl} onChange={e => setVerifySsl(e.target.checked)} />
              Verify SSL
            </label>
            <button onClick={login} disabled={loading || !loginUrl || !username || !effectiveUserField || !effectivePassField}
              className="px-5 py-2 rounded font-bold text-sm bg-[#58a6ff] text-black hover:bg-[#79beff] disabled:opacity-50 transition">
              {loading ? "Logging in…" : "Login →"}
            </button>
          </div>
        </div>
      </div>

      {error && <div className="rounded border border-[#f85149] bg-[#2d0d0d] px-4 py-3 text-[#f85149] text-sm">{error}</div>}

      {result && (
        <div className={`rounded border p-4 ${result.likely_success ? "border-[#56d364] bg-[#0a1f0c]" : "border-[#f0883e] bg-[#2d1b00]"}`}>
          <div className={`font-bold text-sm mb-3 ${result.likely_success ? "text-[#56d364]" : "text-[#f0883e]"}`}>
            {result.likely_success ? "✓ Login appears successful" : "⚠ Login may have failed — check cookies below"}
          </div>
          <div className="space-y-1 text-xs">
            <div className="flex gap-2"><span className="text-[#8b949e] w-24">Final URL</span><span className="text-[#c9d1d9] truncate">{result.final_url}</span></div>
            <div className="flex gap-2"><span className="text-[#8b949e] w-24">Status</span><span className="text-[#c9d1d9]">{result.response_status}</span></div>
            {result.aspnet_session && <div className="flex gap-2"><span className="text-[#8b949e] w-24">Session ID</span><span className="text-[#56d364] font-mono">{result.aspnet_session}</span></div>}
          </div>
          <div className="mt-3 text-xs text-[#8b949e]">
            Cookies saved to cookie jar — switch to the <span className="text-[#58a6ff]">Fetch URL</span> or <span className="text-[#58a6ff]">Intercept</span> tab to continue.
          </div>
        </div>
      )}
    </div>
  );
}

// ── Fetch+Attack Tab ──────────────────────────────────────────────────────────

function FetchTab({ globalCookies, onCookies }: { globalCookies: Record<string, string>; onCookies: (c: Record<string, string>) => void }) {
  const [url, setUrl]             = useState("");
  const [verifySsl, setVerifySsl] = useState(false);
  const [loading, setLoading]     = useState(false);
  const [result, setResult]       = useState<FetchResult | null>(null);
  const [selForm, setSelForm]     = useState(0);
  const [params, setParams]       = useState<Param[]>([]);
  const [response, setResponse]   = useState<ReplayResponse | null>(null);
  const [sending, setSending]     = useState(false);
  const [error, setError]         = useState("");
  const [macResult, setMacResult] = useState<MacResult | null>(null);
  const [macLoading, setMacLoading] = useState(false);
  const [showAll, setShowAll]     = useState(false);

  const fetch_ = async () => {
    setError(""); setLoading(true); setResponse(null);
    try {
      const cookieStr = cookieDictToStr(globalCookies);
      const r = await api.fetchUrl(url, verifySsl, cookieStr || undefined) as FetchResult;
      setResult(r);
      setSelForm(0);
      const form = r.forms[0];
      if (form) setParams(form.all_params);
      // merge any new cookies
      if (r.cookies) onCookies({ ...globalCookies, ...r.cookies });
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const form: FetchedForm | undefined = result?.forms[selForm];

  const send = async () => {
    if (!form) return;
    setSending(true);
    try {
      const body = rebuildBody(params);
      const hdrs: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": url,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
      };
      const cookieStr = cookieDictToStr(globalCookies);
      const r = await api.replay(form.method, form.action, hdrs, body, verifySsl, cookieStr || undefined) as ReplayResponse;
      setResponse(r);
      if (r.new_cookies) onCookies({ ...globalCookies, ...r.new_cookies });
    } catch (e: unknown) {
      alert((e as Error).message);
    } finally {
      setSending(false);
    }
  };

  const checkMac = async () => {
    if (!form) return;
    setMacLoading(true);
    try {
      const body = rebuildBody(params);
      const hdrs: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": url,
      };
      const r = await api.checkMac(form.method, form.action, hdrs, body, verifySsl, cookieDictToStr(globalCookies) || undefined) as MacResult;
      setMacResult(r);
    } catch (e: unknown) {
      alert((e as Error).message);
    } finally {
      setMacLoading(false);
    }
  };

  const selectForm = (i: number) => {
    setSelForm(i);
    if (result?.forms[i]) setParams(result.forms[i].all_params);
    setResponse(null);
  };

  const displayParams = showAll ? params : params.filter(p => p.type === "user");
  const vsParam = params.find(p => p.name === "__VIEWSTATE");
  const userCount = params.filter(p => p.type === "user").length;

  return (
    <div className="flex flex-1 min-h-0">
      {/* Left */}
      <div className="flex flex-col border-r border-[#30363d] min-h-0 overflow-hidden" style={{ width: "55%" }}>
        {/* URL bar */}
        <div className="flex gap-2 p-3 border-b border-[#30363d] bg-[#161b22] flex-shrink-0">
          <input
            type="url"
            className="flex-1 bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-sm outline-none focus:border-[#58a6ff]"
            placeholder="https://target.example/account/Survey.aspx"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") fetch_(); }}
          />
          <label className="flex items-center gap-1 text-xs text-[#8b949e] cursor-pointer flex-shrink-0">
            <input type="checkbox" checked={verifySsl} onChange={e => setVerifySsl(e.target.checked)} />
            SSL
          </label>
          <button onClick={fetch_} disabled={loading || !url}
            className="px-4 py-2 rounded font-bold text-xs bg-[#58a6ff] text-black hover:bg-[#79beff] disabled:opacity-50 transition flex-shrink-0">
            {loading ? "Fetching…" : "Fetch"}
          </button>
        </div>

        {error && <div className="px-3 py-2 bg-[#2d0d0d] text-[#f85149] text-xs border-b border-[#f85149]">{error}</div>}

        {result && (
          <>
            {/* Form selector */}
            {result.forms.length > 1 && (
              <div className="flex gap-2 px-3 py-2 border-b border-[#30363d] flex-shrink-0 overflow-x-auto">
                {result.forms.map((f, i) => (
                  <button key={i} onClick={() => selectForm(i)}
                    className="px-3 py-1 rounded text-xs border flex-shrink-0 transition"
                    style={{
                      borderColor: selForm === i ? "#58a6ff" : "#30363d",
                      color: selForm === i ? "#58a6ff" : "#8b949e",
                      background: selForm === i ? "#0d2244" : "#161b22",
                    }}>
                    Form {i + 1} · {f.param_counts.user} user
                  </button>
                ))}
              </div>
            )}

            {form && (
              <>
                {/* Meta + controls */}
                <div className="px-3 py-2 border-b border-[#30363d] bg-[#0d1117] flex items-center gap-2 flex-wrap flex-shrink-0">
                  <span className="font-bold text-xs px-2 py-0.5 rounded"
                    style={{ background: form.method === "POST" ? "#1a365d" : "#0a1f0c", color: form.method === "POST" ? "#58a6ff" : "#56d364" }}>
                    {form.method}
                  </span>
                  <span className="text-[#8b949e] text-xs truncate flex-1" title={form.action}>{form.action}</span>
                  <span className="text-[10px] font-bold text-[#56d364] bg-[#0f2a16] px-1.5 py-0.5 rounded flex-shrink-0">
                    {userCount} user param{userCount !== 1 ? "s" : ""}
                  </span>
                </div>

                <div className="px-3 py-2 border-b border-[#30363d] flex items-center gap-2 flex-shrink-0">
                  <button onClick={send} disabled={sending}
                    className="px-4 py-1.5 rounded font-bold text-xs bg-[#56d364] text-black hover:bg-[#3fb950] disabled:opacity-50 transition">
                    {sending ? "Sending…" : "▶ Send Request"}
                  </button>
                  {vsParam && (
                    <button onClick={checkMac} disabled={macLoading}
                      className="px-3 py-1.5 rounded font-bold text-xs bg-[#2d1b00] text-[#f0883e] border border-[#f0883e] hover:bg-[#f0883e] hover:text-black disabled:opacity-50 transition">
                      {macLoading ? "Testing…" : "🔐 MAC Bypass"}
                    </button>
                  )}
                  <label className="flex items-center gap-1 text-xs text-[#8b949e] cursor-pointer ml-auto">
                    <input type="checkbox" checked={showAll} onChange={e => setShowAll(e.target.checked)} />
                    Show all params
                  </label>
                </div>

                {/* Param editor */}
                <div className="flex-1 overflow-auto px-3 py-3">
                  {userCount === 0 && !showAll ? (
                    <div className="text-center py-8 text-[#484f58]">
                      <div className="text-2xl mb-2">🔍</div>
                      No user-controllable inputs found on this form.
                      <div className="text-xs mt-1">
                        <button onClick={() => setShowAll(true)} className="text-[#58a6ff] underline">Show all {params.length} params</button>
                      </div>
                    </div>
                  ) : (
                    <ParamEditor
                      params={displayParams}
                      onChange={updated => {
                        const nameSet = new Set(updated.map(p => p.name));
                        const merged = params.map(p => {
                          const u = updated.find(up => up.name === p.name);
                          return u ?? p;
                        });
                        setParams(merged);
                      }}
                    />
                  )}

                  {vsParam?.viewstate && (
                    <div className="mt-4 rounded border border-[#f0883e33] bg-[#161b22]">
                      <div className="px-3 py-2 border-b border-[#30363d] flex items-center gap-2">
                        <span className="text-[#f0883e] font-bold text-xs">__VIEWSTATE Inspector</span>
                        {vsParam.viewstate.mac_present && (
                          <span className="text-[10px] text-[#f0883e] bg-[#2d1b00] px-1.5 rounded">MAC present</span>
                        )}
                      </div>
                      <div className="p-3"><ViewStatePanel info={vsParam.viewstate} /></div>
                    </div>
                  )}
                </div>
              </>
            )}

            {!form && (
              <div className="flex items-center justify-center flex-1 text-[#484f58]">No forms found on this page</div>
            )}
          </>
        )}

        {!result && !loading && (
          <div className="flex items-center justify-center flex-1 text-[#484f58]">
            <div className="text-center">
              <div className="text-4xl mb-3 opacity-20">🌐</div>
              <div>Enter a URL above and click Fetch</div>
              <div className="text-xs mt-1 opacity-60">Set cookies first via Login tab if authentication is required</div>
            </div>
          </div>
        )}
      </div>

      {/* Right — response */}
      <div className="flex-1 flex flex-col min-h-0">
        <ResponsePanel response={response} loading={sending} renderPages />
      </div>

      {macResult && <MacModal result={macResult} onClose={() => setMacResult(null)} />}
    </div>
  );
}

// ── Intercept Tab (raw HTTP) ──────────────────────────────────────────────────

function InterceptTab({ globalCookies, onCookies }: { globalCookies: Record<string, string>; onCookies: (c: Record<string, string>) => void }) {
  const [rawHttp, setRawHttp]       = useState("");
  const [parsed, setParsed]         = useState<ParsedRequest | null>(null);
  const [params, setParams]         = useState<Param[]>([]);
  const [response, setResponse]     = useState<ReplayResponse | null>(null);
  const [loading, setLoading]       = useState(false);
  const [parseError, setParseError] = useState("");
  const [macResult, setMacResult]   = useState<MacResult | null>(null);
  const [macLoading, setMacLoading] = useState(false);
  const [verifySsl, setVerifySsl]   = useState(false);
  const [scheme, setScheme]         = useState<"http" | "https">("https");
  const [showAll, setShowAll]       = useState(false);

  const parse = useCallback(async () => {
    setParseError("");
    try {
      const r = await api.parseRequest(rawHttp, scheme) as ParsedRequest;
      setParsed(r); setParams(r.params); setResponse(null);
    } catch (e: unknown) {
      setParseError((e as Error).message);
    }
  }, [rawHttp, scheme]);

  const send = useCallback(async () => {
    if (!parsed) return;
    setLoading(true);
    try {
      const url = rebuildUrl(parsed, params);
      const body = rebuildBody(params);
      const cookieStr = cookieDictToStr(globalCookies);
      const r = await api.replay(parsed.method, url, parsed.headers, body, verifySsl, cookieStr || undefined) as ReplayResponse;
      setResponse(r);
      if (r.new_cookies) onCookies({ ...globalCookies, ...r.new_cookies });
    } catch (e: unknown) {
      alert((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [parsed, params, verifySsl, globalCookies, onCookies]);

  const checkMac = useCallback(async () => {
    if (!parsed) return;
    setMacLoading(true);
    try {
      const url = rebuildUrl(parsed, params);
      const body = rebuildBody(params);
      const cookieStr = cookieDictToStr(globalCookies);
      const r = await api.checkMac(parsed.method, url, parsed.headers, body, verifySsl, cookieStr || undefined) as MacResult;
      setMacResult(r);
    } catch (e: unknown) {
      alert((e as Error).message);
    } finally {
      setMacLoading(false);
    }
  }, [parsed, params, verifySsl, globalCookies]);

  const vsParam = params.find(p => p.name === "__VIEWSTATE");
  const userCount = params.filter(p => p.type === "user").length;
  const displayParams = showAll ? params : params.filter(p => p.type === "user");

  return (
    <div className="flex flex-1 min-h-0">
      <div className="flex flex-col border-r border-[#30363d] min-h-0" style={{ width: "55%" }}>
        {/* Raw input */}
        <div className="flex flex-col border-b border-[#30363d]" style={{ height: "45%" }}>
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#30363d] bg-[#161b22] flex-shrink-0">
            <span className="text-[#8b949e] text-xs font-semibold uppercase tracking-wider">Raw HTTP Request</span>
            <div className="flex items-center gap-2">
              <select
                value={scheme}
                onChange={e => setScheme(e.target.value as "http" | "https")}
                title="Scheme to use when sending this request — raw HTTP requests don't carry one. Most production ASP.NET targets are HTTPS; pick HTTP for legacy/intranet plaintext apps."
                className="bg-[#0d1117] border border-[#30363d] rounded px-1.5 py-0.5 text-[10px] text-[#8b949e] cursor-pointer"
              >
                <option value="https">HTTPS</option>
                <option value="http">HTTP</option>
              </select>
              <label className="flex items-center gap-1 text-xs text-[#8b949e] cursor-pointer">
                <input type="checkbox" checked={verifySsl} onChange={e => setVerifySsl(e.target.checked)} /> SSL
              </label>
              <button onClick={parse}
                className="px-3 py-1 rounded text-xs font-bold bg-[#1a365d] text-[#58a6ff] border border-[#58a6ff] hover:bg-[#58a6ff] hover:text-black transition">
                Parse →
              </button>
            </div>
          </div>
          <textarea
            className="flex-1 bg-[#0d1117] text-[#c9d1d9] px-3 py-2 text-[11px] resize-none outline-none font-mono leading-relaxed"
            placeholder={"POST /account/MfaVerify.aspx HTTP/2\nHost: target.example\nCookie: ASP.NET_SessionId=…\nContent-Type: application/x-www-form-urlencoded\n\n__VIEWSTATE=…&__EVENTTARGET=…&ctl00%24cphMaster%24txtCode=123456"}
            value={rawHttp}
            onChange={e => setRawHttp(e.target.value)}
            spellCheck={false}
          />
          {parseError && <div className="px-3 py-1 bg-[#2d0d0d] text-[#f85149] text-xs border-t border-[#f85149]">{parseError}</div>}
        </div>

        <div className="flex-1 overflow-auto flex flex-col min-h-0">
          {parsed ? (
            <>
              <div className="px-3 py-2 border-b border-[#30363d] bg-[#161b22] flex items-center gap-3 flex-shrink-0">
                <span className="font-bold text-xs px-2 py-0.5 rounded"
                  style={{ background: parsed.method === "POST" ? "#1a365d" : "#0a1f0c", color: parsed.method === "POST" ? "#58a6ff" : "#56d364" }}>
                  {parsed.method}
                </span>
                <span className="text-[#c9d1d9] text-xs truncate flex-1">{parsed.url}</span>
                {parsed.is_ajax && <span className="text-[10px] text-[#bc8cff] bg-[#1c1440] px-2 py-0.5 rounded font-bold">AJAX</span>}
                <span className="text-[10px] text-[#56d364] bg-[#0f2a16] px-2 py-0.5 rounded font-bold flex-shrink-0">
                  {userCount} user
                </span>
              </div>

              <div className="px-3 py-2 border-b border-[#30363d] flex items-center gap-2 flex-shrink-0">
                <button onClick={send} disabled={loading}
                  className="px-4 py-1.5 rounded font-bold text-xs bg-[#56d364] text-black hover:bg-[#3fb950] disabled:opacity-50 transition">
                  {loading ? "Sending…" : "▶ Send"}
                </button>
                {vsParam && (
                  <button onClick={checkMac} disabled={macLoading}
                    className="px-3 py-1.5 rounded font-bold text-xs bg-[#2d1b00] text-[#f0883e] border border-[#f0883e] hover:bg-[#f0883e] hover:text-black disabled:opacity-50 transition">
                    {macLoading ? "Testing…" : "🔐 MAC"}
                  </button>
                )}
                <label className="flex items-center gap-1 text-xs text-[#8b949e] cursor-pointer ml-auto">
                  <input type="checkbox" checked={showAll} onChange={e => setShowAll(e.target.checked)} />
                  All params
                </label>
              </div>

              <div className="flex-1 overflow-auto px-3 py-3">
                <ParamEditor params={displayParams} onChange={updated => {
                  const merged = params.map(p => {
                    const u = updated.find(up => up.name === p.name);
                    return u ?? p;
                  });
                  setParams(merged);
                }} />
                {vsParam?.viewstate && (
                  <div className="mt-4 rounded border border-[#f0883e33] bg-[#161b22]">
                    <div className="px-3 py-2 border-b border-[#30363d]">
                      <span className="text-[#f0883e] font-bold text-xs">__VIEWSTATE</span>
                      {vsParam.viewstate.mac_present && <span className="ml-2 text-[10px] text-[#f0883e] bg-[#2d1b00] px-1.5 rounded">MAC</span>}
                    </div>
                    <div className="p-3"><ViewStatePanel info={vsParam.viewstate} /></div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center flex-1 text-[#484f58]">
              <div className="text-center"><div className="text-4xl mb-3 opacity-20">📋</div>Paste a raw HTTP request above and click Parse</div>
            </div>
          )}
        </div>
      </div>

      <div className="flex-1 flex flex-col min-h-0">
        <ResponsePanel response={response} loading={loading} renderPages />
      </div>

      {macResult && <MacModal result={macResult} onClose={() => setMacResult(null)} />}
    </div>
  );
}

// ── ViewState Tab ─────────────────────────────────────────────────────────────

function ViewstateTab() {
  const [input, setInput]     = useState("");
  const [result, setResult]   = useState<ViewStateInfo | null>(null);
  const [loading, setLoading] = useState(false);

  const decode = async () => {
    setLoading(true);
    try {
      const r = await api.decodeViewstate(input) as ViewStateInfo;
      setResult(r);
    } catch (e: unknown) {
      alert((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full p-4 gap-4 max-w-4xl mx-auto w-full overflow-auto">
      <div className="rounded border border-[#30363d] bg-[#161b22] p-4">
        <div className="text-xs text-[#8b949e] mb-2 font-semibold uppercase tracking-wider">ViewState / EventValidation (base64)</div>
        <textarea
          className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-xs font-mono outline-none focus:border-[#bc8cff] resize-none h-28"
          placeholder="Paste base64-encoded ViewState…"
          value={input} onChange={e => setInput(e.target.value)} spellCheck={false}
        />
        <button onClick={decode} disabled={loading || !input.trim()}
          className="mt-2 px-5 py-1.5 rounded font-bold text-sm bg-[#bc8cff] text-black hover:bg-[#d2a8ff] disabled:opacity-50 transition">
          {loading ? "Decoding…" : "Decode ViewState"}
        </button>
      </div>
      {result && (
        <div className="rounded border border-[#30363d] bg-[#161b22] p-4">
          <div className="text-xs text-[#8b949e] font-semibold uppercase tracking-wider mb-3">Decoded Result</div>
          <ViewStatePanel info={result} />
        </div>
      )}
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────

export default function App() {
  const [tab, setTab]           = useState<TabId>("fetch");
  const [cookies, setCookies]   = useState<Record<string, string>>({});

  const tabs: { id: TabId; label: string; desc: string }[] = [
    { id: "fetch",     label: "Attack",   desc: "Fetch URL → edit → send" },
    { id: "intercept", label: "Intercept", desc: "Raw HTTP editor" },
    { id: "viewstate", label: "ViewState", desc: "Decode & analyse" },
  ];

  return (
    <div className="flex flex-col h-screen bg-bg text-[#c9d1d9]">
      <header className="flex items-center border-b border-[#30363d] bg-[#161b22] flex-shrink-0">
        <div className="px-4 py-2 border-r border-[#30363d] flex-shrink-0">
          <div className="flex items-center gap-1">
            <span className="text-lg font-black" style={{ color: "#f0883e" }}>De</span>
            <span className="text-lg font-black text-[#58a6ff]">Asp</span>
            <span className="text-[9px] text-[#6e7681] ml-1 border border-[#30363d] px-1 rounded">ASP.NET</span>
          </div>
        </div>

        <nav className="flex h-full">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className="flex flex-col justify-center px-5 py-1 text-left transition border-b-2 h-full"
              style={{
                borderBottomColor: tab === t.id ? "#58a6ff" : "transparent",
                background: tab === t.id ? "#0d2244" : "transparent",
                color: tab === t.id ? "#58a6ff" : "#8b949e",
              }}>
              <span className="text-xs font-semibold">{t.label}</span>
              <span className="text-[10px] opacity-60">{t.desc}</span>
            </button>
          ))}
          {/* Login is a special tab in the same nav */}
          <button onClick={() => setTab("login" as TabId)}
            className="flex flex-col justify-center px-5 py-1 text-left transition border-b-2 h-full"
            style={{
              borderBottomColor: tab === ("login" as TabId) ? "#56d364" : "transparent",
              background: tab === ("login" as TabId) ? "#0a1f0c" : "transparent",
              color: tab === ("login" as TabId) ? "#56d364" : "#8b949e",
            }}>
            <span className="text-xs font-semibold">Login</span>
            <span className="text-[10px] opacity-60">Grab session</span>
          </button>
        </nav>

        {/* Legend + cookie jar */}
        <div className="ml-auto flex items-center gap-3 px-4">
          <div className="flex gap-1 text-[10px]">
            {([["#56d364","USER"],["#bc8cff","AJAX"],["#58a6ff","EVENT"],["#6e7681","SYSTEM"]] as [string,string][]).map(([c,l]) => (
              <span key={l} className="px-1.5 py-0.5 rounded font-bold"
                style={{ color: c, background: c + "22", border: `1px solid ${c}44` }}>{l}</span>
            ))}
          </div>
          <CookieManager cookies={cookies} onChange={setCookies} />
        </div>
      </header>

      <main className="flex-1 min-h-0 overflow-hidden flex flex-col">
        {tab === "fetch"     && <FetchTab globalCookies={cookies} onCookies={setCookies} />}
        {tab === "intercept" && <InterceptTab globalCookies={cookies} onCookies={setCookies} />}
        {tab === "viewstate" && <ViewstateTab />}
        {tab === ("login" as TabId) && <LoginTab cookies={cookies} onCookies={setCookies} />}
      </main>
    </div>
  );
}
