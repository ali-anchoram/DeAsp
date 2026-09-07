import React, { useState, useCallback } from "react";
import { api } from "./api";
import {
  TabId, ParsedRequest, Param, ReplayResponse,
  MacResult, ViewStateInfo, FetchResult,
} from "./types";
import ParamEditor from "./components/ParamEditor";
import ViewStatePanel from "./components/ViewStatePanel";
import ResponsePanel from "./components/ResponsePanel";

// ── helpers ───────────────────────────────────────────────────────────────────

function rebuildBody(params: Param[]): string {
  return params
    .map(p => `${encodeURIComponent(p.name)}=${encodeURIComponent(p.value)}`)
    .join("&");
}

// ── Mac Checker overlay ───────────────────────────────────────────────────────

function MacCheckerCard({
  result,
  onClose,
}: {
  result: MacResult;
  onClose: () => void;
}) {
  const vuln = result.vulnerable;
  const color = vuln === undefined ? "#58a6ff" : vuln ? "#f85149" : "#56d364";
  const icon = vuln === undefined ? "🔍" : vuln ? "🔓" : "🔒";
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
      <div
        className="rounded-lg border p-6 max-w-lg w-full mx-4"
        style={{ background: "#161b22", borderColor: color }}
      >
        <div className="flex items-start justify-between mb-4">
          <h3 className="text-lg font-bold" style={{ color }}>
            {icon} ViewState MAC Check
          </h3>
          <button onClick={onClose} className="text-[#8b949e] hover:text-white text-xl">✕</button>
        </div>

        <div
          className="rounded p-4 mb-4 border text-sm font-semibold"
          style={{ background: vuln ? "#2d0d0d" : vuln === false ? "#0a1f0c" : "#0d2244", borderColor: color, color }}
        >
          {result.message}
        </div>

        <div className="space-y-2 text-xs text-[#8b949e]">
          {result.mac_algorithm && (
            <div className="flex gap-2">
              <span className="w-32">Algorithm</span>
              <span className="text-[#c9d1d9]">{result.mac_algorithm}</span>
            </div>
          )}
          {result.mac_length !== undefined && (
            <div className="flex gap-2">
              <span className="w-32">MAC length</span>
              <span className="text-[#c9d1d9]">{result.mac_length} bytes</span>
            </div>
          )}
          {result.response_status !== undefined && (
            <div className="flex gap-2">
              <span className="w-32">Response status</span>
              <span className="text-[#c9d1d9]">{result.response_status}</span>
            </div>
          )}
        </div>

        {result.stripped_viewstate && (
          <div className="mt-4">
            <div className="text-xs text-[#8b949e] mb-1">Stripped ViewState (no MAC):</div>
            <textarea
              readOnly
              className="w-full bg-[#0d1117] border border-[#30363d] rounded p-2 text-[#6e7681] text-[10px] font-mono h-20 resize-none"
              value={result.stripped_viewstate}
            />
          </div>
        )}
      </div>
    </div>
  );
}

// ── Intercept Tab ─────────────────────────────────────────────────────────────

function InterceptTab() {
  const [rawHttp, setRawHttp]           = useState("");
  const [parsed, setParsed]             = useState<ParsedRequest | null>(null);
  const [params, setParams]             = useState<Param[]>([]);
  const [response, setResponse]         = useState<ReplayResponse | null>(null);
  const [loading, setLoading]           = useState(false);
  const [parseError, setParseError]     = useState("");
  const [macResult, setMacResult]       = useState<MacResult | null>(null);
  const [macLoading, setMacLoading]     = useState(false);
  const [verifySsl, setVerifySsl]       = useState(false);
  const [leftWidth, setLeftWidth]       = useState(55); // percent

  const parse = useCallback(async () => {
    setParseError("");
    try {
      const r = await api.parseRequest(rawHttp) as ParsedRequest;
      setParsed(r);
      setParams(r.params);
      setResponse(null);
    } catch (e: unknown) {
      setParseError((e as Error).message);
    }
  }, [rawHttp]);

  const send = useCallback(async () => {
    if (!parsed) return;
    setLoading(true);
    try {
      const body = rebuildBody(params);
      const r = await api.replay(parsed.method, parsed.url, parsed.headers, body, verifySsl) as ReplayResponse;
      setResponse(r);
    } catch (e: unknown) {
      alert((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [parsed, params, verifySsl]);

  const checkMac = useCallback(async () => {
    if (!parsed) return;
    setMacLoading(true);
    try {
      const body = rebuildBody(params);
      const r = await api.checkMac(parsed.method, parsed.url, parsed.headers, body, verifySsl) as MacResult;
      setMacResult(r);
    } catch (e: unknown) {
      alert((e as Error).message);
    } finally {
      setMacLoading(false);
    }
  }, [parsed, params, verifySsl]);

  const vsParam = params.find(p => p.name === "__VIEWSTATE");
  const userParams = params.filter(p => p.type === "user");

  return (
    <div className="flex flex-1 min-h-0">
      {/* Left pane */}
      <div
        className="flex flex-col border-r border-[#30363d] min-h-0"
        style={{ width: `${leftWidth}%` }}
      >
        {/* Raw HTTP input */}
        <div className="flex flex-col border-b border-[#30363d]" style={{ height: "45%" }}>
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#30363d] bg-[#161b22]">
            <span className="text-[#8b949e] text-xs font-semibold tracking-wider uppercase">Raw HTTP Request</span>
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-1 text-xs text-[#8b949e] cursor-pointer">
                <input type="checkbox" checked={verifySsl} onChange={e => setVerifySsl(e.target.checked)} />
                Verify SSL
              </label>
              <button
                onClick={parse}
                className="px-3 py-1 rounded text-xs font-bold bg-[#1a365d] text-[#58a6ff] border border-[#58a6ff] hover:bg-[#58a6ff] hover:text-black transition"
              >
                Parse →
              </button>
            </div>
          </div>
          <textarea
            className="flex-1 bg-[#0d1117] text-[#c9d1d9] px-3 py-2 text-[11px] resize-none outline-none font-mono leading-relaxed"
            placeholder={"Paste raw HTTP request here…\n\nPOST /account/Login.aspx HTTP/2\nHost: target.example\nContent-Type: application/x-www-form-urlencoded\n\n__VIEWSTATE=…&__EVENTTARGET=…&txtUser=admin"}
            value={rawHttp}
            onChange={e => setRawHttp(e.target.value)}
            spellCheck={false}
          />
          {parseError && (
            <div className="px-3 py-1 bg-[#2d0d0d] text-[#f85149] text-xs border-t border-[#f85149]">
              {parseError}
            </div>
          )}
        </div>

        {/* Params + controls */}
        <div className="flex-1 overflow-auto flex flex-col min-h-0">
          {parsed ? (
            <>
              {/* Request meta */}
              <div className="px-3 py-2 border-b border-[#30363d] bg-[#161b22] flex items-center gap-3 flex-shrink-0">
                <span
                  className="font-bold text-xs px-2 py-0.5 rounded"
                  style={{
                    background: parsed.method === "POST" ? "#1a365d" : "#0a1f0c",
                    color: parsed.method === "POST" ? "#58a6ff" : "#56d364",
                  }}
                >
                  {parsed.method}
                </span>
                <span className="text-[#c9d1d9] text-xs truncate flex-1" title={parsed.url}>
                  {parsed.url}
                </span>
                {parsed.is_ajax && (
                  <span className="text-[10px] text-[#bc8cff] bg-[#1c1440] px-2 py-0.5 rounded font-bold flex-shrink-0">
                    AJAX
                  </span>
                )}
                {userParams.length > 0 && (
                  <span className="text-[10px] text-[#56d364] bg-[#0f2a16] px-2 py-0.5 rounded font-bold flex-shrink-0">
                    {userParams.length} user param{userParams.length > 1 ? "s" : ""}
                  </span>
                )}
              </div>

              {/* Send + MAC bar */}
              <div className="px-3 py-2 border-b border-[#30363d] bg-[#0d1117] flex items-center gap-2 flex-shrink-0">
                <button
                  onClick={send}
                  disabled={loading}
                  className="px-4 py-1.5 rounded font-bold text-xs bg-[#56d364] text-black hover:bg-[#3fb950] disabled:opacity-50 transition"
                >
                  {loading ? "Sending…" : "▶ Send Request"}
                </button>
                {vsParam && (
                  <button
                    onClick={checkMac}
                    disabled={macLoading}
                    className="px-3 py-1.5 rounded font-bold text-xs bg-[#2d1b00] text-[#f0883e] border border-[#f0883e] hover:bg-[#f0883e] hover:text-black disabled:opacity-50 transition"
                  >
                    {macLoading ? "Testing…" : "🔐 Test MAC Bypass"}
                  </button>
                )}
                <a
                  href="https://viewstatedecoder.azurewebsites.net/"
                  target="_blank"
                  rel="noreferrer"
                  className="ml-auto text-xs text-[#6e7681] hover:text-[#bc8cff] transition"
                >
                  External VS Decoder ↗
                </a>
              </div>

              {/* Param editor */}
              <div className="flex-1 overflow-auto px-3 py-3">
                <ParamEditor params={params} onChange={setParams} />

                {/* Standalone VS panel */}
                {vsParam?.viewstate && (
                  <div className="mt-4 rounded border border-[#f0883e33] bg-[#161b22]">
                    <div className="px-3 py-2 border-b border-[#30363d] flex items-center gap-2">
                      <span className="text-[#f0883e] font-bold text-xs">__VIEWSTATE</span>
                      {vsParam.viewstate.mac_present && (
                        <span className="text-[10px] text-[#f0883e] bg-[#2d1b00] px-1.5 rounded">
                          MAC detected — run Test MAC Bypass ↑
                        </span>
                      )}
                    </div>
                    <div className="p-3">
                      <ViewStatePanel info={vsParam.viewstate} />
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center flex-1 text-[#484f58]">
              <div className="text-center">
                <div className="text-4xl mb-3 opacity-20">🔎</div>
                <div>Paste a request above and click Parse</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Right pane — response */}
      <div className="flex-1 flex flex-col min-h-0">
        <ResponsePanel response={response} loading={loading} />
      </div>

      {/* MAC result modal */}
      {macResult && (
        <MacCheckerCard result={macResult} onClose={() => setMacResult(null)} />
      )}
    </div>
  );
}

// ── Fetch URL Tab ─────────────────────────────────────────────────────────────

function FetchTab() {
  const [url, setUrl]               = useState("");
  const [cookies, setCookies]       = useState("");
  const [verifySsl, setVerifySsl]   = useState(false);
  const [loading, setLoading]       = useState(false);
  const [result, setResult]         = useState<FetchResult | null>(null);
  const [error, setError]           = useState("");
  const [selForm, setSelForm]       = useState(0);

  const fetch_ = async () => {
    setError(""); setLoading(true);
    try {
      const r = await api.fetchUrl(url, verifySsl, cookies || undefined) as FetchResult;
      setResult(r);
      setSelForm(0);
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const form = result?.forms[selForm];

  return (
    <div className="flex flex-col h-full p-4 gap-4 overflow-auto">
      {/* URL input */}
      <div className="rounded border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex gap-2 mb-3">
          <input
            type="url"
            className="flex-1 bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-sm outline-none focus:border-[#58a6ff]"
            placeholder="https://target.example/account/Login.aspx"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") fetch_(); }}
          />
          <button
            onClick={fetch_}
            disabled={loading || !url}
            className="px-5 py-2 rounded font-bold text-sm bg-[#58a6ff] text-black hover:bg-[#79beff] disabled:opacity-50 transition"
          >
            {loading ? "Fetching…" : "Fetch"}
          </button>
        </div>
        <div className="flex gap-4 items-center">
          <input
            type="text"
            className="flex-1 bg-[#0d1117] border border-[#30363d] rounded px-3 py-1.5 text-[#8b949e] text-xs outline-none focus:border-[#30363d]"
            placeholder="Cookies (optional): ASP.NET_SessionId=abc; other=xyz"
            value={cookies}
            onChange={e => setCookies(e.target.value)}
          />
          <label className="flex items-center gap-1 text-xs text-[#8b949e] cursor-pointer flex-shrink-0">
            <input type="checkbox" checked={verifySsl} onChange={e => setVerifySsl(e.target.checked)} />
            Verify SSL
          </label>
        </div>
      </div>

      {error && (
        <div className="rounded border border-[#f85149] bg-[#2d0d0d] px-4 py-3 text-[#f85149] text-sm">
          {error}
        </div>
      )}

      {result && (
        <>
          <div className="flex items-center gap-3 text-xs">
            <span className="text-[#56d364] font-bold">{result.status}</span>
            <span className="text-[#8b949e] truncate">{result.url}</span>
            {result.aspnet_session && (
              <span className="ml-auto text-[#bc8cff]">Session: {result.aspnet_session}</span>
            )}
          </div>

          {result.forms.length === 0 ? (
            <div className="text-[#8b949e] text-sm text-center py-8">No forms found on this page</div>
          ) : (
            <>
              {result.forms.length > 1 && (
                <div className="flex gap-2">
                  {result.forms.map((f, i) => (
                    <button
                      key={i}
                      onClick={() => setSelForm(i)}
                      className="px-3 py-1 rounded text-xs border transition"
                      style={{
                        borderColor: selForm === i ? "#58a6ff" : "#30363d",
                        color: selForm === i ? "#58a6ff" : "#8b949e",
                        background: selForm === i ? "#0d2244" : "#161b22",
                      }}
                    >
                      Form {i + 1} ({f.method})
                    </button>
                  ))}
                </div>
              )}

              {form && (
                <div className="rounded border border-[#30363d] bg-[#161b22]">
                  <div className="px-4 py-2 border-b border-[#30363d] flex items-center gap-3">
                    <span className="font-bold text-xs" style={{ color: form.method === "POST" ? "#58a6ff" : "#56d364" }}>
                      {form.method}
                    </span>
                    <span className="text-[#8b949e] text-xs truncate">{form.action}</span>
                    <span className="ml-auto text-xs text-[#56d364]">{form.params.filter(p => p.type === "user").length} user params</span>
                  </div>
                  <div className="p-4">
                    <ParamEditor
                      params={form.params}
                      onChange={updated => {
                        const newForms = [...result.forms];
                        newForms[selForm] = { ...form, params: updated };
                        setResult({ ...result, forms: newForms });
                      }}
                    />
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}
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
        <div className="text-xs text-[#8b949e] mb-2 font-semibold tracking-wider uppercase">
          ViewState / EventValidation (base64)
        </div>
        <textarea
          className="w-full bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-[#c9d1d9] text-xs font-mono outline-none focus:border-[#58a6ff] resize-none h-28"
          placeholder="Paste base64-encoded ViewState here…"
          value={input}
          onChange={e => setInput(e.target.value)}
          spellCheck={false}
        />
        <button
          onClick={decode}
          disabled={loading || !input.trim()}
          className="mt-2 px-5 py-1.5 rounded font-bold text-sm bg-[#bc8cff] text-black hover:bg-[#d2a8ff] disabled:opacity-50 transition"
        >
          {loading ? "Decoding…" : "Decode ViewState"}
        </button>
      </div>

      {result && (
        <div className="rounded border border-[#30363d] bg-[#161b22] p-4">
          <div className="text-xs text-[#8b949e] font-semibold tracking-wider uppercase mb-3">
            Decoded Result
          </div>
          <ViewStatePanel info={result} />
        </div>
      )}
    </div>
  );
}

// ── Root App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [tab, setTab] = useState<TabId>("intercept");

  const tabs: { id: TabId; label: string; desc: string }[] = [
    { id: "intercept", label: "Intercept",  desc: "Parse & replay requests" },
    { id: "fetch",     label: "Fetch URL",  desc: "Auto-extract forms" },
    { id: "viewstate", label: "ViewState",  desc: "Decode & analyse" },
  ];

  return (
    <div className="flex flex-col h-screen bg-bg text-[#c9d1d9]">
      {/* Header */}
      <header className="flex items-center gap-0 border-b border-[#30363d] bg-[#161b22] flex-shrink-0">
        {/* Brand */}
        <div className="px-4 py-2.5 border-r border-[#30363d] flex-shrink-0">
          <div className="flex items-center gap-2">
            <span className="text-lg font-black tracking-tight" style={{ color: "#f0883e" }}>
              De
            </span>
            <span className="text-lg font-black tracking-tight text-[#58a6ff]">
              Asp
            </span>
            <span className="text-[10px] text-[#6e7681] ml-1 border border-[#30363d] px-1 rounded">
              ASP.NET Pentest
            </span>
          </div>
        </div>

        {/* Tabs */}
        <nav className="flex h-full">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className="flex flex-col justify-center px-5 py-1 text-left transition border-b-2 h-full"
              style={{
                borderBottomColor: tab === t.id ? "#58a6ff" : "transparent",
                background: tab === t.id ? "#0d2244" : "transparent",
                color: tab === t.id ? "#58a6ff" : "#8b949e",
              }}
            >
              <span className="text-xs font-semibold">{t.label}</span>
              <span className="text-[10px] opacity-60">{t.desc}</span>
            </button>
          ))}
        </nav>

        {/* Info chips */}
        <div className="ml-auto flex items-center gap-2 px-4">
          <div className="flex gap-1.5 text-[10px]">
            {[
              { color: "#56d364", label: "USER" },
              { color: "#bc8cff", label: "AJAX" },
              { color: "#58a6ff", label: "EVENT" },
              { color: "#6e7681", label: "SYSTEM" },
            ].map(({ color, label }) => (
              <span
                key={label}
                className="px-1.5 py-0.5 rounded font-bold"
                style={{ color, background: color + "22", border: `1px solid ${color}44` }}
              >
                {label}
              </span>
            ))}
          </div>
        </div>
      </header>

      {/* Tab content */}
      <main className="flex-1 min-h-0 overflow-hidden">
        {tab === "intercept" && <InterceptTab />}
        {tab === "fetch"     && <FetchTab />}
        {tab === "viewstate" && <ViewstateTab />}
      </main>
    </div>
  );
}
