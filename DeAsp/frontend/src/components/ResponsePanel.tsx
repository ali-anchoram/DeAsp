import React, { useState, useEffect } from "react";
import type { ReplayResponse, AjaxPart } from "../types";
import ViewStatePanel from "./ViewStatePanel";

// XSS patterns to look for in content
const XSS_PROBES = ["<script", "javascript:", "onerror=", "onload=", "onfocus=", "alert(", "prompt(", "confirm(", "document.cookie", "eval(", "innerHTML"];

// Patterns so commonly used for entirely benign UI purposes (e.g. href="javascript:void(0)"
// as a no-op link idiom) that flagging them with the same urgency as the others is more
// noise than signal. Still shown as a low-priority match with context, never hidden.
const XSS_LOW_PRIORITY = new Set(["javascript:"]);

function detectXss(content: string): string[] {
  const lc = content.toLowerCase();
  const hits = XSS_PROBES.filter(p => lc.includes(p.toLowerCase()));
  // Sort so a genuinely dangerous match (e.g. "<script") leads the badge text
  // over a low-priority one (e.g. "javascript:") when both are present.
  return hits.sort((a, b) => Number(XSS_LOW_PRIORITY.has(a)) - Number(XSS_LOW_PRIORITY.has(b)));
}

/** ~50 chars of context around each matched pattern's first occurrence, so a
 *  benign idiom like javascript:void(0) is visually distinguishable from a
 *  real payload without hunting through the raw content by hand. */
function matchContexts(content: string, matches: string[]): { pattern: string; context: string }[] {
  const lc = content.toLowerCase();
  return matches.map(pattern => {
    const idx = lc.indexOf(pattern.toLowerCase());
    if (idx === -1) return { pattern, context: "" };
    const start = Math.max(0, idx - 30);
    const end = Math.min(content.length, idx + pattern.length + 40);
    const prefix = start > 0 ? "…" : "";
    const suffix = end < content.length ? "…" : "";
    return { pattern, context: prefix + content.slice(start, end) + suffix };
  });
}

// ── XSS Proof modal ────────────────────────────────────────────────────────────
//
// A pattern match ("contains '<script'") is a hint, not proof — the payload
// could be sitting inside an HTML-encoded attribute, a <textarea>, a comment,
// or a harmless idiom like href="javascript:void(0)". This renders the actual
// content in a sandboxed iframe with scripting ALLOWED (so a genuine injection
// actually runs) but same-origin access DENIED (unique opaque origin — no
// access to DeAsp's cookies, DOM, or parent window beyond postMessage). A
// harness overrides alert/prompt/confirm, document.cookie, fetch, and
// XMLHttpRequest.open to report back via postMessage whenever the payload
// does any of the things real XSS exploits actually do, plus a canary that
// confirms the sandbox's JS environment itself came up — so "nothing fired"
// can be told apart from "the harness never even loaded."
const XSS_HARNESS = `<script>
(function(){
  function report(kind, detail){
    try { window.parent.postMessage({ __deaspXssProof: true, kind: kind, detail: detail }, "*"); } catch (e) {}
  }
  window.alert = function(){ report("alert", "alert(" + Array.prototype.map.call(arguments, String).join(", ") + ")"); };
  window.prompt = function(){ report("prompt", "prompt(" + Array.prototype.map.call(arguments, String).join(", ") + ")"); return null; };
  window.confirm = function(){ report("confirm", "confirm(" + Array.prototype.map.call(arguments, String).join(", ") + ")"); return false; };
  try {
    Object.defineProperty(document, "cookie", {
      get: function(){ report("cookie-read", "document.cookie was read"); return ""; },
      set: function(v){ report("cookie-write", "document.cookie = " + v); },
      configurable: true,
    });
  } catch (e) {}
  var origFetch = window.fetch;
  window.fetch = function(url){ report("network", "fetch(" + url + ")"); return origFetch ? origFetch.apply(this, arguments) : Promise.reject(new Error("blocked")); };
  if (window.XMLHttpRequest) {
    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url){ report("network", "XHR " + method + " " + url); return origOpen.apply(this, arguments); };
  }
  window.addEventListener("error", function(e){ report("script-error", "Script error: " + e.message); });
  report("harness-loaded", "sandbox JS environment is running");
})();
</script>`;

const EVENT_LABEL: Record<string, string> = {
  alert: "alert() called", prompt: "prompt() called", confirm: "confirm() called",
  "cookie-read": "document.cookie read", "cookie-write": "document.cookie written",
  network: "outbound request attempted", "script-error": "script ran and threw an error",
};

function XssProofModal({ html, matches, onClose }: { html: string; matches: string[]; onClose: () => void }) {
  const [fired, setFired] = useState<{ kind: string; detail: string }[]>([]);

  useEffect(() => {
    function onMsg(e: MessageEvent) {
      if (e.data && e.data.__deaspXssProof) {
        setFired(f => [...f, { kind: e.data.kind, detail: e.data.detail }]);
      }
    }
    window.addEventListener("message", onMsg);
    return () => window.removeEventListener("message", onMsg);
  }, []);

  const harnessLoaded = fired.some(f => f.kind === "harness-loaded");
  const payloadEvents = fired.filter(f => f.kind !== "harness-loaded");
  const contexts = matchContexts(html, matches);

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="rounded-lg border border-[#f85149] bg-[#161b22] p-5 max-w-2xl w-full mx-4 max-h-[85vh] overflow-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-[#f85149] font-bold text-lg">⚡ XSS Proof of Concept</h3>
          <button onClick={onClose} className="text-[#8b949e] hover:text-white text-xl">✕</button>
        </div>

        <div className="text-xs text-[#8b949e] mb-1 uppercase tracking-wider font-semibold">Matched pattern(s) — with context</div>
        <div className="space-y-1 mb-3">
          {contexts.map(({ pattern, context }, i) => (
            <div key={i} className="flex gap-2 items-start">
              <span
                className="text-[10px] font-mono px-1.5 py-0.5 rounded flex-shrink-0"
                style={XSS_LOW_PRIORITY.has(pattern)
                  ? { color: "#8b949e", background: "#1a1d23" }
                  : { color: "#f85149", background: "#2d0d0d" }}
              >
                {pattern}
              </span>
              <span className="text-[10px] font-mono text-[#8b949e] break-all">{context}</span>
            </div>
          ))}
        </div>

        <div className="mb-1 text-xs text-[#8b949e] uppercase tracking-wider font-semibold">
          Live execution — sandboxed, isolated origin (no cookie/DOM access to the real page)
        </div>
        <iframe
          title="xss-proof"
          sandbox="allow-scripts"
          srcDoc={`<!doctype html><html><head>${XSS_HARNESS}</head><body>${html}</body></html>`}
          className="w-full border border-[#30363d] rounded bg-white mb-3"
          style={{ height: 200 }}
        />

        {payloadEvents.length > 0 ? (
          <div className="rounded border border-[#f85149] bg-[#2d0d0d] px-3 py-2 mb-3">
            <div className="text-[#f85149] font-bold text-xs mb-1">✅ CONFIRMED — JavaScript executed:</div>
            {payloadEvents.map((f, i) => (
              <div key={i} className="text-[#f85149] text-xs font-mono">
                {EVENT_LABEL[f.kind] ?? f.kind}: {f.detail}
              </div>
            ))}
          </div>
        ) : harnessLoaded ? (
          <div className="rounded border border-[#f0883e] bg-[#2d1b00] px-3 py-2 mb-3 text-[#f0883e] text-xs">
            ⚠ Sandbox's own JS ran fine, but the payload triggered nothing observable —
            it may be inert (sitting inside an attribute, encoded, or in a &lt;textarea&gt;),
            or it uses a technique this harness doesn't track (direct DOM writes with no
            side effect we watch for). Check the rendered output and raw content below.
          </div>
        ) : (
          <div className="rounded border border-[#30363d] bg-[#0d1117] px-3 py-2 mb-3 text-[#8b949e] text-xs">
            The sandbox's own script never ran — something in the content likely broke HTML
            parsing before reaching it (e.g. an unclosed tag/quote). Check the raw content below.
          </div>
        )}

        <div className="mb-1 text-xs text-[#8b949e] uppercase tracking-wider font-semibold">Raw content</div>
        <pre className="bg-[#0d1117] border border-[#30363d] rounded p-2 text-[10px] text-[#c9d1d9] overflow-auto max-h-40 whitespace-pre-wrap break-all">
          {html}
        </pre>
      </div>
    </div>
  );
}

function XssBadge({ matches, onProof }: { matches: string[]; onProof: () => void }) {
  if (matches.length === 0) return null;
  return (
    <button
      onClick={e => { e.stopPropagation(); onProof(); }}
      className="text-[#f85149] text-[10px] font-bold bg-[#2d0d0d] px-2 py-0.5 rounded border border-[#f85149] animate-pulse hover:bg-[#f85149] hover:text-black transition cursor-pointer"
      title="Click to see proof of execution"
    >
      ⚡ XSS? {matches[0]} — view proof
    </button>
  );
}

// ── Rendered HTML panel (iframe) ─────────────────────────────────────────────

function RenderedHtml({ html, label }: { html: string; label: string }) {
  const [show, setShow] = useState(true);
  const [showProof, setShowProof] = useState(false);
  const xssHits = detectXss(html);

  return (
    <div className="rounded border mt-2" style={{ borderColor: xssHits.length ? "#f85149" : "#30363d" }}>
      <div
        role="button"
        tabIndex={0}
        onClick={() => setShow(v => !v)}
        onKeyDown={e => { if (e.key === "Enter") setShow(v => !v); }}
        className="w-full flex items-center justify-between px-3 py-2 text-xs hover:bg-[#1a1f2e] transition text-left cursor-pointer"
      >
        <span className="font-semibold text-[#58a6ff]">🖥 {label}</span>
        <div className="flex items-center gap-2">
          <XssBadge matches={xssHits} onProof={() => setShowProof(true)} />
          {xssHits.length === 0 && (
            <span className="text-[#56d364] text-[10px] bg-[#0a1f0c] px-2 py-0.5 rounded">
              ✓ No obvious XSS
            </span>
          )}
          <span className="text-[#8b949e]">{show ? "▲" : "▼"}</span>
        </div>
      </div>

      {show && (
        <div className="border-t border-[#30363d]">
          <iframe
            title={label}
            sandbox="allow-same-origin"
            srcDoc={`<!doctype html><html><head>
              <meta charset="utf-8">
              <style>
                body{background:#fff;font-family:Arial,sans-serif;font-size:14px;padding:12px;margin:0;}
                table{border-collapse:collapse;} td,th{padding:4px 8px;}
                .ihpa-msgbar-warning{background:#fff3cd;border:1px solid #ffc107;border-radius:4px;color:#856404;}
                .ihpa-msgbar-danger{background:#f8d7da;border:1px solid #f5c6cb;border-radius:4px;color:#721c24;}
                .ihpa-msgbar-info{background:#d1ecf1;border:1px solid #bee5eb;border-radius:4px;color:#0c5460;}
              </style>
              </head><body>${html}</body></html>`}
            className="w-full border-0 bg-white"
            style={{ height: "280px" }}
          />
          <details className="border-t border-[#30363d]">
            <summary className="px-3 py-1.5 text-xs text-[#8b949e] cursor-pointer hover:text-[#c9d1d9] select-none">
              Raw HTML
            </summary>
            <pre className="px-3 py-2 text-[10px] text-[#8b949e] overflow-auto max-h-40 bg-[#0d1117] font-mono whitespace-pre-wrap break-all">
              {html}
            </pre>
          </details>
        </div>
      )}

      {showProof && <XssProofModal html={html} matches={xssHits} onClose={() => setShowProof(false)} />}
    </div>
  );
}

// ── AJAX part card ────────────────────────────────────────────────────────────

const PART_COLOR: Record<string, string> = {
  updatePanel:      "#58a6ff",
  hiddenField:      "#f0883e",
  scriptBlock:      "#bc8cff",
  scriptStartupBlock: "#bc8cff",
  arrayDeclaration: "#6e7681",
  pageRedirect:     "#3fb950",
  error:            "#f85149",
  pageTitle:        "#56d364",
  asyncPostBackControlIDs: "#6e7681",
  postBackControlIDs: "#6e7681",
  updatePanelIDs:   "#6e7681",
  panelsToRefreshIDs: "#6e7681",
  asyncPostBackTimeout: "#6e7681",
  formAction:       "#6e7681",
  childUpdatePanelIDs: "#6e7681",
};

function AjaxPart({ part }: { part: AjaxPart }) {
  const [open, setOpen] = useState(
    part.highlight || part.is_error || part.type === "pageRedirect" || part.type === "updatePanel"
  );
  const [showProof, setShowProof] = useState(false);
  const color = PART_COLOR[part.type] ?? "#8b949e";
  const isUpdatePanel = part.type === "updatePanel";
  const isScript = part.type === "scriptBlock" || part.type === "scriptStartupBlock";
  const isHidden = part.type === "hiddenField";
  const xssHits = detectXss(part.content);

  return (
    <div className="rounded border mb-1.5" style={{ borderColor: part.is_error ? "#f85149" : xssHits.length ? "#f0883e" : "#30363d" }}>
      <div
        role="button"
        tabIndex={0}
        className="w-full flex items-center gap-2 px-3 py-1.5 text-left hover:bg-[#1a1f2e] text-xs transition cursor-pointer"
        onClick={() => setOpen(v => !v)}
        onKeyDown={e => { if (e.key === "Enter") setOpen(v => !v); }}
      >
        <span className="font-bold flex-shrink-0" style={{ color }}>{part.type}</span>
        {part.id && <span className="text-[#8b949e] truncate max-w-[180px]">#{part.id}</span>}
        <span className="text-[#6e7681] flex-shrink-0">{part.length}B</span>
        {part.highlight && <span className="text-[#f0883e] text-[10px] font-bold flex-shrink-0">★ VS UPDATED</span>}
        {part.is_error && <span className="text-[#f85149] text-[10px] font-bold flex-shrink-0">⚠ ERROR</span>}
        <XssBadge matches={xssHits} onProof={() => setShowProof(true)} />
        {part.text_preview && (
          <span className="text-[#8b949e] text-[10px] truncate flex-1 ml-1 italic">{part.text_preview.slice(0, 60)}</span>
        )}
        <span className="ml-auto text-[#8b949e] flex-shrink-0">{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div className="border-t border-[#30363d] px-3 py-2">
          {part.viewstate_decoded && (
            <ViewStatePanel info={part.viewstate_decoded} compact />
          )}
          {part.redirect_url && (
            <div className="text-[#3fb950] text-xs">→ Redirect: {part.redirect_url}</div>
          )}
          {isUpdatePanel && part.content && (
            <RenderedHtml html={part.content} label={`UpdatePanel: ${part.id}`} />
          )}
          {isScript && (
            <pre className="text-[#bc8cff] text-[10px] overflow-auto max-h-32 font-mono whitespace-pre-wrap break-all bg-[#0d1117] rounded p-2">
              {part.content}
            </pre>
          )}
          {isHidden && !part.viewstate_decoded && (
            <div className="text-[#c9d1d9] text-xs font-mono break-all">{part.content}</div>
          )}
          {!part.viewstate_decoded && !part.redirect_url && !isUpdatePanel && !isScript && !isHidden && (
            <pre className="text-[#8b949e] text-[11px] overflow-auto max-h-24 whitespace-pre-wrap break-all">
              {part.content}
            </pre>
          )}
        </div>
      )}

      {showProof && <XssProofModal html={part.content} matches={xssHits} onClose={() => setShowProof(false)} />}
    </div>
  );
}

// ── Response panel ────────────────────────────────────────────────────────────

interface Props {
  response: ReplayResponse | null;
  loading: boolean;
  renderPages?: boolean;
}

const statusColor = (s: number) =>
  s >= 500 ? "#f85149" : s >= 400 ? "#f0883e" : s >= 300 ? "#bc8cff" : "#56d364";

export default function ResponsePanel({ response, loading, renderPages }: Props) {
  const [tab, setTab] = useState<"pretty" | "rendered" | "ajax" | "headers">("pretty");
  const [showProof, setShowProof] = useState(false);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-[#8b949e]">
        <div className="text-center"><div className="text-2xl mb-2 animate-spin">⟳</div>Sending…</div>
      </div>
    );
  }

  if (!response) {
    return (
      <div className="flex items-center justify-center h-full text-[#484f58]">
        <div className="text-center">
          <div className="text-3xl mb-3 opacity-30">📡</div>
          <div>Response appears here</div>
          <div className="text-xs mt-1 opacity-60">Edit params and hit Send</div>
        </div>
      </div>
    );
  }

  const tabs = [
    ...(response.is_ajax ? ["ajax"] : []),
    ...(renderPages && !response.is_ajax ? ["rendered"] : []),
    "pretty",
    "headers",
  ] as const;

  // Auto-select best tab
  const firstTab = (tabs[0] as typeof tab) ?? "pretty";
  const activeTab = tabs.includes(tab as typeof tabs[number]) ? tab : firstTab;

  // For AJAX responses, response.body is the raw pipe-delimited envelope
  // ("735|updatePanel|id|<div>...</div>|0|hiddenField|..."), not HTML. Testing
  // that directly in an iframe is misleading — a real payload can end up
  // buried in protocol noise instead of being evaluated cleanly. Use the
  // already-parsed updatePanel/script content (the pieces that actually get
  // injected into the real page's DOM) for both detection and the proof view.
  const proofContent = response.is_ajax
    ? response.ajax_parts
        .filter(p => p.type === "updatePanel" || p.type === "scriptBlock" || p.type === "scriptStartupBlock")
        .map(p => p.content)
        .join("\n")
    : response.body;
  const bodyXss = detectXss(proofContent);

  return (
    <div className="flex flex-col h-full">
      {/* Status bar */}
      <div className="flex items-center gap-3 px-3 py-2 border-b border-[#30363d] bg-[#161b22] flex-shrink-0 flex-wrap gap-y-1">
        <span className="font-bold text-base" style={{ color: statusColor(response.status) }}>
          {response.status}
        </span>
        <span className="text-[#8b949e] text-xs truncate">{response.content_type}</span>
        {response.aspnet_error && (
          <span className="text-[#f85149] text-[10px] font-bold bg-[#2d0d0d] px-2 py-0.5 rounded">ASP.NET ERROR</span>
        )}
        {response.viewstate_error && (
          <span className="text-[#f0883e] text-[10px] font-bold bg-[#2d1b00] px-2 py-0.5 rounded">VS ERROR</span>
        )}
        {response.is_ajax && (
          <span className="text-[#bc8cff] text-[10px] font-bold bg-[#1c1440] px-2 py-0.5 rounded">AJAX</span>
        )}
        <XssBadge matches={bodyXss} onProof={() => setShowProof(true)} />
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[#30363d] flex-shrink-0">
        {tabs.map(t => (
          <button key={t} onClick={() => setTab(t as typeof tab)}
            className="px-4 py-2 text-xs capitalize transition"
            style={{
              color: activeTab === t ? "#58a6ff" : "#8b949e",
              borderBottom: activeTab === t ? "2px solid #58a6ff" : "2px solid transparent",
              background: "transparent",
            }}>
            {t === "ajax" ? `AJAX (${response.ajax_parts.length})` :
             t === "rendered" ? "Rendered" :
             t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-3">
        {activeTab === "ajax" && (
          <div>
            {response.ajax_parts.map((p, i) => <AjaxPart key={i} part={p} />)}
          </div>
        )}
        {activeTab === "rendered" && (
          <RenderedHtml html={response.body} label="Full Response" />
        )}
        {activeTab === "pretty" && (
          <pre className="text-[#c9d1d9] text-[11px] whitespace-pre-wrap break-all leading-relaxed">
            {response.body}
          </pre>
        )}
        {activeTab === "headers" && (
          <div className="space-y-1">
            {Object.entries(response.headers).map(([k, v]) => (
              <div key={k} className="flex gap-3">
                <span className="text-[#58a6ff] text-xs w-44 flex-shrink-0 truncate">{k}</span>
                <span className="text-[#c9d1d9] text-xs break-all">{v}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {showProof && <XssProofModal html={proofContent} matches={bodyXss} onClose={() => setShowProof(false)} />}
    </div>
  );
}
