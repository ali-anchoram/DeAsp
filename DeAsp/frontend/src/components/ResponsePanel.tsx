import React, { useState } from "react";
import { ReplayResponse, AjaxPart } from "../types";
import ViewStatePanel from "./ViewStatePanel";

const AJAX_TYPE_COLOR: Record<string, string> = {
  updatePanel:      "#58a6ff",
  hiddenField:      "#f0883e",
  scriptBlock:      "#bc8cff",
  arrayDeclaration: "#6e7681",
  pageRedirect:     "#3fb950",
  error:            "#f85149",
  pageTitle:        "#56d364",
  asyncPostBackControlIDs: "#6e7681",
  postBackControlIDs: "#6e7681",
  updatePanelIDs:   "#6e7681",
  asyncPostBackTimeout: "#6e7681",
  formAction:       "#6e7681",
};

function AjaxPartCard({ part }: { part: AjaxPart }) {
  const [open, setOpen] = useState(part.highlight || part.is_error || part.type === "pageRedirect");
  const color = AJAX_TYPE_COLOR[part.type] ?? "#8b949e";

  return (
    <div
      className="rounded border mb-1"
      style={{ borderColor: part.highlight ? "#f0883e" : "#30363d" }}
    >
      <button
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-[#1a1f2e] text-xs"
        onClick={() => setOpen(v => !v)}
      >
        <span className="font-bold" style={{ color }}>{part.type}</span>
        {part.id && <span className="text-[#8b949e]">#{part.id}</span>}
        <span className="text-[#6e7681]">{part.length}B</span>
        {part.highlight && <span className="text-[#f0883e] text-[10px] font-bold">⭐ VIEWSTATE UPDATED</span>}
        {part.is_error && <span className="text-[#f85149] text-[10px] font-bold">⚠ ERROR</span>}
        <span className="ml-auto text-[#8b949e]">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="border-t border-[#30363d] px-3 py-2">
          {part.viewstate_decoded && (
            <ViewStatePanel info={part.viewstate_decoded} compact />
          )}
          {part.redirect_url && (
            <div className="text-[#3fb950] text-xs">Redirect → {part.redirect_url}</div>
          )}
          {!part.viewstate_decoded && !part.redirect_url && (
            <pre className="text-[#8b949e] text-[11px] overflow-auto max-h-48 whitespace-pre-wrap break-all">
              {part.content}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

interface Props {
  response: ReplayResponse | null;
  loading: boolean;
}

const STATUS_COLOR = (s: number) =>
  s >= 500 ? "#f85149" : s >= 400 ? "#f0883e" : s >= 300 ? "#bc8cff" : "#56d364";

export default function ResponsePanel({ response, loading }: Props) {
  const [tab, setTab] = useState<"pretty" | "raw" | "headers" | "ajax">("pretty");

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-[#8b949e]">
        <div className="text-center">
          <div className="text-2xl mb-2 animate-pulse">⟳</div>
          Sending request…
        </div>
      </div>
    );
  }

  if (!response) {
    return (
      <div className="flex items-center justify-center h-full text-[#484f58]">
        <div className="text-center">
          <div className="text-3xl mb-3 opacity-30">📡</div>
          <div>Response will appear here</div>
          <div className="text-xs mt-1 opacity-60">Parse a request and hit Send</div>
        </div>
      </div>
    );
  }

  const tabs = ["pretty", "raw", "headers", ...(response.is_ajax ? ["ajax"] : [])] as const;

  return (
    <div className="flex flex-col h-full">
      {/* Status bar */}
      <div className="flex items-center gap-3 px-3 py-2 border-b border-[#30363d] bg-[#161b22] flex-shrink-0">
        <span
          className="font-bold text-lg"
          style={{ color: STATUS_COLOR(response.status) }}
        >
          {response.status}
        </span>
        <span className="text-[#8b949e] text-xs">{response.content_type}</span>
        {response.aspnet_error && (
          <span className="text-[#f85149] text-xs font-bold bg-[#2d0d0d] px-2 py-0.5 rounded">
            ASP.NET ERROR
          </span>
        )}
        {response.viewstate_error && (
          <span className="text-[#f0883e] text-xs font-bold bg-[#2d1b00] px-2 py-0.5 rounded">
            VIEWSTATE ERROR
          </span>
        )}
        {response.is_ajax && (
          <span className="text-[#bc8cff] text-xs font-bold bg-[#1c1440] px-2 py-0.5 rounded">
            AJAX RESPONSE
          </span>
        )}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[#30363d] flex-shrink-0">
        {tabs.map(t => (
          <button
            key={t}
            onClick={() => setTab(t as typeof tab)}
            className="px-4 py-2 text-xs capitalize transition"
            style={{
              color: tab === t ? "#58a6ff" : "#8b949e",
              borderBottom: tab === t ? "2px solid #58a6ff" : "2px solid transparent",
              background: "transparent",
            }}
          >
            {t === "ajax" ? "AJAX Parts" : t.charAt(0).toUpperCase() + t.slice(1)}
            {t === "ajax" && response.ajax_parts.length > 0 && (
              <span className="ml-1 text-[10px] text-[#bc8cff]">({response.ajax_parts.length})</span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-3">
        {tab === "pretty" && (
          <pre className="text-[#c9d1d9] text-[11px] whitespace-pre-wrap break-all leading-relaxed">
            {response.body}
          </pre>
        )}
        {tab === "raw" && (
          <pre className="text-[#8b949e] text-[11px] whitespace-pre-wrap break-all font-mono">
            {response.body}
          </pre>
        )}
        {tab === "headers" && (
          <div className="space-y-1">
            {Object.entries(response.headers).map(([k, v]) => (
              <div key={k} className="flex gap-3">
                <span className="text-[#58a6ff] text-xs flex-shrink-0 w-48 truncate">{k}</span>
                <span className="text-[#c9d1d9] text-xs break-all">{v}</span>
              </div>
            ))}
          </div>
        )}
        {tab === "ajax" && (
          <div>
            {response.ajax_parts.map((p, i) => (
              <AjaxPartCard key={i} part={p} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
