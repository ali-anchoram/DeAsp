import React, { useState } from "react";
import { Param, ParamType, ViewStateInfo } from "../types";
import ViewStatePanel from "./ViewStatePanel";

const TYPE_META: Record<ParamType, { label: string; color: string; bg: string; desc: string }> = {
  system: { label: "SYSTEM",  color: "#6e7681", bg: "#1a1d23", desc: "ASP.NET infrastructure field" },
  event:  { label: "EVENT",   color: "#58a6ff", bg: "#0d2244", desc: "__EVENTTARGET / __EVENTARGUMENT" },
  ajax:   { label: "AJAX",    color: "#bc8cff", bg: "#1c1440", desc: "ScriptManager / UpdatePanel" },
  user:   { label: "USER",    color: "#56d364", bg: "#0f2a16", desc: "User-controlled input — attack surface" },
};

function Badge({ type }: { type: ParamType }) {
  const m = TYPE_META[type];
  return (
    <span
      className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider"
      style={{ color: m.color, background: m.bg, border: `1px solid ${m.color}33` }}
    >
      {m.label}
    </span>
  );
}

interface RowProps {
  param: Param;
  onChange: (name: string, value: string) => void;
}

function ParamRow({ param, onChange }: RowProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(param.value);
  const [showVs, setShowVs] = useState(false);
  const isUser = param.type === "user";
  const hasVs = !!param.viewstate;

  const save = () => {
    onChange(param.name, draft);
    setEditing(false);
  };

  return (
    <div
      className="rounded border mb-1 transition-all"
      style={{
        borderColor: isUser ? "#56d364" : "#30363d",
        background: isUser ? "#0f2a1688" : "#161b22",
        boxShadow: isUser ? "0 0 0 1px #56d36422, 0 0 12px rgba(86,211,100,0.08)" : "none",
      }}
    >
      <div className="flex items-center gap-2 px-3 py-2">
        <Badge type={param.type} />

        {/* name */}
        <span
          className="font-mono font-semibold flex-shrink-0 min-w-[120px] max-w-[280px] truncate"
          style={{ color: isUser ? "#56d364" : "#c9d1d9" }}
          title={param.name}
        >
          {param.name}
        </span>

        {/* value area */}
        <div className="flex-1 min-w-0">
          {editing ? (
            <div className="flex gap-2">
              <input
                autoFocus
                className="flex-1 bg-[#0d1117] border border-[#58a6ff] rounded px-2 py-1 text-[#c9d1d9] outline-none text-xs"
                value={draft}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") save(); if (e.key === "Escape") setEditing(false); }}
              />
              <button onClick={save}
                className="px-3 py-1 rounded bg-[#58a6ff] text-black font-bold text-xs hover:bg-[#79beff]">
                Save
              </button>
              <button onClick={() => setEditing(false)}
                className="px-2 py-1 rounded bg-[#30363d] text-[#8b949e] text-xs hover:bg-[#3d444e]">
                ✕
              </button>
            </div>
          ) : (
            <span
              className="block truncate text-[#8b949e] text-xs max-w-full"
              title={param.value}
            >
              {param.value || <em className="text-[#484f58]">(empty)</em>}
            </span>
          )}
        </div>

        {/* actions */}
        <div className="flex gap-1 flex-shrink-0">
          {!editing && (
            <button
              onClick={() => { setDraft(param.value); setEditing(true); }}
              className="px-2 py-1 rounded text-xs font-mono hover:opacity-80 transition"
              style={isUser
                ? { background: "#0f2a16", color: "#56d364", border: "1px solid #56d364" }
                : { background: "#1a1d23", color: "#58a6ff", border: "1px solid #30363d" }}
            >
              Edit
            </button>
          )}
          {hasVs && (
            <button
              onClick={() => setShowVs(v => !v)}
              className="px-2 py-1 rounded text-xs font-mono bg-[#1c1440] text-[#bc8cff] border border-[#30363d] hover:border-[#bc8cff] transition"
            >
              {showVs ? "▲ VS" : "▼ VS"}
            </button>
          )}
        </div>
      </div>

      {showVs && param.viewstate && (
        <div className="border-t border-[#30363d] px-3 py-2">
          <ViewStatePanel info={param.viewstate} compact />
        </div>
      )}
    </div>
  );
}

interface Section {
  type: ParamType;
  params: Param[];
  defaultOpen: boolean;
}

interface Props {
  params: Param[];
  onChange: (params: Param[]) => void;
}

export default function ParamEditor({ params, onChange }: Props) {
  const [collapsed, setCollapsed] = useState<Record<ParamType, boolean>>({
    system: true,
    event: false,
    ajax: false,
    user: false,
  });

  const sections: Section[] = (["user", "ajax", "event", "system"] as ParamType[]).map(t => ({
    type: t,
    params: params.filter(p => p.type === t),
    defaultOpen: t === "user",
  }));

  const handleChange = (name: string, value: string) => {
    const updated = params.map(p =>
      p.name === name ? { ...p, value, raw_value: encodeURIComponent(value) } : p
    );
    onChange(updated);
  };

  const toggle = (t: ParamType) => setCollapsed(c => ({ ...c, [t]: !c[t] }));

  return (
    <div className="space-y-2">
      {sections.map(({ type, params: ps }) => {
        if (ps.length === 0) return null;
        const m = TYPE_META[type];
        const isOpen = !collapsed[type];
        return (
          <div key={type} className="rounded border border-[#30363d]">
            <button
              className="w-full flex items-center justify-between px-3 py-2 hover:bg-[#1a1f2e] transition text-left"
              onClick={() => toggle(type)}
            >
              <span className="flex items-center gap-2">
                <span className="font-bold text-xs tracking-widest" style={{ color: m.color }}>
                  {m.label}
                </span>
                <span className="text-[#8b949e] text-xs">{m.desc}</span>
              </span>
              <span className="flex items-center gap-2">
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded-full font-bold"
                  style={{ background: m.bg, color: m.color }}
                >
                  {ps.length}
                </span>
                <span className="text-[#8b949e]">{isOpen ? "▲" : "▼"}</span>
              </span>
            </button>

            {isOpen && (
              <div className="px-3 pb-3 pt-1 border-t border-[#30363d]">
                {ps.map(p => (
                  <ParamRow key={p.name} param={p} onChange={handleChange} />
                ))}
              </div>
            )}
          </div>
        );
      })}

      {params.length === 0 && (
        <div className="text-center py-8 text-[#484f58]">
          No parameters parsed yet
        </div>
      )}
    </div>
  );
}
