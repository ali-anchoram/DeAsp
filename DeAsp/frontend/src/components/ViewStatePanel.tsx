import React, { useState } from "react";
import { ViewStateInfo } from "../types";

function JsonTree({ data, depth = 0 }: { data: unknown; depth?: number }) {
  const [open, setOpen] = useState(depth < 2);

  if (data === null || data === undefined) {
    return <span className="text-[#8b949e] italic">null</span>;
  }
  if (typeof data === "boolean") {
    return <span className="text-[#f0883e]">{String(data)}</span>;
  }
  if (typeof data === "number") {
    return <span className="text-[#79c0ff]">{data}</span>;
  }
  if (typeof data === "string") {
    return <span className="text-[#a5d6ff] break-all">"{data}"</span>;
  }
  if (typeof data === "object") {
    const d = data as Record<string, unknown>;
    const type = d._T as string | undefined;
    const keys = Object.keys(d).filter(k => k !== "_T");

    if (keys.length === 0) return <span className="text-[#8b949e]">{"{}"}</span>;

    return (
      <span>
        <button
          onClick={() => setOpen(v => !v)}
          className="text-[#bc8cff] hover:text-white font-mono text-xs"
        >
          {open ? "▼" : "▶"} {type ?? "Object"}
        </button>
        {open && (
          <div className="ml-4 border-l border-[#30363d] pl-3 mt-0.5">
            {keys.map(k => (
              <div key={k} className="flex gap-2 py-0.5">
                <span className="text-[#79beff] flex-shrink-0">{k}:</span>
                <JsonTree data={d[k]} depth={depth + 1} />
              </div>
            ))}
          </div>
        )}
      </span>
    );
  }
  return <span>{String(data)}</span>;
}

interface Props {
  info: ViewStateInfo;
  compact?: boolean;
}

export default function ViewStatePanel({ info, compact }: Props) {
  const [showTree, setShowTree] = useState(false);

  const macColor = info.mac_present ? "#f0883e" : "#56d364";
  const macLabel = info.mac_present
    ? `MAC: ${info.mac_algorithm ?? "present"} (${info.mac_length}B) — STRIP TO TEST`
    : "No MAC detected";

  return (
    <div className={compact ? "text-xs" : "text-sm"}>
      {info.error && (
        <div className="text-[#f85149] bg-[#2d0d0d] border border-[#f85149] rounded px-3 py-2 mb-2">
          ⚠ {info.error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 mb-2">
        {info.total_bytes !== undefined && (
          <>
            <span className="text-[#8b949e]">Total bytes</span>
            <span className="text-[#c9d1d9]">{info.total_bytes}</span>
            <span className="text-[#8b949e]">Serialized</span>
            <span className="text-[#c9d1d9]">{info.serialized_bytes}B</span>
          </>
        )}
        <span className="text-[#8b949e]">MAC status</span>
        <span style={{ color: macColor }} className="font-semibold">{macLabel}</span>
        {info.hex_preview && (
          <>
            <span className="text-[#8b949e]">Hex preview</span>
            <span className="text-[#6e7681] font-mono text-[10px] break-all">{info.hex_preview}</span>
          </>
        )}
      </div>

      {info.mac_bytes && (
        <div className="mb-2 rounded border border-[#f0883e33] bg-[#2d1b00] px-3 py-2">
          <span className="text-[#8b949e] text-xs">MAC bytes: </span>
          <span className="text-[#f0883e] font-mono text-[10px] break-all">{info.mac_bytes}</span>
        </div>
      )}

      {info.value !== undefined && (
        <div>
          <button
            onClick={() => setShowTree(v => !v)}
            className="flex items-center gap-2 text-xs text-[#bc8cff] hover:text-white mb-1"
          >
            {showTree ? "▼" : "▶"} Decoded ViewState tree
          </button>
          {showTree && (
            <div className="bg-[#0d1117] rounded border border-[#30363d] p-3 font-mono text-xs overflow-auto max-h-64">
              <JsonTree data={info.value} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
