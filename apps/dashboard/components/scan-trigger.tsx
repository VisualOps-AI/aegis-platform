"use client";

import { useState } from "react";

export function ScanTrigger() {
  const [open, setOpen] = useState(false);
  const [configPath, setConfigPath] = useState("");
  const [status, setStatus] = useState<"idle" | "running" | "done" | "error">("idle");
  const [message, setMessage] = useState("");

  async function handleTrigger() {
    if (!configPath.trim()) return;
    setStatus("running");
    setMessage("");

    try {
      const res = await fetch("/api/scans/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configPath: configPath.trim() }),
      });

      const data = await res.json();

      if (!res.ok) {
        setStatus("error");
        setMessage(data.error ?? "Scan failed");
        return;
      }

      const scanId = data.scanId;
      const eventSource = new EventSource(`/api/scans/${scanId}/stream`);

      eventSource.addEventListener("complete", (e) => {
        const result = JSON.parse(e.data);
        setStatus("done");
        setMessage(
          `Score: ${result.riskScore}/10 — ${result.totalFindings} findings`
        );
        eventSource.close();
        setTimeout(() => window.location.reload(), 1500);
      });

      eventSource.addEventListener("failed", (e) => {
        const result = JSON.parse(e.data);
        setStatus("error");
        setMessage(result.error ?? "Scan failed");
        eventSource.close();
      });

      eventSource.onerror = () => {
        if (status === "running") {
          setTimeout(() => window.location.reload(), 2000);
        }
        eventSource.close();
      };
    } catch {
      setStatus("error");
      setMessage("Network error");
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="text-[10px] uppercase tracking-wider px-3 py-1.5 transition-colors cursor-pointer"
        style={{
          color: "var(--accent)",
          background: "transparent",
          border: "1px solid var(--accent-dim)",
          borderRadius: "var(--radius)",
        }}
      >
        New Scan
      </button>
    );
  }

  return (
    <div
      className="flex items-center gap-2"
      style={{ animation: "fade-in 0.15s ease-out" }}
    >
      <input
        type="text"
        placeholder="Path to MCP config..."
        value={configPath}
        onChange={(e) => setConfigPath(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && handleTrigger()}
        className="text-xs px-3 py-1.5 w-64 outline-none"
        style={{
          color: "var(--text)",
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
        }}
        autoFocus
        disabled={status === "running"}
      />
      <button
        onClick={handleTrigger}
        disabled={status === "running" || !configPath.trim()}
        className="text-[10px] uppercase tracking-wider px-3 py-1.5 cursor-pointer transition-colors"
        style={{
          color: status === "running" ? "var(--text-dim)" : "var(--bg)",
          background: status === "running" ? "var(--surface)" : "var(--accent)",
          border: "none",
          borderRadius: "var(--radius)",
          opacity: !configPath.trim() ? 0.5 : 1,
        }}
      >
        {status === "running" ? "Scanning..." : "Run"}
      </button>
      <button
        onClick={() => { setOpen(false); setStatus("idle"); setMessage(""); }}
        className="text-[10px] px-2 py-1.5 cursor-pointer"
        style={{
          color: "var(--text-dim)",
          background: "transparent",
          border: "none",
        }}
      >
        Cancel
      </button>
      {message && (
        <span
          className="text-[10px]"
          style={{
            color: status === "error" ? "var(--critical)" : "var(--accent)",
          }}
        >
          {message}
        </span>
      )}
    </div>
  );
}
