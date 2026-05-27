import { listScans } from "@/lib/scan-store";
import { ScanCard } from "@/components/scan-card";

export const dynamic = "force-dynamic";

export default function ScansPage() {
  const scans = listScans();

  return (
    <div>
      <div className="flex items-center justify-between mb-6 animate-in">
        <div>
          <h1
            className="text-base font-bold tracking-wide"
            style={{ color: "var(--text)" }}
          >
            Scan History
          </h1>
          <div
            className="text-[11px] mt-0.5"
            style={{ color: "var(--text-muted)" }}
          >
            {scans.length} scan{scans.length !== 1 ? "s" : ""} recorded
          </div>
        </div>
      </div>

      {scans.length === 0 ? (
        <div
          className="text-xs py-16 text-center animate-in"
          style={{ color: "var(--text-muted)" }}
        >
          No scans found. Run{" "}
          <code style={{ color: "var(--accent)" }}>aegis scan --save config.json</code>
          {" "}to start.
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan, i) => (
            <div key={scan.id} className={`animate-in stagger-${Math.min(i + 1, 8)}`}>
              <ScanCard scan={scan} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
