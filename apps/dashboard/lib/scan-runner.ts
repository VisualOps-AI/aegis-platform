import { runScan } from "@aegis/phantom";
import { writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { ScanReport, AttackCategory } from "@aegis/shared";

export type ScanStatus = "queued" | "running" | "complete" | "failed";

interface TrackedScan {
  id: string;
  status: ScanStatus;
  configPath: string;
  startedAt: string;
  completedAt?: string;
  report?: ScanReport;
  error?: string;
}

const activeScans = new Map<string, TrackedScan>();
const scanListeners = new Map<string, Array<(event: ScanEvent) => void>>();

export interface ScanEvent {
  type: "started" | "module-progress" | "complete" | "failed";
  scanId: string;
  timestamp: string;
  data?: Record<string, unknown>;
}

function emitEvent(scanId: string, event: ScanEvent): void {
  const listeners = scanListeners.get(scanId);
  if (listeners) {
    for (const listener of listeners) {
      listener(event);
    }
  }
}

export function subscribeScan(scanId: string, listener: (event: ScanEvent) => void): () => void {
  const existing = scanListeners.get(scanId) ?? [];
  existing.push(listener);
  scanListeners.set(scanId, existing);

  return () => {
    const listeners = scanListeners.get(scanId);
    if (listeners) {
      const idx = listeners.indexOf(listener);
      if (idx >= 0) listeners.splice(idx, 1);
      if (listeners.length === 0) scanListeners.delete(scanId);
    }
  };
}

export function getScanStatus(scanId: string): TrackedScan | undefined {
  return activeScans.get(scanId);
}

function saveScanReport(report: ScanReport): void {
  const scanDir = join(homedir(), ".aegis", "scans");
  if (!existsSync(scanDir)) {
    mkdirSync(scanDir, { recursive: true });
  }
  const filePath = join(scanDir, `${report.id}.json`);
  writeFileSync(filePath, JSON.stringify(report, null, 2), "utf-8");
}

export async function triggerScan(
  configPath: string,
  modules?: AttackCategory[]
): Promise<string> {
  const placeholderId = `pending-${Date.now()}`;

  const tracked: TrackedScan = {
    id: placeholderId,
    status: "running",
    configPath,
    startedAt: new Date().toISOString(),
  };
  activeScans.set(placeholderId, tracked);

  (async () => {
    try {
      emitEvent(placeholderId, {
        type: "started",
        scanId: placeholderId,
        timestamp: new Date().toISOString(),
        data: { configPath, modules },
      });

      const report = await runScan({ configPath, modules });

      tracked.id = report.id;
      tracked.status = "complete";
      tracked.completedAt = new Date().toISOString();
      tracked.report = report;

      activeScans.set(report.id, tracked);
      if (report.id !== placeholderId) {
        activeScans.delete(placeholderId);
      }

      saveScanReport(report);

      emitEvent(placeholderId, {
        type: "complete",
        scanId: report.id,
        timestamp: new Date().toISOString(),
        data: {
          riskScore: report.summary.riskScore,
          totalFindings: report.summary.totalFindings,
          bySeverity: report.summary.bySeverity,
          duration: report.duration,
        },
      });
    } catch (err) {
      tracked.status = "failed";
      tracked.completedAt = new Date().toISOString();
      tracked.error = err instanceof Error ? err.message : String(err);

      emitEvent(placeholderId, {
        type: "failed",
        scanId: placeholderId,
        timestamp: new Date().toISOString(),
        data: { error: tracked.error },
      });
    } finally {
      scanListeners.delete(placeholderId);
    }
  })();

  return placeholderId;
}
