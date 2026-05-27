import { readFileSync, readdirSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type {
  ScanReport,
  ReportSummary,
  Severity,
  AttackCategory,
  Finding,
  AttackResult,
} from "@aegis/shared";

const SCAN_DIR = join(homedir(), ".aegis", "scans");

export interface ScanSummaryItem {
  id: string;
  timestamp: string;
  target: string;
  riskScore: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  duration: number;
}

interface JsonReportEnvelope {
  meta: {
    scanId: string;
    timestamp: string;
    target: string;
    duration: string;
  };
  summary: {
    riskScore: number;
    totalFindings: number;
    bySeverity: Record<Severity, number>;
    byCategory: Record<AttackCategory, number>;
  };
  owaspCompliance: Array<{
    id: string;
    name: string;
    status: "pass" | "warn" | "fail";
    findingCount: number;
  }>;
  findings: Finding[];
  modules: Array<{
    name: AttackCategory;
    duration: string;
    toolsTested: number;
    chainsTested: number;
    findingCount: number;
  }>;
}

function ensureScanDir(): void {
  if (!existsSync(SCAN_DIR)) {
    mkdirSync(SCAN_DIR, { recursive: true });
  }
}

function parseDuration(d: string | number): number {
  if (typeof d === "number") return d;
  return parseInt(d.replace("ms", ""), 10) || 0;
}

function envelopeToScanReport(envelope: JsonReportEnvelope): ScanReport {
  const results: AttackResult[] = envelope.modules.map((mod) => ({
    module: mod.name,
    findings: envelope.findings.filter((f) => f.category === mod.name),
    duration: parseDuration(mod.duration),
    toolsTested: mod.toolsTested,
    chainsTested: mod.chainsTested,
  }));

  const byOwasp: Partial<Record<string, number>> = {};
  for (const item of envelope.owaspCompliance) {
    byOwasp[item.id] = item.findingCount;
  }

  const summary: ReportSummary = {
    totalFindings: envelope.summary.totalFindings,
    bySeverity: envelope.summary.bySeverity,
    byCategory: envelope.summary.byCategory,
    byOwasp: byOwasp as ReportSummary["byOwasp"],
    riskScore: envelope.summary.riskScore,
  };

  return {
    id: envelope.meta.scanId,
    timestamp: envelope.meta.timestamp,
    target: envelope.meta.target,
    duration: parseDuration(envelope.meta.duration),
    results,
    summary,
  };
}

function readScanFile(filePath: string): ScanReport | null {
  try {
    const raw = JSON.parse(readFileSync(filePath, "utf-8"));
    if (raw.meta && raw.findings) {
      return envelopeToScanReport(raw as JsonReportEnvelope);
    }
    if (raw.id && raw.results && raw.summary) {
      return raw as ScanReport;
    }
    return null;
  } catch {
    return null;
  }
}

export function listScans(): ScanSummaryItem[] {
  ensureScanDir();
  const files = readdirSync(SCAN_DIR).filter((f) => f.endsWith(".json"));

  const scans: ScanSummaryItem[] = [];
  for (const file of files) {
    const report = readScanFile(join(SCAN_DIR, file));
    if (!report) continue;
    scans.push({
      id: report.id,
      timestamp: report.timestamp,
      target: report.target,
      riskScore: report.summary.riskScore,
      totalFindings: report.summary.totalFindings,
      bySeverity: report.summary.bySeverity,
      duration: report.duration,
    });
  }

  return scans.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export function getScan(scanId: string): ScanReport | null {
  ensureScanDir();
  const files = readdirSync(SCAN_DIR).filter((f) => f.endsWith(".json"));

  for (const file of files) {
    const report = readScanFile(join(SCAN_DIR, file));
    if (report && report.id === scanId) return report;
  }

  return null;
}

export function getLatestScan(): ScanReport | null {
  const scans = listScans();
  if (scans.length === 0) return null;
  return getScan(scans[0].id);
}

export function compareScanIds(idA: string, idB: string): {
  a: ScanReport;
  b: ScanReport;
  riskDelta: number;
  findingsDelta: number;
  newFindings: Finding[];
  resolvedFindings: Finding[];
} | null {
  const a = getScan(idA);
  const b = getScan(idB);
  if (!a || !b) return null;

  const aFindings = a.results.flatMap((r) => r.findings);
  const bFindings = b.results.flatMap((r) => r.findings);
  const aIds = new Set(aFindings.map((f) => f.title));
  const bIds = new Set(bFindings.map((f) => f.title));

  return {
    a,
    b,
    riskDelta: b.summary.riskScore - a.summary.riskScore,
    findingsDelta: b.summary.totalFindings - a.summary.totalFindings,
    newFindings: bFindings.filter((f) => !aIds.has(f.title)),
    resolvedFindings: aFindings.filter((f) => !bIds.has(f.title)),
  };
}
