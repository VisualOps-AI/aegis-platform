import { NextResponse } from "next/server";
import { compareScanIds } from "@/lib/scan-store";
import { requireAuth } from "@/lib/auth";

export const dynamic = "force-dynamic";

export function GET(request: Request): NextResponse {
  const auth = requireAuth(request, "readonly");
  if (auth instanceof NextResponse) return auth;

  const { searchParams } = new URL(request.url);
  const a = searchParams.get("a");
  const b = searchParams.get("b");

  if (!a || !b) {
    return NextResponse.json(
      { error: "Both 'a' and 'b' scan IDs are required" },
      { status: 400 }
    );
  }

  const comparison = compareScanIds(a, b);
  if (!comparison) {
    return NextResponse.json(
      { error: "One or both scans not found" },
      { status: 404 }
    );
  }

  return NextResponse.json({
    riskDelta: comparison.riskDelta,
    findingsDelta: comparison.findingsDelta,
    newFindings: comparison.newFindings.length,
    resolvedFindings: comparison.resolvedFindings.length,
    scanA: {
      id: comparison.a.id,
      timestamp: comparison.a.timestamp,
      riskScore: comparison.a.summary.riskScore,
      totalFindings: comparison.a.summary.totalFindings,
    },
    scanB: {
      id: comparison.b.id,
      timestamp: comparison.b.timestamp,
      riskScore: comparison.b.summary.riskScore,
      totalFindings: comparison.b.summary.totalFindings,
    },
  });
}
