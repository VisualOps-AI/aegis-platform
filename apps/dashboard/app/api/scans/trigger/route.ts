import { NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth";
import { triggerScan, getScanStatus } from "@/lib/scan-runner";
import { existsSync } from "node:fs";
import type { AttackCategory } from "@aegis/shared";

export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<NextResponse> {
  const auth = requireAuth(request, "analyst");
  if (auth instanceof NextResponse) return auth;

  const body = await request.json() as {
    configPath?: string;
    modules?: AttackCategory[];
  };

  if (!body.configPath || typeof body.configPath !== "string") {
    return NextResponse.json(
      { error: "configPath is required" },
      { status: 400 }
    );
  }

  if (!existsSync(body.configPath)) {
    return NextResponse.json(
      { error: `Config file not found: ${body.configPath}` },
      { status: 400 }
    );
  }

  const scanId = await triggerScan(body.configPath, body.modules);

  return NextResponse.json({ scanId, status: "running" }, { status: 202 });
}

export function GET(request: Request): NextResponse {
  const auth = requireAuth(request, "analyst");
  if (auth instanceof NextResponse) return auth;

  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get("id");

  if (!scanId) {
    return NextResponse.json(
      { error: "id query parameter is required" },
      { status: 400 }
    );
  }

  const status = getScanStatus(scanId);
  if (!status) {
    return NextResponse.json(
      { error: "Scan not found in active tracker" },
      { status: 404 }
    );
  }

  return NextResponse.json({
    id: status.id,
    status: status.status,
    configPath: status.configPath,
    startedAt: status.startedAt,
    completedAt: status.completedAt,
    error: status.error,
    summary: status.report?.summary,
  });
}
