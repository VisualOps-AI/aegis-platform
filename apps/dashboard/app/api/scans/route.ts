import { NextResponse } from "next/server";
import { listScans } from "@/lib/scan-store";
import { requireAuth } from "@/lib/auth";

export const dynamic = "force-dynamic";

export function GET(request: Request): NextResponse {
  const auth = requireAuth(request, "readonly");
  if (auth instanceof NextResponse) return auth;

  const scans = listScans();
  return NextResponse.json(scans);
}
