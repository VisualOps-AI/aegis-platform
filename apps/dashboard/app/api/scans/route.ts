import { NextResponse } from "next/server";
import { listScans } from "@/lib/scan-store";

export const dynamic = "force-dynamic";

export function GET(): NextResponse {
  const scans = listScans();
  return NextResponse.json(scans);
}
