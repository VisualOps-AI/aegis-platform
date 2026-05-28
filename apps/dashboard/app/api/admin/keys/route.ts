import { NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth";
import { createKey, listKeys, type Role } from "@/lib/key-store";

export const dynamic = "force-dynamic";

export function GET(request: Request): NextResponse {
  const auth = requireAuth(request, "admin");
  if (auth instanceof NextResponse) return auth;

  return NextResponse.json(listKeys());
}

export async function POST(request: Request): Promise<NextResponse> {
  const auth = requireAuth(request, "admin");
  if (auth instanceof NextResponse) return auth;

  const body = await request.json() as { name?: string; role?: string };
  const name = body.name;
  const role = body.role as Role | undefined;

  if (!name || typeof name !== "string") {
    return NextResponse.json({ error: "name is required" }, { status: 400 });
  }

  const validRoles: Role[] = ["admin", "analyst", "readonly"];
  if (role && !validRoles.includes(role)) {
    return NextResponse.json(
      { error: `role must be one of: ${validRoles.join(", ")}` },
      { status: 400 }
    );
  }

  const result = createKey(name, role ?? "readonly");
  return NextResponse.json(result, { status: 201 });
}
