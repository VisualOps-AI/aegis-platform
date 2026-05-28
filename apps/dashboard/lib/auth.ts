import { NextResponse } from "next/server";
import { validateKey, type Role } from "./key-store";

export interface AuthContext {
  role: Role;
  keyId: string;
  keyName: string;
}

const ROLE_HIERARCHY: Record<Role, number> = {
  readonly: 0,
  analyst: 1,
  admin: 2,
};

function extractBearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7);
}

export function requireAuth(
  request: Request,
  minRole: Role = "readonly"
): AuthContext | NextResponse {
  if (process.env.AEGIS_AUTH_DISABLED === "true") {
    return { role: "admin", keyId: "dev", keyName: "dev-mode" };
  }

  const token = extractBearerToken(request);
  if (!token) {
    return NextResponse.json(
      { error: "Missing Authorization header" },
      { status: 401 }
    );
  }

  const masterKey = process.env.AEGIS_API_KEY;
  if (masterKey && token === masterKey) {
    return { role: "admin", keyId: "master", keyName: "master-key" };
  }

  const stored = validateKey(token);
  if (!stored) {
    return NextResponse.json({ error: "Invalid API key" }, { status: 401 });
  }

  if (ROLE_HIERARCHY[stored.role] < ROLE_HIERARCHY[minRole]) {
    return NextResponse.json(
      { error: `Requires ${minRole} role, you have ${stored.role}` },
      { status: 403 }
    );
  }

  return { role: stored.role, keyId: stored.id, keyName: stored.name };
}
