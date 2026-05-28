import { NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth";
import { deleteKey } from "@/lib/key-store";

export const dynamic = "force-dynamic";

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  const auth = requireAuth(request, "admin");
  if (auth instanceof NextResponse) return auth;

  const { id } = await params;
  const deleted = deleteKey(id);

  if (!deleted) {
    return NextResponse.json({ error: "Key not found" }, { status: 404 });
  }

  return NextResponse.json({ deleted: true });
}
