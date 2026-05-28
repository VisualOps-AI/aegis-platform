import { subscribeScan, getScanStatus, type ScanEvent } from "@/lib/scan-runner";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
): Promise<Response> {
  const { id } = await params;

  const existing = getScanStatus(id);
  if (!existing) {
    return new Response(JSON.stringify({ error: "Scan not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (existing.status === "complete" || existing.status === "failed") {
    const encoder = new TextEncoder();
    const eventType = existing.status === "complete" ? "complete" : "failed";
    const data = existing.status === "complete"
      ? {
          scanId: existing.id,
          riskScore: existing.report?.summary.riskScore,
          totalFindings: existing.report?.summary.totalFindings,
          bySeverity: existing.report?.summary.bySeverity,
        }
      : { error: existing.error };

    const body = encoder.encode(
      `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`
    );

    return new Response(body, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
    });
  }

  const stream = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();

      function send(event: ScanEvent) {
        const payload = `event: ${event.type}\ndata: ${JSON.stringify(event.data ?? {})}\n\n`;
        try {
          controller.enqueue(encoder.encode(payload));
        } catch {
          unsubscribe();
        }
      }

      send({
        type: "started",
        scanId: id,
        timestamp: new Date().toISOString(),
        data: { status: existing.status },
      });

      const unsubscribe = subscribeScan(id, (event) => {
        send(event);
        if (event.type === "complete" || event.type === "failed") {
          try {
            controller.close();
          } catch { /* already closed */ }
        }
      });

      const timeout = setTimeout(() => {
        unsubscribe();
        try {
          const payload = `event: timeout\ndata: ${JSON.stringify({ error: "Scan timed out" })}\n\n`;
          controller.enqueue(encoder.encode(payload));
          controller.close();
        } catch { /* already closed */ }
      }, 300_000);

      _request.signal.addEventListener("abort", () => {
        unsubscribe();
        clearTimeout(timeout);
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
