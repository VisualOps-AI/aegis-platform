import { Router, type Request, type Response } from 'express';
import { mcpPending } from '../core/mcp-client.js';

const router = Router();
const POLL_INTERVAL_MS = 2000;
const HEARTBEAT_INTERVAL_MS = 15000;

router.get('/stream', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const knownIds = new Set<string>();

  const poll = async (): Promise<void> => {
    const pending = await mcpPending();
    const currentIds = new Set<string>();

    for (const item of pending) {
      const id = (item as Record<string, unknown>).id as string;
      currentIds.add(id);

      if (!knownIds.has(id)) {
        knownIds.add(id);
        res.write(`event: pending_review\ndata: ${JSON.stringify(item)}\n\n`);
      }
    }

    for (const id of knownIds) {
      if (!currentIds.has(id)) {
        knownIds.delete(id);
        res.write(`event: timeline_update\ndata: ${JSON.stringify({ id, status: 'resolved' })}\n\n`);
      }
    }
  };

  const pollTimer = setInterval(poll, POLL_INTERVAL_MS);
  const heartbeatTimer = setInterval(() => {
    res.write(': heartbeat\n\n');
  }, HEARTBEAT_INTERVAL_MS);

  poll();

  _req.on('close', () => {
    clearInterval(pollTimer);
    clearInterval(heartbeatTimer);
  });
});

export default router;
