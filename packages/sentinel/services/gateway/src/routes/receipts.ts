import { Router } from 'express';
import { proxyMcp } from '../core/mcp-client.js';

const router = Router();

router.get('/', async (req, res) => {
  const sessionId = req.query.session_id;
  if (!sessionId) {
    res.status(400).json({ error: 'session_id query parameter required', code: 'MISSING_PARAM' });
    return;
  }
  const { status, data } = await proxyMcp(`/receipts?session_id=${sessionId}`);
  res.status(status).json(data);
});

router.get('/:id', async (req, res) => {
  const sessionId = req.query.session_id;
  if (!sessionId) {
    res.status(400).json({ error: 'session_id query parameter required', code: 'MISSING_PARAM' });
    return;
  }
  const { status, data } = await proxyMcp(`/receipts/${req.params.id}?session_id=${sessionId}`);
  res.status(status).json(data);
});

router.get('/:id/verify', async (req, res) => {
  res.status(501).json({ error: 'Receipt verification not yet implemented (Week 4+)', code: 'NOT_IMPLEMENTED' });
});

export default router;
