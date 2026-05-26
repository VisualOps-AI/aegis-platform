import { Router } from 'express';
import { proxyMcp } from '../core/mcp-client.js';

const router = Router();

router.get('/', async (req, res) => {
  const limit = req.query.limit ?? '20';
  const { status, data } = await proxyMcp(`/sessions?limit=${limit}`);
  res.status(status).json(data);
});

router.get('/:id/events', async (req, res) => {
  const { status, data } = await proxyMcp(`/sessions/${req.params.id}/events`);
  res.status(status).json(data);
});

export default router;
