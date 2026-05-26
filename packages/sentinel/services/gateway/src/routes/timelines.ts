import { Router } from 'express';
import { proxyMcp } from '../core/mcp-client.js';

const router = Router();

router.get('/', async (req, res) => {
  const sessionId = req.query.session_id;
  if (!sessionId) {
    res.status(400).json({ error: 'session_id query parameter required', code: 'MISSING_PARAM' });
    return;
  }
  const { status, data } = await proxyMcp(`/timelines?session_id=${sessionId}`);
  res.status(status).json(data);
});

router.get('/:id', async (req, res) => {
  const { status, data } = await proxyMcp(`/timelines/${req.params.id}`);
  res.status(status).json(data);
});

router.post('/:id/merge', async (req, res) => {
  const { status, data } = await proxyMcp(`/timelines/${req.params.id}/merge`, 'POST');
  res.status(status).json(data);
});

router.post('/:id/abandon', async (req, res) => {
  const { status, data } = await proxyMcp(`/timelines/${req.params.id}/abandon`, 'POST');
  res.status(status).json(data);
});

router.post('/:id/approve', async (req, res) => {
  const { status, data } = await proxyMcp(`/timelines/${req.params.id}/approve`, 'POST', req.body);
  res.status(status).json(data);
});

router.post('/:id/reject', async (req, res) => {
  const { status, data } = await proxyMcp(`/timelines/${req.params.id}/reject`, 'POST', req.body);
  res.status(status).json(data);
});

export default router;
