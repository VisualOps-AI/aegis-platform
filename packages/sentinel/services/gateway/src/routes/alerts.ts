import { Router } from 'express';
import { proxyGovernance } from '../core/governance-client.js';

const router = Router();

router.get('/', async (req, res) => {
  const params = new URLSearchParams();
  if (req.query.limit) params.set('limit', req.query.limit as string);
  if (req.query.severity) params.set('severity', req.query.severity as string);
  const qs = params.toString() ? `?${params.toString()}` : '';
  const { status, data } = await proxyGovernance(`/api/alerts${qs}`);
  res.status(status).json(data);
});

router.get('/channels', async (_req, res) => {
  const { status, data } = await proxyGovernance('/api/alerts/channels');
  res.status(status).json(data);
});

router.post('/test', async (_req, res) => {
  const { status, data } = await proxyGovernance('/api/alerts/test', 'POST');
  res.status(status).json(data);
});

export default router;
