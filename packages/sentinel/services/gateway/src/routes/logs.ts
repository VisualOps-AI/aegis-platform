import { Router } from 'express';
import { proxyGovernance } from '../core/governance-client.js';

const router = Router();

router.get('/', async (_req, res) => {
  const { status, data } = await proxyGovernance('/api/logs');
  res.status(status).json(data);
});

router.get('/kills', async (req, res) => {
  const limit = req.query.limit ?? '50';
  const { status, data } = await proxyGovernance(`/api/kill-audit?limit=${limit}`);
  res.status(status).json(data);
});

export default router;
