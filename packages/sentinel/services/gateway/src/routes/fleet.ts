import { Router } from 'express';
import { proxyGovernance } from '../core/governance-client.js';

const router = Router();

router.get('/status', async (_req, res) => {
  const { status, data } = await proxyGovernance('/api/fleet/status');
  res.status(status).json(data);
});

router.get('/performance', async (_req, res) => {
  const { status, data } = await proxyGovernance('/api/fleet-performance');
  res.status(status).json(data);
});

router.post('/kill', async (req, res) => {
  const { status, data } = await proxyGovernance('/api/fleet/kill', 'POST', {
    reason: req.body?.reason ?? 'Emergency fleet shutdown via gateway',
    actor: req.body?.actor ?? 'gateway',
  });
  res.status(status).json(data);
});

router.post('/revive', async (req, res) => {
  const { status, data } = await proxyGovernance('/api/fleet/revive', 'POST', {
    reason: req.body?.reason ?? 'Fleet revived via gateway',
    actor: req.body?.actor ?? 'gateway',
  });
  res.status(status).json(data);
});

export default router;
