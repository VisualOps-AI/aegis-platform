import { Router } from 'express';
import { proxyGovernance } from '../core/governance-client.js';

const router = Router();

router.get('/', async (_req, res) => {
  const { status, data } = await proxyGovernance('/api/fleet-performance');
  res.status(status).json(data);
});

router.get('/:id', async (req, res) => {
  const { status, data } = await proxyGovernance(`/api/agents/${req.params.id}/status`);
  res.status(status).json(data);
});

router.post('/:id/kill', async (req, res) => {
  const { status, data } = await proxyGovernance(`/api/agents/${req.params.id}/kill`, 'POST', {
    reason: req.body?.reason ?? 'Killed via gateway API',
    actor: req.body?.actor ?? 'gateway',
  });
  res.status(status).json(data);
});

router.post('/:id/revive', async (req, res) => {
  const { status, data } = await proxyGovernance(`/api/agents/${req.params.id}/revive`, 'POST', {
    reason: req.body?.reason ?? 'Revived via gateway API',
    actor: req.body?.actor ?? 'gateway',
  });
  res.status(status).json(data);
});

router.get('/:id/status', async (req, res) => {
  const { status, data } = await proxyGovernance(`/api/agents/${req.params.id}/status`);
  res.status(status).json(data);
});

export default router;
