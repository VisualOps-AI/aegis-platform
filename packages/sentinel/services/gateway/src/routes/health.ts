import { Router } from 'express';
import { governanceHealth } from '../core/governance-client.js';
import { mcpHealth } from '../core/mcp-client.js';
import type { ServiceHealth } from '../core/types.js';

const BRAIN_URL = process.env.WITNESS_BRAIN_URL ?? 'http://localhost:5000';
const SENTINEL_URL = process.env.WITNESS_SENTINEL_URL ?? 'http://localhost:8080';

async function checkService(url: string, name: string): Promise<ServiceHealth> {
  try {
    const res = await fetch(`${url}/health`, { signal: AbortSignal.timeout(3000) });
    const data = (await res.json()) as Record<string, unknown>;
    return { service: name, status: String(data.status ?? 'unknown') };
  } catch {
    return { service: name, status: 'unreachable' };
  }
}

const router = Router();

router.get('/', async (_req, res) => {
  const [governance, mcp, brain, sentinel] = await Promise.all([
    governanceHealth().then((h) => (h ? { service: h.service, status: h.status } : { service: 'witness-governance', status: 'unreachable' })),
    mcpHealth().then((h) => (h ? { service: h.service, status: h.status } : { service: 'witness-mcp-proxy', status: 'unreachable' })),
    checkService(BRAIN_URL, 'witness-brain'),
    checkService(SENTINEL_URL, 'witness-sentinel'),
  ]);

  const services: ServiceHealth[] = [governance, mcp, brain, sentinel];
  const allHealthy = services.every((s) => s.status === 'healthy');

  res.status(allHealthy ? 200 : 207).json({
    status: allHealthy ? 'healthy' : 'degraded',
    service: 'witness-gateway',
    services,
  });
});

export default router;
