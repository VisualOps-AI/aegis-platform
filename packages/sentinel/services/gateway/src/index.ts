import express from 'express';
import { apiKeyAuth } from './middleware/auth.js';
import { rateLimit } from './middleware/rate-limit.js';
import agentsRouter from './routes/agents.js';
import fleetRouter from './routes/fleet.js';
import logsRouter from './routes/logs.js';
import alertsRouter from './routes/alerts.js';
import sessionsRouter from './routes/sessions.js';
import timelinesRouter from './routes/timelines.js';
import receiptsRouter from './routes/receipts.js';
import policiesRouter from './routes/policies.js';
import eventsRouter from './routes/events.js';
import healthRouter from './routes/health.js';

const PORT = parseInt(process.env.WITNESS_GATEWAY_PORT ?? '3001', 10);
const CORS_ORIGINS = (process.env.WITNESS_CORS_ORIGINS ?? 'http://localhost:3000,http://localhost:5173').split(',');

const app = express();

app.use(express.json());

app.use((_req, res, next) => {
  const origin = _req.headers.origin;
  if (origin && CORS_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (_req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});

app.use(rateLimit);
app.use('/api/v1', apiKeyAuth);

app.use('/health', healthRouter);
app.use('/api/v1/agents', agentsRouter);
app.use('/api/v1/fleet', fleetRouter);
app.use('/api/v1/logs', logsRouter);
app.use('/api/v1/audit', logsRouter);
app.use('/api/v1/alerts', alertsRouter);
app.use('/api/v1/sessions', sessionsRouter);
app.use('/api/v1/timelines', timelinesRouter);
app.use('/api/v1/receipts', receiptsRouter);
app.use('/api/v1/policies', policiesRouter);
app.use('/api/v1/events', eventsRouter);

app.listen(PORT, () => {
  process.stderr.write(`[witness-gateway] Listening on port ${PORT}\n`);
  process.stderr.write(`[witness-gateway] CORS origins: ${CORS_ORIGINS.join(', ')}\n`);
});
