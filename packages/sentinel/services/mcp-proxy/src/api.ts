import express from 'express';
import { EventStore } from './receipts/store.js';

const PORT = parseInt(process.env.WITNESS_MCP_PORT ?? '3002', 10);
const DB_PATH = process.env.WITNESS_DB_PATH ?? '.witness/events.db';

const app = express();
app.use(express.json());

let store: EventStore;

try {
  store = new EventStore(DB_PATH);
} catch {
  process.stderr.write(`[witness-mcp-proxy] Failed to open database at ${DB_PATH}\n`);
  process.exit(1);
}

app.get('/health', (_req, res) => {
  res.json({ status: 'healthy', service: 'witness-mcp-proxy' });
});

app.get('/sessions', (req, res) => {
  const limit = parseInt(req.query.limit as string, 10) || 20;
  const sessions = store.getRecentSessions(limit);
  res.json(sessions);
});

app.get('/sessions/:id/events', (req, res) => {
  const events = store.getSessionEvents(req.params.id);
  res.json(events);
});

app.get('/timelines', (req, res) => {
  const sessionId = req.query.session_id as string | undefined;
  if (!sessionId) {
    res.status(400).json({ error: 'session_id query parameter required', code: 'MISSING_PARAM' });
    return;
  }
  const timelines = store.getSessionTimelines(sessionId);
  res.json(timelines);
});

app.get('/timelines/:id', (req, res) => {
  const timeline = store.getTimeline(req.params.id);
  if (!timeline) {
    res.status(404).json({ error: 'Timeline not found', code: 'NOT_FOUND' });
    return;
  }
  const events = store.getTimelineEvents(req.params.id);
  const diff = store.getDiffResult(req.params.id);
  res.json({ ...timeline, events, diff: diff ?? null });
});

app.post('/timelines/:id/merge', (req, res) => {
  const timeline = store.getTimeline(req.params.id);
  if (!timeline) {
    res.status(404).json({ error: 'Timeline not found', code: 'NOT_FOUND' });
    return;
  }
  if (timeline.status !== 'active') {
    res.status(409).json({ error: `Timeline is ${timeline.status}, not active`, code: 'INVALID_STATE' });
    return;
  }
  store.updateTimelineStatus(req.params.id, 'merged');
  store.insertTimelineEvent({
    timelineId: req.params.id,
    eventType: 'merged',
    timestamp: new Date().toISOString(),
    dataJson: JSON.stringify({ merged_by: 'api' }),
  });
  res.json({ status: 'merged', timeline_id: req.params.id });
});

app.post('/timelines/:id/abandon', (req, res) => {
  const timeline = store.getTimeline(req.params.id);
  if (!timeline) {
    res.status(404).json({ error: 'Timeline not found', code: 'NOT_FOUND' });
    return;
  }
  if (timeline.status !== 'active') {
    res.status(409).json({ error: `Timeline is ${timeline.status}, not active`, code: 'INVALID_STATE' });
    return;
  }
  store.updateTimelineStatus(req.params.id, 'abandoned');
  store.insertTimelineEvent({
    timelineId: req.params.id,
    eventType: 'abandoned',
    timestamp: new Date().toISOString(),
    dataJson: JSON.stringify({ abandoned_by: 'api' }),
  });
  res.json({ status: 'abandoned', timeline_id: req.params.id });
});

app.get('/pending', (_req, res) => {
  const timelines = store.getPendingTimelines();
  const result = timelines.map((tl) => {
    const diff = store.getDiffResult(tl.id as string);
    return { ...tl, diff: diff ?? null };
  });
  res.json(result);
});

app.post('/timelines/:id/approve', (req, res) => {
  const timeline = store.getTimeline(req.params.id);
  if (!timeline) {
    res.status(404).json({ error: 'Timeline not found', code: 'NOT_FOUND' });
    return;
  }
  if (timeline.status !== 'pending_review') {
    res.status(409).json({ error: `Timeline is ${timeline.status}, not pending_review`, code: 'INVALID_STATE' });
    return;
  }
  store.updateTimelineStatus(req.params.id, 'merged');
  store.insertTimelineEvent({
    timelineId: req.params.id,
    eventType: 'merged',
    timestamp: new Date().toISOString(),
    dataJson: JSON.stringify({ approved_by: req.body?.actor ?? 'api' }),
  });
  res.json({ status: 'approved', timeline_id: req.params.id });
});

app.post('/timelines/:id/reject', (req, res) => {
  const timeline = store.getTimeline(req.params.id);
  if (!timeline) {
    res.status(404).json({ error: 'Timeline not found', code: 'NOT_FOUND' });
    return;
  }
  if (timeline.status !== 'pending_review') {
    res.status(409).json({ error: `Timeline is ${timeline.status}, not pending_review`, code: 'INVALID_STATE' });
    return;
  }
  store.updateTimelineStatus(req.params.id, 'abandoned');
  store.insertTimelineEvent({
    timelineId: req.params.id,
    eventType: 'abandoned',
    timestamp: new Date().toISOString(),
    dataJson: JSON.stringify({ rejected_by: req.body?.actor ?? 'api', reason: req.body?.reason ?? null }),
  });
  res.json({ status: 'rejected', timeline_id: req.params.id });
});

app.get('/receipts', (req, res) => {
  const sessionId = req.query.session_id as string | undefined;
  if (!sessionId) {
    res.status(400).json({ error: 'session_id query parameter required', code: 'MISSING_PARAM' });
    return;
  }
  const events = store.getSessionEvents(sessionId);
  res.json(events);
});

app.get('/receipts/:id', (req, res) => {
  const eventId = req.params.id;
  const sessionId = req.query.session_id as string | undefined;
  if (!sessionId) {
    res.status(400).json({ error: 'session_id query parameter required', code: 'MISSING_PARAM' });
    return;
  }
  const events = store.getSessionEvents(sessionId);
  const event = events.find((e) => String(e.id) === eventId);
  if (!event) {
    res.status(404).json({ error: 'Receipt not found', code: 'NOT_FOUND' });
    return;
  }
  res.json(event);
});

const server = app.listen(PORT, () => {
  process.stderr.write(`[witness-mcp-proxy] HTTP API listening on port ${PORT}\n`);
  process.stderr.write(`[witness-mcp-proxy] Database: ${DB_PATH}\n`);
});

const shutdown = (): void => {
  process.stderr.write('[witness-mcp-proxy] Shutting down...\n');
  store.close();
  server.close();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
