import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

export interface SessionRecord {
  id: string;
  started_at: string;
  agent_name: string | null;
  command: string | null;
}

export interface EventRecord {
  id: number;
  session_id: string;
  timestamp: string;
  tool_name: string;
  args_json: string | null;
  result_json: string | null;
  duration_ms: number | null;
  status: string;
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    agent_name TEXT,
    command TEXT
  );

  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    timestamp TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args_json TEXT,
    result_json TEXT,
    duration_ms INTEGER,
    status TEXT NOT NULL DEFAULT 'pending'
  );

  CREATE TABLE IF NOT EXISTS timelines (
    id TEXT PRIMARY KEY,
    parent_id TEXT NOT NULL DEFAULT 'tl_main',
    session_id TEXT NOT NULL REFERENCES sessions(id),
    status TEXT NOT NULL DEFAULT 'active',
    branch_point TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timeline_id TEXT NOT NULL REFERENCES timelines(id),
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    data_json TEXT
  );
`;

export class EventStore {
  private db: DatabaseSync;

  constructor(dbPath = ".witness/events.db") {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec(SCHEMA);
  }

  createSession(agentName: string, command: string): string {
    const id = randomUUID();
    const stmt = this.db.prepare(
      "INSERT INTO sessions (id, started_at, agent_name, command) VALUES (?, ?, ?, ?)"
    );
    stmt.run(id, new Date().toISOString(), agentName, command);
    return id;
  }

  logEvent(sessionId: string, toolName: string, args: unknown): string {
    const stmt = this.db.prepare(
      "INSERT INTO events (session_id, timestamp, tool_name, args_json, status) VALUES (?, ?, ?, ?, 'pending')"
    );
    const result = stmt.run(
      sessionId,
      new Date().toISOString(),
      toolName,
      JSON.stringify(args)
    );
    return String(result.lastInsertRowid);
  }

  completeEvent(eventId: string, result: unknown, durationMs: number): void {
    const stmt = this.db.prepare(
      "UPDATE events SET result_json = ?, duration_ms = ?, status = 'completed' WHERE id = ?"
    );
    stmt.run(JSON.stringify(result), durationMs, Number(eventId));
  }

  failEvent(eventId: string, error: string, durationMs: number): void {
    const stmt = this.db.prepare(
      "UPDATE events SET result_json = ?, duration_ms = ?, status = 'failed' WHERE id = ?"
    );
    stmt.run(JSON.stringify({ error }), durationMs, Number(eventId));
  }

  getSessionEvents(sessionId: string): EventRecord[] {
    const stmt = this.db.prepare(
      "SELECT * FROM events WHERE session_id = ? ORDER BY id ASC"
    );
    return stmt.all(sessionId) as unknown as EventRecord[];
  }

  getRecentSessions(limit = 20): SessionRecord[] {
    const stmt = this.db.prepare(
      "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?"
    );
    return stmt.all(limit) as unknown as SessionRecord[];
  }

  insertTimeline(timeline: {
    id: string;
    parentId: string;
    sessionId: string;
    status: string;
    branchPoint: string;
    toolName: string;
    description?: string;
  }): void {
    const stmt = this.db.prepare(
      "INSERT INTO timelines (id, parent_id, session_id, status, branch_point, tool_name, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    );
    stmt.run(
      timeline.id,
      timeline.parentId,
      timeline.sessionId,
      timeline.status,
      timeline.branchPoint,
      timeline.toolName,
      timeline.description ?? null,
      new Date().toISOString()
    );
  }

  getTimeline(id: string): Record<string, unknown> | null {
    const stmt = this.db.prepare("SELECT * FROM timelines WHERE id = ?");
    const rows = stmt.all(id) as unknown as Record<string, unknown>[];
    return rows.length > 0 ? rows[0] : null;
  }

  getSessionTimelines(sessionId: string): Record<string, unknown>[] {
    const stmt = this.db.prepare(
      "SELECT * FROM timelines WHERE session_id = ? ORDER BY created_at ASC"
    );
    return stmt.all(sessionId) as unknown as Record<string, unknown>[];
  }

  getChildTimelines(parentId: string): Record<string, unknown>[] {
    const stmt = this.db.prepare(
      "SELECT * FROM timelines WHERE parent_id = ? ORDER BY created_at ASC"
    );
    return stmt.all(parentId) as unknown as Record<string, unknown>[];
  }

  updateTimelineStatus(id: string, status: string): void {
    const stmt = this.db.prepare(
      "UPDATE timelines SET status = ? WHERE id = ?"
    );
    stmt.run(status, id);
  }

  insertTimelineEvent(event: {
    timelineId: string;
    eventType: string;
    timestamp: string;
    dataJson?: string;
  }): void {
    const stmt = this.db.prepare(
      "INSERT INTO timeline_events (timeline_id, event_type, timestamp, data_json) VALUES (?, ?, ?, ?)"
    );
    stmt.run(
      event.timelineId,
      event.eventType,
      event.timestamp,
      event.dataJson ?? null
    );
  }

  getTimelineEvents(timelineId: string): Record<string, unknown>[] {
    const stmt = this.db.prepare(
      "SELECT * FROM timeline_events WHERE timeline_id = ? ORDER BY id ASC"
    );
    return stmt.all(timelineId) as unknown as Record<string, unknown>[];
  }

  close(): void {
    this.db.close();
  }
}
