import { randomUUID } from "node:crypto";

import { EventStore } from "../receipts/store.js";

export type TimelineStatus = "active" | "merged" | "abandoned" | "pending_review";

export interface Timeline {
  id: string;
  parentId: string;
  sessionId: string;
  status: TimelineStatus;
  branchPoint: string;
  metadata: {
    toolName: string;
    description?: string;
  };
}

export interface TimelineEvent {
  timelineId: string;
  eventId: string;
  type:
    | "branch_created"
    | "execution_complete"
    | "diff_generated"
    | "merged"
    | "abandoned";
  timestamp: string;
  data?: Record<string, unknown>;
}

function generateTimelineId(): string {
  return "tl_" + randomUUID().replace(/-/g, "").slice(0, 12);
}

export class TimelineManager {
  private store: EventStore;

  constructor(store: EventStore) {
    this.store = store;
  }

  createTimeline(
    sessionId: string,
    parentId: string,
    toolName: string,
    description?: string
  ): Timeline {
    const id = generateTimelineId();
    const branchPoint = new Date().toISOString();

    const timeline: Timeline = {
      id,
      parentId,
      sessionId,
      status: "active",
      branchPoint,
      metadata: { toolName, description },
    };

    this.store.insertTimeline({
      id,
      parentId,
      sessionId,
      status: "active",
      branchPoint,
      toolName,
      description,
    });

    this.logTimelineEvent({
      timelineId: id,
      eventId: "branch_created",
      type: "branch_created",
      data: { parentId, toolName },
    });

    return timeline;
  }

  getTimeline(timelineId: string): Timeline | null {
    const row = this.store.getTimeline(timelineId);
    if (!row) return null;
    return this.rowToTimeline(row);
  }

  getSessionTimelines(sessionId: string): Timeline[] {
    const rows = this.store.getSessionTimelines(sessionId);
    return rows.map((row) => this.rowToTimeline(row));
  }

  getChildTimelines(parentId: string): Timeline[] {
    const rows = this.store.getChildTimelines(parentId);
    return rows.map((row) => this.rowToTimeline(row));
  }

  updateStatus(timelineId: string, status: TimelineStatus): void {
    this.store.updateTimelineStatus(timelineId, status);

    const eventType = status === "merged" ? "merged" : "abandoned";
    if (status === "merged" || status === "abandoned") {
      this.logTimelineEvent({
        timelineId,
        eventId: eventType,
        type: eventType,
      });
    }
  }

  logTimelineEvent(event: Omit<TimelineEvent, "timestamp">): void {
    this.store.insertTimelineEvent({
      timelineId: event.timelineId,
      eventType: event.type,
      timestamp: new Date().toISOString(),
      dataJson: event.data ? JSON.stringify(event.data) : undefined,
    });
  }

  getTimelineEvents(timelineId: string): TimelineEvent[] {
    const rows = this.store.getTimelineEvents(timelineId);
    return rows.map((row) => ({
      timelineId: row.timeline_id as string,
      eventId: row.event_type as string,
      type: row.event_type as TimelineEvent["type"],
      timestamp: row.timestamp as string,
      data: row.data_json
        ? (JSON.parse(row.data_json as string) as Record<string, unknown>)
        : undefined,
    }));
  }

  private rowToTimeline(row: Record<string, unknown>): Timeline {
    return {
      id: row.id as string,
      parentId: row.parent_id as string,
      sessionId: row.session_id as string,
      status: row.status as TimelineStatus,
      branchPoint: row.branch_point as string,
      metadata: {
        toolName: row.tool_name as string,
        description: (row.description as string) ?? undefined,
      },
    };
  }
}
