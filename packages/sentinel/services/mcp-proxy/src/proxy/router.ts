import { EventStore } from '../receipts/store.js';
import { PolicyEngine } from '../policy/engine.js';
import type { PolicyDecision } from '../policy/engine.js';
import { WitnessClient } from './client.js';
import { ShadowManager } from '../sandbox/manager.js';

import type { ToolRouter, ToolInfo, ToolResult } from './server.js';

export type { ToolRouter };

export interface RouterOptions {
  eventStore: EventStore;
  policyEngine: PolicyEngine;
  client: WitnessClient;
  sessionId: string;
  shadowManager?: ShadowManager;
}

export class ToolCallRouter implements ToolRouter {
  private eventStore: EventStore;
  private policyEngine: PolicyEngine;
  private client: WitnessClient;
  private sessionId: string;
  private shadowManager: ShadowManager | null;

  constructor(options: RouterOptions) {
    this.eventStore = options.eventStore;
    this.policyEngine = options.policyEngine;
    this.client = options.client;
    this.sessionId = options.sessionId;
    this.shadowManager = options.shadowManager ?? null;
  }

  async listTools(): Promise<ToolInfo[]> {
    return this.client.listAllTools();
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const decision = this.policyEngine.evaluate(name, args);
    const eventId = this.eventStore.logEvent(this.sessionId, name, args);
    const startTime = performance.now();

    if (decision.decision === 'deny') {
      const durationMs = Math.round(performance.now() - startTime);
      const errorMsg = `Policy denied: ${decision.reason ?? 'not allowed'}`;
      this.eventStore.failEvent(eventId, errorMsg, durationMs);
      return {
        content: [{ type: 'text', text: errorMsg }],
        isError: true,
      };
    }

    if (decision.decision === 'allow_shadow' && this.shadowManager) {
      return this.executeShadow(name, args, eventId, startTime);
    }

    if (decision.decision === 'require_approval' && this.shadowManager) {
      return this.executePendingReview(name, args, eventId, startTime, decision);
    }

    try {
      const result = await this.client.callTool(name, args);
      const durationMs = Math.round(performance.now() - startTime);
      this.eventStore.completeEvent(eventId, result, durationMs);
      return result;
    } catch (err) {
      const durationMs = Math.round(performance.now() - startTime);
      const errorMsg = err instanceof Error ? err.message : String(err);
      this.eventStore.failEvent(eventId, errorMsg, durationMs);
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${errorMsg}` }],
        isError: true,
      };
    }
  }

  async cleanupShadows(): Promise<void> {
    if (this.shadowManager) {
      await this.shadowManager.cleanupAll();
    }
  }

  private async executePendingReview(
    name: string,
    args: Record<string, unknown>,
    eventId: string,
    startTime: number,
    decision: PolicyDecision,
  ): Promise<ToolResult> {
    try {
      const shadow = await this.shadowManager!.createShadow(
        this.sessionId,
        name,
        `Pending review: ${name} (risk ${decision.riskScore})`,
      );

      const result = await this.client.callTool(name, args);
      const diff = await this.shadowManager!.computeDiff(shadow.timeline.id);
      const durationMs = Math.round(performance.now() - startTime);

      this.eventStore.storeDiffResult(shadow.timeline.id, diff);
      this.shadowManager!.setPendingReview(shadow.timeline.id);

      this.eventStore.completeEvent(eventId, {
        pending: true,
        timelineId: shadow.timeline.id,
        diff: diff.summary,
      }, durationMs);

      const summary = `${diff.summary.filesAdded} added, ${diff.summary.filesModified} modified, ${diff.summary.filesDeleted} deleted`;

      return {
        content: [{
          type: 'text',
          text: `Tool execution pending review. Timeline: ${shadow.timeline.id}. Changes: ${summary}. Reason: ${decision.reason ?? 'requires approval'}`,
        }],
        isError: false,
      };
    } catch (err) {
      const durationMs = Math.round(performance.now() - startTime);
      const errorMsg = err instanceof Error ? err.message : String(err);
      this.eventStore.failEvent(eventId, errorMsg, durationMs);
      return {
        content: [{ type: 'text', text: `Pending review setup failed: ${errorMsg}` }],
        isError: true,
      };
    }
  }

  private async executeShadow(
    name: string,
    args: Record<string, unknown>,
    eventId: string,
    startTime: number,
  ): Promise<ToolResult> {
    try {
      const shadow = await this.shadowManager!.createShadow(
        this.sessionId,
        name,
        `Shadow execution of ${name}`,
      );

      const result = await this.client.callTool(name, args);

      const diff = await this.shadowManager!.computeDiff(shadow.timeline.id);
      const durationMs = Math.round(performance.now() - startTime);

      this.eventStore.completeEvent(eventId, {
        ...result,
        shadow: {
          timelineId: shadow.timeline.id,
          diff: diff.summary,
        },
      }, durationMs);

      await this.shadowManager!.merge(shadow.timeline.id);

      const diffText = this.shadowManager!.formatDiff(diff);

      return {
        content: [
          ...result.content,
          ...(diff.changes.length > 0
            ? [{ type: 'text', text: `\n--- Shadow Timeline ${shadow.timeline.id} ---\n${diffText}` }]
            : []),
        ],
        isError: result.isError,
      };
    } catch (err) {
      const durationMs = Math.round(performance.now() - startTime);
      const errorMsg = err instanceof Error ? err.message : String(err);
      this.eventStore.failEvent(eventId, errorMsg, durationMs);
      return {
        content: [{ type: 'text', text: `Shadow execution failed: ${errorMsg}` }],
        isError: true,
      };
    }
  }
}
