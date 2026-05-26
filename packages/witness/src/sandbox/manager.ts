import { ShadowWorkspace } from './workspace.js';
import type { ShadowWorkspaceOptions } from './workspace.js';
import { DiffEngine } from './diff.js';
import type { DiffResult } from './diff.js';
import { TimelineManager } from '../timeline/branch.js';
import type { Timeline } from '../timeline/branch.js';
import { EventStore } from '../receipts/store.js';
import { copyFile, mkdir } from 'node:fs/promises';
import { join, dirname, relative } from 'node:path';

export type MergeDecision = 'merge' | 'abandon' | 'pending';

export interface ShadowExecutionResult {
  timeline: Timeline;
  diff: DiffResult;
  workspace: ShadowWorkspace;
}

export interface ShadowManagerOptions {
  workspaceOptions?: ShadowWorkspaceOptions;
  sourceDir: string;
}

export class ShadowManager {
  private timelineManager: TimelineManager;
  private diffEngine: DiffEngine;
  private sourceDir: string;
  private workspaceOptions: ShadowWorkspaceOptions;
  private activeWorkspaces = new Map<string, ShadowWorkspace>();

  constructor(store: EventStore, options: ShadowManagerOptions) {
    this.timelineManager = new TimelineManager(store);
    this.diffEngine = new DiffEngine();
    this.sourceDir = options.sourceDir;
    this.workspaceOptions = options.workspaceOptions ?? {};
  }

  async createShadow(
    sessionId: string,
    toolName: string,
    description?: string,
  ): Promise<ShadowExecutionResult> {
    const timeline = this.timelineManager.createTimeline(
      sessionId,
      'tl_main',
      toolName,
      description,
    );

    const workspace = await ShadowWorkspace.create(
      this.sourceDir,
      this.workspaceOptions,
    );

    this.activeWorkspaces.set(timeline.id, workspace);

    const beforeSnapshot = await workspace.getFileSnapshot();

    return {
      timeline,
      diff: {
        timelineId: timeline.id,
        timestamp: new Date().toISOString(),
        changes: [],
        summary: {
          filesAdded: 0,
          filesModified: 0,
          filesDeleted: 0,
          totalInsertions: 0,
          totalDeletions: 0,
        },
      },
      workspace,
    };
  }

  async computeDiff(timelineId: string): Promise<DiffResult> {
    const workspace = this.activeWorkspaces.get(timelineId);
    if (!workspace) {
      throw new Error(`No active workspace for timeline: ${timelineId}`);
    }

    const result = await this.diffEngine.computeDiff(
      workspace.getSourceDir(),
      workspace.getPath(),
      { timelineId },
    );

    this.timelineManager.logTimelineEvent({
      timelineId,
      eventId: 'diff_generated',
      type: 'diff_generated',
      data: { summary: result.summary },
    });

    return result;
  }

  async merge(timelineId: string): Promise<DiffResult> {
    const workspace = this.activeWorkspaces.get(timelineId);
    if (!workspace) {
      throw new Error(`No active workspace for timeline: ${timelineId}`);
    }

    const diff = await this.computeDiff(timelineId);

    for (const change of diff.changes) {
      const destPath = join(this.sourceDir, change.path);

      if (change.type === 'added' || change.type === 'modified') {
        const shadowPath = await workspace.resolveInShadow(change.path);
        await mkdir(dirname(destPath), { recursive: true });
        await copyFile(shadowPath, destPath);
      }
    }

    this.timelineManager.updateStatus(timelineId, 'merged');
    await this.cleanupTimeline(timelineId);

    return diff;
  }

  async abandon(timelineId: string): Promise<void> {
    this.timelineManager.updateStatus(timelineId, 'abandoned');
    await this.cleanupTimeline(timelineId);
  }

  getWorkspace(timelineId: string): ShadowWorkspace | undefined {
    return this.activeWorkspaces.get(timelineId);
  }

  getTimeline(timelineId: string): Timeline | null {
    return this.timelineManager.getTimeline(timelineId);
  }

  getSessionTimelines(sessionId: string): Timeline[] {
    return this.timelineManager.getSessionTimelines(sessionId);
  }

  formatDiff(diff: DiffResult): string {
    return this.diffEngine.formatDiffAsText(diff);
  }

  async cleanupAll(): Promise<void> {
    for (const [id, workspace] of this.activeWorkspaces) {
      await workspace.cleanup();
    }
    this.activeWorkspaces.clear();
  }

  private async cleanupTimeline(timelineId: string): Promise<void> {
    const workspace = this.activeWorkspaces.get(timelineId);
    if (workspace) {
      await workspace.cleanup();
      this.activeWorkspaces.delete(timelineId);
    }
  }
}
