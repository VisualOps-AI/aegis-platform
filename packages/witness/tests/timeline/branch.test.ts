import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { EventStore } from '../../src/receipts/store.js';
import { TimelineManager } from '../../src/timeline/branch.js';

describe('TimelineManager', () => {
  let store: EventStore;
  let manager: TimelineManager;
  let sessionId: string;

  before(() => {
    const dbPath = join(tmpdir(), `witness-test-${randomUUID()}.db`);
    store = new EventStore(dbPath);
    manager = new TimelineManager(store);
    sessionId = store.createSession('test-agent', 'test-command');
  });

  after(() => {
    store.close();
  });

  it('creates a timeline with correct properties', () => {
    const tl = manager.createTimeline(sessionId, 'tl_main', 'filesystem.write', 'test write');

    assert.ok(tl.id.startsWith('tl_'));
    assert.equal(tl.parentId, 'tl_main');
    assert.equal(tl.sessionId, sessionId);
    assert.equal(tl.status, 'active');
    assert.equal(tl.metadata.toolName, 'filesystem.write');
    assert.equal(tl.metadata.description, 'test write');
    assert.ok(tl.branchPoint);
  });

  it('retrieves a timeline by id', () => {
    const created = manager.createTimeline(sessionId, 'tl_main', 'terminal.exec');
    const fetched = manager.getTimeline(created.id);

    assert.ok(fetched);
    assert.equal(fetched!.id, created.id);
    assert.equal(fetched!.metadata.toolName, 'terminal.exec');
  });

  it('lists session timelines', () => {
    const before = manager.getSessionTimelines(sessionId).length;
    manager.createTimeline(sessionId, 'tl_main', 'tool.a');
    manager.createTimeline(sessionId, 'tl_main', 'tool.b');
    const after = manager.getSessionTimelines(sessionId).length;

    assert.equal(after - before, 2);
  });

  it('gets child timelines', () => {
    const parent = manager.createTimeline(sessionId, 'tl_main', 'parent.tool');
    manager.createTimeline(sessionId, parent.id, 'child.tool');
    manager.createTimeline(sessionId, parent.id, 'child.tool.2');

    const children = manager.getChildTimelines(parent.id);
    assert.equal(children.length, 2);
  });

  it('updates timeline status', () => {
    const tl = manager.createTimeline(sessionId, 'tl_main', 'test.tool');
    assert.equal(tl.status, 'active');

    manager.updateStatus(tl.id, 'merged');
    const updated = manager.getTimeline(tl.id);
    assert.equal(updated!.status, 'merged');
  });

  it('logs and retrieves timeline events', () => {
    const tl = manager.createTimeline(sessionId, 'tl_main', 'event.tool');

    manager.logTimelineEvent({
      timelineId: tl.id,
      eventId: 'exec_complete',
      type: 'execution_complete',
      data: { result: 'success' },
    });

    const events = manager.getTimelineEvents(tl.id);
    const execEvent = events.find(e => e.type === 'execution_complete');
    assert.ok(execEvent);
    assert.deepEqual(execEvent!.data, { result: 'success' });
  });

  it('auto-logs branch_created event on timeline creation', () => {
    const tl = manager.createTimeline(sessionId, 'tl_main', 'auto.tool');
    const events = manager.getTimelineEvents(tl.id);

    assert.ok(events.some(e => e.type === 'branch_created'));
  });
});
