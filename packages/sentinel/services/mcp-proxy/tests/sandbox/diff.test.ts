import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { DiffEngine } from '../../src/sandbox/diff.js';

describe('DiffEngine', () => {
  let sourceDir: string;
  let shadowDir: string;
  let engine: DiffEngine;

  before(async () => {
    engine = new DiffEngine();

    sourceDir = join(tmpdir(), `witness-diff-source-${randomUUID()}`);
    shadowDir = join(tmpdir(), `witness-diff-shadow-${randomUUID()}`);

    await mkdir(join(sourceDir, 'src'), { recursive: true });
    await mkdir(join(shadowDir, 'src'), { recursive: true });
  });

  it('detects added files', async () => {
    const src = join(tmpdir(), `diff-add-src-${randomUUID()}`);
    const shd = join(tmpdir(), `diff-add-shd-${randomUUID()}`);
    await mkdir(src, { recursive: true });
    await mkdir(shd, { recursive: true });

    await writeFile(join(src, 'a.txt'), 'hello');
    await writeFile(join(shd, 'a.txt'), 'hello');
    await writeFile(join(shd, 'b.txt'), 'new file');

    const result = await engine.computeDiff(src, shd);

    assert.equal(result.summary.filesAdded, 1);
    assert.equal(result.summary.filesModified, 0);
    assert.equal(result.summary.filesDeleted, 0);

    const added = result.changes.find(c => c.path === 'b.txt');
    assert.ok(added);
    assert.equal(added!.type, 'added');

    await rm(src, { recursive: true, force: true });
    await rm(shd, { recursive: true, force: true });
  });

  it('detects modified files', async () => {
    const src = join(tmpdir(), `diff-mod-src-${randomUUID()}`);
    const shd = join(tmpdir(), `diff-mod-shd-${randomUUID()}`);
    await mkdir(src, { recursive: true });
    await mkdir(shd, { recursive: true });

    await writeFile(join(src, 'file.txt'), 'line1\nline2\nline3');
    await writeFile(join(shd, 'file.txt'), 'line1\nmodified\nline3');

    const result = await engine.computeDiff(src, shd);

    assert.equal(result.summary.filesModified, 1);
    const mod = result.changes.find(c => c.type === 'modified');
    assert.ok(mod);
    assert.ok(mod!.diff?.includes('-line2'));
    assert.ok(mod!.diff?.includes('+modified'));

    await rm(src, { recursive: true, force: true });
    await rm(shd, { recursive: true, force: true });
  });

  it('detects deleted files', async () => {
    const src = join(tmpdir(), `diff-del-src-${randomUUID()}`);
    const shd = join(tmpdir(), `diff-del-shd-${randomUUID()}`);
    await mkdir(src, { recursive: true });
    await mkdir(shd, { recursive: true });

    await writeFile(join(src, 'keep.txt'), 'keep');
    await writeFile(join(src, 'remove.txt'), 'gone');
    await writeFile(join(shd, 'keep.txt'), 'keep');

    const result = await engine.computeDiff(src, shd);

    assert.equal(result.summary.filesDeleted, 1);
    const deleted = result.changes.find(c => c.type === 'deleted');
    assert.ok(deleted);
    assert.equal(deleted!.path, 'remove.txt');

    await rm(src, { recursive: true, force: true });
    await rm(shd, { recursive: true, force: true });
  });

  it('formats diff as readable text', async () => {
    const src = join(tmpdir(), `diff-fmt-src-${randomUUID()}`);
    const shd = join(tmpdir(), `diff-fmt-shd-${randomUUID()}`);
    await mkdir(src, { recursive: true });
    await mkdir(shd, { recursive: true });

    await writeFile(join(src, 'a.txt'), 'before');
    await writeFile(join(shd, 'a.txt'), 'after');

    const result = await engine.computeDiff(src, shd);
    const text = engine.formatDiffAsText(result);

    assert.ok(text.includes('Timeline:'));
    assert.ok(text.includes('1 modified'));
    assert.ok(text.includes('--- a/a.txt'));
    assert.ok(text.includes('+++ b/a.txt'));

    await rm(src, { recursive: true, force: true });
    await rm(shd, { recursive: true, force: true });
  });

  it('handles identical directories with no changes', async () => {
    const src = join(tmpdir(), `diff-same-src-${randomUUID()}`);
    const shd = join(tmpdir(), `diff-same-shd-${randomUUID()}`);
    await mkdir(src, { recursive: true });
    await mkdir(shd, { recursive: true });

    await writeFile(join(src, 'same.txt'), 'identical');
    await writeFile(join(shd, 'same.txt'), 'identical');

    const result = await engine.computeDiff(src, shd);

    assert.equal(result.changes.length, 0);
    assert.equal(result.summary.filesAdded, 0);
    assert.equal(result.summary.filesModified, 0);
    assert.equal(result.summary.filesDeleted, 0);

    await rm(src, { recursive: true, force: true });
    await rm(shd, { recursive: true, force: true });
  });
});
