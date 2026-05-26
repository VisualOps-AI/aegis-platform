import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { ShadowWorkspace } from '../../src/sandbox/workspace.js';

describe('ShadowWorkspace', () => {
  let testDir: string;

  before(async () => {
    testDir = join(tmpdir(), `witness-test-${randomUUID()}`);
    await mkdir(join(testDir, 'src'), { recursive: true });
    await mkdir(join(testDir, 'node_modules', 'dep'), { recursive: true });
    await writeFile(join(testDir, 'src', 'index.ts'), 'console.log("hello");');
    await writeFile(join(testDir, 'src', 'util.ts'), 'export const x = 1;');
    await writeFile(join(testDir, 'package.json'), '{"name":"test"}');
    await writeFile(join(testDir, 'node_modules', 'dep', 'index.js'), 'module.exports = {};');
  });

  it('creates a shadow workspace with correct files', async () => {
    const shadow = await ShadowWorkspace.create(testDir);
    const files = await shadow.getTrackedFiles();

    assert.ok(files.includes(join('src', 'index.ts').replace(/\\/g, '\\')));
    assert.ok(files.includes(join('src', 'util.ts').replace(/\\/g, '\\')));
    assert.ok(files.includes('package.json'));

    await shadow.cleanup();
  });

  it('excludes node_modules by default', async () => {
    const shadow = await ShadowWorkspace.create(testDir);
    const files = await shadow.getTrackedFiles();

    const hasNodeModules = files.some(f => f.includes('node_modules'));
    assert.equal(hasNodeModules, false);

    await shadow.cleanup();
  });

  it('returns correct source and shadow paths', async () => {
    const shadow = await ShadowWorkspace.create(testDir);

    assert.ok(shadow.getPath().includes('witness-shadow-'));
    assert.equal(shadow.getSourceDir(), testDir.replace(/\\/g, '\\'));

    await shadow.cleanup();
  });

  it('produces file snapshots with hashes', async () => {
    const shadow = await ShadowWorkspace.create(testDir);
    const snapshot = await shadow.getFileSnapshot();

    assert.ok(snapshot.size > 0);
    for (const [, snap] of snapshot) {
      assert.ok(snap.hash.length === 64);
      assert.ok(snap.size > 0);
    }

    await shadow.cleanup();
  });

  it('detects changes after modification in shadow', async () => {
    const shadow = await ShadowWorkspace.create(testDir);
    const before = await shadow.getFileSnapshot();

    const shadowFile = await shadow.resolveInShadow(join('src', 'index.ts'));
    await writeFile(shadowFile, 'console.log("modified");');

    const after = await shadow.getFileSnapshot();
    const indexKey = [...after.keys()].find(k => k.includes('index.ts'));
    assert.ok(indexKey);

    const beforeHash = before.get(indexKey!)?.hash;
    const afterHash = after.get(indexKey!)?.hash;
    assert.notEqual(beforeHash, afterHash);

    await shadow.cleanup();
  });

  it('cleans up the shadow directory', async () => {
    const shadow = await ShadowWorkspace.create(testDir);
    const path = shadow.getPath();
    await shadow.cleanup();

    try {
      await readFile(join(path, 'package.json'));
      assert.fail('Expected file to not exist after cleanup');
    } catch {
      // expected
    }
  });
});
