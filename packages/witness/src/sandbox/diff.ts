import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, posix } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export type FileChangeType = 'added' | 'modified' | 'deleted';

export interface FileSnapshot {
  hash: string;
  size: number;
  content?: string;
}

export interface FileChange {
  path: string;
  type: FileChangeType;
  before?: FileSnapshot;
  after?: FileSnapshot;
  diff?: string;
}

export interface DiffSummary {
  filesAdded: number;
  filesModified: number;
  filesDeleted: number;
  totalInsertions: number;
  totalDeletions: number;
}

export interface DiffResult {
  timelineId: string;
  timestamp: string;
  changes: FileChange[];
  summary: DiffSummary;
}

export interface DiffOptions {
  timelineId?: string;
  includeContent?: boolean;
  maxFileSizeKB?: number;
  exclude?: string[];
}

export class DiffEngine {
  async computeDiff(
    sourceDir: string,
    shadowDir: string,
    options?: DiffOptions,
  ): Promise<DiffResult> {
    const opts = resolveOptions(options);
    const [sourceFiles, shadowFiles] = await Promise.all([
      collectFiles(sourceDir, sourceDir, opts),
      collectFiles(shadowDir, shadowDir, opts),
    ]);

    return this.computeSnapshotDiff(sourceFiles, shadowFiles, shadowDir, options);
  }

  async computeSnapshotDiff(
    before: Map<string, FileSnapshot>,
    after: Map<string, FileSnapshot>,
    _shadowDir: string,
    options?: DiffOptions,
  ): Promise<DiffResult> {
    const opts = resolveOptions(options);
    const changes: FileChange[] = [];
    let totalInsertions = 0;
    let totalDeletions = 0;

    const allPaths = new Set([...before.keys(), ...after.keys()]);

    for (const filePath of allPaths) {
      const beforeSnap = before.get(filePath);
      const afterSnap = after.get(filePath);

      if (!beforeSnap && afterSnap) {
        const diffText = generateAddedDiff(filePath, afterSnap);
        const counts = countDiffLines(diffText);
        totalInsertions += counts.insertions;
        totalDeletions += counts.deletions;
        changes.push({
          path: filePath,
          type: 'added',
          after: sanitizeSnapshot(afterSnap, opts.includeContent),
          diff: diffText,
        });
      } else if (beforeSnap && !afterSnap) {
        const diffText = generateDeletedDiff(filePath, beforeSnap);
        const counts = countDiffLines(diffText);
        totalInsertions += counts.insertions;
        totalDeletions += counts.deletions;
        changes.push({
          path: filePath,
          type: 'deleted',
          before: sanitizeSnapshot(beforeSnap, opts.includeContent),
          diff: diffText,
        });
      } else if (beforeSnap && afterSnap && beforeSnap.hash !== afterSnap.hash) {
        const diffText = generateModifiedDiff(filePath, beforeSnap, afterSnap);
        const counts = countDiffLines(diffText);
        totalInsertions += counts.insertions;
        totalDeletions += counts.deletions;
        changes.push({
          path: filePath,
          type: 'modified',
          before: sanitizeSnapshot(beforeSnap, opts.includeContent),
          after: sanitizeSnapshot(afterSnap, opts.includeContent),
          diff: diffText,
        });
      }
    }

    changes.sort((a, b) => a.path.localeCompare(b.path));

    return {
      timelineId: opts.timelineId,
      timestamp: new Date().toISOString(),
      changes,
      summary: {
        filesAdded: changes.filter(c => c.type === 'added').length,
        filesModified: changes.filter(c => c.type === 'modified').length,
        filesDeleted: changes.filter(c => c.type === 'deleted').length,
        totalInsertions,
        totalDeletions,
      },
    };
  }

  formatDiffAsText(result: DiffResult): string {
    const lines: string[] = [];
    lines.push(`Timeline: ${result.timelineId}`);
    lines.push(`Timestamp: ${result.timestamp}`);
    lines.push(
      `${result.summary.filesAdded} added, ` +
      `${result.summary.filesModified} modified, ` +
      `${result.summary.filesDeleted} deleted`,
    );
    lines.push(
      `+${result.summary.totalInsertions} -${result.summary.totalDeletions}`,
    );
    lines.push('');

    for (const change of result.changes) {
      if (change.diff) {
        lines.push(change.diff);
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}

interface ResolvedOptions {
  timelineId: string;
  includeContent: boolean;
  maxFileSizeKB: number;
  exclude: string[];
}

function resolveOptions(options?: DiffOptions): ResolvedOptions {
  return {
    timelineId: options?.timelineId ?? randomUUID(),
    includeContent: options?.includeContent ?? false,
    maxFileSizeKB: options?.maxFileSizeKB ?? 1024,
    exclude: options?.exclude ?? [],
  };
}

function sanitizeSnapshot(snap: FileSnapshot, includeContent: boolean): FileSnapshot {
  if (includeContent) return snap;
  const { content: _, ...rest } = snap;
  return rest;
}

async function collectFiles(
  dir: string,
  baseDir: string,
  opts: ResolvedOptions,
): Promise<Map<string, FileSnapshot>> {
  const results = new Map<string, FileSnapshot>();
  await walkDir(dir, baseDir, opts, results);
  return results;
}

async function walkDir(
  dir: string,
  baseDir: string,
  opts: ResolvedOptions,
  results: Map<string, FileSnapshot>,
): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const relPath = normalizePath(relative(baseDir, fullPath));

    if (isExcluded(relPath, opts.exclude)) continue;

    if (entry.isDirectory()) {
      await walkDir(fullPath, baseDir, opts, results);
    } else if (entry.isFile()) {
      const fileStat = await stat(fullPath);
      const sizeKB = fileStat.size / 1024;

      if (sizeKB > opts.maxFileSizeKB) continue;

      const buffer = await readFile(fullPath);
      const hash = createHash('sha256').update(buffer).digest('hex');
      const binary = isBinary(buffer);

      const snapshot: FileSnapshot = {
        hash,
        size: fileStat.size,
      };

      if (!binary) {
        snapshot.content = buffer.toString('utf-8');
      }

      results.set(relPath, snapshot);
    }
  }
}

function isBinary(buffer: Buffer): boolean {
  const checkLength = Math.min(buffer.length, 8192);
  for (let i = 0; i < checkLength; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

function isExcluded(filePath: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (matchGlob(pattern, filePath)) return true;
  }
  return false;
}

function matchGlob(pattern: string, filePath: string): boolean {
  if (pattern === filePath) return true;

  if (pattern.startsWith('**/')) {
    const suffix = pattern.slice(3);
    if (!suffix.includes('*')) {
      return filePath.endsWith(suffix) || filePath.includes(`/${suffix}`);
    }
    const segments = filePath.split('/');
    for (let i = 0; i < segments.length; i++) {
      if (matchSimpleGlob(suffix, segments.slice(i).join('/'))) return true;
    }
    return false;
  }

  if (pattern.endsWith('/**')) {
    const prefix = pattern.slice(0, -3);
    return filePath.startsWith(prefix + '/') || filePath === prefix;
  }

  return matchSimpleGlob(pattern, filePath);
}

function matchSimpleGlob(pattern: string, str: string): boolean {
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\x00')
    .replace(/\*/g, '[^/]*')
    .replace(/\x00/g, '.*')
    .replace(/\?/g, '[^/]');
  return new RegExp(`^${regexStr}$`).test(str);
}

function normalizePath(p: string): string {
  return p.split('\\').join('/');
}

function generateAddedDiff(filePath: string, snap: FileSnapshot): string {
  if (!snap.content) return `Binary file ${filePath} added`;

  const lines = snap.content.split('\n');
  const header = [
    `--- /dev/null`,
    `+++ b/${filePath}`,
    `@@ -0,0 +1,${lines.length} @@`,
  ];
  return [...header, ...lines.map(l => `+${l}`)].join('\n');
}

function generateDeletedDiff(filePath: string, snap: FileSnapshot): string {
  if (!snap.content) return `Binary file ${filePath} deleted`;

  const lines = snap.content.split('\n');
  const header = [
    `--- a/${filePath}`,
    `+++ /dev/null`,
    `@@ -1,${lines.length} +0,0 @@`,
  ];
  return [...header, ...lines.map(l => `-${l}`)].join('\n');
}

function generateModifiedDiff(
  filePath: string,
  before: FileSnapshot,
  after: FileSnapshot,
): string {
  if (!before.content || !after.content) return `Binary file ${filePath} changed`;

  const oldLines = before.content.split('\n');
  const newLines = after.content.split('\n');
  const hunks = computeHunks(oldLines, newLines);

  if (hunks.length === 0) return '';

  const header = [
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
  ];

  const hunkTexts: string[] = [];
  for (const hunk of hunks) {
    hunkTexts.push(formatHunk(hunk));
  }

  return [...header, ...hunkTexts].join('\n');
}

interface Hunk {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: string[];
}

interface EditOp {
  type: 'equal' | 'insert' | 'delete';
  oldIdx: number;
  newIdx: number;
  line: string;
}

function computeHunks(oldLines: string[], newLines: string[]): Hunk[] {
  const ops = computeEditOps(oldLines, newLines);
  return groupIntoHunks(ops, 3);
}

function computeEditOps(oldLines: string[], newLines: string[]): EditOp[] {
  const lcs = longestCommonSubsequence(oldLines, newLines);
  const ops: EditOp[] = [];
  let oi = 0;
  let ni = 0;
  let li = 0;

  while (oi < oldLines.length || ni < newLines.length) {
    if (li < lcs.length && oi === lcs[li].oldIdx && ni === lcs[li].newIdx) {
      ops.push({ type: 'equal', oldIdx: oi, newIdx: ni, line: oldLines[oi] });
      oi++;
      ni++;
      li++;
    } else if (oi < oldLines.length && (li >= lcs.length || oi < lcs[li].oldIdx)) {
      ops.push({ type: 'delete', oldIdx: oi, newIdx: ni, line: oldLines[oi] });
      oi++;
    } else if (ni < newLines.length && (li >= lcs.length || ni < lcs[li].newIdx)) {
      ops.push({ type: 'insert', oldIdx: oi, newIdx: ni, line: newLines[ni] });
      ni++;
    }
  }

  return ops;
}

interface LcsEntry {
  oldIdx: number;
  newIdx: number;
}

function longestCommonSubsequence(a: string[], b: string[]): LcsEntry[] {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  const result: LcsEntry[] = [];
  let i = m;
  let j = n;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      result.push({ oldIdx: i - 1, newIdx: j - 1 });
      i--;
      j--;
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }

  result.reverse();
  return result;
}

function groupIntoHunks(ops: EditOp[], contextSize: number): Hunk[] {
  const changeIndices: number[] = [];
  for (let i = 0; i < ops.length; i++) {
    if (ops[i].type !== 'equal') changeIndices.push(i);
  }

  if (changeIndices.length === 0) return [];

  const groups: number[][] = [];
  let currentGroup: number[] = [changeIndices[0]];

  for (let i = 1; i < changeIndices.length; i++) {
    const gap = changeIndices[i] - changeIndices[i - 1];
    if (gap <= contextSize * 2 + 1) {
      currentGroup.push(changeIndices[i]);
    } else {
      groups.push(currentGroup);
      currentGroup = [changeIndices[i]];
    }
  }
  groups.push(currentGroup);

  const hunks: Hunk[] = [];
  for (const group of groups) {
    const firstChange = group[0];
    const lastChange = group[group.length - 1];
    const start = Math.max(0, firstChange - contextSize);
    const end = Math.min(ops.length - 1, lastChange + contextSize);

    const hunkOps = ops.slice(start, end + 1);
    let oldCount = 0;
    let newCount = 0;
    let oldStart = -1;
    let newStart = -1;
    const lines: string[] = [];

    for (const op of hunkOps) {
      if (oldStart === -1 && (op.type === 'equal' || op.type === 'delete')) {
        oldStart = op.oldIdx + 1;
      }
      if (newStart === -1 && (op.type === 'equal' || op.type === 'insert')) {
        newStart = op.newIdx + 1;
      }

      switch (op.type) {
        case 'equal':
          lines.push(` ${op.line}`);
          oldCount++;
          newCount++;
          break;
        case 'delete':
          lines.push(`-${op.line}`);
          oldCount++;
          break;
        case 'insert':
          lines.push(`+${op.line}`);
          newCount++;
          break;
      }
    }

    if (oldStart === -1) oldStart = 1;
    if (newStart === -1) newStart = 1;

    hunks.push({ oldStart, oldCount, newStart, newCount, lines });
  }

  return hunks;
}

function formatHunk(hunk: Hunk): string {
  const header = `@@ -${hunk.oldStart},${hunk.oldCount} +${hunk.newStart},${hunk.newCount} @@`;
  return [header, ...hunk.lines].join('\n');
}

function countDiffLines(diffText: string): { insertions: number; deletions: number } {
  let insertions = 0;
  let deletions = 0;

  for (const line of diffText.split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) insertions++;
    if (line.startsWith('-') && !line.startsWith('---')) deletions++;
  }

  return { insertions, deletions };
}
