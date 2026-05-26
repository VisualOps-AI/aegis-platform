import { mkdir, cp, rm, readdir, readFile, stat } from "node:fs/promises";
import { join, resolve, relative, sep } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, createHash } from "node:crypto";

export interface ShadowWorkspaceOptions {
  include?: string[];
  exclude?: string[];
  maxSizeMB?: number;
}

interface FileSnapshot {
  hash: string;
  size: number;
  mtime: number;
}

const DEFAULT_EXCLUDES = ["node_modules", ".git", ".witness", "dist"];
const DEFAULT_MAX_SIZE_MB = 500;

export class ShadowWorkspace {
  private shadowRoot: string;
  private sourceDir: string;
  private trackedFiles: string[];

  private constructor(
    shadowRoot: string,
    sourceDir: string,
    trackedFiles: string[],
  ) {
    this.shadowRoot = shadowRoot;
    this.sourceDir = sourceDir;
    this.trackedFiles = trackedFiles;
  }

  static async create(
    sourceDir: string,
    options?: ShadowWorkspaceOptions,
  ): Promise<ShadowWorkspace> {
    const resolvedSource = resolve(sourceDir);
    const shadowRoot = join(tmpdir(), `witness-shadow-${randomUUID()}`);
    await mkdir(shadowRoot, { recursive: true });

    const excludes = options?.exclude ?? DEFAULT_EXCLUDES;
    const maxSizeBytes = (options?.maxSizeMB ?? DEFAULT_MAX_SIZE_MB) * 1024 * 1024;

    const trackedFiles: string[] = [];
    let totalSize = 0;

    await copyRecursive(
      resolvedSource,
      shadowRoot,
      resolvedSource,
      excludes,
      options?.include,
      trackedFiles,
      { totalSize, maxSizeBytes },
    );

    return new ShadowWorkspace(shadowRoot, resolvedSource, trackedFiles);
  }

  getPath(): string {
    return this.shadowRoot;
  }

  getSourceDir(): string {
    return this.sourceDir;
  }

  async resolveInShadow(relativePath: string): Promise<string> {
    return join(this.shadowRoot, relativePath);
  }

  async cleanup(): Promise<void> {
    await rm(this.shadowRoot, { recursive: true, force: true });
  }

  async getTrackedFiles(): Promise<string[]> {
    const files: string[] = [];
    await collectFiles(this.shadowRoot, this.shadowRoot, files);
    return files;
  }

  async getFileSnapshot(): Promise<Map<string, FileSnapshot>> {
    const snapshot = new Map<string, FileSnapshot>();
    const files = await this.getTrackedFiles();

    for (const relativePath of files) {
      const fullPath = join(this.shadowRoot, relativePath);
      const [content, fileStat] = await Promise.all([
        readFile(fullPath),
        stat(fullPath),
      ]);

      const hash = createHash("sha256").update(content).digest("hex");
      snapshot.set(relativePath, {
        hash,
        size: fileStat.size,
        mtime: fileStat.mtimeMs,
      });
    }

    return snapshot;
  }
}

async function collectFiles(
  dir: string,
  root: string,
  out: string[],
): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectFiles(fullPath, root, out);
    } else if (entry.isFile()) {
      out.push(relative(root, fullPath));
    }
  }
}

interface SizeTracker {
  totalSize: number;
  maxSizeBytes: number;
}

function shouldExclude(
  name: string,
  relativePath: string,
  excludes: string[],
  includes: string[] | undefined,
): boolean {
  for (const pattern of excludes) {
    if (name === pattern || relativePath === pattern) {
      return true;
    }
  }

  if (includes && includes.length > 0) {
    return !includes.some((pattern) => matchGlob(pattern, relativePath));
  }

  return false;
}

function matchGlob(pattern: string, filePath: string): boolean {
  const normalized = filePath.split(sep).join("/");

  if (pattern === "**" || pattern === "**/*") return true;

  if (pattern.startsWith("**/")) {
    const suffix = pattern.slice(3);
    if (suffix.startsWith(".")) {
      return normalized.endsWith(suffix);
    }
    return normalized.endsWith(suffix) || normalized.includes(`/${suffix}`);
  }

  if (pattern.startsWith("*.")) {
    const ext = pattern.slice(1);
    return normalized.endsWith(ext);
  }

  return normalized === pattern || normalized.startsWith(pattern.replace(/\*$/, ""));
}

async function copyRecursive(
  currentDir: string,
  destDir: string,
  sourceRoot: string,
  excludes: string[],
  includes: string[] | undefined,
  trackedFiles: string[],
  sizeTracker: SizeTracker,
): Promise<void> {
  const entries = await readdir(currentDir, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = join(currentDir, entry.name);
    const destPath = join(destDir, entry.name);
    const relativePath = relative(sourceRoot, srcPath);

    if (entry.isDirectory()) {
      if (shouldExclude(entry.name, relativePath, excludes, undefined)) {
        continue;
      }
      await mkdir(destPath, { recursive: true });
      await copyRecursive(
        srcPath,
        destPath,
        sourceRoot,
        excludes,
        includes,
        trackedFiles,
        sizeTracker,
      );
    } else if (entry.isFile()) {
      if (shouldExclude(entry.name, relativePath, excludes, includes)) {
        continue;
      }

      const fileStat = await stat(srcPath);
      sizeTracker.totalSize += fileStat.size;
      if (sizeTracker.totalSize > sizeTracker.maxSizeBytes) {
        throw new Error(
          `Shadow workspace exceeds max size of ${sizeTracker.maxSizeBytes / (1024 * 1024)}MB`,
        );
      }

      await cp(srcPath, destPath, { preserveTimestamps: true });
      trackedFiles.push(relativePath);
    }
  }
}
