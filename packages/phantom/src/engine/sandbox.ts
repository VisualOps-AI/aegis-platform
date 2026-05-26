import { mkdtempSync, cpSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface SandboxConfig {
  workDir?: string;
  timeout?: number;
  allowNetwork?: boolean;
}

export interface Sandbox {
  workDir: string;
  cleanup: () => void;
  execute: (fn: () => Promise<string>) => Promise<SandboxResult>;
}

export interface SandboxResult {
  output: string;
  error?: string;
  timedOut: boolean;
  duration: number;
}

export function createSandbox(config: SandboxConfig = {}): Sandbox {
  const workDir =
    config.workDir ?? mkdtempSync(join(tmpdir(), "phantom-sandbox-"));
  const timeout = config.timeout ?? 30_000;

  return {
    workDir,
    cleanup() {
      if (existsSync(workDir) && workDir.includes("phantom-sandbox-")) {
        rmSync(workDir, { recursive: true, force: true });
      }
    },
    async execute(fn: () => Promise<string>): Promise<SandboxResult> {
      const start = Date.now();

      try {
        const result = await Promise.race([
          fn(),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("Sandbox timeout")), timeout)
          ),
        ]);

        return {
          output: result,
          timedOut: false,
          duration: Date.now() - start,
        };
      } catch (err) {
        const isTimeout =
          err instanceof Error && err.message === "Sandbox timeout";
        return {
          output: "",
          error: err instanceof Error ? err.message : String(err),
          timedOut: isTimeout,
          duration: Date.now() - start,
        };
      }
    },
  };
}

export function cloneToSandbox(sourcePath: string, sandbox: Sandbox): string {
  const dest = join(sandbox.workDir, "target");
  cpSync(sourcePath, dest, { recursive: true });
  return dest;
}
