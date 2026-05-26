#!/usr/bin/env node

import { Command } from 'commander';
import { writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { stringify } from 'yaml';
import { resolve, join } from 'node:path';
import { WitnessServer } from './proxy/server.js';
import { WitnessClient } from './proxy/client.js';
import { ToolCallRouter } from './proxy/router.js';
import { EventStore } from './receipts/store.js';
import { PolicyEngine } from './policy/engine.js';
import { ShadowManager } from './sandbox/manager.js';
import { loadPolicy, loadDefaultPolicy } from './policy/parser.js';

const program = new Command();

program
  .name('witness')
  .description('MCP proxy that intercepts agent tool calls with cryptographic receipts')
  .version('0.1.0');

program
  .command('run')
  .description('Run an MCP tool server with Witness protection')
  .requiredOption('--server <command>', 'MCP server command to proxy (e.g., "npx @modelcontextprotocol/server-filesystem .")')
  .option('--policy <path>', 'Path to witness.yaml policy file')
  .option('--db <path>', 'Path to SQLite database', '.witness/events.db')
  .option('--agent-name <name>', 'Name of the connecting agent', 'unknown')
  .option('--no-shadow', 'Disable shadow timeline execution')
  .option('--shadow-dir <path>', 'Source directory for shadow workspaces', '.')
  .action(async (opts: {
    server: string;
    policy?: string;
    db: string;
    agentName: string;
    shadow: boolean;
    shadowDir: string;
  }) => {
    const policyConfig = opts.policy && existsSync(opts.policy)
      ? loadPolicy(opts.policy)
      : existsSync('witness.yaml')
        ? loadPolicy('witness.yaml')
        : loadDefaultPolicy();

    const policyEngine = new PolicyEngine(policyConfig);
    const eventStore = new EventStore(opts.db);
    const sessionId = eventStore.createSession(opts.agentName, opts.server);

    const client = new WitnessClient();
    const [command, ...args] = opts.server.split(' ');
    await client.connectServer('upstream', { command, args });

    const shadowManager = opts.shadow
      ? new ShadowManager(eventStore, { sourceDir: resolve(opts.shadowDir) })
      : undefined;

    const router = new ToolCallRouter({
      eventStore,
      policyEngine,
      client,
      sessionId,
      shadowManager,
    });

    const server = new WitnessServer();
    server.setToolRouter(router);

    const shutdown = async () => {
      await router.cleanupShadows();
      await server.close();
      await client.disconnectAll();
      eventStore.close();
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    process.stderr.write(`[witness] Session ${sessionId} started\n`);
    process.stderr.write(`[witness] Policy: ${policyConfig.policy_name}\n`);
    process.stderr.write(`[witness] Shadow: ${opts.shadow ? 'enabled' : 'disabled'}\n`);
    process.stderr.write(`[witness] Proxying: ${opts.server}\n`);

    await server.start();
  });

program
  .command('init')
  .description('Create a witness.yaml config file in the current directory')
  .option('--force', 'Overwrite existing witness.yaml')
  .action((opts: { force?: boolean }) => {
    const target = resolve('witness.yaml');
    if (existsSync(target) && !opts.force) {
      process.stderr.write('witness.yaml already exists. Use --force to overwrite.\n');
      process.exit(1);
    }

    const examplePath = join(import.meta.dirname, '..', 'witness.yaml.example');
    if (existsSync(examplePath)) {
      copyFileSync(examplePath, target);
    } else {
      const defaultPolicy = loadDefaultPolicy();
      writeFileSync(target, stringify(defaultPolicy), 'utf-8');
    }

    process.stderr.write(`Created ${target}\n`);
  });

program
  .command('receipts')
  .description('View logged tool call events')
  .option('--db <path>', 'Path to SQLite database', '.witness/events.db')
  .option('--session <id>', 'Filter by session ID')
  .option('--limit <n>', 'Number of sessions to show', '10')
  .action((opts: { db: string; session?: string; limit: string }) => {
    const store = new EventStore(opts.db);

    if (opts.session) {
      const events = store.getSessionEvents(opts.session);
      for (const event of events) {
        const status = event.status === 'completed' ? '\u2713' : event.status === 'failed' ? '\u2717' : '\u25CB';
        const duration = event.duration_ms !== null ? `${event.duration_ms}ms` : 'pending';
        process.stdout.write(`  ${status} ${event.tool_name} [${duration}]\n`);
        if (event.args_json) {
          process.stdout.write(`    args: ${event.args_json}\n`);
        }
      }
    } else {
      const sessions = store.getRecentSessions(parseInt(opts.limit, 10));
      for (const session of sessions) {
        process.stdout.write(`${session.id}  ${session.started_at}  ${session.agent_name ?? 'unknown'}  ${session.command ?? ''}\n`);
      }
    }

    store.close();
  });

program
  .command('timeline')
  .description('View shadow timelines for a session')
  .option('--db <path>', 'Path to SQLite database', '.witness/events.db')
  .requiredOption('--session <id>', 'Session ID to view timelines for')
  .action((opts: { db: string; session: string }) => {
    const store = new EventStore(opts.db);
    const timelines = store.getSessionTimelines(opts.session);

    if (timelines.length === 0) {
      process.stdout.write('No timelines found for this session.\n');
    } else {
      for (const tl of timelines) {
        const status = tl.status as string;
        const icon = status === 'merged' ? '\u2713' : status === 'abandoned' ? '\u2717' : '\u25CB';
        process.stdout.write(
          `  ${icon} ${tl.id}  ${tl.tool_name}  [${status}]  ${tl.branch_point}\n`,
        );
        if (tl.description) {
          process.stdout.write(`    ${tl.description}\n`);
        }
      }
    }

    store.close();
  });

program.parse();
