import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export interface UpstreamServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface ToolCallResult {
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

interface ConnectedServer {
  client: Client;
  transport: StdioClientTransport;
}

export class WitnessClient {
  private servers = new Map<string, ConnectedServer>();
  private toolRoutes = new Map<string, string>();

  async connectServer(name: string, config: UpstreamServerConfig): Promise<void> {
    const transport = new StdioClientTransport({
      command: config.command,
      args: config.args,
      env: config.env,
      cwd: config.cwd,
      stderr: 'pipe',
    });

    const client = new Client(
      { name: `witness-client-${name}`, version: '0.1.0' },
    );

    await client.connect(transport);

    const { tools } = await client.listTools();
    for (const tool of tools) {
      this.toolRoutes.set(tool.name, name);
    }

    this.servers.set(name, { client, transport });
  }

  async listAllTools(): Promise<ToolInfo[]> {
    const allTools: ToolInfo[] = [];

    for (const { client } of this.servers.values()) {
      const { tools } = await client.listTools();
      for (const tool of tools) {
        allTools.push({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
        });
      }
    }

    return allTools;
  }

  async callTool(toolName: string, args: Record<string, unknown>): Promise<ToolCallResult> {
    const serverName = this.toolRoutes.get(toolName);
    if (!serverName) {
      return {
        content: [{ type: 'text', text: `Unknown tool: ${toolName}` }],
        isError: true,
      };
    }

    const server = this.servers.get(serverName);
    if (!server) {
      return {
        content: [{ type: 'text', text: `Server not found: ${serverName}` }],
        isError: true,
      };
    }

    const result = await server.client.callTool({ name: toolName, arguments: args });

    return {
      content: (result.content as ToolCallResult['content']),
      isError: (result.isError === true),
    };
  }

  async disconnectAll(): Promise<void> {
    for (const { client, transport } of this.servers.values()) {
      await client.close();
      await transport.close();
    }
    this.servers.clear();
    this.toolRoutes.clear();
  }
}
