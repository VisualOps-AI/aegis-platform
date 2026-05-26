import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';

export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export interface ToolRouter {
  listTools(): Promise<ToolInfo[]>;
  callTool(name: string, args: Record<string, unknown>): Promise<ToolResult>;
}

function toCallToolResult(result: ToolResult): CallToolResult {
  return {
    content: result.content.map((c) => ({
      type: 'text' as const,
      text: c.text,
    })),
    isError: result.isError,
  };
}

export class WitnessServer {
  private server: Server;
  private router: ToolRouter | null = null;

  constructor(options: { name?: string; version?: string } = {}) {
    this.server = new Server(
      {
        name: options.name ?? 'witness-protocol',
        version: options.version ?? '0.1.0',
      },
      { capabilities: { tools: {} } },
    );

    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      if (!this.router) {
        return { tools: [] };
      }
      const tools = await this.router.listTools();
      return { tools };
    });

    this.server.setRequestHandler(
      CallToolRequestSchema,
      async (request): Promise<CallToolResult> => {
        if (!this.router) {
          return {
            content: [{ type: 'text', text: 'No tool router configured' }],
            isError: true,
          };
        }
        const { name, arguments: args } = request.params;
        const result = await this.router.callTool(name, args ?? {});
        return toCallToolResult(result);
      },
    );
  }

  setToolRouter(router: ToolRouter): void {
    this.router = router;
  }

  async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }

  async close(): Promise<void> {
    await this.server.close();
  }
}
