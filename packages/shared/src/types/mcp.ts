export interface MCPConfig {
  mcpServers: Record<string, MCPServerConfig>;
}

export interface MCPServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport?: "stdio" | "sse" | "streamable-http";
}

export interface MCPToolDefinition {
  name: string;
  description: string;
  inputSchema: MCPToolSchema;
  server: string;
}

export interface MCPToolSchema {
  type: "object";
  properties: Record<string, MCPPropertySchema>;
  required?: string[];
}

export interface MCPPropertySchema {
  type: string;
  description?: string;
  enum?: string[];
  items?: MCPPropertySchema;
}

export interface ToolCapability {
  reads: string[];
  writes: string[];
  executes: string[];
  network: boolean;
  filesystem: boolean;
  database: boolean;
  messaging: boolean;
}

export interface ToolNode {
  tool: MCPToolDefinition;
  capabilities: ToolCapability;
  riskScore: number;
}

export interface ToolEdge {
  from: string;
  to: string;
  relationship: "data-flow" | "escalation" | "exfiltration" | "mutation";
  risk: number;
}

export interface ToolGraph {
  nodes: Map<string, ToolNode>;
  edges: ToolEdge[];
}
