const MCP_PROXY_URL = process.env.WITNESS_MCP_PROXY_URL ?? 'http://localhost:3002';

export async function proxyMcp(
  path: string,
  method: string = 'GET',
  body?: unknown,
): Promise<{ status: number; data: unknown }> {
  const url = `${MCP_PROXY_URL}${path}`;
  const init: RequestInit = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }

  const res = await fetch(url, init);
  const data = await res.json();
  return { status: res.status, data };
}

export async function mcpPending(): Promise<unknown[]> {
  try {
    const res = await fetch(`${MCP_PROXY_URL}/pending`, { signal: AbortSignal.timeout(3000) });
    return (await res.json()) as unknown[];
  } catch {
    return [];
  }
}

export async function mcpHealth(): Promise<{ status: string; service: string } | null> {
  try {
    const res = await fetch(`${MCP_PROXY_URL}/health`, { signal: AbortSignal.timeout(3000) });
    return (await res.json()) as { status: string; service: string };
  } catch {
    return null;
  }
}
