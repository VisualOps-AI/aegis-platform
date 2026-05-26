const GOVERNANCE_URL = process.env.WITNESS_GOVERNANCE_URL ?? 'http://localhost:9000';
const API_KEY = process.env.WITNESS_API_KEY;

function headers(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (API_KEY) h['X-API-Key'] = API_KEY;
  return h;
}

export async function proxyGovernance(
  path: string,
  method: string = 'GET',
  body?: unknown,
): Promise<{ status: number; data: unknown }> {
  const url = `${GOVERNANCE_URL}${path}`;
  const init: RequestInit = {
    method,
    headers: headers(),
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }

  const res = await fetch(url, init);
  const data = await res.json();
  return { status: res.status, data };
}

export async function governanceHealth(): Promise<{ status: string; service: string } | null> {
  try {
    const res = await fetch(`${GOVERNANCE_URL}/health`, { signal: AbortSignal.timeout(3000) });
    return (await res.json()) as { status: string; service: string };
  } catch {
    return null;
  }
}
