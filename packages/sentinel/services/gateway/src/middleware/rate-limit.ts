import type { Request, Response, NextFunction } from 'express';

const WINDOW_MS = 60_000;
const MAX_REQUESTS = parseInt(process.env.WITNESS_RATE_LIMIT ?? '200', 10);

interface BucketEntry {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, BucketEntry>();

export function rateLimit(req: Request, res: Response, next: NextFunction): void {
  const key = (req.headers['x-api-key'] as string) ?? req.ip ?? 'unknown';
  const now = Date.now();

  let entry = buckets.get(key);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + WINDOW_MS };
    buckets.set(key, entry);
  }

  entry.count++;

  if (entry.count > MAX_REQUESTS) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    res.set('Retry-After', String(retryAfter));
    res.status(429).json({ error: 'Rate limit exceeded.', code: 'RATE_LIMITED' });
    return;
  }

  next();
}
