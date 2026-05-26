import type { Request, Response, NextFunction } from 'express';

const API_KEY = process.env.WITNESS_API_KEY;

export function apiKeyAuth(req: Request, res: Response, next: NextFunction): void {
  if (!API_KEY) {
    next();
    return;
  }

  const provided = req.headers['x-api-key'] as string | undefined;
  if (!provided) {
    res.status(401).json({ error: 'Missing API key. Provide X-API-Key header.', code: 'UNAUTHORIZED' });
    return;
  }

  if (provided !== API_KEY) {
    res.status(403).json({ error: 'Invalid API key.', code: 'FORBIDDEN' });
    return;
  }

  next();
}
