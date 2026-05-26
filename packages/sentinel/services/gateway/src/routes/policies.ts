import { Router } from 'express';

const router = Router();

router.get('/current', async (_req, res) => {
  res.status(501).json({
    error: 'Policy endpoint requires witness.yaml parsing — coming in Phase F',
    code: 'NOT_IMPLEMENTED',
  });
});

export default router;
