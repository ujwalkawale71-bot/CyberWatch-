import { Router } from 'express';
import { aiSupportController } from '../controllers/ai-support.controller';
import { optionalAuth, requireAuth } from '../middleware/auth.middleware';
import { chatMessageLimiter } from '../middleware/support-rate-limit.middleware';

const router = Router();

/**
 * POST /api/v1/live-chat/ai
 * Dedicated, isolated Live Chat AI Assistant endpoint
 */
router.post(
  '/ai',
  optionalAuth,
  chatMessageLimiter,
  aiSupportController.processChat
);

/**
 * GET /api/v1/live-chat/quick-actions
 */
router.get(
  '/quick-actions',
  aiSupportController.getQuickActions
);

/**
 * GET /api/v1/live-chat/user-scans
 */
router.get(
  '/user-scans',
  requireAuth,
  aiSupportController.getUserScans
);

export default router;
