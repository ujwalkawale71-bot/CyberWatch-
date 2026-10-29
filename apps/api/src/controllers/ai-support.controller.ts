import { Request, Response, NextFunction } from 'express';
import { aiSupportService } from '../services/ai-support.service';
import type { AISupportChatRequest } from '@cyberwatch/shared';

export const aiSupportController = {
  /**
   * POST /api/v1/support/ai/chat
   */
  async processChat(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.user?.userId;
      const payload: AISupportChatRequest = req.body;

      const result = await aiSupportService.processAIChat(userId, payload);

      res.status(200).json({
        success: true,
        message: 'AI support response generated successfully.',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/support/ai/quick-actions
   */
  async getQuickActions(_req: Request, res: Response, next: NextFunction) {
    try {
      const actions = aiSupportService.getQuickActions();
      res.status(200).json({
        success: true,
        data: actions,
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/support/ai/user-scans
   */
  async getUserScans(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        return res.status(200).json({
          success: true,
          data: [],
        });
      }

      const scans = await aiSupportService.getUserScansForAI(userId);
      res.status(200).json({
        success: true,
        data: scans,
      });
    } catch (error) {
      next(error);
    }
  },
};
