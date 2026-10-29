import type { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { registerSchema, loginSchema } from '../schemas/auth.schema';
import { ZodError } from 'zod';

// ─── Auth Controller ──────────────────────────────────────────────────────────
// Handles HTTP concerns: parsing requests, calling service, sending responses.
// All business logic lives in authService.

export const authController = {
  // ── POST /api/v1/auth/register ────────────────────────────────────────────
  async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = registerSchema.parse(req.body);
      const result = await authService.register(input);

      res.status(201).json({
        success: true,
        message: 'Account created successfully.',
        data: result,
      });
    } catch (err) {
      next(err);
    }
  },

  // ── POST /api/v1/auth/login ───────────────────────────────────────────────
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = loginSchema.parse(req.body);
      const result = await authService.login(input);

      // Trigger account security notification
      const { notificationService } = await import('../services/notification.service');
      notificationService.createAccountSecurityNotification({
        userId: result.user.id,
        title: 'New Session Authenticated',
        message: `A new session was authenticated for account ${result.user.email}.`,
        severity: 'INFO',
        ipAddress: req.ip || (req.headers['x-forwarded-for'] as string),
        userAgent: req.headers['user-agent'],
      }).catch((err) => {
        console.error('[NotificationService] Failed to emit login notification:', err);
      });

      res.status(200).json({
        success: true,
        message: 'Login successful.',
        data: result,
      });
    } catch (err) {
      next(err);
    }
  },

  // ── GET /api/v1/auth/me ───────────────────────────────────────────────────
  // Protected route — requireAuth middleware must run first.
  async me(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Not authenticated.' });
        return;
      }

      const user = await authService.getUserById(req.user.userId);

      res.status(200).json({
        success: true,
        message: 'User retrieved successfully.',
        data: { user },
      });
    } catch (err) {
      next(err);
    }
  },

  // ── POST /api/v1/auth/logout ──────────────────────────────────────────────
  // JWT is stateless — the server cannot invalidate a token.
  // The client is responsible for removing the stored token.
  // This endpoint exists so the frontend can call a consistent logout API
  // and the architecture can be upgraded to token revocation/refresh later.
  async logout(_req: Request, res: Response): Promise<void> {
    res.status(200).json({
      success: true,
      message: 'Logged out successfully. Please remove your authentication token.',
    });
  },
};
