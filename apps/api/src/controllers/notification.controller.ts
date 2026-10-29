import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { notificationService } from '../services/notification.service';
import { NotificationCategory, NotificationSeverity } from '@cyberwatch/shared';

const getNotificationsQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  category: z.string().optional(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).optional(),
  isRead: z.enum(['true', 'false', 'all']).optional(),
  search: z.string().optional(),
});

const updatePreferencesSchema = z.object({
  securityAlerts: z.boolean().optional(),
  scanCompletion: z.boolean().optional(),
  threatIntelAlerts: z.boolean().optional(),
  reportReady: z.boolean().optional(),
  supportUpdates: z.boolean().optional(),
  accountSecurity: z.boolean().optional(),
  browserExtensionAlerts: z.boolean().optional(),
  systemAnnouncements: z.boolean().optional(),
  emailNotifications: z.boolean().optional(),
  inAppNotifications: z.boolean().optional(),
});

export class NotificationController {
  async getNotifications(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return;
      }

      const parsed = getNotificationsQuerySchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          success: false,
          message: 'Invalid query parameters',
          errors: parsed.error.issues,
        });
        return;
      }

      const queryParams: any = {
        page: parsed.data.page,
        limit: parsed.data.limit,
        category: parsed.data.category as NotificationCategory,
        severity: parsed.data.severity as NotificationSeverity,
        search: parsed.data.search,
      };

      if (parsed.data.isRead === 'true') queryParams.isRead = true;
      if (parsed.data.isRead === 'false') queryParams.isRead = false;

      const result = await notificationService.getNotifications(userId, queryParams);

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  async getUnreadCount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return;
      }

      const unreadCount = await notificationService.getUnreadCount(userId);

      res.status(200).json({
        success: true,
        data: { unreadCount },
      });
    } catch (error) {
      next(error);
    }
  }

  async markAsRead(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return;
      }

      const paramId = req.params.id;
      const id = Array.isArray(paramId) ? paramId[0] : paramId;
      const updated = await notificationService.markAsRead(userId, id);

      if (!updated) {
        res.status(404).json({
          success: false,
          message: 'Notification not found or access denied',
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Notification marked as read',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }

  async markAllAsRead(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return;
      }

      const category = req.body?.category as NotificationCategory | undefined;
      const modifiedCount = await notificationService.markAllAsRead(userId, category);

      res.status(200).json({
        success: true,
        message: 'All notifications marked as read',
        data: { modifiedCount },
      });
    } catch (error) {
      next(error);
    }
  }

  async deleteNotification(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return;
      }

      const paramId = req.params.id;
      const id = Array.isArray(paramId) ? paramId[0] : paramId;
      const deleted = await notificationService.deleteNotification(userId, id);

      if (!deleted) {
        res.status(404).json({
          success: false,
          message: 'Notification not found or access denied',
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Notification removed',
      });
    } catch (error) {
      next(error);
    }
  }

  async getPreferences(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return;
      }

      const preferences = await notificationService.getPreferences(userId);

      res.status(200).json({
        success: true,
        data: preferences,
      });
    } catch (error) {
      next(error);
    }
  }

  async updatePreferences(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return;
      }

      const parsed = updatePreferencesSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          success: false,
          message: 'Invalid preferences payload',
          errors: parsed.error.issues,
        });
        return;
      }

      const updated = await notificationService.updatePreferences(userId, parsed.data);

      res.status(200).json({
        success: true,
        message: 'Notification preferences updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }
}

export const notificationController = new NotificationController();
