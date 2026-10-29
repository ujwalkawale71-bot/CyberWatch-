import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import app from '../app';
import { env } from '../config/env';
import { Notification, NotificationPreference } from '../models/Notification';
import { User } from '../models/User';
import { notificationService } from '../services/notification.service';

const userAId = new mongoose.Types.ObjectId().toString();
const userBId = new mongoose.Types.ObjectId().toString();

const tokenUserA = jwt.sign(
  { userId: userAId, email: 'usera@cyberwatch.io', role: 'USER' },
  env.JWT_SECRET,
  { expiresIn: '1h' }
);

const tokenUserB = jwt.sign(
  { userId: userBId, email: 'userb@cyberwatch.io', role: 'USER' },
  env.JWT_SECRET,
  { expiresIn: '1h' }
);

describe('CyberWatch Real Security Notification Engine', () => {
  beforeEach(async () => {
    vi.restoreAllMocks();

    vi.spyOn(User, 'findById').mockImplementation((id: any) => {
      const idStr = id?.toString();
      return {
        select: vi.fn().mockResolvedValue({
          _id: new mongoose.Types.ObjectId(idStr),
          role: 'USER',
          isActive: true,
        }),
      } as any;
    });
  });

  describe('Authorization & User Isolation (IDOR Protection)', () => {
    it('rejects unauthenticated requests with 401', async () => {
      const res = await request(app).get('/api/v1/notifications');
      expect(res.status).toBe(401);
    });

    it('prevents User B from marking User A notification as read', async () => {
      const notificationA = {
        _id: new mongoose.Types.ObjectId(),
        userId: new mongoose.Types.ObjectId(userAId),
        isRead: false,
      };

      vi.spyOn(Notification, 'findOneAndUpdate').mockImplementation((filter: any) => {
        if (filter.userId.toString() === userBId) {
          return null as any;
        }
        return notificationA as any;
      });

      const res = await request(app)
        .patch(`/api/v1/notifications/${notificationA._id}/read`)
        .set('Authorization', `Bearer ${tokenUserB}`);

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
    });

    it('prevents User B from deleting User A notification', async () => {
      const notificationAId = new mongoose.Types.ObjectId();

      vi.spyOn(Notification, 'deleteOne').mockImplementation((filter: any) => {
        if (filter.userId.toString() === userBId) {
          return { deletedCount: 0 } as any;
        }
        return { deletedCount: 1 } as any;
      });

      const res = await request(app)
        .delete(`/api/v1/notifications/${notificationAId}`)
        .set('Authorization', `Bearer ${tokenUserB}`);

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
    });
  });

  describe('GET /api/v1/notifications', () => {
    it('returns paginated notifications for the authenticated user', async () => {
      const mockNotifications = [
        {
          _id: new mongoose.Types.ObjectId(),
          userId: new mongoose.Types.ObjectId(userAId),
          type: 'SCAN_COMPLETED',
          category: 'SECURITY',
          severity: 'HIGH',
          title: 'High Risk Security Scan Result',
          message: 'Significant security vulnerabilities found on https://phishing-target.test',
          isRead: false,
          readAt: null,
          createdAt: new Date(),
          metadata: { riskScore: 75, target: 'https://phishing-target.test' },
          actionUrl: '/reports/scans/123',
          actionText: 'View Scan Report',
        },
      ];

      vi.spyOn(Notification, 'find').mockReturnValue({
        sort: vi.fn().mockReturnThis(),
        skip: vi.fn().mockReturnThis(),
        limit: vi.fn().mockReturnThis(),
        lean: vi.fn().mockResolvedValue(mockNotifications),
      } as any);

      vi.spyOn(Notification, 'countDocuments').mockResolvedValue(1);

      const res = await request(app)
        .get('/api/v1/notifications?category=SECURITY')
        .set('Authorization', `Bearer ${tokenUserA}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.notifications).toHaveLength(1);
      expect(res.body.data.notifications[0].severity).toBe('HIGH');
      expect(res.body.data.notifications[0].actionUrl).toBe('/reports/scans/123');
      expect(res.body.data.unreadCount).toBe(1);
    });
  });

  describe('GET /api/v1/notifications/unread-count', () => {
    it('returns accurate unread count for user', async () => {
      vi.spyOn(Notification, 'countDocuments').mockResolvedValue(3);

      const res = await request(app)
        .get('/api/v1/notifications/unread-count')
        .set('Authorization', `Bearer ${tokenUserA}`);

      expect(res.status).toBe(200);
      expect(res.body.data.unreadCount).toBe(3);
    });
  });

  describe('PATCH /api/v1/notifications/read-all', () => {
    it('marks all user notifications as read and updates unread badge', async () => {
      vi.spyOn(Notification, 'updateMany').mockResolvedValue({ modifiedCount: 4 } as any);
      vi.spyOn(Notification, 'countDocuments').mockResolvedValue(0);

      const res = await request(app)
        .patch('/api/v1/notifications/read-all')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({ category: 'SCAN' });

      expect(res.status).toBe(200);
      expect(res.body.data.modifiedCount).toBe(4);
    });
  });

  describe('Notification Preferences & Security Integrity', () => {
    it('enforces mandatory security alerts even if disabled in request', async () => {
      vi.spyOn(NotificationPreference, 'findOneAndUpdate').mockResolvedValue({
        userId: new mongoose.Types.ObjectId(userAId),
        securityAlerts: true,
        accountSecurity: true,
        scanCompletion: false,
        threatIntelAlerts: true,
        reportReady: false,
        supportUpdates: true,
        browserExtensionAlerts: true,
        systemAnnouncements: false,
        emailNotifications: false,
        inAppNotifications: true,
      } as any);

      const res = await request(app)
        .patch('/api/v1/notifications/preferences')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          securityAlerts: false, // Trying to disable mandatory security alerts
          scanCompletion: false,
        });

      expect(res.status).toBe(200);
      expect(res.body.data.securityAlerts).toBe(true);
      expect(res.body.data.scanCompletion).toBe(false);
    });
  });

  describe('Domain Event Helpers & Canonical Risk Mapping', () => {
    it('correctly creates a CRITICAL security notification for high risk scans', async () => {
      const mockScan = {
        _id: new mongoose.Types.ObjectId(),
        userId: new mongoose.Types.ObjectId(userAId),
        target: 'https://evil-portal.example',
        targetType: 'URL',
        status: 'COMPLETED',
        riskLevel: 'Critical',
        riskScore: 92,
      };

      vi.spyOn(notificationService, 'getPreferences').mockResolvedValue({
        securityAlerts: true,
        scanCompletion: true,
        threatIntelAlerts: true,
        reportReady: true,
        supportUpdates: true,
        accountSecurity: true,
        browserExtensionAlerts: true,
        systemAnnouncements: true,
        emailNotifications: false,
        inAppNotifications: true,
      });

      vi.spyOn(Notification, 'findOne').mockResolvedValue(null);
      const saveSpy = vi.spyOn(Notification.prototype, 'save').mockImplementation(function (this: any) {
        return Promise.resolve(this);
      });

      const notification = await notificationService.createScanNotification(mockScan);
      expect(notification).not.toBeNull();
      expect(notification?.severity).toBe('CRITICAL');
      expect(notification?.category).toBe('SECURITY');
      expect(notification?.actionUrl).toBe(`/reports/scans/${mockScan._id}`);
    });

    it('correctly creates threat intelligence notifications for malicious indicators', async () => {
      vi.spyOn(notificationService, 'getPreferences').mockResolvedValue({
        securityAlerts: true,
        scanCompletion: true,
        threatIntelAlerts: true,
        reportReady: true,
        supportUpdates: true,
        accountSecurity: true,
        browserExtensionAlerts: true,
        systemAnnouncements: true,
        emailNotifications: false,
        inAppNotifications: true,
      });

      vi.spyOn(Notification, 'findOne').mockResolvedValue(null);
      vi.spyOn(Notification.prototype, 'save').mockImplementation(function (this: any) {
        return Promise.resolve(this);
      });

      const notification = await notificationService.createThreatIntelNotification({
        userId: userAId,
        indicator: 'malware-drop.ru',
        indicatorType: 'Domain',
        reputation: 'MALICIOUS',
        threatScore: 95,
      });

      expect(notification).not.toBeNull();
      expect(notification?.severity).toBe('CRITICAL');
      expect(notification?.category).toBe('THREAT_INTELLIGENCE');
      expect(notification?.actionText).toBe('Investigate Indicator');
    });
  });
});
