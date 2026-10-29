import { Types } from 'mongoose';
import {
  NotificationCategory,
  NotificationSeverity,
  NotificationType,
  NotificationPreferences,
  GetNotificationsQuery,
  GetNotificationsResponse,
} from '@cyberwatch/shared';
import {
  Notification,
  NotificationPreference,
  INotification,
  toSafeNotification,
} from '../models/Notification';
import { getIO } from '../socket/support-chat.socket';

export interface CreateNotificationParams {
  userId: string | Types.ObjectId;
  type: NotificationType;
  category: NotificationCategory;
  severity: NotificationSeverity;
  title: string;
  message: string;
  entityType?: string;
  entityId?: string;
  metadata?: Record<string, unknown>;
  actionUrl?: string;
  actionText?: string;
  eventKey?: string;
  expiresAt?: Date | null;
}

export class NotificationService {
  /**
   * Create a new structured notification with user preference validation and deduplication.
   */
  async createNotification(params: CreateNotificationParams): Promise<INotification | null> {
    try {
      const rawUserId = params.userId.toString();
      if (!Types.ObjectId.isValid(rawUserId)) {
        return null;
      }
      const userObjectId = new Types.ObjectId(rawUserId);

      // 1. Check user preferences (Security & Account Security cannot be disabled)
      const preferences = await this.getPreferences(userObjectId.toString());
      if (!this.isCategoryEnabled(preferences, params.category, params.severity)) {
        return null;
      }

      // 2. Deduplication check via deterministic eventKey
      if (params.eventKey) {
        const existing = await Notification.findOne({
          userId: userObjectId,
          eventKey: params.eventKey,
        });
        if (existing) {
          // Update timestamp and metadata without duplicating
          existing.title = params.title;
          existing.message = params.message;
          existing.metadata = { ...existing.metadata, ...params.metadata };
          existing.severity = params.severity;
          await existing.save();
          this.emitRealtimeNotification(userObjectId.toString(), existing);
          return existing;
        }
      }

      // 3. Create and persist notification
      const notification = new Notification({
        userId: userObjectId,
        type: params.type,
        category: params.category,
        severity: params.severity,
        title: params.title,
        message: params.message,
        entityType: params.entityType,
        entityId: params.entityId,
        metadata: params.metadata || {},
        actionUrl: params.actionUrl,
        actionText: params.actionText,
        eventKey: params.eventKey,
        expiresAt: params.expiresAt || null,
        isRead: false,
      });

      const saved = await notification.save();

      // 4. Real-time push via Socket.IO
      this.emitRealtimeNotification(userObjectId.toString(), saved);

      return saved;
    } catch (error) {
      console.error('[NotificationService] Failed to create notification:', error);
      return null;
    }
  }

  /**
   * Helper: Scan Completion / Failure Event Integration
   */
  async createScanNotification(scan: {
    _id: Types.ObjectId | string;
    userId?: Types.ObjectId | string;
    target: string;
    targetType?: string;
    status: string;
    riskLevel?: string;
    riskScore?: number;
    findings?: Array<{ severity: string; title: string }>;
  }): Promise<INotification | null> {
    if (!scan.userId) return null;

    const scanId = scan._id.toString();
    const targetType = scan.targetType || 'Target';
    const riskLevel = scan.riskLevel || 'Safe';
    const riskScore = typeof scan.riskScore === 'number' ? scan.riskScore : 0;
    const isCompleted = scan.status === 'COMPLETED';
    const isFailed = scan.status === 'FAILED';

    let severity: NotificationSeverity = 'INFO';
    let title = `${targetType} Scan Completed`;
    let message = `Security assessment for ${scan.target} completed with risk score ${riskScore}/100 (${riskLevel}).`;
    let category: NotificationCategory = 'SCAN';

    if (isFailed) {
      severity = 'MEDIUM';
      title = `${targetType} Scan Incomplete / Failed`;
      message = `The security analysis for ${scan.target} could not be completed. Check scanner diagnostics for details.`;
      category = 'SCAN';
    } else if (riskLevel === 'Critical' || riskScore >= 80) {
      severity = 'CRITICAL';
      category = 'SECURITY';
      title = `Critical Security Threat Detected`;
      message = `High-confidence security threats were discovered on ${scan.target} (Risk Score: ${riskScore}/100). Immediate mitigation recommended.`;
    } else if (riskLevel === 'High Risk' || riskScore >= 60) {
      severity = 'HIGH';
      category = 'SECURITY';
      title = `High Risk Security Scan Result`;
      message = `Significant security vulnerabilities or indicators were found on ${scan.target} (Risk Score: ${riskScore}/100).`;
    } else if (riskLevel === 'Suspicious' || riskScore >= 35) {
      severity = 'MEDIUM';
      category = 'SCAN';
      title = `Suspicious Indicators Found`;
      message = `Suspicious patterns were flagged during scan of ${scan.target} (Risk Score: ${riskScore}/100).`;
    } else if (riskLevel === 'Low Risk') {
      severity = 'LOW';
      category = 'SCAN';
      title = `Scan Completed (Low Risk)`;
      message = `Security scan completed for ${scan.target}. Minor security recommendations available.`;
    }

    return this.createNotification({
      userId: scan.userId,
      type: isFailed ? 'SCAN_FAILED' : 'SCAN_COMPLETED',
      category,
      severity,
      title,
      message,
      entityType: 'scan',
      entityId: scanId,
      metadata: {
        scanId,
        target: scan.target,
        targetType,
        riskScore,
        riskLevel,
        status: scan.status,
      },
      actionUrl: `/reports/scans/${scanId}`,
      actionText: 'View Scan Report',
      eventKey: `scan:${scanId}:${scan.userId}`,
    });
  }

  /**
   * Helper: Threat Intelligence Event Integration
   */
  async createThreatIntelNotification(params: {
    userId: string | Types.ObjectId;
    indicator: string;
    indicatorType: string;
    reputation: string;
    threatScore?: number;
    providersCount?: number;
    analysisId?: string;
  }): Promise<INotification | null> {
    const isMalicious = params.reputation.toUpperCase() === 'MALICIOUS';
    const isSuspicious = params.reputation.toUpperCase() === 'SUSPICIOUS';

    const severity: NotificationSeverity = isMalicious
      ? 'CRITICAL'
      : isSuspicious
      ? 'HIGH'
      : 'INFO';

    const category: NotificationCategory = 'THREAT_INTELLIGENCE';

    return this.createNotification({
      userId: params.userId,
      type: 'THREAT_INTEL_MATCH',
      category,
      severity,
      title: isMalicious
        ? `Malicious Threat Intelligence Match`
        : `Threat Intelligence Signal Detected`,
      message: `Indicator "${params.indicator}" (${params.indicatorType}) was flagged as ${params.reputation} by Threat Intelligence feeds.`,
      entityType: 'threat_intel',
      entityId: params.analysisId || params.indicator,
      metadata: {
        indicator: params.indicator,
        indicatorType: params.indicatorType,
        reputation: params.reputation,
        threatScore: params.threatScore,
      },
      actionUrl: `/threat-intelligence?indicator=${encodeURIComponent(params.indicator)}`,
      actionText: 'Investigate Indicator',
      eventKey: `ti:${params.indicator}:${params.userId}`,
    });
  }

  /**
   * Helper: Report Generation Event Integration
   */
  async createReportNotification(params: {
    userId: string | Types.ObjectId;
    reportId: string;
    title: string;
    reportType?: string;
    target?: string;
    status?: 'READY' | 'FAILED';
  }): Promise<INotification | null> {
    const isFailed = params.status === 'FAILED';

    return this.createNotification({
      userId: params.userId,
      type: isFailed ? 'REPORT_FAILED' : 'REPORT_READY',
      category: 'REPORT',
      severity: isFailed ? 'MEDIUM' : 'INFO',
      title: isFailed ? 'Report Generation Failed' : 'Security Report Ready',
      message: isFailed
        ? `Security report for ${params.target || params.title} could not be generated.`
        : `Your ${params.reportType || 'security assessment'} report "${params.title}" is ready for review and download.`,
      entityType: 'report',
      entityId: params.reportId,
      metadata: {
        reportId: params.reportId,
        reportType: params.reportType,
        target: params.target,
      },
      actionUrl: `/reports/scans/${params.reportId}`,
      actionText: 'View Report',
      eventKey: `report:${params.reportId}:${params.userId}`,
    });
  }

  /**
   * Helper: Support Ticket Event Integration
   */
  async createSupportNotification(params: {
    userId: string | Types.ObjectId;
    ticketId: string;
    ticketNumber: string;
    subject: string;
    type: 'SUPPORT_TICKET_CREATED' | 'SUPPORT_RESPONSE_RECEIVED';
    responderName?: string;
  }): Promise<INotification | null> {
    const isResponse = params.type === 'SUPPORT_RESPONSE_RECEIVED';

    return this.createNotification({
      userId: params.userId,
      type: params.type,
      category: 'SUPPORT',
      severity: isResponse ? 'MEDIUM' : 'INFO',
      title: isResponse ? `Support Reply: ${params.ticketNumber}` : `Support Ticket Created: ${params.ticketNumber}`,
      message: isResponse
        ? `${params.responderName || 'A CyberWatch Security Engineer'} replied to ticket "${params.subject}".`
        : `Ticket ${params.ticketNumber} ("${params.subject}") has been submitted to the CyberWatch Help Desk.`,
      entityType: 'support_ticket',
      entityId: params.ticketId,
      metadata: {
        ticketId: params.ticketId,
        ticketNumber: params.ticketNumber,
        subject: params.subject,
      },
      actionUrl: `/help-support`,
      actionText: 'Open Help Desk',
      eventKey: `support:${params.ticketId}:${params.type}:${Date.now()}`,
    });
  }

  /**
   * Helper: Account Security Event Integration
   */
  async createAccountSecurityNotification(params: {
    userId: string | Types.ObjectId;
    title: string;
    message: string;
    severity?: NotificationSeverity;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<INotification | null> {
    return this.createNotification({
      userId: params.userId,
      type: 'ACCOUNT_SECURITY',
      category: 'ACCOUNT_SECURITY',
      severity: params.severity || 'MEDIUM',
      title: params.title,
      message: params.message,
      entityType: 'account',
      entityId: params.userId.toString(),
      metadata: {
        ipAddress: params.ipAddress,
        userAgent: params.userAgent,
      },
      actionUrl: `/settings`,
      actionText: 'Review Security Settings',
      eventKey: `account_sec:${params.userId}:${Date.now()}`,
    });
  }

  /**
   * Helper: Admin / System Announcement Event Integration
   */
  async createSystemNotification(params: {
    userId: string | Types.ObjectId;
    title: string;
    message: string;
    severity?: NotificationSeverity;
    actionUrl?: string;
    actionText?: string;
  }): Promise<INotification | null> {
    return this.createNotification({
      userId: params.userId,
      type: 'SYSTEM_ANNOUNCEMENT',
      category: 'SYSTEM',
      severity: params.severity || 'INFO',
      title: params.title,
      message: params.message,
      entityType: 'system',
      actionUrl: params.actionUrl,
      actionText: params.actionText,
    });
  }

  /**
   * Retrieve paginated notifications for the authenticated user with filtering.
   */
  async getNotifications(
    userId: string,
    query: GetNotificationsQuery
  ): Promise<GetNotificationsResponse> {
    if (!Types.ObjectId.isValid(userId)) {
      return {
        notifications: [],
        total: 0,
        page: 1,
        limit: 20,
        totalPages: 1,
        unreadCount: 0,
      };
    }
    const userObjectId = new Types.ObjectId(userId);
    const page = Math.max(1, Number(query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(query.limit) || 20));
    const skip = (page - 1) * limit;

    const filter: Record<string, unknown> = { userId: userObjectId };

    if (query.category && query.category !== ('ALL' as any)) {
      filter.category = query.category;
    }

    if (query.severity) {
      filter.severity = query.severity;
    }

    if (typeof query.isRead === 'boolean') {
      filter.isRead = query.isRead;
    } else if (query.isRead === ('true' as any)) {
      filter.isRead = true;
    } else if (query.isRead === ('false' as any)) {
      filter.isRead = false;
    }

    if (query.search) {
      const searchRegex = new RegExp(query.search.trim(), 'i');
      filter.$or = [{ title: searchRegex }, { message: searchRegex }];
    }

    const [items, total, unreadCount] = await Promise.all([
      Notification.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Notification.countDocuments(filter),
      this.getUnreadCount(userId),
    ]);

    const notifications = items.map((doc) => toSafeNotification(doc as any));

    return {
      notifications,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
      unreadCount,
    };
  }

  /**
   * Get total unread count for user.
   */
  async getUnreadCount(userId: string): Promise<number> {
    if (!Types.ObjectId.isValid(userId)) {
      return 0;
    }
    const userObjectId = new Types.ObjectId(userId);
    return Notification.countDocuments({
      userId: userObjectId,
      isRead: false,
    });
  }

  /**
   * Mark a single notification as read (Strictly IDOR protected).
   */
  async markAsRead(userId: string, notificationId: string): Promise<INotification | null> {
    if (!Types.ObjectId.isValid(notificationId)) {
      return null;
    }

    const userObjectId = new Types.ObjectId(userId);
    const notification = await Notification.findOneAndUpdate(
      { _id: new Types.ObjectId(notificationId), userId: userObjectId },
      { isRead: true, readAt: new Date() },
      { new: true }
    );

    if (notification) {
      this.emitUnreadCount(userId);
    }

    return notification;
  }

  /**
   * Mark all notifications as read for user (optionally filtered by category).
   */
  async markAllAsRead(userId: string, category?: NotificationCategory): Promise<number> {
    if (!Types.ObjectId.isValid(userId)) {
      return 0;
    }
    const userObjectId = new Types.ObjectId(userId);
    const filter: Record<string, unknown> = {
      userId: userObjectId,
      isRead: false,
    };

    if (category) {
      filter.category = category;
    }

    const result = await Notification.updateMany(filter, {
      isRead: true,
      readAt: new Date(),
    });

    this.emitUnreadCount(userId);
    return result.modifiedCount;
  }

  /**
   * Delete a notification (Strictly IDOR protected).
   */
  async deleteNotification(userId: string, notificationId: string): Promise<boolean> {
    if (!Types.ObjectId.isValid(notificationId) || !Types.ObjectId.isValid(userId)) {
      return false;
    }

    const userObjectId = new Types.ObjectId(userId);
    const result = await Notification.deleteOne({
      _id: new Types.ObjectId(notificationId),
      userId: userObjectId,
    });

    if (result.deletedCount > 0) {
      this.emitUnreadCount(userId);
      return true;
    }
    return false;
  }

  /**
   * Get user notification preferences (or default settings if not yet saved).
   */
  async getPreferences(userId: string): Promise<NotificationPreferences> {
    const defaultPrefs: NotificationPreferences = {
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
    };

    if (!Types.ObjectId.isValid(userId)) {
      return defaultPrefs;
    }

    const userObjectId = new Types.ObjectId(userId);
    let pref = await NotificationPreference.findOne({ userId: userObjectId }).lean();

    if (!pref) {
      return defaultPrefs;
    }

    if (!pref) {
      return {
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
      };
    }

    return {
      securityAlerts: pref.securityAlerts ?? true,
      scanCompletion: pref.scanCompletion ?? true,
      threatIntelAlerts: pref.threatIntelAlerts ?? true,
      reportReady: pref.reportReady ?? true,
      supportUpdates: pref.supportUpdates ?? true,
      accountSecurity: pref.accountSecurity ?? true,
      browserExtensionAlerts: pref.browserExtensionAlerts ?? true,
      systemAnnouncements: pref.systemAnnouncements ?? true,
      emailNotifications: pref.emailNotifications ?? false,
      inAppNotifications: pref.inAppNotifications ?? true,
    };
  }

  /**
   * Update user notification preferences.
   */
  async updatePreferences(
    userId: string,
    updates: Partial<NotificationPreferences>
  ): Promise<NotificationPreferences> {
    if (!Types.ObjectId.isValid(userId)) {
      return this.getPreferences(userId);
    }
    const userObjectId = new Types.ObjectId(userId);

    // Enforce security alerts are mandatory
    const safeUpdates = {
      ...updates,
      securityAlerts: true,
      accountSecurity: true,
    };

    const pref = await NotificationPreference.findOneAndUpdate(
      { userId: userObjectId },
      { $set: safeUpdates },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    return {
      securityAlerts: true,
      scanCompletion: pref.scanCompletion ?? true,
      threatIntelAlerts: pref.threatIntelAlerts ?? true,
      reportReady: pref.reportReady ?? true,
      supportUpdates: pref.supportUpdates ?? true,
      accountSecurity: true,
      browserExtensionAlerts: pref.browserExtensionAlerts ?? true,
      systemAnnouncements: pref.systemAnnouncements ?? true,
      emailNotifications: pref.emailNotifications ?? false,
      inAppNotifications: pref.inAppNotifications ?? true,
    };
  }

  private isCategoryEnabled(
    prefs: NotificationPreferences,
    category: NotificationCategory,
    severity: NotificationSeverity
  ): boolean {
    // Critical and high severity security & account notifications are always enabled
    if (category === 'SECURITY' || category === 'ACCOUNT_SECURITY' || severity === 'CRITICAL') {
      return true;
    }

    if (!prefs.inAppNotifications) {
      return false;
    }

    switch (category) {
      case 'SCAN':
        return prefs.scanCompletion !== false && prefs.scanCompletions !== false;
      case 'THREAT_INTELLIGENCE':
        return prefs.threatIntelAlerts !== false;
      case 'REPORT':
        return prefs.reportReady !== false && prefs.reportNotifications !== false;
      case 'SUPPORT':
        return prefs.supportUpdates !== false;
      case 'BROWSER_EXTENSION':
        return prefs.browserExtensionAlerts !== false;
      case 'SYSTEM':
        return prefs.systemAnnouncements !== false;
      default:
        return true;
    }
  }

  private emitRealtimeNotification(userId: string, notification: INotification): void {
    const io = getIO();
    if (io) {
      const safe = toSafeNotification(notification);
      io.to(`user:${userId}`).emit('notification:new', safe);
      this.emitUnreadCount(userId);
    }
  }

  private async emitUnreadCount(userId: string): Promise<void> {
    const io = getIO();
    if (io) {
      const unreadCount = await this.getUnreadCount(userId);
      io.to(`user:${userId}`).emit('notification:unread_count', { unreadCount });
    }
  }
}

export const notificationService = new NotificationService();
