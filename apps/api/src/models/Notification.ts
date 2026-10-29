import { Schema, model, Document, Types } from 'mongoose';
import {
  NotificationCategory,
  NotificationSeverity,
  NotificationType,
  NotificationPreferences,
} from '@cyberwatch/shared';

export interface INotification extends Document {
  userId: Types.ObjectId;
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
  isRead: boolean;
  readAt?: Date | null;
  eventKey?: string;
  expiresAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

const notificationSchema = new Schema<INotification>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    type: {
      type: String,
      required: true,
      index: true,
    },
    category: {
      type: String,
      enum: [
        'SECURITY',
        'SCAN',
        'THREAT_INTELLIGENCE',
        'REPORT',
        'BROWSER_EXTENSION',
        'ACCOUNT_SECURITY',
        'SYSTEM',
        'SUPPORT',
      ],
      required: true,
      index: true,
    },
    severity: {
      type: String,
      enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      required: true,
      index: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200,
    },
    message: {
      type: String,
      required: true,
      trim: true,
      maxlength: 1500,
    },
    entityType: {
      type: String,
      trim: true,
    },
    entityId: {
      type: String,
      trim: true,
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: {},
    },
    actionUrl: {
      type: String,
      trim: true,
    },
    actionText: {
      type: String,
      trim: true,
      maxlength: 50,
    },
    isRead: {
      type: Boolean,
      default: false,
      index: true,
    },
    readAt: {
      type: Date,
      default: null,
    },
    eventKey: {
      type: String,
      trim: true,
      sparse: true,
      index: true,
    },
    expiresAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// Compound indexes for optimal queries
notificationSchema.index({ userId: 1, createdAt: -1 });
notificationSchema.index({ userId: 1, isRead: 1, createdAt: -1 });
notificationSchema.index({ userId: 1, category: 1, createdAt: -1 });
notificationSchema.index({ userId: 1, eventKey: 1 }, { unique: true, sparse: true });

export const Notification = model<INotification>('Notification', notificationSchema);

// ─── Notification Preferences Schema ──────────────────────────────────────────
export interface INotificationPreference extends Document {
  userId: Types.ObjectId;
  securityAlerts: boolean;
  scanCompletion: boolean;
  threatIntelAlerts: boolean;
  reportReady: boolean;
  supportUpdates: boolean;
  accountSecurity: boolean;
  browserExtensionAlerts: boolean;
  systemAnnouncements: boolean;
  emailNotifications: boolean;
  inAppNotifications: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const notificationPreferenceSchema = new Schema<INotificationPreference>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      unique: true,
      index: true,
    },
    securityAlerts: { type: Boolean, default: true }, // Mandatory security alerts
    scanCompletion: { type: Boolean, default: true },
    threatIntelAlerts: { type: Boolean, default: true },
    reportReady: { type: Boolean, default: true },
    supportUpdates: { type: Boolean, default: true },
    accountSecurity: { type: Boolean, default: true },
    browserExtensionAlerts: { type: Boolean, default: true },
    systemAnnouncements: { type: Boolean, default: true },
    emailNotifications: { type: Boolean, default: false },
    inAppNotifications: { type: Boolean, default: true },
  },
  {
    timestamps: true,
  }
);

export const NotificationPreference = model<INotificationPreference>(
  'NotificationPreference',
  notificationPreferenceSchema
);

export function toSafeNotification(doc: INotification) {
  return {
    id: doc._id.toString(),
    _id: doc._id.toString(),
    userId: doc.userId.toString(),
    type: doc.type,
    category: doc.category,
    severity: doc.severity,
    title: doc.title,
    message: doc.message,
    entityType: doc.entityType,
    entityId: doc.entityId,
    metadata: doc.metadata || {},
    actionUrl: doc.actionUrl,
    actionText: doc.actionText,
    isRead: doc.isRead,
    readAt: doc.readAt ? doc.readAt.toISOString() : null,
    createdAt: doc.createdAt.toISOString(),
    expiresAt: doc.expiresAt ? doc.expiresAt.toISOString() : null,
  };
}
