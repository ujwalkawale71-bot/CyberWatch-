import { Schema, model, Document, Types } from 'mongoose';
import type {
  SupportCategory,
  SupportPriority,
  SupportStatus,
  SupportSenderType,
} from '@cyberwatch/shared';

export const SUPPORT_CATEGORIES = [
  'SCANNER_ISSUE',
  'INCORRECT_SCAN_RESULT',
  'THREAT_INTELLIGENCE',
  'REPORT_EXPORT',
  'ACCOUNT_LOGIN',
  'BILLING_SUBSCRIPTION',
  'TECHNICAL_ISSUE',
  'FEATURE_REQUEST',
  'SECURITY_VULNERABILITY',
  'OTHER',
] as const;

export const SUPPORT_PRIORITIES = ['LOW', 'MEDIUM', 'HIGH', 'URGENT'] as const;

export const SUPPORT_STATUSES = [
  'OPEN',
  'INVESTIGATING',
  'WAITING_FOR_USER',
  'RESOLVED',
  'CLOSED',
] as const;

// ─── Attachment Schema ───────────────────────────────────────────────────────
export interface ISupportAttachment {
  _id?: Types.ObjectId;
  originalName: string;
  sanitizedName: string;
  mimeType: string;
  sizeBytes: number;
  storagePath: string;
  downloadUrl: string;
  createdAt: Date;
}

const attachmentSchema = new Schema<ISupportAttachment>(
  {
    originalName: { type: String, required: true, trim: true },
    sanitizedName: { type: String, required: true, trim: true },
    mimeType: { type: String, required: true, trim: true },
    sizeBytes: { type: Number, required: true },
    storagePath: { type: String, required: true },
    downloadUrl: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: true }
);

// ─── Message Schema ──────────────────────────────────────────────────────────
export interface ISupportMessage {
  _id?: Types.ObjectId;
  senderType: SupportSenderType;
  senderUserId?: Types.ObjectId;
  senderName: string;
  message: string;
  attachments: ISupportAttachment[];
  createdAt: Date;
}

const messageSchema = new Schema<ISupportMessage>(
  {
    senderType: {
      type: String,
      enum: ['USER', 'SUPPORT', 'SYSTEM'],
      required: true,
      default: 'USER',
    },
    senderUserId: { type: Schema.Types.ObjectId, ref: 'User' },
    senderName: { type: String, required: true, trim: true },
    message: { type: String, required: true, trim: true, maxlength: 10000 },
    attachments: [attachmentSchema],
    createdAt: { type: Date, default: Date.now },
  },
  { _id: true }
);

// ─── Support Ticket Interface ────────────────────────────────────────────────
export interface ISupportTicket extends Document {
  ticketNumber: string;
  userId: Types.ObjectId;
  name: string;
  email: string;
  category: SupportCategory;
  priority: SupportPriority;
  subject: string;
  description: string;
  scanId?: string;
  reportId?: string;
  targetUrl?: string;
  browserEnvironment?: string;
  status: SupportStatus;
  assignedTo?: Types.ObjectId;
  assignedAgentName?: string;
  messages: ISupportMessage[];
  attachments: ISupportAttachment[];
  isSecurityReport: boolean;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
  closedAt?: Date;
}

// ─── Support Ticket Schema ───────────────────────────────────────────────────
const supportTicketSchema = new Schema<ISupportTicket>(
  {
    ticketNumber: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      index: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 100,
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
    },
    category: {
      type: String,
      enum: SUPPORT_CATEGORIES,
      required: true,
    },
    priority: {
      type: String,
      enum: SUPPORT_PRIORITIES,
      default: 'MEDIUM',
      required: true,
    },
    subject: {
      type: String,
      required: true,
      trim: true,
      minlength: 5,
      maxlength: 200,
    },
    description: {
      type: String,
      required: true,
      trim: true,
      minlength: 10,
      maxlength: 10000,
    },
    scanId: { type: String, trim: true },
    reportId: { type: String, trim: true },
    targetUrl: { type: String, trim: true },
    browserEnvironment: { type: String, trim: true },
    status: {
      type: String,
      enum: SUPPORT_STATUSES,
      default: 'OPEN',
      required: true,
      index: true,
    },
    assignedTo: { type: Schema.Types.ObjectId, ref: 'User' },
    assignedAgentName: { type: String, trim: true },
    messages: [messageSchema],
    attachments: [attachmentSchema],
    isSecurityReport: { type: Boolean, default: false },
    metadata: { type: Schema.Types.Mixed, default: {} },
    resolvedAt: { type: Date },
    closedAt: { type: Date },
  },
  {
    timestamps: true,
  }
);

// Compound indexes for user ticket queries and ordering
supportTicketSchema.index({ userId: 1, createdAt: -1 });
supportTicketSchema.index({ status: 1, createdAt: -1 });

// Helper to format safe SupportTicket object for client
export function toSafeSupportTicket(ticket: ISupportTicket) {
  return {
    id: ticket._id.toString(),
    ticketNumber: ticket.ticketNumber,
    userId: ticket.userId.toString(),
    name: ticket.name,
    email: ticket.email,
    category: ticket.category,
    priority: ticket.priority,
    subject: ticket.subject,
    description: ticket.description,
    scanId: ticket.scanId,
    reportId: ticket.reportId,
    targetUrl: ticket.targetUrl,
    browserEnvironment: ticket.browserEnvironment,
    status: ticket.status,
    assignedTo: ticket.assignedTo ? ticket.assignedTo.toString() : undefined,
    assignedAgentName: ticket.assignedAgentName,
    messages: (ticket.messages || []).map((msg) => ({
      id: msg._id ? msg._id.toString() : '',
      senderType: msg.senderType,
      senderUserId: msg.senderUserId ? msg.senderUserId.toString() : undefined,
      senderName: msg.senderName,
      message: msg.message,
      attachments: (msg.attachments || []).map((att) => ({
        id: att._id ? att._id.toString() : '',
        originalName: att.originalName,
        sanitizedName: att.sanitizedName,
        mimeType: att.mimeType,
        sizeBytes: att.sizeBytes,
        downloadUrl: att.downloadUrl,
        createdAt: att.createdAt ? att.createdAt.toISOString() : new Date().toISOString(),
      })),
      createdAt: msg.createdAt ? msg.createdAt.toISOString() : new Date().toISOString(),
    })),
    attachments: (ticket.attachments || []).map((att) => ({
      id: att._id ? att._id.toString() : '',
      originalName: att.originalName,
      sanitizedName: att.sanitizedName,
      mimeType: att.mimeType,
      sizeBytes: att.sizeBytes,
      downloadUrl: att.downloadUrl,
      createdAt: att.createdAt ? att.createdAt.toISOString() : new Date().toISOString(),
    })),
    isSecurityReport: ticket.isSecurityReport,
    metadata: ticket.metadata,
    createdAt: ticket.createdAt.toISOString(),
    updatedAt: ticket.updatedAt.toISOString(),
    resolvedAt: ticket.resolvedAt ? ticket.resolvedAt.toISOString() : undefined,
    closedAt: ticket.closedAt ? ticket.closedAt.toISOString() : undefined,
  };
}

export const SupportTicket = model<ISupportTicket>('SupportTicket', supportTicketSchema);
