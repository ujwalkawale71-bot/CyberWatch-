import { Schema, model, Document, Types } from 'mongoose';
import type { SupportChatSessionStatus, SupportSenderType, SupportPriority } from '@cyberwatch/shared';
import type { ISupportAttachment } from './SupportTicket';

export interface ISupportChatMessage {
  _id?: Types.ObjectId;
  senderType: SupportSenderType;
  senderName: string;
  senderUserId?: Types.ObjectId;
  message: string;
  readAt?: Date;
  attachments?: ISupportAttachment[];
  createdAt: Date;
}

export interface ISupportChatSession extends Document {
  sessionId: string;
  userId?: Types.ObjectId;
  userName: string;
  userEmail: string;
  status: SupportChatSessionStatus;
  agentName?: string;
  assignedAgentId?: Types.ObjectId;
  assignedAgentName?: string;
  priority: SupportPriority;
  messages: ISupportChatMessage[];
  convertedTicketNumber?: string;
  createdAt: Date;
  updatedAt: Date;
  endedAt?: Date;
  closedAt?: Date;
}

const chatAttachmentSchema = new Schema<ISupportAttachment>(
  {
    originalName: { type: String, required: true, trim: true },
    sanitizedName: { type: String, required: true, trim: true },
    storagePath: { type: String, required: true, trim: true },
    downloadUrl: { type: String, required: true, trim: true },
    mimeType: { type: String, required: true, trim: true },
    sizeBytes: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: true }
);

const chatMessageSchema = new Schema<ISupportChatMessage>(
  {
    senderType: {
      type: String,
      enum: ['USER', 'SUPPORT', 'SYSTEM'],
      required: true,
      default: 'USER',
    },
    senderName: { type: String, required: true, trim: true },
    senderUserId: { type: Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, required: true, trim: true, maxlength: 4000 },
    readAt: { type: Date },
    attachments: [chatAttachmentSchema],
    createdAt: { type: Date, default: Date.now },
  },
  { _id: true }
);

const supportChatSessionSchema = new Schema<ISupportChatSession>(
  {
    sessionId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      index: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      index: true,
    },
    userName: {
      type: String,
      required: true,
      trim: true,
    },
    userEmail: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
    },
    status: {
      type: String,
      enum: ['CONNECTING', 'WAITING_FOR_AGENT', 'WAITING', 'ACTIVE', 'CLOSED', 'ENDED'],
      default: 'WAITING_FOR_AGENT',
      required: true,
      index: true,
    },
    agentName: {
      type: String,
      trim: true,
    },
    assignedAgentId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      index: true,
    },
    assignedAgentName: {
      type: String,
      trim: true,
    },
    priority: {
      type: String,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'URGENT'],
      default: 'MEDIUM',
    },
    convertedTicketNumber: {
      type: String,
      trim: true,
    },
    messages: [chatMessageSchema],
    endedAt: { type: Date },
    closedAt: { type: Date },
  },
  {
    timestamps: true,
  }
);

supportChatSessionSchema.index({ userId: 1, createdAt: -1 });
supportChatSessionSchema.index({ status: 1, createdAt: -1 });

export function toSafeChatSession(session: ISupportChatSession) {
  return {
    id: session._id.toString(),
    sessionId: session.sessionId,
    userId: session.userId ? session.userId.toString() : undefined,
    userName: session.userName,
    userEmail: session.userEmail,
    status: session.status,
    agentName: session.agentName || session.assignedAgentName,
    assignedAgentId: session.assignedAgentId ? session.assignedAgentId.toString() : undefined,
    assignedAgentName: session.assignedAgentName || session.agentName,
    priority: session.priority || 'MEDIUM',
    convertedTicketNumber: session.convertedTicketNumber,
    messages: (session.messages || []).map((msg) => ({
      id: msg._id ? msg._id.toString() : '',
      senderType: msg.senderType,
      senderName: msg.senderName,
      message: msg.message,
      readAt: msg.readAt ? msg.readAt.toISOString() : undefined,
      attachments: (msg.attachments || []).map((att) => ({
        id: att._id ? att._id.toString() : '',
        originalName: att.originalName,
        sanitizedName: att.sanitizedName,
        mimeType: att.mimeType,
        sizeBytes: att.sizeBytes,
        downloadUrl: `/api/v1/support/attachments/${encodeURIComponent(att.sanitizedName)}`,
        createdAt: att.createdAt ? att.createdAt.toISOString() : new Date().toISOString(),
      })),
      createdAt: msg.createdAt ? msg.createdAt.toISOString() : new Date().toISOString(),
    })),
    createdAt: session.createdAt.toISOString(),
    updatedAt: session.updatedAt.toISOString(),
    endedAt: session.endedAt ? session.endedAt.toISOString() : undefined,
    closedAt: session.closedAt ? session.closedAt.toISOString() : undefined,
  };
}

export const SupportChatSession = model<ISupportChatSession>('SupportChatSession', supportChatSessionSchema);

