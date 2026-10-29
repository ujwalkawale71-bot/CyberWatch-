import { Schema, model, Document, Types } from 'mongoose';
import type {
  SecurityVulnerabilityType,
  SecurityReportSeverity,
  SecurityReportStatus,
} from '@cyberwatch/shared';
import type { ISupportAttachment } from './SupportTicket';

export const SECURITY_VULNERABILITY_TYPES = [
  'AUTHENTICATION',
  'AUTHORIZATION',
  'XSS',
  'CSRF',
  'SSRF',
  'INJECTION',
  'DATA_EXPOSURE',
  'API_SECURITY',
  'PRIVACY',
  'ACCOUNT_TAKEOVER',
  'OTHER',
] as const;

export const SECURITY_REPORT_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

export const SECURITY_REPORT_STATUSES = [
  'SUBMITTED',
  'TRIAGED',
  'FIX_IN_PROGRESS',
  'RESOLVED',
  'CLOSED',
  'INVALID',
] as const;

export interface ISecurityReport extends Document {
  reportNumber: string;
  userId?: Types.ObjectId;
  email: string;
  vulnerabilityType: SecurityVulnerabilityType;
  severity: SecurityReportSeverity;
  affectedComponent: string;
  affectedUrl?: string;
  description: string;
  stepsToReproduce: string;
  impact: string;
  suggestedFix?: string;
  attachments: ISupportAttachment[];
  status: SecurityReportStatus;
  createdAt: Date;
  updatedAt: Date;
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

const securityReportSchema = new Schema<ISecurityReport>(
  {
    reportNumber: {
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
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
    },
    vulnerabilityType: {
      type: String,
      enum: SECURITY_VULNERABILITY_TYPES,
      required: true,
    },
    severity: {
      type: String,
      enum: SECURITY_REPORT_SEVERITIES,
      default: 'MEDIUM',
      required: true,
    },
    affectedComponent: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200,
    },
    affectedUrl: {
      type: String,
      trim: true,
      maxlength: 500,
    },
    description: {
      type: String,
      required: true,
      trim: true,
      minlength: 20,
      maxlength: 10000,
    },
    stepsToReproduce: {
      type: String,
      required: true,
      trim: true,
      minlength: 20,
      maxlength: 10000,
    },
    impact: {
      type: String,
      required: true,
      trim: true,
      minlength: 10,
      maxlength: 5000,
    },
    suggestedFix: {
      type: String,
      trim: true,
      maxlength: 5000,
    },
    attachments: [attachmentSchema],
    status: {
      type: String,
      enum: SECURITY_REPORT_STATUSES,
      default: 'SUBMITTED',
      required: true,
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

securityReportSchema.index({ userId: 1, createdAt: -1 });

export function toSafeSecurityReport(report: ISecurityReport) {
  return {
    id: report._id.toString(),
    reportNumber: report.reportNumber,
    userId: report.userId ? report.userId.toString() : undefined,
    email: report.email,
    vulnerabilityType: report.vulnerabilityType,
    severity: report.severity,
    affectedComponent: report.affectedComponent,
    affectedUrl: report.affectedUrl,
    description: report.description,
    stepsToReproduce: report.stepsToReproduce,
    impact: report.impact,
    suggestedFix: report.suggestedFix,
    attachments: (report.attachments || []).map((att) => ({
      id: att._id ? att._id.toString() : '',
      originalName: att.originalName,
      sanitizedName: att.sanitizedName,
      mimeType: att.mimeType,
      sizeBytes: att.sizeBytes,
      downloadUrl: att.downloadUrl,
      createdAt: att.createdAt ? att.createdAt.toISOString() : new Date().toISOString(),
    })),
    status: report.status,
    createdAt: report.createdAt.toISOString(),
    updatedAt: report.updatedAt.toISOString(),
  };
}

export const SecurityReport = model<ISecurityReport>('SecurityReport', securityReportSchema);
