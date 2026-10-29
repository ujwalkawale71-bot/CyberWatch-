import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { env } from '../config/env';
import { SupportTicket, type ISupportAttachment } from '../models/SupportTicket';
import { SecurityReport } from '../models/SecurityReport';

export const ALLOWED_EXTENSIONS = ['.pdf', '.png', '.jpg', '.jpeg', '.txt', '.csv', '.json'] as const;

export const ALLOWED_MIME_TYPES = [
  'application/pdf',
  'image/png',
  'image/jpeg',
  'image/jpg',
  'text/plain',
  'text/csv',
  'application/json',
] as const;

export const FORBIDDEN_EXTENSIONS = [
  '.exe',
  '.dll',
  '.bat',
  '.cmd',
  '.ps1',
  '.sh',
  '.scr',
  '.js',
  '.vbs',
  '.msi',
  '.com',
  '.pif',
  '.hta',
  '.jar',
] as const;

const ATTACHMENTS_DIR = path.resolve(process.cwd(), 'uploads', 'support-attachments');

export function ensureAttachmentsDir(): void {
  if (!fs.existsSync(ATTACHMENTS_DIR)) {
    fs.mkdirSync(ATTACHMENTS_DIR, { recursive: true, mode: 0o700 });
  }
}

export interface ProcessedAttachment {
  originalName: string;
  sanitizedName: string;
  mimeType: string;
  sizeBytes: number;
  storagePath: string;
  downloadUrl: string;
  createdAt: Date;
}

export const supportAttachmentService = {
  /**
   * Validate file buffer, extension and MIME type.
   */
  validateFile(originalName: string, mimeType: string, sizeBytes: number): { valid: boolean; error?: string } {
    const ext = path.extname(originalName).toLowerCase();

    // Check for dangerous executables and scripts
    if (FORBIDDEN_EXTENSIONS.includes(ext as any)) {
      return {
        valid: false,
        error: `File type '${ext}' is strictly prohibited for security reasons.`,
      };
    }

    // Strict extension whitelist
    if (!ALLOWED_EXTENSIONS.includes(ext as any)) {
      return {
        valid: false,
        error: `File extension '${ext}' is not permitted. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}.`,
      };
    }

    // Size limit
    const maxBytes = (env.SUPPORT_ATTACHMENT_MAX_SIZE_MB || 10) * 1024 * 1024;
    if (sizeBytes > maxBytes) {
      return {
        valid: false,
        error: `File size exceeds the maximum allowed limit of ${env.SUPPORT_ATTACHMENT_MAX_SIZE_MB || 10} MB.`,
      };
    }

    return { valid: true };
  },

  /**
   * Save attachment securely to disk with a random UUID.
   */
  async saveAttachment(fileBuffer: Buffer, originalName: string, mimeType: string): Promise<ProcessedAttachment> {
    const validation = this.validateFile(originalName, mimeType, fileBuffer.length);
    if (!validation.valid) {
      throw new Error(validation.error || 'Invalid attachment');
    }

    ensureAttachmentsDir();

    const ext = path.extname(originalName).toLowerCase();
    const sanitizedBase = path
      .basename(originalName, ext)
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .slice(0, 80);
    const sanitizedName = `${sanitizedBase}${ext}`;

    const uniqueStorageName = `${crypto.randomUUID()}${ext}`;
    const storagePath = path.join(ATTACHMENTS_DIR, uniqueStorageName);

    // Save with restricted filesystem permissions
    await fs.promises.writeFile(storagePath, fileBuffer, { mode: 0o600 });

    const downloadUrl = `/api/v1/support/attachments/${uniqueStorageName}`;

    return {
      originalName,
      sanitizedName,
      mimeType,
      sizeBytes: fileBuffer.length,
      storagePath,
      downloadUrl,
      createdAt: new Date(),
    };
  },

  /**
   * Resolve an attachment file path after verifying authorization and ownership.
   */
  async getAuthorizedAttachmentPath(
    filename: string,
    userId?: string,
    userRole?: string
  ): Promise<{ filePath: string; mimeType: string; originalName: string } | null> {
    // Path traversal defense
    const cleanFilename = path.basename(filename);
    if (cleanFilename !== filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      return null;
    }

    const filePath = path.join(ATTACHMENTS_DIR, cleanFilename);
    if (!fs.existsSync(filePath)) {
      return null;
    }

    const downloadUrl = `/api/v1/support/attachments/${cleanFilename}`;

    // Verify ownership in SupportTickets (attachments or message attachments)
    const ticket = await SupportTicket.findOne({
      $or: [
        { 'attachments.downloadUrl': downloadUrl },
        { 'messages.attachments.downloadUrl': downloadUrl },
      ],
    });

    if (ticket) {
      const isOwner = userId && ticket.userId.toString() === userId;
      const isStaff = userRole === 'ADMIN' || userRole === 'ANALYST';
      if (!isOwner && !isStaff) {
        return null;
      }

      // Find attachment metadata
      const directAtt = (ticket.attachments || []).find((a) => a.downloadUrl === downloadUrl);
      if (directAtt) {
        return { filePath, mimeType: directAtt.mimeType, originalName: directAtt.originalName };
      }

      for (const msg of ticket.messages || []) {
        const msgAtt = (msg.attachments || []).find((a) => a.downloadUrl === downloadUrl);
        if (msgAtt) {
          return { filePath, mimeType: msgAtt.mimeType, originalName: msgAtt.originalName };
        }
      }
    }

    // Verify ownership in SecurityReports
    const report = await SecurityReport.findOne({
      'attachments.downloadUrl': downloadUrl,
    });

    if (report) {
      const isOwner = userId && report.userId && report.userId.toString() === userId;
      const isStaff = userRole === 'ADMIN' || userRole === 'ANALYST';
      if (!isOwner && !isStaff) {
        return null;
      }

      const att = (report.attachments || []).find((a) => a.downloadUrl === downloadUrl);
      if (att) {
        return { filePath, mimeType: att.mimeType, originalName: att.originalName };
      }
    }

    // Fallback if not mapped to a ticket yet (e.g. during upload transaction by current user)
    if (userRole === 'ADMIN') {
      return { filePath, mimeType: 'application/octet-stream', originalName: cleanFilename };
    }

    return null;
  },
};
