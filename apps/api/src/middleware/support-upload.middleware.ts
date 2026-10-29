import type { Request, Response, NextFunction } from 'express';
import { env } from '../config/env';
import { supportAttachmentService } from '../services/support-attachment.service';
import type { ISupportAttachment } from '../models/SupportTicket';

declare global {
  namespace Express {
    interface Request {
      supportAttachments?: ISupportAttachment[];
    }
  }
}

/**
 * Streaming file upload middleware specifically for Help & Support attachments.
 * Enforces:
 * - Content-Length and buffer size check
 * - Strict extension & MIME validation
 * - Random storage names
 * - Populates req.supportAttachments
 */
export async function handleSupportAttachmentUpload(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('multipart/form-data') && !contentType.includes('application/octet-stream')) {
    // Normal JSON request or no attachments attached
    return next();
  }

  const maxMb = env.SUPPORT_ATTACHMENT_MAX_SIZE_MB || 10;
  const maxBytes = maxMb * 1024 * 1024;
  const contentLength = parseInt(req.headers['content-length'] || '0', 10);

  if (contentLength > maxBytes) {
    res.status(413).json({
      success: false,
      message: `Attachment exceeds the maximum allowed size of ${maxMb} MB.`,
    });
    return;
  }

  const chunks: Buffer[] = [];
  let bytesReceived = 0;
  let isAborted = false;

  req.on('data', (chunk: Buffer) => {
    if (isAborted) return;
    bytesReceived += chunk.length;
    if (bytesReceived > maxBytes) {
      isAborted = true;
      req.pause();
      res.status(413).json({
        success: false,
        message: `Attachment exceeds the maximum allowed size of ${maxMb} MB.`,
      });
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', async () => {
    if (isAborted) return;

    try {
      const fullBuffer = Buffer.concat(chunks);
      if (fullBuffer.length === 0) {
        return next();
      }

      let originalFilename = (req.headers['x-filename'] as string) || 'attachment.txt';
      let fileMimeType = contentType || 'application/octet-stream';
      let filePayloadBuffer = fullBuffer;

      if (contentType.includes('multipart/form-data')) {
        const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
        const boundary = boundaryMatch ? boundaryMatch[1] || boundaryMatch[2] : null;

        if (boundary) {
          const headerSnippet = fullBuffer.slice(0, Math.min(fullBuffer.length, 4096)).toString('latin1');
          const fnMatch = headerSnippet.match(/filename="([^"]+)"/i);
          if (fnMatch && fnMatch[1]) {
            originalFilename = fnMatch[1];
          }
          const ctMatch = headerSnippet.match(/Content-Type:\s*([^\r\n;]+)/i);
          if (ctMatch && ctMatch[1]) {
            fileMimeType = ctMatch[1].trim();
          }

          const boundaryDelimiter = Buffer.from(`--${boundary}`);
          const headerEndPattern = Buffer.from('\r\n\r\n');
          const headerEndIdx = fullBuffer.indexOf(headerEndPattern);

          if (headerEndIdx !== -1) {
            const bodyStart = headerEndIdx + 4;
            const endBoundaryIdx = fullBuffer.indexOf(boundaryDelimiter, bodyStart);
            filePayloadBuffer =
              endBoundaryIdx !== -1
                ? fullBuffer.slice(bodyStart, endBoundaryIdx - 2)
                : fullBuffer.slice(bodyStart);
          }
        }
      }

      if (filePayloadBuffer.length > 0) {
        const savedAttachment = await supportAttachmentService.saveAttachment(
          filePayloadBuffer,
          originalFilename,
          fileMimeType
        );

        req.supportAttachments = [savedAttachment as any];
      }

      next();
    } catch (err) {
      res.status(400).json({
        success: false,
        message: err instanceof Error ? err.message : 'Failed to process attachment.',
      });
    }
  });

  req.on('error', (err) => {
    next(err);
  });
}
