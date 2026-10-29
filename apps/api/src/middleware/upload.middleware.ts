import type { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { env } from '../config/env';

export interface UploadedFileInfo {
  path: string;
  originalName: string;
  mimeType: string;
  size: number;
  buffer?: Buffer;
}

declare global {
  namespace Express {
    interface Request {
      filePayload?: UploadedFileInfo;
    }
  }
}

const TEMP_DIR = path.resolve(process.cwd(), 'temp', 'file-scan');

function ensureTempDir() {
  if (!fs.existsSync(TEMP_DIR)) {
    fs.mkdirSync(TEMP_DIR, { recursive: true, mode: 0o700 });
  }
}

/**
 * Native streaming file upload middleware.
 * Enforces strict maximum file size (413 Payload Too Large) WHILE streaming without loading unbounded files into RAM.
 * Writes directly to isolated temporary storage using a cryptographically random UUID (<uuid>.sample).
 */
export function handleFileUpload(req: Request, res: Response, next: NextFunction): void {
  const maxMb = env.FILE_SCAN_MAX_SIZE_MB || 25;
  const maxBytes = maxMb * 1024 * 1024;
  const contentLength = parseInt(req.headers['content-length'] || '0', 10);

  // Fast check: If Content-Length header is advertised above maxBytes, reject immediately before streaming
  if (contentLength > maxBytes) {
    res.status(413).json({
      success: false,
      message: `File size exceeds the configured maximum limit of ${maxMb} MB.`,
    });
    return;
  }

  ensureTempDir();
  const storageFilename = `${crypto.randomUUID()}.sample`;
  const storagePath = path.join(TEMP_DIR, storageFilename);
  const writeStream = fs.createWriteStream(storagePath, { mode: 0o600 });

  const contentType = req.headers['content-type'] || '';
  let bytesReceived = 0;
  let isLimitExceeded = false;
  let isAborted = false;
  const chunks: Buffer[] = [];

  const isMultipart = contentType.includes('multipart/form-data');
  let originalFilename = 'uploaded_sample.bin';
  let mimeType = 'application/octet-stream';

  req.on('data', (chunk: Buffer) => {
    if (isLimitExceeded || isAborted) return;

    bytesReceived += chunk.length;
    if (bytesReceived > maxBytes) {
      isLimitExceeded = true;
      isAborted = true;
      req.pause();
      writeStream.destroy();

      try {
        if (fs.existsSync(storagePath)) fs.unlinkSync(storagePath);
      } catch {}

      res.status(413).json({
        success: false,
        message: `File size exceeds the configured maximum limit of ${maxMb} MB.`,
      });
      return;
    }

    chunks.push(chunk);
    writeStream.write(chunk);
  });

  req.on('end', () => {
    if (isLimitExceeded || isAborted) return;

    writeStream.end(() => {
      const fullBuffer = Buffer.concat(chunks);

      if (isMultipart) {
        // Parse multipart boundary
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
            mimeType = ctMatch[1].trim();
          }

          // Extract payload between boundaries
          const boundaryDelimiter = Buffer.from(`--${boundary}`);
          const headerEndPattern = Buffer.from('\r\n\r\n');
          const headerEndIdx = fullBuffer.indexOf(headerEndPattern);

          if (headerEndIdx !== -1) {
            const bodyStart = headerEndIdx + 4;
            const endBoundaryIdx = fullBuffer.indexOf(boundaryDelimiter, bodyStart);
            const actualPayload =
              endBoundaryIdx !== -1
                ? fullBuffer.slice(bodyStart, endBoundaryIdx - 2)
                : fullBuffer.slice(bodyStart);

            fs.writeFileSync(storagePath, actualPayload, { mode: 0o600 });
            req.filePayload = {
              path: storagePath,
              originalName: originalFilename,
              mimeType,
              size: actualPayload.length,
              buffer: actualPayload,
            };
            next();
            return;
          }
        }
      }

      req.filePayload = {
        path: storagePath,
        originalName: (req.headers['x-filename'] as string) || originalFilename,
        mimeType: contentType || mimeType,
        size: fullBuffer.length,
        buffer: fullBuffer,
      };
      next();
    });
  });

  req.on('error', (err) => {
    writeStream.destroy();
    try {
      if (fs.existsSync(storagePath)) fs.unlinkSync(storagePath);
    } catch {}
    next(err);
  });
}
