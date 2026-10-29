import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { scanService } from '../services/scan.service';

const initiateScanSchema = z.object({
  target: z.string().min(1, 'Please enter a valid target to scan.'),
  targetType: z.enum(['URL', 'Website', 'API', 'Phishing', 'File', 'Extension', 'Domain']).optional().default('URL'),
  forceRescan: z.boolean().optional(),
});

export class ScanController {
  async initiateScan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = initiateScanSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          success: false,
          message: parsed.error.issues[0]?.message || 'Please enter a valid URL.',
          errors: parsed.error.issues.map((e) => ({
            field: e.path.join('.'),
            message: e.message,
          })),
        });
        return;
      }

      const userId = req.user?.userId;
      const scanResult = await scanService.analyzeAndSave(parsed.data, userId);

      res.status(201).json({
        success: true,
        message: 'Security analysis completed successfully.',
        data: scanResult,
      });
    } catch (error) {
      next(error);
    }
  }

  async uploadAndScanFile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.filePayload || !req.filePayload.buffer) {
        res.status(400).json({
          success: false,
          message: 'No file payload provided for scanning.',
        });
        return;
      }

      const userId = req.user?.userId;
      const scanResult = await scanService.scanUploadedFile(
        req.filePayload.buffer,
        req.filePayload.originalName,
        req.filePayload.mimeType,
        userId
      );

      res.status(201).json({
        success: true,
        message: 'File security analysis completed successfully.',
        data: scanResult,
      });
    } catch (error) {
      next(error);
    }
  }

  async getUserScans(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({
          success: false,
          message: 'Authentication required.',
        });
        return;
      }

      const limit = parseInt(req.query.limit as string, 10) || 10;
      const page = parseInt(req.query.page as string, 10) || 1;

      const result = await scanService.getUserScans(req.user.userId, limit, page);

      res.status(200).json({
        success: true,
        message: 'User scans retrieved successfully.',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  async getUserStats(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({
          success: false,
          message: 'Authentication required.',
        });
        return;
      }

      const stats = await scanService.getUserStats(req.user.userId);

      res.status(200).json({
        success: true,
        message: 'Security statistics retrieved successfully.',
        data: stats,
      });
    } catch (error) {
      next(error);
    }
  }

  async getScanById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const scanId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const userId = req.user?.userId;

      if (!scanId) {
        res.status(400).json({
          success: false,
          message: 'Scan ID is required.',
        });
        return;
      }

      const scan = await scanService.getScanById(scanId, userId);
      if (!scan) {
        res.status(404).json({
          success: false,
          message: 'Scan report not found.',
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Scan report retrieved successfully.',
        data: scan,
      });
    } catch (error) {
      next(error);
    }
  }

  async getScanByHash(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const sha256 = Array.isArray(req.params.sha256) ? req.params.sha256[0] : req.params.sha256;
      if (!sha256 || typeof sha256 !== 'string' || sha256.trim().length !== 64) {
        res.status(400).json({
          success: false,
          message: 'A valid 64-character SHA-256 hash is required.',
        });
        return;
      }

      const scan = await scanService.getScanBySha256(sha256.trim());
      if (!scan) {
        res.status(404).json({
          success: false,
          message: 'No completed scan report found for the specified SHA-256 hash.',
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Scan report retrieved successfully by hash.',
        data: scan,
      });
    } catch (error) {
      next(error);
    }
  }

  async downloadReportJson(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const scanId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const userId = req.user?.userId;

      if (!scanId) {
        res.status(400).json({
          success: false,
          message: 'Scan ID is required.',
        });
        return;
      }

      const scan = await scanService.getScanById(scanId, userId);
      if (!scan) {
        res.status(404).json({
          success: false,
          message: 'Scan report not found.',
        });
        return;
      }

      const filename = `CyberWatch_Scan_Report_${scan.id}.json`;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.status(200).json({
        platform: 'CyberWatch Unified Threat Detection Platform',
        reportType: 'Security Scan Analysis',
        generatedAt: new Date().toISOString(),
        scan,
      });
    } catch (error) {
      next(error);
    }
  }

  async downloadReportPdf(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const scanId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const userId = req.user?.userId;

      if (!scanId) {
        res.status(400).json({
          success: false,
          message: 'Scan ID is required.',
        });
        return;
      }

      const scan = await scanService.getScanById(scanId, userId);
      if (!scan) {
        res.status(404).json({
          success: false,
          message: 'Scan report not found.',
        });
        return;
      }

      const { pdfReportService } = await import('../services/pdf-report.service');
      const pdfBuffer = pdfReportService.generatePdfBuffer(scan);
      const filename = `CyberWatch_Scan_Report_${scan.id}.pdf`;

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.status(200).send(pdfBuffer);
    } catch (error) {
      next(error);
    }
  }
}

export const scanController = new ScanController();
