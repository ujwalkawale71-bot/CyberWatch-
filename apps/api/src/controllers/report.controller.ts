import type { Request, Response, NextFunction } from 'express';
import { reportService } from '../services/report.service';

export class ReportController {
  async getOverview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }
      const overview = await reportService.getReportsOverview(req.user.userId);
      res.status(200).json({
        success: true,
        message: 'Report overview statistics retrieved successfully.',
        data: overview,
      });
    } catch (error) {
      next(error);
    }
  }

  async getFindings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const severity = req.query.severity as any;
      const scanner = req.query.scanner as any;
      const category = req.query.category as string;
      const search = req.query.search as string;
      const target = req.query.target as string;
      const startDate = req.query.startDate as string;
      const endDate = req.query.endDate as string;
      const page = parseInt(req.query.page as string, 10) || 1;
      const limit = parseInt(req.query.limit as string, 10) || 20;

      const result = await reportService.getSecurityFindings(req.user.userId, {
        severity,
        scanner,
        category,
        search,
        target,
        startDate,
        endDate,
        page,
        limit,
      });

      res.status(200).json({
        success: true,
        message: 'Security findings retrieved successfully.',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  async getFindingById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const findingId = Array.isArray(req.params.findingId) ? req.params.findingId[0] : req.params.findingId;
      if (!findingId) {
        res.status(400).json({ success: false, message: 'Finding ID is required.' });
        return;
      }

      const finding = await reportService.getFindingById(req.user.userId, findingId);
      if (!finding) {
        res.status(404).json({ success: false, message: 'Security finding not found.' });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Security finding details retrieved successfully.',
        data: finding,
      });
    } catch (error) {
      next(error);
    }
  }

  async getHistory(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const scanner = req.query.scanner as any;
      const riskLevel = req.query.riskLevel as any;
      const status = req.query.status as any;
      const target = req.query.target as string;
      const search = req.query.search as string;
      const startDate = req.query.startDate as string;
      const endDate = req.query.endDate as string;
      const sortBy = req.query.sortBy as any;
      const page = parseInt(req.query.page as string, 10) || 1;
      const limit = parseInt(req.query.limit as string, 10) || 10;

      const result = await reportService.getScanHistory(req.user.userId, {
        scanner,
        riskLevel,
        status,
        target,
        search,
        startDate,
        endDate,
        sortBy,
        page,
        limit,
      });

      res.status(200).json({
        success: true,
        message: 'Scan history retrieved successfully.',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  async getScanReport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const scanId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const userId = req.user?.userId;

      if (!scanId) {
        res.status(400).json({ success: false, message: 'Scan ID is required.' });
        return;
      }

      const report = await reportService.getScanReport(scanId, userId);
      if (!report) {
        res.status(404).json({ success: false, message: 'Scan report not found.' });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Scan report retrieved successfully.',
        data: report,
      });
    } catch (error) {
      next(error);
    }
  }

  async compareScans(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const scan1 = req.query.scan1 as string;
      const scan2 = req.query.scan2 as string;

      if (!scan1 || !scan2) {
        res.status(400).json({
          success: false,
          message: 'Both scan1 and scan2 query parameters are required for scan comparison.',
        });
        return;
      }

      const comparison = await reportService.compareScans(scan1, scan2, req.user.userId);
      res.status(200).json({
        success: true,
        message: 'Scan comparison generated successfully.',
        data: comparison,
      });
    } catch (error) {
      next(error);
    }
  }

  async exportReport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const { format = 'json', type = 'scan', scanId } = req.body;
      const userId = req.user.userId;

      if (format === 'pdf') {
        if (!scanId) {
          res.status(400).json({ success: false, message: 'Scan ID is required for PDF export.' });
          return;
        }
        const pdfBuffer = await reportService.exportPdf(scanId, userId);
        const filename = `CyberWatch_Security_Report_${scanId}.pdf`;
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.status(200).send(pdfBuffer);
        return;
      }

      if (format === 'csv') {
        const csvContent = await reportService.exportCsv(userId, type, scanId);
        const filename = `CyberWatch_${type}_Export_${Date.now()}.csv`;
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.status(200).send(csvContent);
        return;
      }

      // JSON format default
      const jsonData = await reportService.exportJson(userId, type, scanId);
      const filename = `CyberWatch_${type}_Export_${Date.now()}.json`;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.status(200).json(jsonData);
    } catch (error) {
      next(error);
    }
  }

  async directDownload(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const typeParam = Array.isArray(req.params.type) ? req.params.type[0] : req.params.type;
      const formatParam = Array.isArray(req.params.format) ? req.params.format[0] : req.params.format;
      const type = (typeParam || 'history') as 'scan' | 'findings' | 'history';
      const format = (formatParam || 'json').toLowerCase();
      const scanId = req.query.scanId as string || (req.params.id as string);
      const userId = req.user.userId;

      if (format === 'pdf') {
        if (!scanId) {
          res.status(400).json({ success: false, message: 'Scan ID is required for PDF download.' });
          return;
        }
        const pdfBuffer = await reportService.exportPdf(scanId, userId);
        const filename = `CyberWatch_Security_Report_${scanId}.pdf`;
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.status(200).send(pdfBuffer);
        return;
      }

      if (format === 'csv') {
        const csvContent = await reportService.exportCsv(userId, type, scanId);
        const filename = `CyberWatch_${type}_Export_${Date.now()}.csv`;
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.status(200).send(csvContent);
        return;
      }

      const jsonData = await reportService.exportJson(userId, type, scanId);
      const filename = `CyberWatch_${type}_Export_${Date.now()}.json`;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.status(200).json(jsonData);
    } catch (error) {
      next(error);
    }
  }
}

export const reportController = new ReportController();
