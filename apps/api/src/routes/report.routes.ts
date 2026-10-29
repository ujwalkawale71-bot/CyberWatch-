import { Router } from 'express';
import { reportController } from '../controllers/report.controller';
import { requireAuth } from '../middleware/auth.middleware';

const router = Router();

// GET /api/v1/reports/overview — Executive overview statistics
router.get('/overview', requireAuth, reportController.getOverview);

// GET /api/v1/reports/findings — Centralized security findings repository
router.get('/findings', requireAuth, reportController.getFindings);

// GET /api/v1/reports/findings/:findingId — Specific finding detail with evidence & TI
router.get('/findings/:findingId', requireAuth, reportController.getFindingById);

// GET /api/v1/reports/history — Scan history investigation workspace
router.get('/history', requireAuth, reportController.getHistory);

// GET /api/v1/reports/compare — Comparative scan analysis
router.get('/compare', requireAuth, reportController.compareScans);

// GET /api/v1/reports/export/:type/:format — Direct file download (pdf, json, csv)
router.get('/export/:type/:format', requireAuth, reportController.directDownload);

// POST /api/v1/reports/export — Structured export endpoint
router.post('/export', requireAuth, reportController.exportReport);

// GET /api/v1/reports/scans/:id — Normalized Scan Report DTO
router.get('/scans/:id', requireAuth, reportController.getScanReport);

// GET /api/v1/reports/scan-report/:id — Scan Report DTO alias
router.get('/scan-report/:id', requireAuth, reportController.getScanReport);

export default router;
