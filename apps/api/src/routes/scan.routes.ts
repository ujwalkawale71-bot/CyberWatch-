import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { scanController } from '../controllers/scan.controller';
import { requireAuth } from '../middleware/auth.middleware';
import { handleFileUpload } from '../middleware/upload.middleware';
import { env } from '../config/env';

const router = Router();

// Standard Scan initiation rate limiter — 10 scans per minute per IP
const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 scans per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many scans initiated. Rate limit is 10 scans per minute. Please try again in a moment.',
  },
});

// File upload rate limiter — 5 uploads per minute per IP (configurable)
const fileUploadLimiter = rateLimit({
  windowMs: (env.FILE_SCAN_RATE_WINDOW_SECONDS || 60) * 1000,
  max: env.FILE_SCAN_RATE_LIMIT || 5,
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  message: {
    success: false,
    message: `Too many file uploads. Rate limit is ${env.FILE_SCAN_RATE_LIMIT || 5} uploads per minute. Please try again later.`,
  },
});

// POST /api/v1/scans — Initiate a new security scan (rate limited)
router.post('/', requireAuth, scanLimiter, scanController.initiateScan);

// POST /api/v1/scans/upload — Upload and scan a file statically (rate limited, streaming, isolated)
router.post('/upload', requireAuth, fileUploadLimiter, handleFileUpload, scanController.uploadAndScanFile);

// GET /api/v1/scans — List recent scans for the authenticated user
router.get('/', requireAuth, scanController.getUserScans);

// GET /api/v1/scans/stats — Get security metrics for dashboard
router.get('/stats', requireAuth, scanController.getUserStats);

// GET /api/v1/scans/:id/report.json — Export scan report as JSON
router.get('/:id/report.json', requireAuth, scanController.downloadReportJson);

// GET /api/v1/scans/:id/report.pdf — Export scan report as PDF
router.get('/:id/report.pdf', requireAuth, scanController.downloadReportPdf);

// GET /api/v1/scans/by-hash/:sha256 — Lookup existing scan by SHA256 hash
router.get('/by-hash/:sha256', requireAuth, scanController.getScanByHash);

// GET /api/v1/scans/:id — Get details of a single scan report
router.get('/:id', requireAuth, scanController.getScanById);

export default router;
