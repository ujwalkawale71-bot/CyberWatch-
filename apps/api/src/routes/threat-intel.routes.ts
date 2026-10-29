import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { threatIntelController } from '../controllers/threat-intel.controller';
import { optionalAuth } from '../middleware/auth.middleware';

const router = Router();

// ── Rate Limiter for Threat Intelligence API ──────────────────────────────────
// Allows up to 60 requests per 15-minute window per IP
const threatIntelLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Threat intelligence query rate limit exceeded. Please try again later.',
  },
});

router.use(threatIntelLimiter);

// ── Threat Intelligence Endpoints ─────────────────────────────────────────────
router.post('/analyze', optionalAuth, (req, res, next) =>
  threatIntelController.analyzeIndicator(req, res, next)
);

router.get('/providers', (req, res, next) =>
  threatIntelController.getProviders(req, res, next)
);

router.post('/providers/:id/test', (req, res, next) =>
  threatIntelController.testProvider(req, res, next)
);

router.get('/feeds', (req, res, next) =>
  threatIntelController.getFeeds(req, res, next)
);

router.get('/indicators', (req, res, next) =>
  threatIntelController.listIndicators(req, res, next)
);

router.get('/advisories', (req, res, next) =>
  threatIntelController.getAdvisories(req, res, next)
);

router.post('/correlate', (req, res, next) =>
  threatIntelController.correlateScan(req, res, next)
);

router.post('/normalize', (req, res, next) =>
  threatIntelController.normalize(req, res, next)
);

router.get('/:analysisId', optionalAuth, (req, res, next) =>
  threatIntelController.getAnalysisById(req, res, next)
);

router.get('/:analysisId/report', optionalAuth, (req, res, next) =>
  threatIntelController.getAnalysisById(req, res, next)
);

export default router;


