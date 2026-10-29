import { Router } from 'express';
import { authController } from '../controllers/auth.controller';
import { requireAuth } from '../middleware/auth.middleware';
import rateLimit from 'express-rate-limit';
import { env } from '../config/env';

const router = Router();

// ─── Auth-Specific Rate Limiting ──────────────────────────────────────────────
// Tighter limits for authentication endpoints to prevent brute force.
// More lenient in development to allow normal testing.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: env.isDev ? 50 : 10, // 50 in dev, 10 in production
  message: {
    success: false,
    message: 'Too many authentication attempts. Please try again in 15 minutes.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Auth Routes ──────────────────────────────────────────────────────────────

// POST /api/v1/auth/register — Create new account
router.post('/register', authLimiter, authController.register);

// POST /api/v1/auth/login — Authenticate and receive JWT
router.post('/login', authLimiter, authController.login);

// GET /api/v1/auth/me — Get current authenticated user (protected)
router.get('/me', requireAuth, authController.me);

// POST /api/v1/auth/logout — Signal logout (client removes token)
router.post('/logout', requireAuth, authController.logout);

export default router;
