import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { env } from './config/env';
import authRoutes from './routes/auth.routes';
import scanRoutes from './routes/scan.routes';
import threatIntelRoutes from './routes/threat-intel.routes';
import reportRoutes from './routes/report.routes';
import supportRoutes from './routes/support.routes';
import liveChatRoutes from './routes/live-chat.routes';
import notificationRoutes from './routes/notification.routes';
import { errorHandler, notFoundHandler } from './middleware/error.middleware';

const app = express();


// ─── Security Middleware ──────────────────────────────────────────────────────
app.use(helmet());

// CORS — allow the configured frontend origin as well as localhost / 127.0.0.1 dev origins
const allowedOrigins = Array.from(
  new Set([
    env.FRONTEND_URL,
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:5174',
    'http://127.0.0.1:5174',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
  ])
).filter(Boolean);

const isOriginAllowed = (origin?: string): boolean => {
  if (!origin) return true;
  if (allowedOrigins.includes(origin)) return true;
  if (env.isDev && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
    return true;
  }
  return false;
};

app.use(cors({
  origin: (origin, callback) => {
    if (isOriginAllowed(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ─── Global Rate Limiting ─────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // 200 requests per window globally
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests. Please try again later.',
  },
});
app.use(globalLimiter);

// ─── Body Parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ─── Health Check ─────────────────────────────────────────────────────────────
// GET /api/v1/health — Preserved from Phase 1
app.get('/api/v1/health', (_req, res) => {
  res.status(200).json({
    success: true,
    service: 'cyberwatch-api',
    status: 'healthy',
    message: 'CyberWatch API is healthy',
    environment: env.NODE_ENV,
  });
});

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/scans', scanRoutes);
app.use('/api/v1/threat-intelligence', threatIntelRoutes);
app.use('/api/v1/reports', reportRoutes);
app.use('/api/v1/support', supportRoutes);
app.use('/api/v1/live-chat', liveChatRoutes);
app.use('/api/v1/notifications', notificationRoutes);


// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use(notFoundHandler);

// ─── Global Error Handler ─────────────────────────────────────────────────────
// Must be LAST middleware registered
app.use(errorHandler);

export default app;
