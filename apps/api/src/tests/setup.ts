import { vi } from 'vitest';

// ─── Test Environment Setup ───────────────────────────────────────────────────
// Set required environment variables for tests before any module loads.
// This prevents the env module from throwing during tests.

process.env.NODE_ENV = 'test';
process.env.PORT = '5001';
process.env.JWT_SECRET = 'test-jwt-secret-minimum-32-chars-long-for-security';
process.env.JWT_EXPIRES_IN = '1h';
process.env.FRONTEND_URL = 'http://localhost:5173';

// ─── Mock MongoDB for unit tests ──────────────────────────────────────────────
// We mock mongoose to avoid needing a real database for unit tests.
// Integration tests can use a real test database (e.g. mongodb-memory-server).
vi.mock('mongoose', async () => {
  const actual = await vi.importActual('mongoose');
  return {
    ...actual,
    connect: vi.fn().mockResolvedValue({ connection: { host: 'test-host' } }),
    disconnect: vi.fn().mockResolvedValue(undefined),
  };
});
