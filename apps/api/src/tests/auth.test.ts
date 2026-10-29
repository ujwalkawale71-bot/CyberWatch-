import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import app from '../app';

// ─── Mock the User Model ──────────────────────────────────────────────────────
vi.mock('../models/User', async () => {
  const { USER_ROLES } = await import('../models/User');
  return {
    USER_ROLES,
    User: {
      findOne: vi.fn(),
      findById: vi.fn(),
      create: vi.fn(),
    },
    toSafeUser: (user: any) => ({
      id: user._id?.toString() || 'mock-id',
      name: user.name,
      email: user.email,
      role: user.role || 'USER',
      isActive: user.isActive ?? true,
      createdAt: user.createdAt || new Date(),
    }),
  };
});

// ─── Mock bcryptjs ────────────────────────────────────────────────────────────
vi.mock('bcryptjs', () => ({
  default: {
    hash: vi.fn().mockResolvedValue('$2a$12$mockhash'),
    compare: vi.fn(),
  },
  hash: vi.fn().mockResolvedValue('$2a$12$mockhash'),
  compare: vi.fn(),
}));

import { User, toSafeUser } from '../models/User';
import bcrypt from 'bcryptjs';

const mockUser = {
  _id: { toString: () => 'user-id-123' },
  name: 'Test User',
  email: 'test@example.com',
  passwordHash: '$2a$12$mockhash',
  role: 'USER' as const,
  isActive: true,
  createdAt: new Date(),
};

describe('Auth API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ────────────────────────────────────────────────────────────────────────────
  // REGISTER
  // ────────────────────────────────────────────────────────────────────────────

  describe('POST /api/v1/auth/register', () => {
    it('1. registers a valid user and returns 201 with token', async () => {
      vi.mocked(User.findOne).mockResolvedValue(null);
      vi.mocked(User.create).mockResolvedValue(mockUser as any);
      vi.mocked(bcrypt.hash).mockResolvedValue('$2a$12$mockhash' as never);

      const res = await request(app).post('/api/v1/auth/register').send({
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123',
      });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('token');
      expect(res.body.data.user).not.toHaveProperty('passwordHash');
      expect(res.body.data.user.email).toBe('test@example.com');
    });

    it('2. returns 409 when email already exists', async () => {
      vi.mocked(User.findOne).mockResolvedValue(mockUser as any);

      const res = await request(app).post('/api/v1/auth/register').send({
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123',
      });

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
    });

    it('3. returns 400 for invalid email', async () => {
      const res = await request(app).post('/api/v1/auth/register').send({
        name: 'Test User',
        email: 'not-an-email',
        password: 'password123',
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('4. returns 400 for password shorter than 8 characters', async () => {
      const res = await request(app).post('/api/v1/auth/register').send({
        name: 'Test User',
        email: 'test@example.com',
        password: '1234567',
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('4b. returns 400 when name is missing', async () => {
      const res = await request(app).post('/api/v1/auth/register').send({
        email: 'test@example.com',
        password: 'password123',
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // LOGIN
  // ────────────────────────────────────────────────────────────────────────────

  describe('POST /api/v1/auth/login', () => {
    it('5. logs in with valid credentials and returns token', async () => {
      vi.mocked(User.findOne).mockResolvedValue(mockUser as any);
      vi.mocked(bcrypt.compare).mockResolvedValue(true as never);

      const res = await request(app).post('/api/v1/auth/login').send({
        email: 'test@example.com',
        password: 'password123',
      });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('token');
      expect(res.body.data.user).not.toHaveProperty('passwordHash');
    });

    it('6. returns 401 for invalid credentials (wrong password)', async () => {
      vi.mocked(User.findOne).mockResolvedValue(mockUser as any);
      vi.mocked(bcrypt.compare).mockResolvedValue(false as never);

      const res = await request(app).post('/api/v1/auth/login').send({
        email: 'test@example.com',
        password: 'wrongpassword',
      });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      // Generic message — does not reveal which field is wrong
      expect(res.body.message).toMatch(/invalid email or password/i);
    });

    it('6b. returns 401 for non-existent email (generic message)', async () => {
      vi.mocked(User.findOne).mockResolvedValue(null);

      const res = await request(app).post('/api/v1/auth/login').send({
        email: 'nobody@example.com',
        password: 'password123',
      });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      // Same generic message regardless of whether email exists
      expect(res.body.message).toMatch(/invalid email or password/i);
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // GET /auth/me
  // ────────────────────────────────────────────────────────────────────────────

  describe('GET /api/v1/auth/me', () => {
    it('7. returns 401 without token', async () => {
      const res = await request(app).get('/api/v1/auth/me');
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('8. returns 401 with invalid token', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer invalid-token-here');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('9. returns current user with valid token', async () => {
      // Get a real token by logging in
      vi.mocked(User.findOne).mockResolvedValue(mockUser as any);
      vi.mocked(bcrypt.compare).mockResolvedValue(true as never);

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'test@example.com',
        password: 'password123',
      });

      const token = loginRes.body.data?.token;
      expect(token).toBeTruthy();

      // Use token to get /me
      vi.mocked(User.findById).mockReturnValue({
        select: vi.fn().mockResolvedValue(mockUser),
      } as any);

      const meRes = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(meRes.status).toBe(200);
      expect(meRes.body.success).toBe(true);
      expect(meRes.body.data.user).not.toHaveProperty('passwordHash');
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // PROTECTED ROUTE
  // ────────────────────────────────────────────────────────────────────────────

  describe('Protected Route (POST /api/v1/auth/logout)', () => {
    it('10. returns 401 without authentication', async () => {
      const res = await request(app).post('/api/v1/auth/logout');
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('11. returns 200 with valid authentication', async () => {
      vi.mocked(User.findOne).mockResolvedValue(mockUser as any);
      vi.mocked(bcrypt.compare).mockResolvedValue(true as never);

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'test@example.com',
        password: 'password123',
      });

      const token = loginRes.body.data?.token;

      vi.mocked(User.findById).mockReturnValue({
        select: vi.fn().mockResolvedValue(mockUser),
      } as any);

      const res = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // HEALTH CHECK
  // ────────────────────────────────────────────────────────────────────────────

  describe('GET /api/v1/health', () => {
    it('returns healthy status', async () => {
      const res = await request(app).get('/api/v1/health');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });
});
