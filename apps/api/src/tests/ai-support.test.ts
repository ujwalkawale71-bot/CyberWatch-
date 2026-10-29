import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import app from '../app';
import { env } from '../config/env';
import { Scan } from '../models/Scan';
import { User } from '../models/User';

// ─── Test Fixtures ─────────────────────────────────────────────────────────────

const userAId = new mongoose.Types.ObjectId().toString();
const userBId = new mongoose.Types.ObjectId().toString();

const tokenUserA = jwt.sign(
  { userId: userAId, email: 'usera@example.com', role: 'USER' },
  env.JWT_SECRET,
  { expiresIn: '1h' }
);

const tokenUserB = jwt.sign(
  { userId: userBId, email: 'userb@example.com', role: 'USER' },
  env.JWT_SECRET,
  { expiresIn: '1h' }
);

describe('CyberWatch AI Live Chat Assistant API & Grounded Reasoning', () => {
  beforeEach(async () => {
    vi.restoreAllMocks();

    vi.spyOn(User, 'findById').mockImplementation((id: any) => {
      const idStr = id?.toString();
      return {
        select: vi.fn().mockResolvedValue({
          _id: new mongoose.Types.ObjectId(idStr),
          role: 'USER',
          isActive: true,
        }),
      } as any;
    });
  });

  describe('GET /api/v1/live-chat/quick-actions and /support/ai/quick-actions', () => {
    it('returns standardized quick actions with categories and prompts on /api/v1/live-chat/quick-actions', async () => {
      const res = await request(app).get('/api/v1/live-chat/quick-actions');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(4);

      const actionIds = res.body.data.map((a: any) => a.id);
      expect(actionIds).toContain('explain-scan');
      expect(actionIds).toContain('why-risk-high');
      expect(actionIds).toContain('talk-human');
    });

    it('preserves backwards compatibility on /api/v1/support/ai/quick-actions', async () => {
      const res = await request(app).get('/api/v1/support/ai/quick-actions');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
    });
  });

  describe('POST /api/v1/live-chat/ai (Dedicated Isolated Live Chat AI Endpoint)', () => {
    it('rejects empty message with 400', async () => {
      const res = await request(app)
        .post('/api/v1/live-chat/ai')
        .send({ message: '   ' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('rejects message exceeding max length with 400', async () => {
      const longMessage = 'A'.repeat(4001);
      const res = await request(app)
        .post('/api/v1/live-chat/ai')
        .send({ message: longMessage });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('4000 characters');
    });

    it('answers general cybersecurity and scanner architecture questions with evidence-based facts', async () => {
      const res = await request(app)
        .post('/api/v1/live-chat/ai')
        .send({
          message: 'How does CyberWatch scanning work across websites and APIs?',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.reply).toContain('CyberWatch Scanning Suite Overview');
      expect(res.body.data.sources.length).toBeGreaterThan(0);
      expect(res.body.data.escalateToHuman).toBe(false);
      expect(res.body.data.conversationId).toBeDefined();
    });

    it('explains risk scoring methodology with normalized 0-100 scale without fabricating', async () => {
      const res = await request(app)
        .post('/api/v1/live-chat/ai')
        .send({
          message: 'How is the risk score calculated?',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.reply).toContain('0 to 100');
      expect(res.body.data.reply).toContain('SAFE');
      expect(res.body.data.reply).toContain('CRITICAL');
    });

    it('triggers escalateToHuman when user asks to speak with a human agent or support operator', async () => {
      const res = await request(app)
        .post('/api/v1/live-chat/ai')
        .send({
          message: 'I want to speak with a human support operator regarding an emergency.',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.escalateToHuman).toBe(true);
      expect(res.body.data.suggestedActions).toContain('Start Live Chat');
    });

    it('evaluates direct client scanContext payload accurately without fabricating scores', async () => {
      const clientScanContext = {
        target: 'https://payment-portal.dev/api/v1',
        targetType: 'API',
        riskScore: 75,
        riskLevel: 'High Risk',
        verdict: 'High Risk',
        findings: [
          {
            title: 'Permissive CORS Wildcard with Credentials',
            severity: 'HIGH',
            description: 'Access-Control-Allow-Origin: * combined with credentials.',
            recommendation: 'Specify exact allowed origin whitelist.',
          },
        ],
      };

      const res = await request(app)
        .post('/api/v1/live-chat/ai')
        .send({
          message: 'Why is my API scan high risk?',
          scanContext: clientScanContext,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.scanContext).toBeDefined();
      expect(res.body.data.scanContext.target).toBe('https://payment-portal.dev/api/v1');
      expect(res.body.data.scanContext.riskScore).toBe(75);
      expect(res.body.data.reply).toContain('Permissive CORS Wildcard');
      expect(res.body.data.reply).toContain('75/100 (High Risk)');
    });
  });

  describe('Context-Aware Scan Analysis & IDOR Security on /api/v1/support/ai/chat', () => {
    it('requires authentication to analyze user scan by scanId', async () => {
      const fakeScanId = new mongoose.Types.ObjectId().toString();

      const res = await request(app)
        .post('/api/v1/support/ai/chat')
        .send({
          message: 'Why did this scan get this score?',
          scanId: fakeScanId,
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('prevents User B from accessing User A scan context (IDOR protection)', async () => {
      const mockScan = {
        _id: new mongoose.Types.ObjectId(new mongoose.Types.ObjectId().toString()),
        userId: new mongoose.Types.ObjectId(userAId),
        target: 'https://user-a-target.com',
        targetType: 'Website',
        riskScore: 65,
        result: 'Suspicious',
        findings: [
          {
            title: 'Missing HSTS Header',
            severity: 'HIGH',
            description: 'Strict-Transport-Security header is absent.',
            recommendation: 'Enable HSTS with max-age=31536000.',
          },
        ],
      };

      vi.spyOn(Scan, 'findById').mockResolvedValue(mockScan as any);

      const res = await request(app)
        .post('/api/v1/support/ai/chat')
        .set('Authorization', `Bearer ${tokenUserB}`)
        .send({
          message: 'Why did my scan get 65 score?',
          scanId: mockScan._id.toString(),
        });

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('permission');
    });

    it('successfully explains scan findings and risk contributors when authorized', async () => {
      const mockScan = {
        _id: new mongoose.Types.ObjectId(new mongoose.Types.ObjectId().toString()),
        userId: new mongoose.Types.ObjectId(userAId),
        target: 'https://user-a-target.com',
        targetType: 'Website',
        riskScore: 65,
        result: 'Suspicious',
        findings: [
          {
            title: 'Missing HSTS Header',
            severity: 'HIGH',
            description: 'Strict-Transport-Security header is absent.',
            recommendation: 'Enable HSTS with max-age=31536000.',
          },
        ],
        checks: {},
      };

      vi.spyOn(Scan, 'findById').mockResolvedValue(mockScan as any);

      const res = await request(app)
        .post('/api/v1/support/ai/chat')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          message: 'Why is my risk score high?',
          scanId: mockScan._id.toString(),
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.scanContext).toBeDefined();
      expect(res.body.data.scanContext.scanId).toBe(mockScan._id.toString());
      expect(res.body.data.scanContext.riskScore).toBe(65);
      expect(res.body.data.reply).toContain('Missing HSTS Header');
      expect(res.body.data.reply).toContain('user-a-target.com');
    });
  });

  describe('Failure Isolation & Graceful Degradation', () => {
    it('gracefully handles unavailable microservice and falls back without crashing the app', async () => {
      // Mock fetch throwing connection refused
      const globalFetch = global.fetch;
      global.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

      const res = await request(app)
        .post('/api/v1/live-chat/ai')
        .send({
          message: 'Can you help me troubleshoot a failed scan?',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.reply).toContain('Scanner Troubleshooting Guide');
      expect(res.body.data.provider).toContain('Grounded Intelligence Engine');

      global.fetch = globalFetch;
    });
  });

  describe('GET /api/v1/live-chat/user-scans', () => {
    it('returns empty list or 401 for unauthenticated requests', async () => {
      const res = await request(app).get('/api/v1/live-chat/user-scans');
      expect(res.status).toBe(401);
    });

    it('returns recent user scans when authenticated', async () => {
      const mockScans = [
        {
          _id: new mongoose.Types.ObjectId(),
          target: 'https://myapp.com',
          targetType: 'URL',
          result: 'Safe',
          riskScore: 10,
          createdAt: new Date(),
          findings: [],
        },
      ];

      vi.spyOn(Scan, 'find').mockReturnValue({
        sort: vi.fn().mockReturnValue({
          limit: vi.fn().mockReturnValue({
            select: vi.fn().mockResolvedValue(mockScans),
          }),
        }),
      } as any);

      const res = await request(app)
        .get('/api/v1/live-chat/user-scans')
        .set('Authorization', `Bearer ${tokenUserA}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.length).toBe(1);
      expect(res.body.data[0].target).toBe('https://myapp.com');
    });
  });
});
