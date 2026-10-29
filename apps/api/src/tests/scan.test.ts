import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app';
import { signToken } from '../utils/jwt';


// Mock the User Model for requireAuth
vi.mock('../models/User', async () => {
  const { USER_ROLES } = await import('../models/User');
  return {
    USER_ROLES,
    User: {
      findById: vi.fn(),
      findOne: vi.fn(),
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

// Mock the Scan Model
vi.mock('../models/Scan', async () => {
  const mockScanInstance = {
    _id: { toString: () => 'scan-id-123' },
    userId: { toString: () => 'user-id-123' },
    target: 'https://example.com',
    targetType: 'URL',
    result: 'Safe',
    riskScore: 0,
    status: 'completed',
    checks: {
      urlAnalysis: { status: 'passed', details: 'OK' },
      sslAnalysis: { status: 'passed', protocol: 'TLS 1.3', valid: true, details: 'OK' },
      domainAnalysis: { status: 'passed', hostname: 'example.com', details: 'OK' },
      phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
      redirectAnalysis: { status: 'passed', redirectCount: 0, details: 'OK' },
    },
    findings: [],
    recommendations: ['Safe browsing.'],
    scannedAt: new Date(),
    createdAt: new Date(),
    save: vi.fn().mockResolvedValue({
      _id: { toString: () => 'scan-id-123' },
      userId: { toString: () => 'user-id-123' },
      target: 'https://example.com',
      targetType: 'URL',
      result: 'Safe',
      riskScore: 0,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', protocol: 'TLS 1.3', valid: true, details: 'OK' },
        domainAnalysis: { status: 'passed', hostname: 'example.com', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', redirectCount: 0, details: 'OK' },
      },
      findings: [],
      recommendations: ['Safe browsing.'],
      scannedAt: new Date(),
      createdAt: new Date(),
    }),
  };

  function MockScan(this: any, data: any) {
    Object.assign(this, mockScanInstance, data);
    this.save = vi.fn().mockResolvedValue(this);
  }
  (MockScan as any).find = vi.fn().mockReturnValue({
    sort: vi.fn().mockReturnValue({
      skip: vi.fn().mockReturnValue({
        limit: vi.fn().mockResolvedValue([mockScanInstance]),
      }),
    }),
  });
  (MockScan as any).countDocuments = vi.fn().mockResolvedValue(1);
  (MockScan as any).findOne = vi.fn().mockImplementation((query?: any) => {
    const isCacheLookup = Boolean(query?.createdAt);
    const resolvedValue = isCacheLookup ? null : mockScanInstance;
    const queryObj: any = {
      sort: vi.fn().mockImplementation(() => Promise.resolve(resolvedValue)),
      then: (resolve: any, reject: any) => Promise.resolve(resolvedValue).then(resolve, reject),
      catch: (reject: any) => Promise.resolve(resolvedValue).catch(reject),
    };
    return queryObj;
  });

  return {
    Scan: MockScan,

    SCAN_RESULT_CLASSIFICATIONS: ['Safe', 'Low Risk', 'Suspicious', 'High Risk', 'Critical'],
    SCAN_TARGET_TYPES: ['URL', 'Website', 'API', 'Phishing', 'File', 'Extension', 'Domain'],
    toSafeScanRecord: (scan: any) => ({
      id: scan._id?.toString() || 'scan-id-123',
      userId: scan.userId?.toString() || 'user-id-123',
      target: scan.target,
      targetType: scan.targetType,
      result: scan.result,
      riskScore: scan.riskScore,
      status: scan.status,
      checks: scan.checks,
      findings: scan.findings,
      recommendations: scan.recommendations,
      scannedAt: scan.scannedAt,
      createdAt: scan.createdAt,
    }),
  };
});

import { User } from '../models/User';

const mockUser = {
  _id: { toString: () => 'user-id-123' },
  name: 'Security User',
  email: 'security@cyberwatch.io',
  role: 'USER' as const,
  isActive: true,
};

describe('Scan API', () => {
  let authToken: string;

  beforeEach(() => {
    vi.clearAllMocks();
    authToken = signToken({ userId: 'user-id-123', role: 'USER' });
    vi.mocked(User.findById).mockReturnValue({
      select: vi.fn().mockResolvedValue(mockUser),
    } as any);
  });

  describe('POST /api/v1/scans', () => {
    it('1. rejects unauthenticated requests with 401', async () => {
      const res = await request(app)
        .post('/api/v1/scans')
        .send({ target: 'https://example.com' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('2. returns 400 for empty target', async () => {
      const res = await request(app)
        .post('/api/v1/scans')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ target: '' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('3. scans a valid URL and returns 201 with analysis data', async () => {
      const res = await request(app)
        .post('/api/v1/scans')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ target: 'https://example.com', targetType: 'URL' });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.target).toBe('https://example.com');
      expect(res.body.data.result).toBe('Safe');
    });

    it('3b. scans an API endpoint with targetType API and returns 201', async () => {
      const res = await request(app)
        .post('/api/v1/scans')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ target: 'https://api.example.com/v1/users', targetType: 'API' });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.targetType).toBe('API');
    });

    it('3c. scans a File download with targetType File and returns 201', async () => {
      const res = await request(app)
        .post('/api/v1/scans')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ target: 'https://example.com/assets/report.pdf', targetType: 'File' });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.targetType).toBe('File');
    });

    it('3d. scans a Browser Extension with targetType Extension and returns 201', async () => {
      const res = await request(app)
        .post('/api/v1/scans')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ target: 'https://chromewebstore.google.com/detail/sample/abcdefghijklmnopabcdefghijklmnop', targetType: 'Extension' });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.targetType).toBe('Extension');
    });
  });

  describe('GET /api/v1/scans', () => {
    it('4. returns list of user scans for authenticated user', async () => {
      const res = await request(app)
        .get('/api/v1/scans')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data.scans)).toBe(true);
    });
  });

  describe('GET /api/v1/scans/stats', () => {
    it('5. returns real security stats for authenticated user', async () => {
      const res = await request(app)
        .get('/api/v1/scans/stats')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.totalScans).toBeDefined();
      expect(res.body.data.threatsDetected).toBeDefined();
      expect(res.body.data.activeMonitoring).toBe('Active');
    });
  });

  describe('URL Scanner Target Parsing & Analysis Logic', () => {
    it('6. validates and scans HTTPS targets accurately', async () => {
      const res = await request(app)
        .post('/api/v1/scans')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ target: 'https://secure-portal.example.com/app/login?ref=dashboard#active' });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.target).toBe('https://secure-portal.example.com/app/login?ref=dashboard#active');
      expect(res.body.data.checks).toBeDefined();
      expect(res.body.data.checks.sslAnalysis).toBeDefined();
      expect(res.body.data.checks.urlAnalysis).toBeDefined();
    });
  });
});
