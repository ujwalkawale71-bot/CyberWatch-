import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import { sanitizeCsvField, redactSensitiveText } from '../services/report.service';

const { mockUserId, mockScanId1, mockScanId2, validUser, mockScanRecord1, mockScanRecord2 } = vi.hoisted(() => {
  const userId = '507f1f77bcf86cd799439011';
  const scanId1 = '507f1f77bcf86cd799439022';
  const scanId2 = '507f1f77bcf86cd799439033';

  const user = {
    _id: { toString: () => userId },
    id: userId,
    name: 'Security Analyst',
    email: 'analyst@cyberwatch.internal',
    role: 'ANALYST',
    isActive: true,
  };

  const scan1 = {
    _id: { toString: () => scanId1 },
    userId: { toString: () => userId },
    target: 'https://security-test.example.com',
    targetType: 'URL',
    result: 'Suspicious',
    riskScore: 35,
    status: 'completed',
    checks: {
      urlAnalysis: { status: 'warning', details: 'Suspicious path patterns' },
    },
    findings: [
      {
        id: 'FINDING-001',
        findingId: 'FINDING-001',
        title: 'Missing Security Headers',
        severity: 'MEDIUM',
        category: 'HTTP Security',
        description: 'HSTS header missing',
        evidence: 'Strict-Transport-Security not returned',
        impact: 'Allows potential MITM downgrade attacks',
        recommendation: 'Configure HSTS with max-age=31536000',
      },
      {
        id: 'FINDING-002',
        findingId: 'FINDING-002',
        title: 'Open Directory Listing',
        severity: 'HIGH',
        category: 'Information Disclosure',
        description: 'Directory indexing enabled on /uploads/',
        evidence: 'HTTP 200 Index of /uploads/',
        impact: 'Exposes private files to unauthorized access',
        recommendation: 'Disable directory indexes in web server config',
      },
    ],
    recommendations: ['Enable HSTS', 'Disable directory listing'],
    scannedAt: new Date('2026-10-01T10:00:00Z'),
    createdAt: new Date('2026-10-01T10:00:00Z'),
  };

  const scan2 = {
    _id: { toString: () => scanId2 },
    userId: { toString: () => userId },
    target: 'https://security-test.example.com',
    targetType: 'URL',
    result: 'Low Risk',
    riskScore: 15,
    status: 'completed',
    checks: {
      urlAnalysis: { status: 'passed', details: 'All checks passed' },
    },
    findings: [
      {
        id: 'FINDING-001',
        findingId: 'FINDING-001',
        title: 'Missing Security Headers',
        severity: 'LOW',
        category: 'HTTP Security',
        description: 'X-Content-Type-Options missing',
        evidence: 'Header absent in response',
        recommendation: 'Add X-Content-Type-Options: nosniff',
      },
    ],
    recommendations: ['Add security headers'],
    scannedAt: new Date('2026-10-05T12:00:00Z'),
    createdAt: new Date('2026-10-05T12:00:00Z'),
  };

  return {
    mockUserId: userId,
    mockScanId1: scanId1,
    mockScanId2: scanId2,
    validUser: user,
    mockScanRecord1: scan1,
    mockScanRecord2: scan2,
  };
});

vi.mock('../models/User', async () => {
  const { USER_ROLES } = await import('../models/User');
  return {
    USER_ROLES,
    User: {
      findById: vi.fn().mockImplementation(() => ({
        select: vi.fn().mockResolvedValue(validUser),
      })),
      findOne: vi.fn().mockResolvedValue(validUser),
    },
    toSafeUser: (user: any) => ({
      id: user._id?.toString() || mockUserId,
      name: user.name,
      email: user.email,
      role: user.role || 'ANALYST',
      isActive: user.isActive ?? true,
      createdAt: user.createdAt || new Date(),
    }),
  };
});

vi.mock('../models/Scan', async () => {
  const { SCAN_TARGET_TYPES, SCAN_RESULT_CLASSIFICATIONS, FINDING_SEVERITIES } = await import('../models/Scan');
  
  const mockScansList = [mockScanRecord1, mockScanRecord2];

  const createQueryMock = (data: any) => {
    const query: any = {
      sort: vi.fn().mockReturnThis(),
      skip: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      then: (resolve: any) => Promise.resolve(data).then(resolve),
    };
    return query;
  };

  const MockScan = {
    find: vi.fn().mockImplementation(() => createQueryMock(mockScansList)),
    findOne: vi.fn().mockImplementation((query: any) => {
      if (query._id?.toString() === mockScanId1 || query._id === mockScanId1) {
        return Promise.resolve(mockScanRecord1);
      }
      if (query._id?.toString() === mockScanId2 || query._id === mockScanId2) {
        return Promise.resolve(mockScanRecord2);
      }
      return Promise.resolve(mockScanRecord1);
    }),
    countDocuments: vi.fn().mockResolvedValue(2),
  };

  return {
    SCAN_TARGET_TYPES,
    SCAN_RESULT_CLASSIFICATIONS,
    FINDING_SEVERITIES,
    Scan: MockScan,
    toSafeScanRecord: (scan: any) => ({
      id: scan._id?.toString ? scan._id.toString() : scan.id,
      userId: scan.userId ? (scan.userId.toString ? scan.userId.toString() : scan.userId) : undefined,
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

import app from '../app';
import { signToken } from '../utils/jwt';

describe('Security Reporting Center — Backend Report APIs & Sanitization', () => {
  let authToken: string;

  beforeEach(() => {
    authToken = signToken({
      userId: mockUserId,
      role: 'ANALYST',
    });
  });

  describe('CSV Injection & Sensitive Data Redaction Utilities', () => {
    it('sanitizes cells starting with formula injection characters (=, +, -, @)', () => {
      expect(sanitizeCsvField('=SUM(A1:A10)')).toBe('"\'=SUM(A1:A10)"');
      expect(sanitizeCsvField('+cmd|/c calc')).toBe('"\'+cmd|/c calc"');
      expect(sanitizeCsvField('-5+2')).toBe('"\' -5+2"'.replace(' ', ''));
      expect(sanitizeCsvField('@SUM(1+1)')).toBe('"\'@SUM(1+1)"');
      expect(sanitizeCsvField('Normal Finding Text')).toBe('"Normal Finding Text"');
    });

    it('redacts sensitive API tokens, bearer keys, and secrets', () => {
      const sensitive1 = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken';
      const redacted1 = redactSensitiveText(sensitive1);
      expect(redacted1).toContain('[REDACTED_TOKEN]');
      expect(redacted1).not.toContain('doNotLeakThisToken');

      const sensitive2 = 'apiKey: secret_live_key_998877665544332211';
      const redacted2 = redactSensitiveText(sensitive2);
      expect(redacted2).toContain('[REDACTED_API_KEY]');
    });
  });

  describe('GET /api/v1/reports/overview', () => {
    it('returns executive overview statistics and authoritative scanner telemetry', async () => {
      const res = await request(app)
        .get('/api/v1/reports/overview')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeDefined();
      expect(res.body.data.totalScans).toBe(2);
      expect(res.body.data.completedScans).toBe(2);
      expect(res.body.data.findingsSeverity).toBeDefined();
      expect(res.body.data.findingsSeverity.high).toBe(1);
      expect(res.body.data.findingsSeverity.medium).toBe(1);

      // Verify Scanner Coverage & Risk Telemetry
      const telemetry = res.body.data.scannerTelemetry;
      expect(telemetry).toBeDefined();
      expect(telemetry.URL).toBeDefined();
      expect(telemetry.URL.totalScans).toBe(2);
      expect(telemetry.URL.completedScans).toBe(2);
      // (35 + 15) / 2 = 25
      expect(telemetry.URL.averageRiskScore).toBe(25);
      expect(telemetry.URL.latestVerdict).toBe('Suspicious');
      expect(telemetry.URL.latestRiskScore).toBe(35);
      expect(telemetry.URL.highFindings).toBe(1);
      expect(telemetry.URL.riskDistribution).toEqual({
        low: 1, // scan2: 15
        medium: 1, // scan1: 35
        high: 0,
        critical: 0,
      });

      // Verify zero-scan scanner returns null averageRiskScore (NEVER 0!)
      expect(telemetry.API.totalScans).toBe(0);
      expect(telemetry.API.completedScans).toBe(0);
      expect(telemetry.API.averageRiskScore).toBeNull();
      expect(telemetry.API.latestVerdict).toBeNull();
      expect(telemetry.API.latestRiskScore).toBeNull();
      expect(telemetry.API.riskDistribution).toEqual({
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
      });
    });

    it('rejects unauthenticated requests with 401', async () => {
      const res = await request(app).get('/api/v1/reports/overview');
      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/v1/reports/findings', () => {
    it('retrieves aggregated security findings with severity and pagination', async () => {
      const res = await request(app)
        .get('/api/v1/reports/findings?severity=HIGH')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.findings).toBeInstanceOf(Array);
      expect(res.body.data.findings.length).toBe(1);
      expect(res.body.data.findings[0].title).toBe('Open Directory Listing');
      expect(res.body.data.findings[0].severity).toBe('HIGH');
    });
  });

  describe('GET /api/v1/reports/findings/:findingId', () => {
    it('retrieves specific finding detail with evidence and recommendations', async () => {
      const res = await request(app)
        .get('/api/v1/reports/findings/FINDING-001')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.findingId).toBe('FINDING-001');
      expect(res.body.data.title).toBe('Missing Security Headers');
      expect(res.body.data.recommendation).toBeDefined();
    });
  });

  describe('GET /api/v1/reports/scans/:id', () => {
    it('retrieves a normalized scan report DTO preserving authentic risk score', async () => {
      const res = await request(app)
        .get(`/api/v1/reports/scans/${mockScanId1}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.scanId).toBe(mockScanId1);
      expect(res.body.data.riskScore).toBe(35);
      expect(res.body.data.verdict).toBe('Suspicious');
      expect(res.body.data.findings.length).toBe(2);
      expect(res.body.data.metadata.engineVersion).toBeDefined();
    });
  });

  describe('GET /api/v1/reports/compare', () => {
    it('compares two real scans and computes metric delta', async () => {
      const res = await request(app)
        .get(`/api/v1/reports/compare?scan1=${mockScanId1}&scan2=${mockScanId2}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.comparison.scoreDifference).toBe(-20); // 15 - 35
      expect(res.body.data.comparison.isImprovement).toBe(true);
    });
  });

  describe('POST /api/v1/reports/export', () => {
    it('exports report data as sanitized JSON', async () => {
      const res = await request(app)
        .post('/api/v1/reports/export')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          format: 'json',
          type: 'findings',
        });

      expect(res.status).toBe(200);
      expect(res.body.platform).toContain('CyberWatch');
      expect(res.body.findings).toBeInstanceOf(Array);
    });

    it('exports report data as sanitized CSV with formula escaping', async () => {
      const res = await request(app)
        .post('/api/v1/reports/export')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          format: 'csv',
          type: 'findings',
        });

      expect(res.status).toBe(200);
      expect(res.header['content-type']).toContain('text/csv');
      expect(res.text).toContain('Finding ID');
      expect(res.text).toContain('Open Directory Listing');
    });
  });
});
