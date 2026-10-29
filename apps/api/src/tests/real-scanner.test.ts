import { describe, it, expect, vi } from 'vitest';
import { scanService } from '../services/scan.service';

// Mock Mongoose model save to avoid needing a live Mongo daemon in unit tests
vi.mock('../models/Scan', async () => {
  const original = await vi.importActual('../models/Scan');
  function MockScan(this: any, data: any) {
    Object.assign(this, data);
    this._id = { toString: () => 'mock-scan-id-456' };
    this.createdAt = new Date();
    this.save = vi.fn().mockResolvedValue(this);
  }
  return {
    ...(original as any),
    Scan: MockScan,
  };
});

describe('Real Six-Scanner Implementation Verification Suite', () => {
  // ── 1. URL Security Scanner ──────────────────────────────────────────────
  describe('1. URL Security Scanner (/services/url-scanner)', () => {
    it('scans https://example.com with real DNS, TLS, and HTTP response', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://example.com', targetType: 'URL' });
      expect(result.target).toBe('https://example.com');
      expect(result.targetType).toBe('URL');
      expect(result.checks.urlSecurityAnalysis).toBeDefined();
      expect(result.checks.domainAnalysis.dnsStatus).toMatch(/Resolved|Direct/i);
      expect(result.checks.sslAnalysis.status).toBe('passed');
      expect(result.checks.sslAnalysis.protocol).toMatch(/TLS/i);
    }, 15000);

    it('detects HTTP 404 on https://httpbin.org/status/404 honestly', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://httpbin.org/status/404', targetType: 'URL' });
      expect(result.checks.httpAnalysis?.statusCode).toBe(404);
      expect(result.checks.urlSecurityAnalysis?.resourceInterpretation).toContain('404');
    }, 15000);

    it('traces multi-hop redirect chain on https://httpbin.org/redirect/2', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://httpbin.org/redirect/2', targetType: 'URL' });
      expect(result.checks.redirectAnalysis.redirectCount).toBeGreaterThanOrEqual(2);
      expect(result.checks.urlSecurityAnalysis?.redirectJourney?.totalHops).toBeGreaterThanOrEqual(2);
    }, 15000);

    it('scans https://wikipedia.org accurately as general public URL', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://wikipedia.org', targetType: 'URL' });
      expect(result.checks.domainAnalysis.resolvedIps?.length).toBeGreaterThan(0);
      expect(result.checks.sslAnalysis.valid).toBe(true);
      expect(result.result).toBe('Safe');
    }, 15000);
  });

  // ── 2. Website Security Scanner ──────────────────────────────────────────
  describe('2. Website Security Scanner (/services/website-scanner)', () => {
    it('scans https://example.com with real headers, overview, and V2 evidence', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://example.com', targetType: 'Website' });
      expect(result.targetType).toBe('Website');
      expect(result.checks.websiteSecurityV2).toBeDefined();
      expect(result.checks.websiteOverview).toBeDefined();
      expect(result.checks.securityHeadersAnalysis).toBeDefined();
      expect(result.checks.websiteOverview?.pageTitle).toBeDefined();
    }, 20000);

    it('scans https://www.wikipedia.org with real security headers and cookies', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://www.wikipedia.org', targetType: 'Website' });
      expect(result.checks.websiteSecurityV2).toBeDefined();
      expect(result.checks.securityHeadersAnalysis?.headers.length).toBeGreaterThan(0);
    }, 20000);
  });

  // ── 3. API Security Scanner ──────────────────────────────────────────────
  describe('3. API Security Scanner (/services/api-scanner)', () => {
    it('scans https://httpbin.org/get and extracts CORS, status, and response structure', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://httpbin.org/get', targetType: 'API' });
      expect(result.targetType).toBe('API');
      expect(result.checks.apiAnalysis).toBeDefined();
      expect(result.checks.apiAnalysis?.httpMethod).toBe('GET');
      expect(result.checks.apiAnalysis?.statusCode).toBe(200);
      expect(result.checks.apiAnalysis?.responseStructure?.format).toBe('JSON');
      expect(result.checks.apiAnalysis?.corsConfig).toBeDefined();
    }, 20000);

    it('scans https://postman-echo.com/get?test=123 preserving query and detecting JSON payload', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://postman-echo.com/get?test=123', targetType: 'API' });
      expect(result.checks.apiAnalysis?.responseStructure?.format).toBe('JSON');
      expect(result.checks.apiAnalysis?.statusCode).toBe(200);
    }, 20000);
  });

  // ── 4. Phishing Scanner ──────────────────────────────────────────────────
  describe('4. Phishing Scanner (/services/phishing)', () => {
    it('scans a benign destination and reports clean credential profile', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://example.com', targetType: 'Phishing' });
      expect(result.targetType).toBe('Phishing');
      expect(result.checks.phishingAnalysis.status).toBe('passed');
      expect(result.checks.phishingAnalysis.confidence).toBe(0);
      expect(result.result).toBe('Safe');
    }, 15000);

    it('detects credential keywords on suspicious URL structure with evidence-based scoring', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://example.com/account-update/verify-paypal/login', targetType: 'Phishing' });
      expect(result.checks.phishingAnalysis).toBeDefined();
      const finding = result.findings.find(f => f.category.includes('Phishing') || f.category.includes('Brand') || f.category.includes('Credential'));
      expect(finding).toBeDefined();
      expect(finding?.evidence).toContain('paypal');
      expect(result.riskScore).toBeGreaterThan(0);
    }, 15000);
  });

  // ── 5. File Security Scanner ─────────────────────────────────────────────
  describe('5. File Security Scanner (/services/file)', () => {
    it('scans benign PDF document URL and computes SHA-256 and MD5 hashes', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://example.com/assets/annual-report.pdf', targetType: 'File' });
      expect(result.targetType).toBe('File');
      expect(result.checks.fileAnalysis).toBeDefined();
      expect(result.checks.fileAnalysis?.filename).toBe('annual-report.pdf');
      expect(result.checks.fileAnalysis?.extension).toBe('.pdf');
      expect(result.checks.fileAnalysis?.sha256).toBeDefined();
      expect(result.checks.fileAnalysis?.md5).toBeDefined();
      expect(result.checks.fileAnalysis?.magicBytes).toContain('%PDF');
      expect(result.checks.fileAnalysis?.structureRisk).toContain('Standard');
    }, 15000);

    it('detects high-risk executable binary extension (.exe)', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://example.com/downloads/setup.exe', targetType: 'File' });
      expect(result.checks.fileAnalysis?.extension).toBe('.exe');
      expect(result.checks.fileAnalysis?.structureRisk).toContain('High Risk');
      const finding = result.findings.find(f => f.category.includes('File Structure'));
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('HIGH');
    }, 15000);

    it('detects double extension evasion cloaking (.pdf.exe)', async () => {
      const result = await scanService.analyzeAndSave({ target: 'https://example.com/downloads/invoice.pdf.exe', targetType: 'File' });
      expect(result.checks.fileAnalysis?.structureRisk).toContain('Double-Extension');
      const cloakingFinding = result.findings.find(f => f.title.includes('Double-Extension') || f.title.includes('Double Extension'));
      expect(cloakingFinding).toBeDefined();
    }, 15000);
  });

  // ── 6. Browser Extension Scanner ─────────────────────────────────────────
  describe('6. Browser Extension Scanner (/services/extension)', () => {
    it('scans benign Manifest V3 extension input and verifies safe permissions', async () => {
      const manifest = JSON.stringify({
        name: 'Safe Note Taker',
        version: '1.2.0',
        manifest_version: 3,
        permissions: ['storage', 'alarms'],
        background: { service_worker: 'background.js' },
      });
      const result = await scanService.analyzeAndSave({ target: manifest, targetType: 'Extension' });
      expect(result.targetType).toBe('Extension');
      expect(result.checks.extensionAnalysis).toBeDefined();
      expect(result.checks.extensionAnalysis?.extensionName).toBe('Safe Note Taker');
      expect(result.checks.extensionAnalysis?.manifestVersion).toBe(3);
      expect(result.checks.extensionAnalysis?.permissions).toContain('storage');
      expect(result.checks.extensionAnalysis?.dangerousPermissions.length).toBe(0);
      expect(result.result).toBe('Safe');
    }, 15000);

    it('detects high-risk dangerous permissions like debugger and webRequestBlocking', async () => {
      const manifest = JSON.stringify({
        name: 'Powerful Network Interceptor',
        version: '2.0.0',
        manifest_version: 3,
        permissions: ['debugger', 'webRequestBlocking', 'proxy', 'cookies'],
        host_permissions: ['<all_urls>'],
      });
      const result = await scanService.analyzeAndSave({ target: manifest, targetType: 'Extension' });
      expect(result.checks.extensionAnalysis?.dangerousPermissions.length).toBeGreaterThanOrEqual(3);
      const debuggerFinding = result.findings.find(f => f.title.toLowerCase().includes('debugger'));
      expect(debuggerFinding).toBeDefined();
      expect(debuggerFinding?.severity).toBe('CRITICAL');
      expect(result.riskScore).toBeGreaterThanOrEqual(50);
    }, 15000);

    it('scans Chrome Web Store URL input structure correctly', async () => {
      const result = await scanService.analyzeAndSave({
        target: 'https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm',
        targetType: 'Extension',
      });
      expect(result.checks.extensionAnalysis?.extensionName).toBeDefined();
      expect(result.checks.extensionAnalysis?.manifestVersion).toBe(3);
    }, 15000);
  });

  // ── SSRF Security Boundaries ─────────────────────────────────────────────
  describe('SSRF Protection Guardrails', () => {
    it('blocks private IP addresses (127.0.0.1) and prevents SSRF', async () => {
      const result = await scanService.analyzeAndSave({ target: 'http://127.0.0.1:8080/admin', targetType: 'URL' });
      expect(result.checks.domainAnalysis.status).toBe('failed');
      expect(result.riskScore).toBeGreaterThanOrEqual(70);
      const ssrfFinding = result.findings.find(f => f.title.includes('SSRF Blocked') || f.title.includes('Private'));
      expect(ssrfFinding).toBeDefined();
    }, 15000);
  });
});
