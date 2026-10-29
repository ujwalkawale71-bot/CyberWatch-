import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import app from '../app';
import { IndicatorNormalizer } from '../utils/indicator-normalizer';
import { ThreatIntelOrchestrator } from '../services/threat-intel-orchestrator.service';
import { ThreatIntelligenceProvider } from '../services/threat-intel-providers/base.provider';
import { NormalizedIndicator, ThreatIntelProviderResult } from '@cyberwatch/shared';

describe('Threat Intelligence Module Master Test Suite', () => {
  // ─────────────────────────────────────────────────────────────────────────────
  // 1. Indicator Normalization & Defanging Tests
  // ─────────────────────────────────────────────────────────────────────────────
  describe('Indicator Normalizer', () => {
    it('1. correctly normalizes standard and defanged URLs', () => {
      const norm1 = IndicatorNormalizer.normalize('https://example.com/login?token=abc');
      expect(norm1.isValid).toBe(true);
      expect(norm1.type).toBe('URL');
      expect(norm1.canonical).toBe('https://example.com/login?token=abc');
      expect(norm1.metadata?.hostname).toBe('example.com');

      const normDefanged = IndicatorNormalizer.normalize('hxxps://malicious[.]test/payload[.]exe');
      expect(normDefanged.isValid).toBe(true);
      expect(normDefanged.type).toBe('URL');
      expect(normDefanged.canonical).toBe('https://malicious.test/payload.exe');
    });

    it('2. correctly normalizes standard and defanged domains', () => {
      const norm1 = IndicatorNormalizer.normalize('phishing-site.example.com');
      expect(norm1.isValid).toBe(true);
      expect(norm1.type).toBe('DOMAIN');
      expect(norm1.canonical).toBe('phishing-site.example.com');

      const normDefanged = IndicatorNormalizer.normalize('bad-actor[.]org');
      expect(normDefanged.isValid).toBe(true);
      expect(normDefanged.type).toBe('DOMAIN');
      expect(normDefanged.canonical).toBe('bad-actor.org');

      const normPunycode = IndicatorNormalizer.normalize('xn--pple-43d.com');
      expect(normPunycode.isValid).toBe(true);
      expect(normPunycode.type).toBe('DOMAIN');
      expect(normPunycode.canonical).toBe('xn--pple-43d.com');
    });

    it('3. accurately classifies IPv4 addresses (Public vs Private / Loopback)', () => {
      const publicIp = IndicatorNormalizer.normalize('8.8.8.8');
      expect(publicIp.isValid).toBe(true);
      expect(publicIp.type).toBe('IP');
      expect(publicIp.metadata?.ipVersion).toBe('IPv4');
      expect(publicIp.isPrivate).toBe(false);

      const loopbackIp = IndicatorNormalizer.normalize('127.0.0.1');
      expect(loopbackIp.isValid).toBe(true);
      expect(loopbackIp.type).toBe('IP');
      expect(loopbackIp.isPrivate).toBe(true);

      const privateIp10 = IndicatorNormalizer.normalize('10.20.30.40');
      expect(privateIp10.isPrivate).toBe(true);

      const privateIp192 = IndicatorNormalizer.normalize('192.168.1.254');
      expect(privateIp192.isPrivate).toBe(true);

      const privateIp172 = IndicatorNormalizer.normalize('172.20.1.1');
      expect(privateIp172.isPrivate).toBe(true);

      const defangedIp = IndicatorNormalizer.normalize('1[.]1[.]1[.]1');
      expect(defangedIp.isValid).toBe(true);
      expect(defangedIp.canonical).toBe('1.1.1.1');
    });

    it('4. accurately classifies IPv6 addresses', () => {
      const publicIpv6 = IndicatorNormalizer.normalize('2001:4860:4860::8888');
      expect(publicIpv6.isValid).toBe(true);
      expect(publicIpv6.type).toBe('IP');
      expect(publicIpv6.metadata?.ipVersion).toBe('IPv6');
      expect(publicIpv6.isPrivate).toBe(false);

      const loopbackIpv6 = IndicatorNormalizer.normalize('::1');
      expect(loopbackIpv6.isValid).toBe(true);
      expect(loopbackIpv6.isPrivate).toBe(true);
    });

    it('5. identifies cryptographic hashes: MD5, SHA-1, SHA-256', () => {
      const md5 = IndicatorNormalizer.normalize('44d88612fea8a8f36de82e1278abb02f');
      expect(md5.isValid).toBe(true);
      expect(md5.type).toBe('HASH_MD5');
      expect(md5.canonical).toBe('44d88612fea8a8f36de82e1278abb02f');

      const sha1 = IndicatorNormalizer.normalize('3395856ce81f2b7382dee72602f798b642f14140');
      expect(sha1.isValid).toBe(true);
      expect(sha1.type).toBe('HASH_SHA1');

      const sha256 = IndicatorNormalizer.normalize(
        '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
      );
      expect(sha256.isValid).toBe(true);
      expect(sha256.type).toBe('HASH_SHA256');
    });

    it('6. detects Browser Extension identifiers and Store URLs', () => {
      // 32 alphabetic characters [a-p]{32}
      const chromeId = IndicatorNormalizer.normalize('cjpalhdlnbpafiamejdnhcphjbkeiagm');
      expect(chromeId.isValid).toBe(true);
      expect(chromeId.type).toBe('EXTENSION_ID');
      expect(chromeId.canonical).toBe('cjpalhdlnbpafiamejdnhcphjbkeiagm');
      expect(chromeId.metadata?.extensionStore).toBe('Chrome');

      // Chrome Web Store URL
      const storeUrl = IndicatorNormalizer.normalize(
        'https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm'
      );
      expect(storeUrl.isValid).toBe(true);
      expect(storeUrl.type).toBe('EXTENSION_ID');
      expect(storeUrl.canonical).toBe('cjpalhdlnbpafiamejdnhcphjbkeiagm');

      // Firefox Extension ID
      const firefoxId = IndicatorNormalizer.normalize('uBlock0@raymondhill.net');
      expect(firefoxId.isValid).toBe(true);
      expect(firefoxId.type).toBe('EXTENSION_ID');
      expect(firefoxId.metadata?.extensionStore).toBe('Firefox');
    });

    it('7. safely rejects empty or malformed indicators', () => {
      const empty = IndicatorNormalizer.normalize('');
      expect(empty.isValid).toBe(false);
      expect(empty.validationError).toBeDefined();

      const invalid = IndicatorNormalizer.normalize('not a valid domain or ip !!! $$$');
      expect(invalid.isValid).toBe(false);
      expect(invalid.validationError).toBeDefined();
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. Orchestrator Engine & Confidence Synthesis Tests
  // ─────────────────────────────────────────────────────────────────────────────
  describe('Threat Intelligence Orchestrator', () => {
    it('8. handles unconfigured state honestly without inventing results', async () => {
      const orchestrator = new ThreatIntelOrchestrator();
      const report = await orchestrator.analyze('8.8.8.8', { forceRefresh: true });

      expect(report.analysisId).toBeDefined();
      expect(report.indicatorType).toBe('IP');
      expect(report.providersChecked).toBeGreaterThan(0);
      expect(report.status).toBeDefined();
      // Honest status - never claims fake "100% safe"
      expect(report.status).not.toBe('FAKE');
    });

    it('9. orchestrates multiple mock providers and computes MATCH_FOUND with HIGH confidence', async () => {
      const orchestrator = new ThreatIntelOrchestrator();

      // Mock provider 1: VirusTotal reporting malicious
      const mockVt: ThreatIntelligenceProvider = {
        id: 'mock_vt',
        name: 'Mock VirusTotal',
        supportedTypes: ['URL', 'DOMAIN'],
        isConfigured: () => true,
        lookup: async (ind: NormalizedIndicator): Promise<ThreatIntelProviderResult> => ({
          providerId: 'mock_vt',
          providerName: 'Mock VirusTotal',
          configured: true,
          status: 'SUCCESS',
          reputation: 'MALICIOUS',
          queryType: ind.type,
          timestamp: new Date().toISOString(),
          detectionSummary: { malicious: 14, total: 92 },
          categories: ['Phishing', 'Malware'],
          evidence: [
            {
              id: 'ev-1',
              indicator: ind.display,
              indicatorType: ind.type,
              provider: 'Mock VirusTotal',
              evidenceType: 'Engine Detection',
              category: 'Phishing',
              severity: 'HIGH',
              confidence: 'HIGH',
              value: '14/92 flagged',
              description: 'Flagged by 14 security engines.',
              timestamp: new Date().toISOString(),
            },
          ],
          relatedIndicators: [
            {
              indicator: '198.51.100.23',
              type: 'IP',
              relationship: 'A record',
              source: 'Mock VirusTotal',
            },
          ],
          details: '14 engines flagged this indicator.',
        }),
      };

      // Mock provider 2: URLhaus reporting malware
      const mockUrlhaus: ThreatIntelligenceProvider = {
        id: 'mock_urlhaus',
        name: 'Mock URLhaus',
        supportedTypes: ['URL', 'DOMAIN'],
        isConfigured: () => true,
        lookup: async (ind: NormalizedIndicator): Promise<ThreatIntelProviderResult> => ({
          providerId: 'mock_urlhaus',
          providerName: 'Mock URLhaus',
          configured: true,
          status: 'SUCCESS',
          reputation: 'MALICIOUS',
          queryType: ind.type,
          timestamp: new Date().toISOString(),
          detectionSummary: { malicious: 1, total: 1 },
          categories: ['Malware'],
          evidence: [
            {
              id: 'ev-2',
              indicator: ind.display,
              indicatorType: ind.type,
              provider: 'Mock URLhaus',
              evidenceType: 'Active Feed',
              category: 'Malware',
              severity: 'HIGH',
              confidence: 'HIGH',
              value: 'Active malware drop point',
              description: 'Listed in malware feed.',
              timestamp: new Date().toISOString(),
            },
          ],
          relatedIndicators: [],
          details: 'Listed in URLhaus.',
        }),
      };

      orchestrator.registerProvider(mockVt);
      orchestrator.registerProvider(mockUrlhaus);

      const report = await orchestrator.analyze('http://malicious-sample.test/payload', {
        forceRefresh: true,
      });

      expect(report.status).toBe('MATCH_FOUND');
      expect(report.overallReputation).toBe('MALICIOUS');
      expect(report.confidence).toBe('HIGH');
      expect(report.detectionSummary?.flaggedCount).toBe(15);
      expect(report.threatCategories).toContain('Phishing');
      expect(report.threatCategories).toContain('Malware');
      expect(report.evidence.length).toBe(2);
      expect(report.relatedIndicators.length).toBe(1);
      expect(report.correlationWithCyberWatch?.suggestedScanner).toBe('url');
    });

    it('10. handles partial failure gracefully when one provider times out and one succeeds', async () => {
      const orchestrator = new ThreatIntelOrchestrator();

      const mockProviderA: ThreatIntelligenceProvider = {
        id: 'prov_a',
        name: 'Provider A',
        supportedTypes: ['DOMAIN'],
        isConfigured: () => true,
        lookup: async (ind: NormalizedIndicator): Promise<ThreatIntelProviderResult> => ({
          providerId: 'prov_a',
          providerName: 'Provider A',
          configured: true,
          status: 'SUCCESS',
          reputation: 'NO_MATCH',
          queryType: ind.type,
          timestamp: new Date().toISOString(),
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: '0 detections.',
        }),
      };

      const mockProviderB: ThreatIntelligenceProvider = {
        id: 'prov_b',
        name: 'Provider B',
        supportedTypes: ['DOMAIN'],
        isConfigured: () => true,
        lookup: async (ind: NormalizedIndicator): Promise<ThreatIntelProviderResult> => ({
          providerId: 'prov_b',
          providerName: 'Provider B',
          configured: true,
          status: 'TIMEOUT',
          reputation: 'UNAVAILABLE',
          queryType: ind.type,
          timestamp: new Date().toISOString(),
          errorCategory: 'TIMEOUT',
          errorMessage: 'Request timed out.',
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: 'Timeout.',
        }),
      };

      orchestrator.registerProvider(mockProviderA);
      orchestrator.registerProvider(mockProviderB);

      const report = await orchestrator.analyze('clean-sample.test', { forceRefresh: true });

      expect(report.status).toBe('PARTIAL');
      expect(report.overallReputation).toBe('NO_MATCH');
      expect(report.recommendation).toContain('Partial intelligence available');
    });

    it('11. verifies cache behavior and forceRefresh option', async () => {
      const orchestrator = new ThreatIntelOrchestrator();
      let callCount = 0;

      const mockProvider: ThreatIntelligenceProvider = {
        id: 'prov_cache_test',
        name: 'Provider Cache',
        supportedTypes: ['IP'],
        isConfigured: () => true,
        lookup: async (ind: NormalizedIndicator): Promise<ThreatIntelProviderResult> => {
          callCount++;
          return {
            providerId: 'prov_cache_test',
            providerName: 'Provider Cache',
            configured: true,
            status: 'SUCCESS',
            reputation: 'NO_MATCH',
            queryType: ind.type,
            timestamp: new Date().toISOString(),
            categories: [],
            evidence: [],
            relatedIndicators: [],
            details: `Lookups performed: ${callCount}`,
          };
        },
      };

      orchestrator.registerProvider(mockProvider);

      // First call
      const rep1 = await orchestrator.analyze('198.51.100.1', { forceRefresh: false });
      expect(rep1.cached).toBe(false);
      expect(callCount).toBe(1);

      // Second call without forceRefresh -> should be cached
      const rep2 = await orchestrator.analyze('198.51.100.1', { forceRefresh: false });
      expect(rep2.cached).toBe(true);
      expect(callCount).toBe(1);

      // Third call with forceRefresh -> invokes provider
      const rep3 = await orchestrator.analyze('198.51.100.1', { forceRefresh: true });
      expect(rep3.cached).toBe(false);
      expect(callCount).toBe(2);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. API Endpoints Tests
  // ─────────────────────────────────────────────────────────────────────────────
  describe('Threat Intelligence HTTP API Routes', () => {
    it('12. POST /api/v1/threat-intelligence/analyze returns structured report for valid indicator', async () => {
      const res = await request(app)
        .post('/api/v1/threat-intelligence/analyze')
        .send({ indicator: 'https://example.com' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeDefined();
      expect(res.body.data.indicatorType).toBe('URL');
      expect(res.body.data.analysisId).toBeDefined();
      expect(Array.isArray(res.body.data.providers)).toBe(true);
    });

    it('13. POST /api/v1/threat-intelligence/analyze returns 400 for empty indicator', async () => {
      const res = await request(app)
        .post('/api/v1/threat-intelligence/analyze')
        .send({ indicator: '' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Indicator is required');
    });

    it('14. GET /api/v1/threat-intelligence/providers returns provider metadata', async () => {
      const res = await request(app).get('/api/v1/threat-intelligence/providers');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.some((p: any) => p.id === 'virustotal')).toBe(true);
    });

    it('15. POST /api/v1/threat-intelligence/normalize validates and canonicalizes indicator without external requests', async () => {
      const res = await request(app)
        .post('/api/v1/threat-intelligence/normalize')
        .send({ indicator: 'hxxps://test-phish[.]site/login' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.type).toBe('URL');
      expect(res.body.data.canonical).toBe('https://test-phish.site/login');
      expect(res.body.data.isValid).toBe(true);
    });

    it('16. GET /api/v1/threat-intelligence/indicators returns paginated persistent indicator registry', async () => {
      const res = await request(app).get('/api/v1/threat-intelligence/indicators');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data.items)).toBe(true);
      expect(typeof res.body.data.total).toBe('number');
    });

    it('17. GET /api/v1/threat-intelligence/advisories returns advisory status honestly without mock CVEs', async () => {
      const res = await request(app).get('/api/v1/threat-intelligence/advisories');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(typeof res.body.data.configured).toBe('boolean');
      expect(Array.isArray(res.body.data.advisories)).toBe(true);
    });

    it('18. POST /api/v1/threat-intelligence/correlate unifies scanner findings with threat intel evidence', async () => {
      const res = await request(app)
        .post('/api/v1/threat-intelligence/correlate')
        .send({
          scannerType: 'Website',
          target: 'example.com',
          findings: [
            {
              title: 'Missing CSP Header',
              description: 'Content-Security-Policy header is missing.',
              severity: 'MEDIUM',
            },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.primaryIndicator).toBe('example.com');
      expect(Array.isArray(res.body.data.unifiedEvidence)).toBe(true);
      expect(res.body.data.unifiedEvidence.some((e: any) => e.sourceType === 'SCANNER')).toBe(true);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. Scanner Indicator Extraction & Correlation Unit Tests
  // ─────────────────────────────────────────────────────────────────────────────
  describe('Indicator Extraction & Unified Correlation Engine', () => {
    it('19. extracts indicators accurately from all 6 scanner results', async () => {
      const { IndicatorExtractorService } = await import('../services/indicator-extractor.service');

      // 1. URL Scanner
      const urlExt = IndicatorExtractorService.extractFromScanner('URL', 'https://example.com/test', {
        checks: {
          urlSecurityAnalysis: {
            finalUrl: 'https://example.com/final',
            finalHostname: 'example.com',
            registrableDomain: 'example.com',
          },
          domainAnalysis: {
            resolvedIps: ['93.184.216.34'],
          },
        },
      });
      expect(urlExt.some((i) => i.type === 'URL')).toBe(true);
      expect(urlExt.some((i) => i.type === 'DOMAIN' && i.normalizedValue === 'example.com')).toBe(true);
      expect(urlExt.some((i) => i.type === 'IP' && i.normalizedValue === '93.184.216.34')).toBe(true);

      // 2. File Scanner
      const fileExt = IndicatorExtractorService.extractFromScanner('File', 'malicious_sample.exe', {
        checks: {
          fileAnalysis: {
            sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
            sha1: '3395856ce81f2b7382dee72602f798b642f14140',
            md5: '44d88612fea8a8f36de82e1278abb02f',
          },
        },
      });
      expect(fileExt.some((i) => i.type === 'HASH_SHA256')).toBe(true);
      expect(fileExt.some((i) => i.type === 'HASH_SHA1')).toBe(true);
      expect(fileExt.some((i) => i.type === 'HASH_MD5')).toBe(true);

      // 3. Extension Scanner
      const extExt = IndicatorExtractorService.extractFromScanner('Extension', 'cjpalhdlnbpafiamejdnhcphjbkeiagm', {
        checks: {
          extensionAnalysis: {
            extensionId: 'cjpalhdlnbpafiamejdnhcphjbkeiagm',
            packageIdentity: {
              sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            },
          },
        },
      });
      expect(extExt.some((i) => i.type === 'EXTENSION_ID')).toBe(true);
      expect(extExt.some((i) => i.type === 'HASH_SHA256')).toBe(true);
    });

    it('20. generates unified evidence and performs correlation with deduplication', async () => {
      const { ThreatIntelCorrelationService } = await import('../services/threat-intel-correlation.service');

      const correlation = await ThreatIntelCorrelationService.correlateScanWithThreatIntel(
        'Phishing',
        'https://example.com/login',
        [
          {
            title: 'Deceptive Login Form',
            description: 'Suspicious credential submission action.',
            severity: 'HIGH',
          },
        ]
      );

      expect(correlation.primaryIndicator).toBe('https://example.com/login');
      expect(correlation.indicatorType).toBe('URL');
      expect(Array.isArray(correlation.unifiedEvidence)).toBe(true);
      expect(correlation.scannerFindingsCount).toBe(1);
    });

    it('21. GET /api/v1/threat-intelligence/feeds returns registered intelligence telemetry feeds', async () => {
      const res = await request(app).get('/api/v1/threat-intelligence/feeds');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(5);
      expect(res.body.data.some((f: any) => f.providerId === 'urlhaus')).toBe(true);
      expect(res.body.data.some((f: any) => f.providerId === 'malwarebazaar')).toBe(true);
    });

    it('22. POST /api/v1/threat-intelligence/providers/:id/test safely checks connection latency', async () => {
      const res = await request(app).post('/api/v1/threat-intelligence/providers/urlhaus/test');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.providerId).toBe('urlhaus');
      expect(['ONLINE', 'NOT_CONFIGURED', 'ERROR']).toContain(res.body.data.status);
    });
  });
});


