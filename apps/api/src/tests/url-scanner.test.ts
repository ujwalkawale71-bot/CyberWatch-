import { describe, it, expect, vi } from 'vitest';
import { scanService } from '../services/scan.service';

// Mock Mongoose model save to avoid needing a live Mongo daemon in unit tests
vi.mock('../models/Scan', async () => {
  const original = await vi.importActual('../models/Scan');
  function MockScan(this: any, data: any) {
    Object.assign(this, data);
    this._id = { toString: () => 'mock-scan-id-url-123' };
    this.createdAt = new Date();
    this.save = vi.fn().mockResolvedValue(this);
  }
  return {
    ...original as any,
    Scan: MockScan,
  };
});

describe('URL Security Scanner Complete Engine Tests', () => {
  // 1. Normal HTTPS URL
  it('1. Scans normal HTTPS URL (https://example.com) and verifies structure, TLS, and 16-section model data', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://example.com',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.checks.urlSecurityAnalysis).toBeDefined();
    const urlSec = result.checks.urlSecurityAnalysis!;

    expect(urlSec.certificateSummary?.httpsEnabled).toBe(true);
    expect(result.checks.domainAnalysis.hostname).toBe('example.com');
    expect(urlSec.auditChecks!.length).toBeGreaterThanOrEqual(13);
    expect(urlSec.positiveSignals.length).toBeGreaterThan(0);
    expect(urlSec.resourceInterpretation).toBeDefined();
    expect(result.riskScore).toBeLessThanOrEqual(20);
  }, 20000);

  // 2. HTTP URL
  it('2. Scans HTTP URL and flags plaintext transport without automatic critical escalation', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'http://example.com',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    const urlSec = result.checks.urlSecurityAnalysis;
    expect(urlSec?.certificateSummary?.httpsEnabled).toBe(false);
    expect(result.findings.some(f => f.title.includes('Unencrypted') || f.category === 'SSL/TLS' || f.category === 'Protocol Security')).toBe(true);
    expect(urlSec?.scoreContributors.some(c => c.name === 'Transport Security' && c.points > 0)).toBe(true);
  }, 20000);

  // 3. Redirect URL
  it('3. Tracks multi-hop redirect journey for redirected targets', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://httpbin.org/redirect/2',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.checks.redirectAnalysis).toBeDefined();
    expect(result.checks.redirectAnalysis?.redirectCount).toBeGreaterThanOrEqual(1);
    expect(result.checks.urlSecurityAnalysis?.redirectJourney?.finalUrl).toBeDefined();
  }, 20000);

  // 4. HTTP 404
  it('4. Handles HTTP 404 response honestly as resource not found without fake phishing flag', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://httpbin.org/status/404',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.checks.httpAnalysis?.statusCode).toBe(404);
    expect(result.checks.urlSecurityAnalysis?.resourceInterpretation).toContain('404');
    expect(result.result).not.toBe('Critical');
  }, 20000);

  // 5. HTTP 500
  it('5. Handles HTTP 500 response as server internal error observation', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://httpbin.org/status/500',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.checks.httpAnalysis?.statusCode).toBe(500);
    expect(result.checks.urlSecurityAnalysis?.resourceInterpretation).toContain('500');
  }, 20000);

  // 6. HTTPS/TLS Information
  it('6. Extracts TLS certificate and cipher details on HTTPS targets', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://httpbin.org/get',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.checks.sslAnalysis).toBeDefined();
    if (result.checks.sslAnalysis?.valid) {
      expect(result.checks.sslAnalysis.issuer).toBeDefined();
      expect(result.checks.sslAnalysis.protocol).toBeDefined();
    }
  }, 20000);

  // 7. DNS Resolution
  it('7. Resolves DNS records and provides IPv4/IPv6 classification', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://example.com',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.checks.domainAnalysis?.dnsStatus).toBeDefined();
    expect(result.checks.domainAnalysis?.resolvedIps?.length).toBeGreaterThan(0);
  }, 20000);

  // 8. Suspicious URL Structure
  it('8. Evaluates structural anomalies (deep nesting, percent encoding) evidence-based', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://example.com/%2e%2e/%2flogin%2fadmin?next=%2fportal',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    const urlSec = result.checks.urlSecurityAnalysis;
    expect(urlSec?.hasEncodedChars).toBe(true);
    expect(urlSec?.auditChecks?.find(c => c.name === 'Suspicious Encoding')?.status).toBe('WARN');
  }, 20000);

  // 9. Punycode Detection
  it('9. Detects punycode internationalized domain names (xn--)', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://xn--e1afmkfd.xn--p1ai/login',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    const urlSec = result.checks.urlSecurityAnalysis;
    expect(urlSec?.hasPunycode).toBe(true);
    expect(urlSec?.auditChecks?.find(c => c.name === 'Punycode / IDN')?.status).toBe('WARN');
    expect(result.findings.some(f => f.title.includes('Punycode') || f.title.includes('IDN'))).toBe(true);
  }, 20000);

  // 10. IP Hostname Detection
  it('10. Detects direct IP address hostnames', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'http://93.184.216.34/test',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    const urlSec = result.checks.urlSecurityAnalysis;
    expect(urlSec?.isDirectIp).toBe(true);
    expect(urlSec?.auditChecks?.find(c => c.name === 'IP-Based Hostname')?.status).toBe('WARN');
    expect(result.findings.some(f => f.title.includes('IP Address'))).toBe(true);
  }, 20000);

  // 11. SSRF / Private IP Blocking
  it('11. Strictly blocks private/loopback IP SSRF attempts (127.0.0.1, localhost, 10.0.0.1)', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'http://127.0.0.1/admin',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.status).toBe('failed');
    expect(result.findings.some(f => f.title.includes('SSRF') || f.title.includes('Private IP') || f.title.includes('Blocked'))).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(70);
  }, 20000);

  // 12. Redirect SSRF Blocking
  it('12. Blocks redirects pointing to private network addresses', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://httpbin.org/redirect-to?url=http%3A%2F%2F127.0.0.1%2Fsecrets',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.findings.some(f => f.title.includes('SSRF') || f.title.includes('Blocked') || f.title.includes('Private IP'))).toBe(true);
  }, 20000);

  // 13. Timeout Handling
  it('13. Reports honest timeout when scanning unreachable host without fake safe results', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://10.255.255.1:81/test', // Unroutable IP / blocked
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    expect(result.status).toBe('failed');
  }, 20000);

  // 14. Sensitive Query Parameter Masking
  it('14. Masks sensitive query parameters (token, api_key, secret, password) in output', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://example.com/api/reset?token=secret12345&api_key=mykey999&password=mypassword123&user=alice',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    const targetString = result.target;
    // Values for sensitive params should be redacted
    expect(targetString).not.toContain('secret12345');
    expect(targetString).not.toContain('mykey999');
    expect(targetString).not.toContain('mypassword123');
    expect(targetString).toContain('token=REDACTED');
    expect(targetString).toContain('api_key=REDACTED');
    expect(targetString).toContain('password=REDACTED');
  }, 20000);

  // 15. Risk Score Changes Based on Evidence
  it('15. Dynamically changes risk score and classification based on observed evidence', async () => {
    const safeResult = await scanService.analyzeAndSave({
      target: 'https://example.com',
      targetType: 'URL',
    });

    const riskyResult = await scanService.analyzeAndSave({
      target: 'http://93.184.216.34/%2e%2e/login',
      targetType: 'URL',
    });

    expect(safeResult.riskScore).toBeLessThan(riskyResult.riskScore);
    expect(safeResult.result).toBe('Safe');
    expect(riskyResult.result).not.toBe('Safe');
  }, 20000);

  // 16. Upgraded Contract Fields Verification
  it('16. Populates originalUrl, normalizedUrl, finalUrl, registrableDomain, whyVerdict, primaryFindings, and honest limitations', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://example.com/path/test?a=1#section',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    const urlSec = result.checks.urlSecurityAnalysis!;
    expect(urlSec.originalUrl).toBe('https://example.com/path/test?a=1#section');
    expect(urlSec.normalizedUrl).toBe('https://example.com/path/test?a=1');
    expect(urlSec.finalUrl).toBeDefined();
    expect(urlSec.registrableDomain).toBe('example.com');
    expect(Array.isArray(urlSec.whyVerdict)).toBe(true);
    expect(urlSec.whyVerdict!.length).toBeGreaterThan(0);
    expect(Array.isArray(urlSec.primaryFindings)).toBe(true);
    expect(Array.isArray(urlSec.limitations)).toBe(true);
    expect(urlSec.limitations!.some((l: string) => l.includes('does not guarantee'))).toBe(true);
    expect(urlSec.executionOutcome).toBe('COMPLETED');
  }, 20000);

  // 17. Threat Intelligence "Not Configured" Handling
  it('17. Reports threat intelligence as Not Configured without fabricating clean/malicious state', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://example.com',
      targetType: 'URL',
    });

    expect(result).toBeDefined();
    const urlSec = result.checks.urlSecurityAnalysis!;
    expect(urlSec.threatIntelligence).toBeDefined();
    expect(urlSec.threatIntelligence?.status).toBe('Not Configured');
    expect(urlSec.threatIntelligence?.details).toContain('threat intelligence');
  }, 20000);

  // 18. HTTPS to HTTP Downgrade Finding Generation
  it('18. Detects HTTPS to HTTP downgrade in redirect chain and raises HIGH finding', async () => {
    // Test the analyzeUrlSecurity engine directly with a redirect chain containing a downgrade
    const syntheticAnalysis = scanService.analyzeUrlSecurity({
      originalUrl: 'https://insecure-site.org/redirect-downgrade',
      normalizedUrl: 'https://insecure-site.org/redirect-downgrade',
      targetUrl: 'https://insecure-site.org/redirect-downgrade',
      domain: 'insecure-site.org',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', queryTimeMs: 15 },
      sslData: { valid: true, issuer: 'Let\'s Encrypt', protocol: 'TLSv1.3' },
      httpData: { statusCode: 200, statusText: 'OK', headers: {}, responseTimeMs: 100 },
      redirectData: {
        hasRedirects: true,
        redirectCount: 1,
        finalUrl: 'http://insecure-site.org/landing',
        redirectChain: [
          {
            url: 'http://insecure-site.org/landing',
            status: 302,
            location: 'http://insecure-site.org/landing',
            host: 'insecure-site.org',
            protocol: 'http:',
            isDowngrade: true
          }
        ]
      }
    });

    expect(syntheticAnalysis).toBeDefined();
    expect(syntheticAnalysis.analysis.hasDowngrade).toBe(true);
    expect(syntheticAnalysis.findings.some(f => f.title.includes('Downgrade') && f.severity === 'HIGH')).toBe(true);
    expect(syntheticAnalysis.analysis.auditChecks!.find(c => c.name === 'Redirection Routing' || c.name === 'Redirect Protocol Security')?.status).toBe('FAIL');
    expect(syntheticAnalysis.analysis.whyVerdict!.some(w => /downgrade/i.test(w))).toBe(true);
  });

  // 19. Contextual Brand Deception vs Clean Domain
  it('19. Flags brand token deception when brand appears in subdomain of unrelated domain', async () => {
    const deceptiveAnalysis = scanService.analyzeUrlSecurity({
      originalUrl: 'https://paypal.secure-login-portal-xyz.com',
      normalizedUrl: 'https://paypal.secure-login-portal-xyz.com',
      targetUrl: 'https://paypal.secure-login-portal-xyz.com',
      domain: 'paypal.secure-login-portal-xyz.com',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED' },
      sslData: { valid: true },
      httpData: { statusCode: 200, statusText: 'OK', headers: {} }
    });

    expect(deceptiveAnalysis.findings.some(f => f.title.includes('Brand Name in Subdomain'))).toBe(true);
    expect(deceptiveAnalysis.analysis.auditChecks!.find(c => c.name === 'Brand Impersonation in Subdomain')?.status).toBe('WARN');

    // On the legitimate brand domain itself, brand token check must PASS without warning
    const genuineAnalysis = scanService.analyzeUrlSecurity({
      originalUrl: 'https://www.paypal.com/signin',
      normalizedUrl: 'https://www.paypal.com/signin',
      targetUrl: 'https://www.paypal.com/signin',
      domain: 'www.paypal.com',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED' },
      sslData: { valid: true },
      httpData: { statusCode: 200, statusText: 'OK', headers: {} }
    });

    expect(genuineAnalysis.findings.some(f => f.title.includes('Brand Name in Subdomain'))).toBe(false);
    expect(genuineAnalysis.analysis.auditChecks!.find(c => c.name === 'Brand Impersonation in Subdomain')?.status).toBe('PASS');
  });

  // 20. Public Targets Testing: developer.mozilla.org, github.com, wikipedia.org
  it('20. Accurately scans real public URLs without hardcoded domain scoring', async () => {
    const targets = [
      'https://www.wikipedia.org',
      'https://developer.mozilla.org',
      'https://github.com'
    ];

    for (const target of targets) {
      const result = await scanService.analyzeAndSave({
        target,
        targetType: 'URL',
      });

      expect(result).toBeDefined();
      expect(result.status).toBe('completed');
      expect(result.checks.urlSecurityAnalysis).toBeDefined();
      expect(result.checks.urlSecurityAnalysis?.registrableDomain).toBeDefined();
      expect(result.checks.urlSecurityAnalysis?.positiveSignals.length).toBeGreaterThan(0);
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    }
  }, 45000);
});
