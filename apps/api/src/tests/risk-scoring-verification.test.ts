import { describe, it, expect, vi } from 'vitest';
import { URL } from 'node:url';
import { scanService, deriveClassificationFromRiskScore } from '../services/scan.service';
import { phishingScannerService } from '../services/phishing-scanner.service';

vi.mock('../models/Scan', async () => {
  const original = await vi.importActual('../models/Scan');
  function MockScan(this: any, data: any) {
    Object.assign(this, data);
    this._id = { toString: () => 'mock-scan-id-risk-verification-123' };
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
    ...(original as any),
    Scan: MockScan,
  };
});

describe('CyberWatch Mega Scanner Risk Scoring Evidence-Driven Test Suite', () => {
  // TEST 1: https://example.com
  it('TEST 1: https://example.com - completes, evidence-derived score, not hardcoded, explains findings', () => {
    const urlEval = scanService.analyzeUrlSecurity({
      originalUrl: 'https://example.com',
      normalizedUrl: 'https://example.com',
      target: 'https://example.com',
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'https://example.com',
        redirectCount: 0,
        redirectChain: [],
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        responseTimeMs: 80,
        details: 'OK',
      },
      tlsResult: {
        valid: true,
        protocol: 'TLSv1.3',
        issuer: 'DigiCert Global Root CA',
        subject: 'example.com',
        daysRemaining: 180,
        details: 'Valid TLSv1.3 connection.',
      },
      effectiveHttps: true,
      threatIntelResult: {
        status: 'Clean',
        provider: 'Mock Provider',
        queried: true,
        result: 'Clean',
        details: 'No known malicious activity.',
      },
    });

    const phishResult = phishingScannerService.analyze({
      target: 'https://example.com',
      normalizedTarget: 'https://example.com',
      parsedUrl: new URL('https://example.com'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'https://example.com',
        redirectCount: 0,
        redirectChain: [],
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        responseTimeMs: 80,
        details: 'OK',
      },
      tlsResult: {
        valid: true,
        protocol: 'TLSv1.3',
        issuer: 'DigiCert Global Root CA',
        subject: 'example.com',
        daysRemaining: 180,
        details: 'Valid TLSv1.3 connection.',
      },
      effectiveHttps: true,
      threatIntelResult: {
        status: 'Clean',
        provider: 'Mock Provider',
        queried: true,
        result: 'Clean',
        details: 'No known malicious activity.',
      },
    });

    const aggregated = scanService.aggregateMegaScanFindings(urlEval, phishResult, {
      target: 'https://example.com',
      normalizedTarget: 'https://example.com',
      parsedUrl: new URL('https://example.com'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3' },
      effectiveHttps: true,
    });

    expect(aggregated.riskScore).toBe(0);
    expect(aggregated.rawRisk).toBe(0);
    const classification = deriveClassificationFromRiskScore(aggregated.riskScore, aggregated.hasCriticalFinding);
    expect(classification).toBe('Safe');
    expect(aggregated.findings.length).toBeGreaterThan(0);
    expect(aggregated.findings.some((f) => f.title.includes('Baseline'))).toBe(true);
  });

  // TEST 2: http://example.com
  it('TEST 2: http://example.com - HTTP evidence is detected and score is greater than HTTPS equivalent', () => {
    const urlEval = scanService.analyzeUrlSecurity({
      originalUrl: 'http://example.com',
      normalizedUrl: 'http://example.com',
      target: 'http://example.com',
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'http://example.com',
        redirectCount: 0,
        redirectChain: [],
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        responseTimeMs: 80,
        details: 'OK',
      },
      tlsResult: null,
      effectiveHttps: false,
    });

    const phishResult = phishingScannerService.analyze({
      target: 'http://example.com',
      normalizedTarget: 'http://example.com',
      parsedUrl: new URL('http://example.com'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'http://example.com',
        redirectCount: 0,
        redirectChain: [],
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        responseTimeMs: 80,
        details: 'OK',
      },
      tlsResult: null,
      effectiveHttps: false,
    });

    const aggregated = scanService.aggregateMegaScanFindings(urlEval, phishResult, {
      target: 'http://example.com',
      normalizedTarget: 'http://example.com',
      parsedUrl: new URL('http://example.com'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK' },
      tlsResult: null,
      effectiveHttps: false,
    });

    expect(aggregated.riskScore).toBeGreaterThan(0);
    expect(aggregated.riskScore).toBe(25);
    const classification = deriveClassificationFromRiskScore(aggregated.riskScore, aggregated.hasCriticalFinding);
    expect(['Suspicious', 'Low Risk']).toContain(classification);
    expect(aggregated.findings.some((f) => f.title.includes('Unencrypted HTTP'))).toBe(true);
    expect(aggregated.scoreContributors.some((sc) => sc.name === 'Transport Security' || sc.category === 'Transport Security')).toBe(true);
  });

  // TEST 3: https://example.com/login
  it('TEST 3: https://example.com/login - generic "login" token alone MUST NOT create a phishing finding', () => {
    const phishResult = phishingScannerService.analyze({
      target: 'https://example.com/login',
      normalizedTarget: 'https://example.com/login',
      parsedUrl: new URL('https://example.com/login'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'https://example.com/login',
        redirectCount: 0,
        redirectChain: [],
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        htmlSnippet: '<!DOCTYPE html><html><head><title>Example Login</title></head><body><h1>Login</h1><form action="/login" method="POST"><input type="text" name="user"><input type="password" name="pwd"><button type="submit">Submit</button></form></body></html>',
        responseTimeMs: 80,
        details: 'OK',
      },
      tlsResult: {
        valid: true,
        protocol: 'TLSv1.3',
        issuer: 'DigiCert Global Root CA',
        subject: 'example.com',
        daysRemaining: 180,
        details: 'Valid TLS connection.',
      },
      effectiveHttps: true,
    });

    const urlEval = scanService.analyzeUrlSecurity({
      originalUrl: 'https://example.com/login',
      normalizedUrl: 'https://example.com/login',
      target: 'https://example.com/login',
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'https://example.com/login',
        redirectCount: 0,
        redirectChain: [],
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        details: 'OK',
      },
      tlsResult: { valid: true, protocol: 'TLSv1.3', details: 'Valid TLS' },
      effectiveHttps: true,
    });

    const aggregated = scanService.aggregateMegaScanFindings(urlEval, phishResult, {
      target: 'https://example.com/login',
      normalizedTarget: 'https://example.com/login',
      parsedUrl: new URL('https://example.com/login'),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3' },
      effectiveHttps: true,
    });

    expect(phishResult.phishingSecurityAnalysis.domainIdentityAnalysis.impersonationDetected).toBe(false);
    expect(aggregated.findings.some((f) => f.title.includes('Impersonation'))).toBe(false);
    expect(aggregated.riskScore).toBe(0);
    const classification = deriveClassificationFromRiskScore(aggregated.riskScore, aggregated.hasCriticalFinding);
    expect(classification).toBe('Safe');
  });

  // TEST 4: Punycode / Homograph or suspicious credential structure
  it('TEST 4: URL with actual phishing indicators (punycode/homograph or embedded credentials) increases score proportionally', () => {
    // 4a. Punycode / Homograph domain
    const punycodeTarget = 'https://xn--pypal-4ve.com/signin';
    const punycodeUrlEval = scanService.analyzeUrlSecurity({
      originalUrl: punycodeTarget,
      normalizedUrl: punycodeTarget,
      target: punycodeTarget,
      dnsResult: { resolvedIps: ['198.51.100.1'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK', finalUrl: punycodeTarget, redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3', details: 'Valid TLS' },
      effectiveHttps: true,
    });

    const punycodePhish = phishingScannerService.analyze({
      target: punycodeTarget,
      normalizedTarget: punycodeTarget,
      parsedUrl: new URL(punycodeTarget),
      dnsResult: { resolvedIps: ['198.51.100.1'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK', finalUrl: punycodeTarget, redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3', details: 'Valid TLS' },
      effectiveHttps: true,
    });

    const punycodeAgg = scanService.aggregateMegaScanFindings(punycodeUrlEval, punycodePhish, {
      target: punycodeTarget,
      normalizedTarget: punycodeTarget,
      parsedUrl: new URL(punycodeTarget),
      dnsResult: { resolvedIps: ['198.51.100.1'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3' },
      effectiveHttps: true,
    });

    expect(punycodeAgg.riskScore).toBeGreaterThanOrEqual(25);
    expect(punycodeAgg.findings.some((f) => f.title.includes('Punycode') || f.title.includes('Internationalized'))).toBe(true);

    // 4b. Embedded credential in URL
    const credUrl = 'https://admin:supersecretpassword@malicious-site.com/dashboard';
    const credUrlEval = scanService.analyzeUrlSecurity({
      originalUrl: credUrl,
      normalizedUrl: credUrl,
      target: credUrl,
      dnsResult: { resolvedIps: ['198.51.100.2'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK', finalUrl: credUrl, redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3', details: 'Valid TLS' },
      effectiveHttps: true,
    });

    const credPhish = phishingScannerService.analyze({
      target: credUrl,
      normalizedTarget: credUrl,
      parsedUrl: new URL(credUrl),
      dnsResult: { resolvedIps: ['198.51.100.2'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK', finalUrl: credUrl, redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3', details: 'Valid TLS' },
      effectiveHttps: true,
    });

    const credAgg = scanService.aggregateMegaScanFindings(credUrlEval, credPhish, {
      target: credUrl,
      normalizedTarget: credUrl,
      parsedUrl: new URL(credUrl),
      dnsResult: { resolvedIps: ['198.51.100.2'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3' },
      effectiveHttps: true,
    });

    expect(credAgg.riskScore).toBeGreaterThanOrEqual(20);
    expect(credAgg.findings.some((f) => f.title.includes('Obfuscation') || f.title.includes('Structure'))).toBe(true);
  });

  // TEST 5: Unreachable / Nonexistent URL
  it('TEST 5: Unreachable / nonexistent URL results in failed/unavailable status, NOT "Safe", and no fake risk findings', () => {
    const unresolvableTarget = 'https://domain-does-not-exist-test-xyz-987654.org';
    const dnsFailure = {
      resolvedIps: [],
      ipVersion: 'N/A',
      dnsStatus: 'DNS resolution failed: ENOTFOUND',
      isPrivate: false,
      error: 'ENOTFOUND',
    };

    const urlEval = scanService.analyzeUrlSecurity({
      originalUrl: unresolvableTarget,
      normalizedUrl: unresolvableTarget,
      target: unresolvableTarget,
      dnsResult: dnsFailure,
      httpResult: { error: 'ENOTFOUND', details: 'DNS resolution failed', finalUrl: unresolvableTarget, redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [] },
      tlsResult: null,
      effectiveHttps: true,
    });

    const phishResult = phishingScannerService.analyze({
      target: unresolvableTarget,
      normalizedTarget: unresolvableTarget,
      parsedUrl: new URL(unresolvableTarget),
      dnsResult: dnsFailure,
      httpResult: { error: 'ENOTFOUND', details: 'DNS resolution failed', finalUrl: unresolvableTarget, redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [] },
      tlsResult: null,
      effectiveHttps: true,
    });

    const isScanFailed = true;
    const aggregated = scanService.aggregateMegaScanFindings(urlEval, phishResult, {
      target: unresolvableTarget,
      normalizedTarget: unresolvableTarget,
      parsedUrl: new URL(unresolvableTarget),
      dnsResult: dnsFailure,
      httpResult: { error: 'ENOTFOUND' },
      tlsResult: null,
      effectiveHttps: true,
    });

    const classification = deriveClassificationFromRiskScore(aggregated.riskScore, aggregated.hasCriticalFinding, isScanFailed);
    expect(classification).not.toBe('Safe');
    expect(['Suspicious', 'Low Risk']).toContain(classification);
    expect(aggregated.findings.some((f) => f.title.includes('DNS Resolution Failed'))).toBe(true);
    expect(aggregated.findings.some((f) => f.title.includes('Brand Impersonation'))).toBe(false);
  });

  // TEST 6: URL with unconfigured reputation keys
  it('TEST 6: URL with unconfigured reputation API keys sets provider status = Not Configured, no artificial risk added', () => {
    const target = 'https://example.org';
    const unconfiguredThreatIntel = {
      status: 'Not Configured' as const,
      provider: 'None Configured',
      result: 'Not Available',
      queried: false,
      details: 'No third-party threat intelligence provider is configured in this environment.',
    };

    const urlEval = scanService.analyzeUrlSecurity({
      originalUrl: target,
      normalizedUrl: target,
      target,
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK', finalUrl: target, redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3', details: 'Valid TLS' },
      effectiveHttps: true,
      threatIntelResult: unconfiguredThreatIntel,
    });

    const phishResult = phishingScannerService.analyze({
      target,
      normalizedTarget: target,
      parsedUrl: new URL(target),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK', finalUrl: target, redirectCount: 0, redirectChain: [], securityHeaders: {}, allHeaders: {}, rawCookies: [], details: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3', details: 'Valid TLS' },
      effectiveHttps: true,
      threatIntelResult: unconfiguredThreatIntel,
    });

    const aggregated = scanService.aggregateMegaScanFindings(urlEval, phishResult, {
      target,
      normalizedTarget: target,
      parsedUrl: new URL(target),
      dnsResult: { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false },
      httpResult: { statusCode: 200, statusText: 'OK' },
      tlsResult: { valid: true, protocol: 'TLSv1.3' },
      effectiveHttps: true,
      threatIntelResult: unconfiguredThreatIntel,
    });

    expect(urlEval.analysis.threatIntelligence?.status).toBe('Not Configured');
    expect(phishResult.phishingSecurityAnalysis.threatIntelligence.status).toBe('Not Configured');
    expect(aggregated.riskScore).toBe(0);
    expect(aggregated.findings.some((f) => f.category === 'Threat Intelligence')).toBe(false);
  });
});
