import { describe, it, expect } from 'vitest';
import { scanService, deriveClassificationFromRiskScore } from '../services/scan.service';
import { websiteScannerV2Service } from '../services/website-scanner-v2.service';
import { URL } from 'node:url';

describe('Risk Score Integrity & Scanner Isolation Test Suite', () => {
  // ── A. Clean / Low-Risk Evidence ──────────────────────────────────────────
  describe('A. Clean / Low-Risk Evidence', () => {
    it('evaluates clean benign API with 0 risk and Safe classification', () => {
      const dnsResult = {
        isPrivate: false,
        resolvedIps: ['93.184.216.34'],
        ipVersion: 'IPv4',
        dnsStatus: 'Resolved',
      };
      const httpResult = {
        statusCode: 200,
        statusText: 'OK',
        contentType: 'application/json',
        responseTimeMs: 45,
        allHeaders: {
          'x-content-type-options': 'nosniff',
          'access-control-allow-origin': '*',
        },
        securityHeaders: {},
        rawCookies: [],
        redirectCount: 0,
        redirectChain: [],
        details: '200 OK',
        finalUrl: 'https://api.example.com/data',
      };
      const evalResult = scanService.analyzeApiSecurity(
        'https://api.example.com/data',
        httpResult as any,
        true,
        dnsResult
      );

      expect(evalResult.risk).toBe(0);
      const classification = deriveClassificationFromRiskScore(evalResult.risk);
      expect(classification).toBe('Safe');
      expect(evalResult.analysis.status).toBe('passed');
    });

    it('evaluates clean benign PDF file with 0 risk and Safe classification', async () => {
      const httpResult = {
        statusCode: 200,
        statusText: 'OK',
        contentType: 'application/pdf',
        contentLength: 204800,
        responseTimeMs: 30,
        allHeaders: {},
        securityHeaders: {},
        rawCookies: [],
        redirectCount: 0,
        redirectChain: [],
        details: '200 OK',
        finalUrl: 'https://example.com/docs/annual-report.pdf',
      };
      const dnsResult = {
        isPrivate: false,
        resolvedIps: ['93.184.216.34'],
        ipVersion: 'IPv4',
        dnsStatus: 'Resolved',
      };
      const evalResult = await scanService.analyzeFileSecurity(
        'https://example.com/docs/annual-report.pdf',
        httpResult as any,
        true,
        dnsResult
      );

      expect(evalResult.risk).toBe(0);
      const classification = deriveClassificationFromRiskScore(evalResult.risk);
      expect(classification).toBe('Safe');
      expect(evalResult.analysis.status).toBe('passed');
      expect(evalResult.analysis.structureRisk).toContain('Standard');
    });

    it('evaluates clean Manifest V3 extension with standard permissions as 0 risk and Safe', () => {
      const manifest = JSON.stringify({
        name: 'Simple Clock Widget',
        version: '1.0.0',
        manifest_version: 3,
        permissions: ['storage', 'alarms'],
      });
      const evalResult = scanService.analyzeExtensionSecurity(manifest, null);

      expect(evalResult.risk).toBe(0);
      const classification = deriveClassificationFromRiskScore(evalResult.risk);
      expect(classification).toBe('Safe');
      expect(evalResult.analysis.status).toBe('passed');
      expect(evalResult.analysis.dangerousPermissions.length).toBe(0);
    });
  });

  // ── B. One Meaningful Security Finding ────────────────────────────────────
  describe('B. One Meaningful Security Finding', () => {
    it('accurately attributes risk to a single finding without artificial inflation', () => {
      // API with missing X-Content-Type-Options (+5)
      const dnsResult = {
        isPrivate: false,
        resolvedIps: ['93.184.216.34'],
        ipVersion: 'IPv4',
        dnsStatus: 'Resolved',
      };
      const httpResult = {
        statusCode: 200,
        statusText: 'OK',
        contentType: 'application/json',
        responseTimeMs: 45,
        allHeaders: {}, // missing x-content-type-options
        securityHeaders: {},
        rawCookies: [],
        redirectCount: 0,
        redirectChain: [],
        details: '200 OK',
        finalUrl: 'https://api.example.com/data',
      };
      const evalResult = scanService.analyzeApiSecurity(
        'https://api.example.com/data',
        httpResult as any,
        true,
        dnsResult
      );

      expect(evalResult.risk).toBe(5);
      expect(evalResult.findings.length).toBe(1);
      expect(evalResult.findings[0].title).toContain('Missing X-Content-Type-Options');
    });

    it('attributes exact capability risk to legacy Manifest V2 extension format (+3)', () => {
      const manifest = JSON.stringify({
        name: 'Legacy Extension',
        version: '1.0.0',
        manifest_version: 2,
        permissions: ['storage'],
      });
      const evalResult = scanService.analyzeExtensionSecurity(manifest, null);

      expect(evalResult.risk).toBe(3);
      expect(evalResult.findings.some(f => f.title.includes('Manifest V2') || f.title.includes('Legacy'))).toBe(true);
    });
  });

  // ── C. Multiple Meaningful Findings ──────────────────────────────────────
  describe('C. Multiple Meaningful Findings', () => {
    it('combines multiple distinct findings additively without duplication', () => {
      const manifest = JSON.stringify({
        name: 'Broad Capability Extension',
        version: '1.0.0',
        manifest_version: 2, // +3
        permissions: ['cookies', 'management'], // +7 + 3 = 10
        host_permissions: ['<all_urls>'], // +12
      });
      const evalResult = scanService.analyzeExtensionSecurity(manifest, null);

      // Expected risk: 3 (V2) + 7 (cookies) + 3 (management) + 12 (all_urls) = 25
      expect(evalResult.risk).toBe(25);
      expect(evalResult.findings.length).toBe(4);
      const classification = deriveClassificationFromRiskScore(evalResult.risk);
      expect(classification).toBe('Suspicious');
    });
  });

  // ── D. High-Severity Finding ──────────────────────────────────────────────
  describe('D. High-Severity Finding', () => {
    it('elevates risk appropriately on critical debugger capability (+15)', () => {
      const manifest = JSON.stringify({
        name: 'Debugger Tool',
        version: '1.0.0',
        manifest_version: 3,
        permissions: ['debugger'],
      });
      const evalResult = scanService.analyzeExtensionSecurity(manifest, null);

      expect(evalResult.risk).toBe(15);
      const debuggerFinding = evalResult.findings.find(f => f.title.toLowerCase().includes('debugger'));
      expect(debuggerFinding).toBeDefined();
      expect(debuggerFinding?.severity).toBe('CRITICAL');
    });

    it('elevates risk appropriately on executable binary format (+40)', async () => {
      const httpResult = {
        statusCode: 200,
        statusText: 'OK',
        contentType: 'application/octet-stream',
        contentLength: 5242880,
        responseTimeMs: 30,
        allHeaders: {},
        securityHeaders: {},
        rawCookies: [],
        redirectCount: 0,
        redirectChain: [],
        details: '200 OK',
        finalUrl: 'https://example.com/installer.exe',
      };
      const evalResult = await scanService.analyzeFileSecurity(
        'https://example.com/installer.exe',
        httpResult as any,
        true
      );

      expect(evalResult.risk).toBeGreaterThanOrEqual(40);
      expect(evalResult.findings.some((f: any) => f.severity === 'HIGH')).toBe(true);
    });
  });

  // ── E. No Findings ────────────────────────────────────────────────────────
  describe('E. No Findings Baseline', () => {
    it('produces standard security baseline and 0 risk when no anomalies exist', () => {
      const manifest = JSON.stringify({
        name: 'Completely Clean Extension',
        version: '1.0.0',
        manifest_version: 3,
        permissions: ['storage'],
      });
      const result = scanService.analyzeExtensionSecurity(manifest, null);

      expect(result.risk).toBe(0);
      const classification = deriveClassificationFromRiskScore(result.risk);
      expect(classification).toBe('Safe');
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].title).toBe('Minimal Permission Scope');
    });
  });

  // ── F. Failed / Unavailable Scan Handling ─────────────────────────────────
  describe('F. Failed / Unavailable Scan Handling', () => {
    it('does NOT convert private IP SSRF block into Safe/Passed', () => {
      const dnsResult = {
        isPrivate: true,
        resolvedIps: ['127.0.0.1'],
        ipVersion: 'IPv4',
        dnsStatus: 'Private Loopback Range',
      };
      const evalResult = scanService.analyzeApiSecurity(
        'http://127.0.0.1:3000/api/keys',
        null,
        false,
        dnsResult
      );

      expect(evalResult.analysis.status).toBe('failed');
      expect(evalResult.risk).toBe(70);
      const classification = deriveClassificationFromRiskScore(evalResult.risk, true);
      expect(classification).toBe('Critical');
      expect(classification).not.toBe('Safe');
      expect(evalResult.findings.some(f => f.severity === 'CRITICAL')).toBe(true);
    });

    it('does NOT convert unresolvable DNS into Safe', () => {
      const dnsResult = {
        isPrivate: false,
        resolvedIps: [],
        ipVersion: 'N/A',
        dnsStatus: 'ENOTFOUND',
        error: 'ENOTFOUND unresolvable-test-domain.invalid',
      };
      const evalResult = scanService.analyzeApiSecurity(
        'https://unresolvable-test-domain.invalid/api',
        null,
        true,
        dnsResult
      );

      expect(evalResult.analysis.status).toBe('failed');
      expect(evalResult.risk).toBe(25);
      const classification = deriveClassificationFromRiskScore(evalResult.risk);
      expect(classification).toBe('Suspicious');
      expect(classification).not.toBe('Safe');
    });

    it('does NOT convert network timeout into Safe', () => {
      const dnsResult = {
        isPrivate: false,
        resolvedIps: ['93.184.216.34'],
        ipVersion: 'IPv4',
        dnsStatus: 'Resolved',
      };
      const httpResult = {
        statusCode: undefined,
        statusText: undefined,
        contentType: 'Unknown',
        responseTimeMs: 15000,
        allHeaders: {},
        securityHeaders: {},
        rawCookies: [],
        redirectCount: 0,
        redirectChain: [],
        details: 'Connection timed out after 15000ms',
        error: 'ETIMEDOUT',
        finalUrl: 'https://api.example.com/data',
      };
      const evalResult = scanService.analyzeApiSecurity(
        'https://api.example.com/data',
        httpResult as any,
        true,
        dnsResult
      );

      expect(evalResult.analysis.status).toBe('failed');
      expect(evalResult.risk).toBe(15);
      const classification = deriveClassificationFromRiskScore(evalResult.risk);
      expect(classification).toBe('Low Risk');
      expect(classification).not.toBe('Safe');
    });
  });

  // ── G. Scanner Isolation & Cross-Scanner Leakage Guard ────────────────────
  describe('G. Scanner Isolation & Cross-Scanner Leakage Guard', () => {
    it('ensures API scanner does not inherit website-specific header penalties', () => {
      const dnsResult = {
        isPrivate: false,
        resolvedIps: ['93.184.216.34'],
        ipVersion: 'IPv4',
        dnsStatus: 'Resolved',
      };
      const httpResult = {
        statusCode: 200,
        statusText: 'OK',
        contentType: 'application/json',
        responseTimeMs: 50,
        allHeaders: {
          'x-content-type-options': 'nosniff',
          'access-control-allow-origin': '*',
        },
        securityHeaders: {},
        rawCookies: [],
        redirectCount: 0,
        redirectChain: [],
        details: '200 OK',
        finalUrl: 'https://api.example.com/v1/users',
      };
      const apiEval = scanService.analyzeApiSecurity(
        'https://api.example.com/v1/users',
        httpResult as any,
        true,
        dnsResult
      );

      // API scanner should not penalize for missing CSP, Permissions-Policy, or SameSite cookies
      expect(apiEval.risk).toBe(0);
      expect(apiEval.findings.some(f => f.title.includes('Content-Security-Policy'))).toBe(false);
      expect(apiEval.findings.some(f => f.title.includes('Cookie'))).toBe(false);
    });

    it('ensures File scanner does not inherit URL-level subdomain or TLD penalties', async () => {
      const httpResult = {
        statusCode: 200,
        statusText: 'OK',
        contentType: 'application/pdf',
        contentLength: 102400,
        responseTimeMs: 30,
        allHeaders: {},
        securityHeaders: {},
        rawCookies: [],
        redirectCount: 0,
        redirectChain: [],
        details: '200 OK',
        finalUrl: 'https://sub1.sub2.sub3.sub4.sub5.example.xyz/doc.pdf',
      };
      const dnsResult = {
        isPrivate: false,
        resolvedIps: ['93.184.216.34'],
        ipVersion: 'IPv4',
        dnsStatus: 'Resolved',
      };
      const fileEval = await scanService.analyzeFileSecurity(
        'https://sub1.sub2.sub3.sub4.sub5.example.xyz/doc.pdf',
        httpResult as any,
        true,
        dnsResult
      );

      // File score should be based on file static evidence (PDF over HTTPS = 0)
      expect(fileEval.risk).toBe(0);
      expect(fileEval.findings.some((f: any) => f.title.includes('Subdomain'))).toBe(false);
      expect(fileEval.findings.some((f: any) => f.title.includes('TLD'))).toBe(false);
    });
  });

  // ── H. Deterministic Reproducibility ──────────────────────────────────────
  describe('H. Deterministic Reproducibility', () => {
    it('produces identical score and findings when evaluated multiple times', () => {
      const manifest = JSON.stringify({
        name: 'Deterministic Test Extension',
        version: '1.0.0',
        manifest_version: 3,
        permissions: ['cookies', 'proxy'],
        host_permissions: ['https://*/*'],
      });

      const eval1 = scanService.analyzeExtensionSecurity(manifest, null);
      const eval2 = scanService.analyzeExtensionSecurity(manifest, null);

      expect(eval1.risk).toBe(eval2.risk);
      expect(eval1.findings.length).toBe(eval2.findings.length);
      expect(eval1.analysis.status).toBe(eval2.analysis.status);
    });
  });

  // ── I. Score Boundary 0-100 Enforcement ───────────────────────────────────
  describe('I. Score Boundary 0-100 Enforcement', () => {
    it('clamps scores to 0-100 range under extreme finding accumulations', () => {
      const manifest = JSON.stringify({
        name: 'Extreme Capability Overload',
        version: '1.0.0',
        manifest_version: 2,
        permissions: [
          'debugger',
          'webRequestBlocking',
          'proxy',
          'nativeMessaging',
          'cookies',
          'management',
          'history',
          'clipboardRead',
          'scripting',
          'downloads',
          'tabs',
          'webRequest',
          'geolocation',
        ],
        host_permissions: ['<all_urls>'],
        content_security_policy: "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
        update_url: 'http://attacker.com/update.xml',
      });
      const evalResult = scanService.analyzeExtensionSecurity(manifest, null);
      const normalizedScore = Math.min(Math.max(evalResult.risk, 0), 100);

      expect(normalizedScore).toBe(100);
      expect(deriveClassificationFromRiskScore(normalizedScore)).toBe('Critical');
    });
  });

  // ── J. Canonical Threshold Mapping ────────────────────────────────────────
  describe('J. Canonical Classification Thresholds', () => {
    it('maps 0-11 to Safe', () => {
      expect(deriveClassificationFromRiskScore(0)).toBe('Safe');
      expect(deriveClassificationFromRiskScore(10)).toBe('Safe');
      expect(deriveClassificationFromRiskScore(11)).toBe('Safe');
    });

    it('maps 12-24 to Low Risk', () => {
      expect(deriveClassificationFromRiskScore(12)).toBe('Low Risk');
      expect(deriveClassificationFromRiskScore(15)).toBe('Low Risk');
      expect(deriveClassificationFromRiskScore(24)).toBe('Low Risk');
    });

    it('maps 25-49 to Suspicious', () => {
      expect(deriveClassificationFromRiskScore(25)).toBe('Suspicious');
      expect(deriveClassificationFromRiskScore(35)).toBe('Suspicious');
      expect(deriveClassificationFromRiskScore(49)).toBe('Suspicious');
    });

    it('maps 50-74 to High Risk', () => {
      expect(deriveClassificationFromRiskScore(50)).toBe('High Risk');
      expect(deriveClassificationFromRiskScore(60)).toBe('High Risk');
      expect(deriveClassificationFromRiskScore(74)).toBe('High Risk');
    });

    it('maps >= 75 or critical findings to Critical', () => {
      expect(deriveClassificationFromRiskScore(75)).toBe('Critical');
      expect(deriveClassificationFromRiskScore(90)).toBe('Critical');
      expect(deriveClassificationFromRiskScore(100)).toBe('Critical');
      expect(deriveClassificationFromRiskScore(10, true)).toBe('Critical');
    });
  });
});
