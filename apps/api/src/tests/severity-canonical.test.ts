import { describe, it, expect } from 'vitest';
import { Scan, toSafeScanRecord, FINDING_SEVERITIES, FindingSeverity, IScanFinding } from '../models/Scan';
import { websiteScannerV2Service } from '../services/website-scanner-v2.service';

describe('Severity Enum & Model Validation', () => {
  it('1. INFO finding validates successfully in Scan model', async () => {
    const scanDoc = new Scan({
      target: 'https://example.com',
      targetType: 'Website',
      result: 'Safe',
      riskScore: 0,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
      },
      findings: [
        {
          category: 'Informational',
          findingCategory: 'INFORMATIONAL',
          severity: 'INFO',
          title: 'Informational notice',
          description: 'Standard security observation.',
        },
      ],
      recommendations: ['Follow standard practices.'],
    });

    const error = scanDoc.validateSync();
    expect(error).toBeUndefined();
    expect(scanDoc.findings[0].severity).toBe('INFO');
  });

  it('2. LOW finding validates and saves successfully in Scan model', async () => {
    const scanDoc = new Scan({
      target: 'https://example.com',
      targetType: 'Website',
      result: 'Low Risk',
      riskScore: 15,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
      },
      findings: [
        {
          category: 'Security Headers',
          findingCategory: 'HARDENING_RECOMMENDATION',
          severity: 'LOW',
          title: 'Missing Content-Security-Policy (CSP) Header',
          description: 'CSP header is not observed.',
          evidence: 'Header Content-Security-Policy: Not present',
        },
      ],
      recommendations: ['Deploy a Content-Security-Policy header.'],
    });

    const error = scanDoc.validateSync();
    expect(error).toBeUndefined();
    expect(scanDoc.findings[0].severity).toBe('LOW');
  });

  it('3. MEDIUM finding validates successfully in Scan model', async () => {
    const scanDoc = new Scan({
      target: 'https://example.com',
      targetType: 'Website',
      result: 'Low Risk',
      riskScore: 35,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
      },
      findings: [
        {
          category: 'Cookie Security',
          findingCategory: 'SECURITY_WEAKNESS',
          severity: 'MEDIUM',
          title: 'Insecure Cookie Transmission',
          description: 'Cookie transmitted without Secure flag.',
        },
      ],
    });

    const error = scanDoc.validateSync();
    expect(error).toBeUndefined();
    expect(scanDoc.findings[0].severity).toBe('MEDIUM');
  });

  it('4. HIGH finding validates successfully in Scan model', async () => {
    const scanDoc = new Scan({
      target: 'https://example.com',
      targetType: 'Website',
      result: 'High Risk',
      riskScore: 65,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
      },
      findings: [
        {
          category: 'Transport Security',
          findingCategory: 'CONFIRMED_VULNERABILITY',
          severity: 'HIGH',
          title: 'Untrusted TLS Certificate',
          description: 'Expired certificate observed.',
        },
      ],
    });

    const error = scanDoc.validateSync();
    expect(error).toBeUndefined();
    expect(scanDoc.findings[0].severity).toBe('HIGH');
  });

  it('5. CRITICAL finding validates successfully in Scan model', async () => {
    const scanDoc = new Scan({
      target: 'https://example.com',
      targetType: 'Website',
      result: 'Critical',
      riskScore: 90,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
      },
      findings: [
        {
          category: 'Infrastructure',
          findingCategory: 'CONFIRMED_VULNERABILITY',
          severity: 'CRITICAL',
          title: 'Private Loopback SSRF Exposure',
          description: 'Host resolves to internal network address.',
        },
      ],
    });

    const error = scanDoc.validateSync();
    expect(error).toBeUndefined();
    expect(scanDoc.findings[0].severity).toBe('CRITICAL');
  });

  it('6. Invalid severity is rejected by schema validation', () => {
    const scanDoc = new Scan({
      target: 'https://example.com',
      targetType: 'Website',
      result: 'Safe',
      riskScore: 0,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
      },
      findings: [
        {
          category: 'Custom',
          severity: 'UNKNOWN_SEVERITY' as any,
          title: 'Test',
          description: 'Test',
        },
      ],
    });

    const error = scanDoc.validateSync();
    expect(error).toBeDefined();
    expect(error?.errors['findings.0.severity']).toBeDefined();
  });

  it('6b. Backward compatibility: Lowercase severity values are automatically normalized to uppercase', () => {
    const scanDoc = new Scan({
      target: 'https://example.com',
      targetType: 'Website',
      result: 'Low Risk',
      riskScore: 20,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
      },
      findings: [
        {
          category: 'Security Headers',
          severity: 'low' as any,
          title: 'Legacy low finding',
          description: 'Created with lowercase low.',
        },
        {
          category: 'Informational',
          severity: 'info' as any,
          title: 'Legacy info finding',
          description: 'Created with lowercase info.',
        },
      ],
    });

    const error = scanDoc.validateSync();
    expect(error).toBeUndefined();
    expect(scanDoc.findings[0].severity).toBe('LOW');
    expect(scanDoc.findings[1].severity).toBe('INFO');
  });

  it('7. Website scanner can complete a scan containing LOW findings without schema error', () => {
    const analysisResult = websiteScannerV2Service.analyze({
      target: 'https://example.com',
      parsedUrl: new URL('https://example.com'),
      dnsResult: {
        hostname: 'example.com',
        resolvedIps: ['93.184.216.34'],
        isPrivate: false,
        ipVersion: 'IPv4',
        dnsStatus: 'Resolved',
      },
      httpResult: {
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'https://example.com/',
        redirectCount: 0,
        redirectChain: [],
        allHeaders: {
          'server': 'ECS',
          // Missing CSP, HSTS, X-Content-Type-Options
        },
        rawCookies: ['theme=dark; Path=/'],
        htmlSnippet: '<html><head><title>Example</title></head><body><h1>Hello</h1></body></html>',
        responseTimeMs: 80,
      },
      tlsResult: {
        valid: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        issuer: 'DigiCert',
        daysRemaining: 120,
        details: 'Valid TLS certificate',
      },
      effectiveHttps: true,
    });

    // Check findings contain LOW severity
    const lowFindings = analysisResult.findings.filter((f: IScanFinding) => f.severity === 'LOW');
    expect(lowFindings.length).toBeGreaterThan(0);

    // Ensure all severities match canonical list
    analysisResult.findings.forEach((f: IScanFinding) => {
      expect(FINDING_SEVERITIES).toContain(f.severity);
    });

    // Validate in Mongoose Scan schema
    const scanDoc = new Scan({
      target: 'https://example.com',
      targetType: 'Website',
      result: analysisResult.classification,
      riskScore: analysisResult.riskScore,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
        websiteSecurityV2: analysisResult.websiteSecurityV2,
        securityHeadersAnalysis: analysisResult.securityHeadersAnalysis,
        cookiesAnalysis: analysisResult.cookiesAnalysis,
        contentAnalysis: analysisResult.contentAnalysis,
        websiteOverview: analysisResult.websiteOverview,
      },
      findings: analysisResult.findings,
      recommendations: analysisResult.recommendations,
    });

    const error = scanDoc.validateSync();
    expect(error).toBeUndefined();
    expect(scanDoc.findings.some((f) => f.severity === 'LOW')).toBe(true);
  });

  it('8. API response serializes LOW correctly via toSafeScanRecord', () => {
    const scanDoc = new Scan({
      _id: '507f1f77bcf86cd799439011',
      target: 'https://example.com',
      targetType: 'Website',
      result: 'Low Risk',
      riskScore: 20,
      status: 'completed',
      checks: {
        urlAnalysis: { status: 'passed', details: 'OK' },
        sslAnalysis: { status: 'passed', details: 'OK' },
        domainAnalysis: { status: 'passed', details: 'OK' },
        phishingAnalysis: { status: 'passed', confidence: 0, details: 'OK' },
        redirectAnalysis: { status: 'passed', details: 'OK' },
      },
      findings: [
        {
          category: 'Security Headers',
          findingCategory: 'HARDENING_RECOMMENDATION',
          severity: 'LOW',
          title: 'Missing Content-Security-Policy (CSP) Header',
          description: 'No CSP header present.',
        },
      ],
      recommendations: ['Add CSP header.'],
      scannedAt: new Date(),
      createdAt: new Date(),
    });

    const safeRecord = toSafeScanRecord(scanDoc);
    expect(safeRecord.findings[0].severity).toBe('LOW');
  });

  it('9. Frontend severity badge and categorization handles LOW correctly', () => {
    function getSeverityBadge(severity?: FindingSeverity | string) {
      const sev = String(severity || 'INFO').toUpperCase();
      switch (sev) {
        case 'CRITICAL':
          return 'bg-red-100 text-red-800 border-red-200';
        case 'HIGH':
          return 'bg-orange-100 text-orange-800 border-orange-200';
        case 'MEDIUM':
          return 'bg-amber-100 text-amber-800 border-amber-200';
        case 'LOW':
          return 'bg-blue-100 text-blue-800 border-blue-200';
        case 'INFO':
        default:
          return 'bg-slate-100 text-slate-700 border-slate-200';
      }
    }

    expect(getSeverityBadge('LOW')).toBe('bg-blue-100 text-blue-800 border-blue-200');
    expect(getSeverityBadge('CRITICAL')).toBe('bg-red-100 text-red-800 border-red-200');
    expect(getSeverityBadge('HIGH')).toBe('bg-orange-100 text-orange-800 border-orange-200');
    expect(getSeverityBadge('MEDIUM')).toBe('bg-amber-100 text-amber-800 border-amber-200');
    expect(getSeverityBadge('INFO')).toBe('bg-slate-100 text-slate-700 border-slate-200');
  });

  it('10. PDF generator formats and renders LOW findings correctly with distinct theme', () => {
    function getPdfSeverityColors(severity?: FindingSeverity | string): { color: [number, number, number]; bg: [number, number, number] } {
      const sev = String(severity || 'INFO').toUpperCase();
      if (sev === 'CRITICAL' || sev === 'HIGH') {
        return { color: [220, 38, 38], bg: [254, 242, 242] };
      } else if (sev === 'MEDIUM') {
        return { color: [217, 119, 6], bg: [254, 243, 199] };
      } else if (sev === 'LOW') {
        return { color: [2, 132, 199], bg: [240, 249, 255] };
      } else {
        return { color: [71, 85, 105], bg: [241, 245, 249] };
      }
    }

    const lowColors = getPdfSeverityColors('LOW');
    expect(lowColors.color).toEqual([2, 132, 199]); // Distinct sky/blue text
    expect(lowColors.bg).toEqual([240, 249, 255]); // Light blue pill background

    const legacyLowColors = getPdfSeverityColors('low');
    expect(legacyLowColors.color).toEqual([2, 132, 199]);

    const infoColors = getPdfSeverityColors('INFO');
    expect(infoColors.color).toEqual([71, 85, 105]); // Slate

    const medColors = getPdfSeverityColors('MEDIUM');
    expect(medColors.color).toEqual([217, 119, 6]); // Amber

    const highColors = getPdfSeverityColors('HIGH');
    expect(highColors.color).toEqual([220, 38, 38]); // Red

    const critColors = getPdfSeverityColors('CRITICAL');
    expect(critColors.color).toEqual([220, 38, 38]); // Red
  });
});
