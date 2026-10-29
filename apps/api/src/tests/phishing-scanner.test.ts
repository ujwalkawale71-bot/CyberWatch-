import { describe, it, expect, beforeEach } from 'vitest';
import { URL } from 'node:url';
import { phishingScannerService } from '../services/phishing-scanner.service';
import { scanService } from '../services/scan.service';

describe('Phishing Scanner Production-Grade Engine Tests', () => {
  const baseDnsOk = {
    resolvedIps: ['93.184.216.34'],
    ipVersion: 'IPv4',
    dnsStatus: 'Resolved',
    isPrivate: false,
  };

  const baseTlsOk = {
    valid: true,
    protocol: 'TLSv1.3',
    issuer: 'DigiCert Global Root CA',
    subject: 'example.com',
    daysRemaining: 180,
    cipher: 'TLS_AES_256_GCM_SHA384',
    details: 'Valid TLSv1.3 Certificate',
  };

  const baseHttpOk = {
    statusCode: 200,
    statusText: 'OK',
    contentType: 'text/html; charset=UTF-8',
    contentLength: 1256,
    server: 'ECS (dsa/675)',
    responseTimeMs: 85,
    finalUrl: 'https://example.com',
    redirectCount: 0,
    redirectChain: [],
    securityHeaders: {},
    allHeaders: {},
    rawCookies: [],
    htmlSnippet: '<html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples in documents.</p></body></html>',
    details: 'HTTP 200 OK',
  };

  // ── 1. Valid Normal HTTPS URL ─────────────────────────────────────────────
  it('1. Analyzes a standard benign URL with 0 risk score and clean baseline', () => {
    const url = new URL('https://example.com');
    const result = phishingScannerService.analyze({
      target: 'https://example.com',
      normalizedTarget: 'https://example.com',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: baseHttpOk,
      tlsResult: baseTlsOk,
      effectiveHttps: true,
    });

    expect(result.riskScore).toBe(0);
    expect(result.classification).toBe('Safe');
    expect(result.phishingSecurityAnalysis.status).toBe('passed');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].title).toBe('Clean Phishing Security Profile');
    expect(result.positiveSignals.length).toBeGreaterThan(0);
  });

  // ── 2. Plaintext HTTP URL (Unencrypted Transport Finding) ──────────────────
  it('2. Flags unencrypted plain HTTP transport as an evidence-based finding', () => {
    const url = new URL('http://example.com');
    const result = phishingScannerService.analyze({
      target: 'http://example.com',
      normalizedTarget: 'http://example.com',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: { ...baseHttpOk, finalUrl: 'http://example.com' },
      tlsResult: null,
      effectiveHttps: false,
    });

    expect(result.riskScore).toBeGreaterThan(0);
    const transportFinding = result.findings.find((f) => f.category.includes('Transport Security'));
    expect(transportFinding).toBeDefined();
    expect(transportFinding?.severity).toBe('MEDIUM');
    expect(transportFinding?.evidence).toBe('Protocol: http:');
  });

  // ── 3. Target Blocked by SSRF Policy ──────────────────────────────────────
  it('3. Fails scan when target resolves to private/internal IP (SSRF Protection)', () => {
    const url = new URL('http://127.0.0.1:8080');
    const result = phishingScannerService.analyze({
      target: 'http://127.0.0.1:8080',
      normalizedTarget: 'http://127.0.0.1:8080',
      parsedUrl: url,
      dnsResult: {
        resolvedIps: ['127.0.0.1'],
        ipVersion: 'IPv4',
        dnsStatus: 'Private / Loopback IP',
        isPrivate: true,
      },
      httpResult: null,
      tlsResult: null,
      effectiveHttps: false,
    });

    expect(result.phishingSecurityAnalysis.status).toBe('failed');
    expect(result.phishingSecurityAnalysis.executionOutcome).toBe('BLOCKED_BY_SSRF_POLICY');
    expect(result.classification).toBe('Critical');
    expect(result.riskScore).toBe(80);
    const ssrfFinding = result.findings.find((f) => f.severity === 'CRITICAL');
    expect(ssrfFinding).toBeDefined();
    expect(ssrfFinding?.title).toContain('SSRF Blocked');
  });

  // ── 4. DNS Resolution Failure ─────────────────────────────────────────────
  it('4. Reports failed scan status on DNS resolution failure without claiming safe', () => {
    const url = new URL('https://nonexistent-fake-domain-12345.com');
    const result = phishingScannerService.analyze({
      target: 'https://nonexistent-fake-domain-12345.com',
      normalizedTarget: 'https://nonexistent-fake-domain-12345.com',
      parsedUrl: url,
      dnsResult: {
        resolvedIps: [],
        ipVersion: 'N/A',
        dnsStatus: 'DNS query failed (ENOTFOUND)',
        isPrivate: false,
        error: 'ENOTFOUND',
      },
      httpResult: null,
      tlsResult: null,
      effectiveHttps: true,
    });

    expect(result.phishingSecurityAnalysis.status).toBe('failed');
    expect(result.phishingSecurityAnalysis.executionOutcome).toBe('DNS_FAILURE');
    expect(result.findings.some((f) => f.title.includes('DNS'))).toBe(true);
  });

  // ── 5. Connection Timeout ─────────────────────────────────────────────────
  it('5. Handles HTTP timeout honestly with failed scan outcome', () => {
    const url = new URL('https://example.com');
    const result = phishingScannerService.analyze({
      target: 'https://example.com',
      normalizedTarget: 'https://example.com',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: {
        ...baseHttpOk,
        statusCode: undefined,
        error: 'ETIMEDOUT',
      },
      tlsResult: null,
      effectiveHttps: true,
    });

    expect(result.phishingSecurityAnalysis.status).toBe('failed');
    expect(result.phishingSecurityAnalysis.executionOutcome).toBe('TIMEOUT');
  });

  // ── 6. Normal Legitimate Login Page ───────────────────────────────────────
  it('6. Does NOT falsely classify a standard first-party HTTPS login page as phishing', () => {
    const url = new URL('https://accounts.google.com/signin');
    const legitLoginHtml = `
      <html>
        <head><title>Sign in - Google Accounts</title></head>
        <body>
          <h1>Sign in with your Google Account</h1>
          <form action="https://accounts.google.com/signin/v2/challenge/pwd" method="POST">
            <input type="email" name="identifier" placeholder="Email or phone" />
            <input type="password" name="password" placeholder="Enter your password" />
            <button type="submit">Next</button>
          </form>
        </body>
      </html>
    `;

    const result = phishingScannerService.analyze({
      target: 'https://accounts.google.com/signin',
      normalizedTarget: 'https://accounts.google.com/signin',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: { ...baseHttpOk, htmlSnippet: legitLoginHtml, finalUrl: 'https://accounts.google.com/signin' },
      tlsResult: baseTlsOk,
      effectiveHttps: true,
    });

    // Legitimate first-party Google login page on google.com domain should have 0 phishing risk
    expect(result.riskScore).toBe(0);
    expect(result.classification).toBe('Safe');
    expect(result.phishingSecurityAnalysis.domainIdentityAnalysis.impersonationDetected).toBe(false);
    expect(result.phishingSecurityAnalysis.credentialAnalysis.hasPasswordField).toBe(true);
    expect(result.positiveSignals.some((s) => s.title.includes('First-Party') || s.title.includes('Login'))).toBe(true);
  });

  // ── 7. Password Input on Plaintext HTTP ───────────────────────────────────
  it('7. Flags password field served over plaintext HTTP as High Risk', () => {
    const url = new URL('http://unsecured-login.com/login');
    const httpLoginHtml = `
      <html>
        <head><title>Login</title></head>
        <body>
          <form action="/auth" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
            <button type="submit">Log In</button>
          </form>
        </body>
      </html>
    `;

    const result = phishingScannerService.analyze({
      target: 'http://unsecured-login.com/login',
      normalizedTarget: 'http://unsecured-login.com/login',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: { ...baseHttpOk, htmlSnippet: httpLoginHtml, finalUrl: 'http://unsecured-login.com/login' },
      tlsResult: null,
      effectiveHttps: false,
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(50);
    const passFinding = result.findings.find((f) => f.title.includes('Password Credential Form') || f.title.includes('Unencrypted HTTP'));
    expect(passFinding).toBeDefined();
    expect(passFinding?.severity).toBe('HIGH');
  });

  // ── 8. Form Action Submits Credentials to External Origin ─────────────────
  it('8. Flags password form that posts credentials to an external third-party domain', () => {
    const url = new URL('https://portal-check.com/login');
    const externalFormHtml = `
      <html>
        <head><title>Member Portal</title></head>
        <body>
          <form action="https://evil-credential-harvest.net/collect" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Submit</button>
          </form>
        </body>
      </html>
    `;

    const result = phishingScannerService.analyze({
      target: 'https://portal-check.com/login',
      normalizedTarget: 'https://portal-check.com/login',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: { ...baseHttpOk, htmlSnippet: externalFormHtml, finalUrl: 'https://portal-check.com/login' },
      tlsResult: baseTlsOk,
      effectiveHttps: true,
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(30);
    const extFinding = result.findings.find((f) => f.title.includes('External Destination') || f.title.includes('Third-Party Origin'));
    expect(extFinding).toBeDefined();
    expect(extFinding?.severity).toBe('HIGH');
    expect(extFinding?.evidence).toContain('evil-credential-harvest.net');
  });

  // ── 9. Direct Raw IP Hostname ─────────────────────────────────────────────
  it('9. Detects direct IP address hostname and flags as High severity observation', () => {
    const url = new URL('http://198.51.100.45/account/verify');
    const result = phishingScannerService.analyze({
      target: 'http://198.51.100.45/account/verify',
      normalizedTarget: 'http://198.51.100.45/account/verify',
      parsedUrl: url,
      dnsResult: {
        resolvedIps: ['198.51.100.45'],
        ipVersion: 'IPv4',
        dnsStatus: 'Public IP',
        isPrivate: false,
      },
      httpResult: { ...baseHttpOk, finalUrl: 'http://198.51.100.45/account/verify' },
      tlsResult: null,
      effectiveHttps: false,
    });

    const ipFinding = result.findings.find((f) => f.title.includes('Direct IP'));
    expect(ipFinding).toBeDefined();
    expect(ipFinding?.severity).toBe('HIGH');
  });

  // ── 10. Punycode IDN Homograph Domain ─────────────────────────────────────
  it('10. Detects Punycode (xn--) internationalized domain labels', () => {
    const url = new URL('https://xn--pypal-4ve.com/signin');
    const result = phishingScannerService.analyze({
      target: 'https://xn--pypal-4ve.com/signin',
      normalizedTarget: 'https://xn--pypal-4ve.com/signin',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: { ...baseHttpOk, finalUrl: 'https://xn--pypal-4ve.com/signin' },
      tlsResult: baseTlsOk,
      effectiveHttps: true,
    });

    const punyFinding = result.findings.find((f) => f.title.includes('Punycode'));
    expect(punyFinding).toBeDefined();
    expect(punyFinding?.severity).toBe('HIGH');
    expect(punyFinding?.evidence).toContain('xn--pypal-4ve');
  });

  // ── 11. Brand Impersonation & Identity Mismatch ───────────────────────────
  it('11. Detects brand identity claim mismatch (PayPal login on unauthorized domain)', () => {
    const url = new URL('https://secure-update-center-99.com/paypal/verify');
    const phishHtml = `
      <html>
        <head><title>PayPal - Account Security Verification</title></head>
        <body>
          <h1>Log in to your PayPal account</h1>
          <form action="/confirm" method="POST">
            <input type="email" name="login_email" placeholder="Email" />
            <input type="password" name="login_password" placeholder="Password" />
            <button type="submit">Log In</button>
          </form>
        </body>
      </html>
    `;

    const result = phishingScannerService.analyze({
      target: 'https://secure-update-center-99.com/paypal/verify',
      normalizedTarget: 'https://secure-update-center-99.com/paypal/verify',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: { ...baseHttpOk, htmlSnippet: phishHtml, finalUrl: 'https://secure-update-center-99.com/paypal/verify' },
      tlsResult: baseTlsOk,
      effectiveHttps: true,
    });

    expect(result.phishingSecurityAnalysis.domainIdentityAnalysis.impersonationDetected).toBe(true);
    expect(result.phishingSecurityAnalysis.domainIdentityAnalysis.claimedBrand).toBe('PayPal');
    const brandFinding = result.findings.find((f) => f.title.includes('Brand Impersonation'));
    expect(brandFinding).toBeDefined();
    expect(brandFinding?.severity).toBe('HIGH');
  });

  // ── 12. Urgency Coercion Patterns (Heuristic) ─────────────────────────────
  it('12. Detects urgency coercion phrases as heuristic indicators', () => {
    const url = new URL('https://notice-alert-portal.com');
    const urgentHtml = `
      <html>
        <head><title>Urgent Notice</title></head>
        <body>
          <h1>Security Alert: Unusual Activity</h1>
          <p>Your account will be temporarily suspended within 24 hours unless you confirm your identity.</p>
        </body>
      </html>
    `;

    const result = phishingScannerService.analyze({
      target: 'https://notice-alert-portal.com',
      normalizedTarget: 'https://notice-alert-portal.com',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: { ...baseHttpOk, htmlSnippet: urgentHtml, finalUrl: 'https://notice-alert-portal.com' },
      tlsResult: baseTlsOk,
      effectiveHttps: true,
    });

    const socialInd = result.indicators.find((i) => i.category === 'SOCIAL_ENGINEERING');
    expect(socialInd?.status).toBe('WARN');
    expect(result.phishingSecurityAnalysis.socialEngineeringAnalysis.urgencyKeywordsFound.length).toBeGreaterThan(0);
  });

  // ── 13. Multi-Signal High Risk Phishing Scenario ──────────────────────────
  it('13. Multi-signal case (brand mismatch + external form action + plaintext HTTP) produces High/Critical risk', () => {
    const url = new URL('http://microsoft-online-portal-365.info/login');
    const multiPhishHtml = `
      <html>
        <head><title>Sign in to your Microsoft account</title></head>
        <body>
          <h1>Sign in</h1>
          <p>Account suspended. Action required immediately within 24 hours.</p>
          <form action="http://data-collector-harvest.cc/dump" method="POST">
            <input type="text" name="loginfmt" />
            <input type="password" name="passwd" />
            <button type="submit">Sign In</button>
          </form>
        </body>
      </html>
    `;

    const result = phishingScannerService.analyze({
      target: 'http://microsoft-online-portal-365.info/login',
      normalizedTarget: 'http://microsoft-online-portal-365.info/login',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: { ...baseHttpOk, htmlSnippet: multiPhishHtml, finalUrl: 'http://microsoft-online-portal-365.info/login' },
      tlsResult: null,
      effectiveHttps: false,
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(75);
    expect(result.classification).toBe('Critical');
    expect(result.phishingSecurityAnalysis.domainIdentityAnalysis.impersonationDetected).toBe(true);
    expect(result.scoreContributors.length).toBeGreaterThanOrEqual(3);
  });

  // ── 14. Threat Intelligence Provider Handling ─────────────────────────────
  it('14. Reports Threat Intelligence as Not Configured without fabricating clean reputation', () => {
    const url = new URL('https://example.com');
    const result = phishingScannerService.analyze({
      target: 'https://example.com',
      normalizedTarget: 'https://example.com',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: baseHttpOk,
      tlsResult: baseTlsOk,
      effectiveHttps: true,
      threatIntelResult: undefined,
    });

    expect(result.phishingSecurityAnalysis.threatIntelligence.status).toBe('Not Configured');
    expect(result.phishingSecurityAnalysis.threatIntelligence.queried).toBe(false);
  });

  it('14b. Incorporates real configured Threat Intelligence feed hit when provided', () => {
    const url = new URL('https://known-bad-phish.net');
    const result = phishingScannerService.analyze({
      target: 'https://known-bad-phish.net',
      normalizedTarget: 'https://known-bad-phish.net',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: baseHttpOk,
      tlsResult: baseTlsOk,
      effectiveHttps: true,
      threatIntelResult: {
        status: 'Threat Detected',
        provider: 'Custom Threat Feed',
        queried: true,
        result: 'Confirmed Phishing Campaign #994',
        details: 'Listed on active credential harvesting blocklist.',
      },
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(45);
    const tiFinding = result.findings.find((f) => f.category === 'Threat Intelligence');
    expect(tiFinding).toBeDefined();
    expect(tiFinding?.severity).toBe('CRITICAL');
  });

  // ── 15. Deterministic Scoring ─────────────────────────────────────────────
  it('15. Same evidence strictly produces the exact same score (Deterministic)', () => {
    const url = new URL('https://example.com');
    const run1 = phishingScannerService.analyze({
      target: 'https://example.com',
      normalizedTarget: 'https://example.com',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: baseHttpOk,
      tlsResult: baseTlsOk,
      effectiveHttps: true,
    });

    const run2 = phishingScannerService.analyze({
      target: 'https://example.com',
      normalizedTarget: 'https://example.com',
      parsedUrl: url,
      dnsResult: baseDnsOk,
      httpResult: baseHttpOk,
      tlsResult: baseTlsOk,
      effectiveHttps: true,
    });

    expect(run1.riskScore).toBe(run2.riskScore);
    expect(run1.classification).toBe(run2.classification);
    expect(run1.findings.length).toBe(run2.findings.length);
  });
});
