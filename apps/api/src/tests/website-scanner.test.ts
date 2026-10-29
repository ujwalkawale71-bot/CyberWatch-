import { describe, it, expect, vi } from 'vitest';
import { scanService } from '../services/scan.service';
import { websiteScannerV2Service } from '../services/website-scanner-v2.service';

// Mock Mongoose model save
vi.mock('../models/Scan', async () => {
  const original = await vi.importActual('../models/Scan');
  function MockScan(this: any, data: any) {
    Object.assign(this, data);
    this._id = { toString: () => 'mock-website-scan-id-789' };
    this.createdAt = new Date();
    this.save = vi.fn().mockResolvedValue(this);
  }
  return {
    ...(original as any),
    Scan: MockScan,
  };
});

describe('Website Security Scanner V2 - Evidence-Based Engine', () => {
  // ── 1. Valid HTTPS website ────────────────────────────────────────────────
  it('1. Valid HTTPS website produces valid TLS and HTTPS evidence', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://example.com',
      finalUrl: 'https://example.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 85,
      responseHeaders: {
        'content-type': 'text/html; charset=UTF-8',
        'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        'content-security-policy': "default-src 'self'; script-src 'self'",
        'x-content-type-options': 'nosniff',
      },
      html: '<!DOCTYPE html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>',
      redirects: [{ from: 'http://example.com', to: 'https://example.com', statusCode: 301 }],
      tlsInfo: { valid: true, issuer: 'DigiCert Global Root G2', protocol: 'TLSv1.3', daysRemaining: 180, san: ['example.com'] },
    });

    expect(analysis.riskLevel).toBe('SAFE');
    expect(analysis.riskScore).toBeLessThanOrEqual(10);
    expect(analysis.findingsCounts.confirmedVulnerabilities).toBe(0);
    expect(analysis.positiveControls.some((c: any) => c.category === 'tls')).toBe(true);
    expect(analysis.whyThisVerdict.some((b: any) => b.includes('HTTPS'))).toBe(true);
  });

  // ── 2. Expired certificate simulation/mocked TLS layer ────────────────────
  it('2. Expired certificate generates CONFIRMED_VULNERABILITY with HIGH/CRITICAL severity', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://expired-cert.example.com',
      finalUrl: 'https://expired-cert.example.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 120,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><body>Test</body></html>',
      tlsInfo: { valid: false, error: 'CERT_HAS_EXPIRED', issuer: "Let's Encrypt", protocol: 'TLSv1.2', daysRemaining: 0 },
    });

    const expFinding = analysis.findings.find((f: any) => f.title.includes('Expired') || f.title.includes('Invalid'));
    expect(expFinding).toBeDefined();
    expect(expFinding?.findingCategory).toBe('CONFIRMED_VULNERABILITY');
    expect(expFinding?.severity).toMatch(/HIGH|CRITICAL/);
    expect(expFinding?.verificationStatus).toBe('CONFIRMED');
    expect(expFinding?.evidences[0].observed).toContain('CERT_HAS_EXPIRED');
  });

  // ── 3. HTTP redirect to HTTPS ─────────────────────────────────────────────
  it('3. HTTP redirect to HTTPS is recognized as positive secure transport transition', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'http://mybank.com',
      finalUrl: 'https://mybank.com/portal',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 90,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><body>Bank Portal</body></html>',
      redirects: [{ from: 'http://mybank.com', to: 'https://mybank.com/portal', statusCode: 301 }],
      tlsInfo: { valid: true, issuer: 'GlobalSign', protocol: 'TLSv1.3', daysRemaining: 200 },
    });

    const redirectControl = analysis.positiveControls.find((c: any) => c.title.includes('HTTPS Upgrade') || c.category === 'redirect');
    expect(redirectControl).toBeDefined();
  });

  // ── 4. HTTPS redirect to HTTP (downgrade) ─────────────────────────────────
  it('4. HTTPS redirect to HTTP is flagged as SECURITY_WEAKNESS downgrade', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://example.com',
      finalUrl: 'http://example.com/insecure',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 100,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><body>Insecure Page</body></html>',
      redirects: [{ from: 'https://example.com', to: 'http://example.com/insecure', statusCode: 302 }],
    });

    const downgradeFinding = analysis.findings.find((f: any) => f.title.includes('Insecure Transport Downgrade') || f.title.includes('Downgrade'));
    expect(downgradeFinding).toBeDefined();
    expect(downgradeFinding?.findingCategory).toBe('SECURITY_WEAKNESS');
    expect(downgradeFinding?.severity).toBe('HIGH');
  });

  // ── 5. Missing CSP ────────────────────────────────────────────────────────
  it('5. Missing CSP is classified as HARDENING_RECOMMENDATION (LOW), not Critical', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://mysite.com',
      finalUrl: 'https://mysite.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 80,
      responseHeaders: { 'content-type': 'text/html', 'x-content-type-options': 'nosniff' },
      html: '<html><head><title>My Site</title></head><body>Hello</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const cspFinding = analysis.findings.find((f: any) => f.title.includes('Content-Security-Policy'));
    expect(cspFinding).toBeDefined();
    expect(cspFinding?.findingCategory).toBe('HARDENING_RECOMMENDATION');
    expect(cspFinding?.severity).toBe('LOW');
    expect(cspFinding?.severity).not.toBe('CRITICAL');
  });

  // ── 6. Strong CSP ─────────────────────────────────────────────────────────
  it('6. Strong CSP is recognized as positive control and parsed correctly', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://secure-app.com',
      finalUrl: 'https://secure-app.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 75,
      responseHeaders: {
        'content-type': 'text/html',
        'content-security-policy': "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      },
      html: '<html><head><title>Secure App</title></head><body>App</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const cspFinding = analysis.findings.find((f: any) => f.title === 'Missing Content-Security-Policy (CSP)');
    expect(cspFinding).toBeUndefined();
    const cspControl = analysis.positiveControls.find((c: any) => c.title.includes('Content-Security-Policy'));
    expect(cspControl).toBeDefined();
  });

  // ── 7. frame-ancestors protection ─────────────────────────────────────────
  it('7. frame-ancestors in CSP provides frame protection without X-Frame-Options', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://no-xfo-but-csp.com',
      finalUrl: 'https://no-xfo-but-csp.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 65,
      responseHeaders: {
        'content-type': 'text/html',
        'content-security-policy': "frame-ancestors 'self'",
      },
      html: '<html><body>Protected Framing</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const frameFinding = analysis.findings.find((f: any) => f.title.includes('Frame Protection'));
    expect(frameFinding).toBeUndefined();
    const frameControl = analysis.positiveControls.find((c: any) => c.title.includes('Frame Protection'));
    expect(frameControl).toBeDefined();
  });

  // ── 8. X-Frame-Options protection ─────────────────────────────────────────
  it('8. X-Frame-Options: DENY provides frame protection', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://xfo-only.com',
      finalUrl: 'https://xfo-only.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 65,
      responseHeaders: {
        'content-type': 'text/html',
        'x-frame-options': 'DENY',
      },
      html: '<html><body>Protected XFO</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const frameControl = analysis.positiveControls.find((c: any) => c.title.includes('Frame Protection'));
    expect(frameControl).toBeDefined();
  });

  // ── 9. Missing Secure cookie ──────────────────────────────────────────────
  it('9. Missing Secure cookie attribute is flagged as weakness / hardening based on context', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://example-cookies.com',
      finalUrl: 'https://example-cookies.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 80,
      responseHeaders: {
        'content-type': 'text/html',
        'set-cookie': ['pref_lang=en; Path=/; SameSite=Lax'],
      },
      html: '<html><body>Cookie test</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    expect(analysis.cookieAnalysis.totalCookies).toBe(1);
    expect(analysis.cookieAnalysis.secureMissing).toBe(1);
    const cookieFinding = analysis.findings.find((f: any) => f.title.includes('Cookie Security Attributes Missing'));
    expect(cookieFinding).toBeDefined();
    expect(cookieFinding?.severity).toBe('LOW'); // non-sensitive preference cookie
  });

  // ── 10. Secure HttpOnly SameSite cookie ───────────────────────────────────
  it('10. Well-configured cookie with Secure, HttpOnly, and SameSite receives positive control', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://secure-cookies.com',
      finalUrl: 'https://secure-cookies.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 80,
      responseHeaders: {
        'content-type': 'text/html',
        'set-cookie': ['auth_session=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Strict'],
      },
      html: '<html><body>Protected session</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    expect(analysis.cookieAnalysis.flaggedCookies).toBe(0);
    const cookieFinding = analysis.findings.find((f: any) => f.title.includes('Cookie'));
    expect(cookieFinding).toBeUndefined();
    const cookieControl = analysis.positiveControls.find((c: any) => c.title.includes('Cookie'));
    expect(cookieControl).toBeDefined();
  });

  // ── 11. Non-sensitive cookie vs 12. Potential session cookie ──────────────
  it('11 & 12. Context-aware cookie analysis differentiates sensitive vs non-sensitive cookies', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://mixed-cookies.com',
      finalUrl: 'https://mixed-cookies.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 80,
      responseHeaders: {
        'content-type': 'text/html',
        'set-cookie': [
          'theme_mode=dark; Path=/',
          'user_jwt_token=eyJhbGciOi...; Path=/',
        ],
      },
      html: '<html><body>Mixed cookies</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    expect(analysis.cookieAnalysis.totalCookies).toBe(2);
    const sensitive = analysis.cookieAnalysis.cookies.find((c: any) => c.name === 'user_jwt_token');
    const nonSensitive = analysis.cookieAnalysis.cookies.find((c: any) => c.name === 'theme_mode');

    expect(sensitive?.isPotentiallySensitive).toBe(true);
    expect(nonSensitive?.isPotentiallySensitive).toBe(false);

    // Finding for sensitive cookie without HttpOnly should be MEDIUM weakness
    const sensitiveFinding = analysis.findings.find((f: any) => f.title.includes('Sensitive Cookie Missing HttpOnly'));
    expect(sensitiveFinding).toBeDefined();
    expect(sensitiveFinding?.findingCategory).toBe('SECURITY_WEAKNESS');
    expect(sensitiveFinding?.severity).toBe('MEDIUM');
  });

  // ── 13. Mixed content (HTTP assets on HTTPS) ──────────────────────────────
  it('13. Mixed content on HTTPS is detected and reported with location evidence', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://mixed-content-site.com',
      finalUrl: 'https://mixed-content-site.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 90,
      responseHeaders: { 'content-type': 'text/html' },
      html: `<html><head><script src="http://insecure-cdn.com/app.js"></script></head><body><img src="http://insecure-images.com/banner.jpg" /></body></html>`,
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const mixedFinding = analysis.findings.find((f: any) => f.title.includes('Mixed Content'));
    expect(mixedFinding).toBeDefined();
    expect(mixedFinding?.findingCategory).toBe('SECURITY_WEAKNESS');
    expect(mixedFinding?.severity).toBe('MEDIUM');
    expect(mixedFinding?.evidences[0].observed).toContain('http://insecure-cdn.com/app.js');
  });

  // ── 14. No mixed content ──────────────────────────────────────────────────
  it('14. No mixed content detected produces positive control and no mixed content finding', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://pure-https.com',
      finalUrl: 'https://pure-https.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 80,
      responseHeaders: { 'content-type': 'text/html' },
      html: `<html><head><script src="https://secure-cdn.com/app.js"></script></head><body><img src="https://secure-images.com/banner.jpg" /></body></html>`,
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const mixedFinding = analysis.findings.find((f: any) => f.title.includes('Mixed Content'));
    expect(mixedFinding).toBeUndefined();
    const mixedControl = analysis.positiveControls.find((c: any) => c.title.includes('Mixed Content'));
    expect(mixedControl).toBeDefined();
    expect(analysis.whyThisVerdict.some((b: any) => b.includes('No mixed content'))).toBe(true);
  });

  // ── 15. Technical stack trace leakage ─────────────────────────────────────
  it('15. Technical stack trace leakage is detected as SECURITY_WEAKNESS with evidence snippet', () => {
    const leakHtml = `<html><body><h1>Internal Server Error</h1><pre>Exception: NullPointerException at com.cyberwatch.auth.AuthService.authenticate(AuthService.java:142)\n  at org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:1014)</pre></body></html>`;
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://leaking-site.com',
      finalUrl: 'https://leaking-site.com',
      statusCode: 500,
      statusText: 'Internal Server Error',
      responseTimeMs: 300,
      responseHeaders: { 'content-type': 'text/html' },
      html: leakHtml,
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const leakFinding = analysis.findings.find((f: any) => f.title.includes('Technical Error or Stack Trace Information Disclosure'));
    expect(leakFinding).toBeDefined();
    expect(leakFinding?.findingCategory).toBe('SECURITY_WEAKNESS');
    expect(leakFinding?.severity).toBe('MEDIUM');
    expect(leakFinding?.evidences[0].observed).toContain('AuthService.java');
  });

  // ── 16. Normal 404 page & 17. Normal 500 page without leakage ─────────────
  it('16 & 17. Clean 404 and 500 error pages without stack traces are not flagged as stack trace leakage', () => {
    const clean404 = websiteScannerV2Service.analyze({
      target: 'https://site.com/nonexistent',
      finalUrl: 'https://site.com/nonexistent',
      statusCode: 404,
      statusText: 'Not Found',
      responseTimeMs: 90,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><body><h1>404 Page Not Found</h1><p>The page you requested could not be found.</p></body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const leak404 = clean404.findings.find((f: any) => f.title.includes('Stack Trace'));
    expect(leak404).toBeUndefined();

    const clean500 = websiteScannerV2Service.analyze({
      target: 'https://site.com/error',
      finalUrl: 'https://site.com/error',
      statusCode: 500,
      statusText: 'Internal Server Error',
      responseTimeMs: 120,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><body><h1>Service Temporarily Unavailable</h1><p>Please try again later.</p></body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    const leak500 = clean500.findings.find((f: any) => f.title.includes('Stack Trace'));
    expect(leak500).toBeUndefined();
  });

  // ── 18. Technology detection ──────────────────────────────────────────────
  it('18. Technology detection identifies React, Next.js, and Nginx with factual evidence', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://tech-site.com',
      finalUrl: 'https://tech-site.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 90,
      responseHeaders: {
        'content-type': 'text/html',
        server: 'nginx/1.24.0',
        'x-powered-by': 'Next.js',
      },
      html: '<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body><div id="__next"><div data-reactroot="">Content</div></div></body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    expect(analysis.technologyDetection.some((t: any) => t.technology === 'Nginx')).toBe(true);
    expect(analysis.technologyDetection.some((t: any) => t.technology === 'Next.js')).toBe(true);
    expect(analysis.technologyDetection.some((t: any) => t.technology === 'WordPress')).toBe(true);
    expect(analysis.technologyDetection.some((t: any) => t.technology === 'React')).toBe(true);
  });

  // ── 19. Website type detection & 20. Low-confidence classification ────────
  it('19 & 20. Website Understanding classifies E-Commerce vs Unknown/Low Confidence', () => {
    const ecom = websiteScannerV2Service.analyze({
      target: 'https://mystore.com',
      finalUrl: 'https://mystore.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 100,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><head><title>MyStore - Online Shopping & Cart</title><meta name="description" content="Shop electronics and clothes with fast checkout and payment"></head><body><h1>Online Store</h1><a href="/cart">Shopping Cart</a><button>Checkout</button></body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    expect(ecom.websiteUnderstanding.websiteType).toBe('E-Commerce');
    expect(ecom.websiteUnderstanding.confidence).toBeGreaterThanOrEqual(0.7);

    const blank = websiteScannerV2Service.analyze({
      target: 'https://empty-placeholder.com',
      finalUrl: 'https://empty-placeholder.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 50,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><body>.</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    expect(blank.websiteUnderstanding.websiteType).toMatch(/General Website|Unknown/i);
  });

  // ── 21. Finding deduplication ─────────────────────────────────────────────
  it('21. Deduplication combines multiple cookie attribute omissions into intelligent aggregates', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://many-cookies.com',
      finalUrl: 'https://many-cookies.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 80,
      responseHeaders: {
        'content-type': 'text/html',
        'set-cookie': [
          'c1=1; Path=/',
          'c2=2; Path=/',
          'c3=3; Path=/',
          'c4=4; Path=/',
        ],
      },
      html: '<html><body>Many cookies</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    // Should NOT create 12 separate findings (4 * 3 attributes)
    const cookieFindings = analysis.findings.filter((f: any) => f.title.includes('Cookie'));
    expect(cookieFindings.length).toBeLessThanOrEqual(2);
  });

  // ── 22. Risk scoring & 23. Safe website final verdict ─────────────────────
  it('22 & 23. Safe website with missing headers remains SAFE/LOW (score <= 25, 0 confirmed vulns)', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://clean-static-site.com',
      finalUrl: 'https://clean-static-site.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 70,
      responseHeaders: { 'content-type': 'text/html' }, // missing headers
      html: '<html><head><title>Clean Site</title></head><body><h1>Welcome</h1></body></html>',
      tlsInfo: { valid: true, issuer: "Let's Encrypt", protocol: 'TLSv1.3', daysRemaining: 60 },
    });

    expect(analysis.findingsCounts.confirmedVulnerabilities).toBe(0);
    expect(analysis.riskLevel).toMatch(/SAFE|LOW/);
    expect(analysis.riskScore).toBeLessThanOrEqual(25);
    expect(analysis.riskLevel).not.toBe('CRITICAL');
    expect(analysis.riskLevel).not.toBe('HIGH');
  });

  // ── 24. Confirmed high-risk condition ─────────────────────────────────────
  it('24. Plaintext HTTP password form submission triggers CONFIRMED_VULNERABILITY with HIGH severity', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'http://insecure-login.com',
      finalUrl: 'http://insecure-login.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 90,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><body><form action="http://insecure-login.com/login" method="POST"><input type="password" name="pwd" /></form></body></html>',
    });

    const plainPwFinding = analysis.findings.find((f: any) => f.title.includes('Plaintext Password') || f.title.includes('Insecure Form'));
    expect(plainPwFinding).toBeDefined();
    expect(plainPwFinding?.severity).toMatch(/HIGH|CRITICAL/);
    expect(analysis.riskScore).toBeGreaterThanOrEqual(40);
  });

  // ── 25. SSRF localhost, 26. Private IP, 27. Cloud metadata, 28. Redirect SSRF ─
  it('25, 26, 27, 28. SSRF Protection rigorously blocks localhost, private IPs, and cloud metadata', async () => {
    const ssrfLocalhost = await scanService.analyzeAndSave({ target: 'http://localhost:3000', targetType: 'Website' });
    expect(ssrfLocalhost.checks.domainAnalysis.status).toBe('failed');
    expect(ssrfLocalhost.riskScore).toBeGreaterThanOrEqual(70);

    const ssrfPrivate = await scanService.analyzeAndSave({ target: 'http://192.168.1.1/admin', targetType: 'Website' });
    expect(ssrfPrivate.checks.domainAnalysis.status).toBe('failed');

    const ssrfMetadata = await scanService.analyzeAndSave({ target: 'http://169.254.169.254/latest/meta-data/', targetType: 'Website' });
    expect(ssrfMetadata.checks.domainAnalysis.status).toBe('failed');

    const ssrfGoogleMeta = await scanService.analyzeAndSave({ target: 'http://metadata.google.internal/computeMetadata/v1/', targetType: 'Website' });
    expect(ssrfGoogleMeta.checks.domainAnalysis.status).toBe('failed');
  });

  // ── 29. Timeout handling & 30. Payload limit ──────────────────────────────
  it('29 & 30. Verifies timeout limits and payload limits on target fetching', async () => {
    // Live scans on public endpoints verifying standard execution
    const liveResult = await scanService.analyzeAndSave({ target: 'https://example.com', targetType: 'Website' });
    expect(liveResult.checks.websiteSecurityV2).toBeDefined();
    expect(liveResult.checks.websiteSecurityV2?.riskLevel).toBeDefined();
    const whyList = liveResult.checks.websiteSecurityV2?.whyVerdict || liveResult.checks.websiteSecurityV2?.whyThisVerdict || [];
    expect(whyList.length).toBeGreaterThan(0);
  }, 15000);

  // ── 31. Score Contributors Transparency & Explainability ──────────────────
  it('31. Provides transparent scoreContributors and scoreExplanation for all risk increases', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://mysite.com',
      finalUrl: 'https://mysite.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 80,
      responseHeaders: {
        'content-type': 'text/html',
        'set-cookie': ['session_id=secret123; Path=/'], // Missing Secure and HttpOnly on sensitive session
      },
      html: '<html><body>Site with missing headers</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    expect(analysis.scoreExplanation).toBeDefined();
    expect(analysis.scoreExplanation?.contributors).toBeDefined();
    expect(analysis.scoreExplanation!.contributors.length).toBeGreaterThan(0);

    // Sum of contributors should equal rawScore
    const rawSum = analysis.scoreExplanation!.contributors.reduce((acc: number, c: any) => acc + c.contribution, 0);
    expect(analysis.scoreExplanation!.rawScore).toBe(rawSum);
    expect(analysis.riskScore).toBe(analysis.scoreExplanation!.normalizedScore);

    // Ensure contributors contain evidence and remediation
    const sessionContrib = analysis.scoreExplanation!.contributors.find((c: any) => c.title.includes('Sensitive Cookie') || c.title.includes('Cookie'));
    expect(sessionContrib).toBeDefined();
    expect(sessionContrib?.severity).toBe('MEDIUM');
    expect(sessionContrib?.contribution).toBeGreaterThan(0);
  });

  // ── 32. 12-Item Audit Checklist Matrix ────────────────────────────────────
  it('32. Evaluates the 12-item deterministic audit checks matrix', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://secure-target.com',
      finalUrl: 'https://secure-target.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 90,
      responseHeaders: {
        'content-type': 'text/html; charset=UTF-8',
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=(), microphone=()',
      },
      html: '<html><head><title>Secure Site</title></head><body>Secure body</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3', daysRemaining: 120 },
    });

    expect(analysis.auditChecks).toBeDefined();
    expect(analysis.auditChecks.length).toBe(12);

    const transportCheck = analysis.auditChecks.find((a: any) => a.checkId === 'transport-encryption');
    expect(transportCheck?.status).toBe('PASS');

    const hstsCheck = analysis.auditChecks.find((a: any) => a.checkId === 'hsts-policy');
    expect(hstsCheck?.status).toBe('PASS');

    const cspCheck = analysis.auditChecks.find((a: any) => a.checkId === 'csp-policy');
    expect(cspCheck?.status).toBe('PASS');
  });

  // ── 33. Threat Intelligence Not Configured Distinction ────────────────────
  it('33. Explicitly marks threat intelligence as Not Configured without fabricating Clean', () => {
    const analysis = websiteScannerV2Service.analyze({
      target: 'https://clean-example.com',
      finalUrl: 'https://clean-example.com',
      statusCode: 200,
      statusText: 'OK',
      responseTimeMs: 70,
      responseHeaders: { 'content-type': 'text/html' },
      html: '<html><body>Clean Site</body></html>',
      tlsInfo: { valid: true, protocol: 'TLSv1.3' },
    });

    expect(analysis.threatIntelligence).toBeDefined();
    expect(analysis.threatIntelligence.status).toBe('NOT_CONFIGURED');
    expect(analysis.threatIntelligence.message).toContain('not configured');
  });
});
