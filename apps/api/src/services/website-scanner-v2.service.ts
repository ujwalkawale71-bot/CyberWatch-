import {
  IScanFinding,
  ISecurityEvidence,
  IWebsiteSecurityV2Analysis,
  IWebsiteScoreContributor,
  IWebsiteScoreExplanation,
  IWebsiteAuditCheck,
  IScanChecks,
  ScanResultClassification,
  FindingCategory,
  FindingVerificationStatus,
  FindingSeverity,
} from '../models/Scan';

export interface WebsiteV2Input {
  target: string;
  parsedUrl: URL;
  dnsResult: {
    resolvedIps: string[];
    ipVersion: string;
    dnsStatus: string;
    isPrivate: boolean;
    error?: string;
  };
  httpResult: {
    statusCode?: number;
    statusText?: string;
    contentType?: string;
    contentLength?: number;
    server?: string;
    responseTimeMs?: number;
    finalUrl: string;
    redirectCount: number;
    redirectChain: Array<{ url: string; statusCode?: number; statusText?: string }>;
    securityHeaders: Record<string, string>;
    allHeaders: Record<string, string>;
    rawCookies: string[];
    htmlSnippet?: string;
    bodySnippet?: string;
    details: string;
    error?: string;
  } | null;
  tlsResult: {
    valid?: boolean;
    protocol?: string;
    issuer?: string;
    subject?: string;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    cipher?: string;
    details: string;
    error?: string;
  } | null;
  effectiveHttps: boolean;
}

export interface WebsiteV2AnalysisResult {
  websiteSecurityV2: IWebsiteSecurityV2Analysis;
  findings: IScanFinding[];
  recommendations: string[];
  riskScore: number;
  riskLevel: 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  confidence: number;
  executionOutcome?: 'COMPLETED' | 'BLOCKED_BY_SSRF_POLICY' | 'TARGET_UNREACHABLE' | 'TIMEOUT' | 'DNS_FAILURE' | 'ANALYSIS_UNAVAILABLE' | 'FAILED';
  findingsCounts: {
    confirmedVulnerabilities: number;
    securityWeaknesses: number;
    hardeningRecommendations: number;
    informationalFindings: number;
    total: number;
  };
  whyThisVerdict: string[];
  whyVerdict: string[];
  scoreContributors: IWebsiteScoreContributor[];
  scoreExplanation: IWebsiteScoreExplanation;
  positiveControls: Array<{ title: string; desc: string; category?: string; evidence?: string }>;
  cookieAnalysis: {
    totalCookies: number;
    secureMissing: number;
    httpOnlyMissing: number;
    sameSiteMissing: number;
    flaggedCookies: number;
    cookies: Array<{
      name: string;
      valueMasked?: string;
      secure: boolean;
      httpOnly: boolean;
      sameSite?: string;
      domain?: string;
      path?: string;
      expires?: string;
      maxAge?: string;
      isPotentiallySensitive: boolean;
      isFlagged: boolean;
      issues: string[];
      details?: string;
    }>;
    table: any[];
  };
  cookiesAnalysis: NonNullable<IScanChecks['cookiesAnalysis']>;
  technologyDetection: Array<{ technology: string; category?: string; evidence: string; confidence: number }>;
  websiteUnderstanding: {
    websiteType: string;
    industry: string;
    primaryPurpose: string;
    confidence: number;
    confidenceLabel: string;
    evidence: string[];
    pageTitle?: string;
    metaDescription?: string;
    headings?: string[];
    canonicalUrl?: string;
  };
  classification: ScanResultClassification;
  securityHeadersAnalysis: NonNullable<IScanChecks['securityHeadersAnalysis']>;
  contentAnalysis: NonNullable<IScanChecks['contentAnalysis']>;
  websiteOverview: NonNullable<IScanChecks['websiteOverview']>;
  auditChecks?: IWebsiteAuditCheck[];
  threatIntelligence?: { status: string; message: string; provider?: string };
}

export class WebsiteScannerV2Service {
  /**
   * Helper to decode standard HTML entities safely.
   */
  public decodeHtmlEntities(str: string): string {
    return str
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#39;|&apos;|&#x27;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&nbsp;/g, ' ')
      .replace(/&middot;/g, '·')
      .replace(/&#8211;/g, '–')
      .replace(/&#8212;/g, '—')
      .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Detect stack traces, database exceptions, internal paths, and debug information.
   */
  public detectTechnicalErrorLeakage(
    body: string | undefined,
    headers: Record<string, string>
  ): { detected: boolean; findings: string[]; details?: string; leakEvidence: string[] } {
    if (!body || body.length < 5) {
      return { detected: false, findings: [], leakEvidence: [] };
    }

    const leakFindings: string[] = [];
    const leakEvidence: string[] = [];

    // 1. Stack Traces (Java, Node, Python, C#, PHP, Go)
    const stackTracePatterns = [
      /at\s+[\w$./\\-]+\s*\([\w$./\\-]+:\d+(?::\d+)?\)/i,
      /at\s+[\w$./\\-]+\s*\([\w$./\\-]+\.java:\d+\)/i,
      /Traceback\s+\(most\s+recent\s+call\s+last\):/i,
      /(?:Exception|Error)\s+in\s+thread\s+"[\w-]+"/i,
      /(?:NullPointerException|IllegalArgumentException|SQLException|ClassNotFoundException)/i,
      /java\.lang\.[\w$]+Exception/i,
      /Fatal\s+error:\s+Uncaught\s+/i,
      /System\.(?:NullReference|Argument|InvalidOperation)Exception:/i,
      /goroutine\s+\d+\s+\[running\]:/i,
    ];

    for (const pattern of stackTracePatterns) {
      const match = body.match(pattern);
      if (match) {
        leakFindings.push('Technical stack trace disclosure observed in response body.');
        leakEvidence.push(match[0].slice(0, 120));
        break;
      }
    }

    // 2. Database Error Messages
    const dbPatterns = [
      /SQL\s+syntax.*MySQL/i,
      /ORA-\d{5}/i,
      /PostgreSQL.*ERROR:\s+/i,
      /sqlite3\.OperationalError/i,
      /MongoServerError:/i,
      /Unclosed\s+quotation\s+mark\s+after\s+the\s+character\s+string/i,
      /Microsoft\s+OLE\s+DB\s+Provider\s+for\s+SQL\s+Server/i,
    ];

    for (const pattern of dbPatterns) {
      const match = body.match(pattern);
      if (match) {
        leakFindings.push('Database error message disclosure observed.');
        leakEvidence.push(match[0].slice(0, 120));
        break;
      }
    }

    // 3. Sensitive Internal Filesystem Paths
    const pathPatterns = [
      /(?:\/var\/www\/[\w./\\-]+)/i,
      /(?:[A-Z]:\\inetpub\\wwwroot\\[\w./\\-]+)/i,
      /(?:\/home\/[a-z0-9_-]+\/(?:app|public_html|src)\/[\w./\\-]+)/i,
    ];

    for (const pattern of pathPatterns) {
      const match = body.match(pattern);
      if (match) {
        leakFindings.push('Internal filesystem path disclosed in response.');
        leakEvidence.push(match[0].slice(0, 100));
        break;
      }
    }

    // 4. Debug Mode Markers
    if (
      body.includes('DJANGO_SETTINGS_MODULE') ||
      body.includes('Whoops! There was an error.') ||
      body.includes('Symfony \\ Component \\ ErrorHandler')
    ) {
      leakFindings.push('Framework debug/error handler screen exposed.');
      leakEvidence.push('Active framework debug handler');
    }

    return {
      detected: leakFindings.length > 0,
      findings: leakFindings,
      details: leakFindings.length > 0 ? leakFindings.join(' ') : undefined,
      leakEvidence,
    };
  }

  /**
   * Evidence-based Technology Detection without guessing.
   */
  public detectTechnologies(
    headers: Record<string, string>,
    html: string | undefined
  ): Array<{ technology: string; category?: string; evidence: string; confidence: number }> {
    const results: Array<{ technology: string; category?: string; evidence: string; confidence: number }> = [];
    const seen = new Set<string>();

    const addTech = (technology: string, category: string, evidence: string, confidence: number) => {
      if (!seen.has(technology)) {
        seen.add(technology);
        results.push({ technology, category, evidence, confidence });
      }
    };

    // 1. Headers
    const server = headers['server'];
    if (server) {
      if (server.toLowerCase().includes('nginx')) {
        addTech('Nginx', 'Web Server', `Server response header: ${server}`, 0.95);
      } else if (server.toLowerCase().includes('apache')) {
        addTech('Apache HTTP Server', 'Web Server', `Server response header: ${server}`, 0.95);
      } else if (server.toLowerCase().includes('cloudflare')) {
        addTech('Cloudflare', 'CDN & Reverse Proxy', `Server response header: ${server}`, 0.95);
      } else {
        addTech(server, 'Web Server', `Server response header: ${server}`, 0.90);
      }
    }

    const poweredBy = headers['x-powered-by'];
    if (poweredBy) {
      if (poweredBy.toLowerCase().includes('next.js') || poweredBy.toLowerCase() === 'nextjs') {
        addTech('Next.js', 'Application Framework', `X-Powered-By header: ${poweredBy}`, 0.98);
      } else if (poweredBy.toLowerCase().includes('express')) {
        addTech('Express.js', 'Web Framework', `X-Powered-By header: ${poweredBy}`, 0.98);
      } else {
        addTech(poweredBy, 'Application Framework', `X-Powered-By header: ${poweredBy}`, 0.95);
      }
    }

    const aspNet = headers['x-aspnet-version'];
    if (aspNet) {
      addTech(`ASP.NET v${aspNet}`, 'Framework', `X-AspNet-Version header: ${aspNet}`, 0.98);
    }
    const generator = headers['x-generator'];
    if (generator) {
      addTech(generator, 'CMS / Platform', `X-Generator header: ${generator}`, 0.95);
    }
    if (headers['cf-ray'] || headers['cf-cache-status'] || (server && server.toLowerCase().includes('cloudflare'))) {
      addTech('Cloudflare Edge Network', 'CDN & Reverse Proxy', 'CF-Ray / Server header detected', 0.98);
    }
    if (headers['via']?.toLowerCase().includes('cloudfront') || headers['x-amz-cf-id']) {
      addTech('Amazon CloudFront', 'CDN', 'CloudFront headers detected', 0.98);
    }
    if (headers['x-vercel-id']) {
      addTech('Vercel Edge Platform', 'PaaS / Hosting', 'X-Vercel-Id header detected', 0.98);
    }
    if (headers['x-nf-request-id']) {
      addTech('Netlify Edge', 'PaaS / Hosting', 'X-Nf-Request-Id header detected', 0.98);
    }

    // 2. HTML Markers & Meta Tags
    if (html && html.length > 0) {
      const metaGenMatch = html.match(/<meta\b[^>]*\bname=["']generator["'][^>]*\bcontent=["']([^"']+)["']/i);
      if (metaGenMatch && metaGenMatch[1]) {
        const gen = this.decodeHtmlEntities(metaGenMatch[1]);
        if (gen.toLowerCase().includes('wordpress')) {
          addTech('WordPress', 'CMS / Blogging', `<meta name="generator" content="${metaGenMatch[1]}">`, 0.98);
        } else {
          addTech(gen, 'CMS / Generator', `<meta name="generator" content="${metaGenMatch[1]}">`, 0.95);
        }
      }

      if (html.includes('/wp-content/') || html.includes('/wp-includes/')) {
        addTech('WordPress', 'CMS / Blogging', 'Observed /wp-content/ asset paths in HTML', 0.95);
      }
      if (html.includes('/_next/') || html.includes('id="__next"')) {
        addTech('Next.js', 'Web Framework', 'Observed Next.js container / bundle structure', 0.95);
      }
      if (html.includes('/_nuxt/')) {
        addTech('Nuxt (Vue.js)', 'Web Framework', 'Observed /_nuxt/ JavaScript bundles', 0.95);
      }
      if (html.includes('cdn.shopify.com')) {
        addTech('Shopify', 'E-Commerce Platform', 'Observed Shopify CDN assets', 0.95);
      }
      if (html.includes('bootstrap.min.css') || html.includes('bootstrap.css')) {
        addTech('Bootstrap CSS', 'UI Framework', 'Observed Bootstrap stylesheet link', 0.90);
      }
      if (html.includes('tailwind') || html.includes('tailwindcss')) {
        addTech('Tailwind CSS', 'CSS Framework', 'Observed Tailwind stylesheet or classes', 0.85);
      }
      if (html.includes('data-reactroot') || html.includes('react.production.min.js') || html.includes('react-dom') || html.includes('/_next/')) {
        addTech('React', 'JavaScript Library', 'Observed React library / root attribute', 0.90);
      }
      if (html.includes('vue.min.js') || html.includes('vue.global.js')) {
        addTech('Vue.js', 'JavaScript Framework', 'Observed Vue.js library scripts', 0.90);
      }
    }

    return results;
  }

  /**
   * Safe passive Website Understanding & Classification.
   * Deterministic signals from HTML, title, meta description, and keywords.
   */
  public analyzeWebsiteUnderstanding(
    html: string | undefined,
    finalUrl: string,
    techs: Array<{ technology: string; category?: string }>
  ): {
    websiteType: string;
    industry: string;
    primaryPurpose: string;
    confidence: number;
    confidenceLabel: 'High' | 'Medium' | 'Low' | 'Unknown';
    evidence: string[];
    pageTitle?: string;
    metaDescription?: string;
    headings: string[];
    keywords: string[];
    canonicalUrl?: string;
  } {
    let pageTitle: string | undefined = undefined;
    let metaDescription: string | undefined = undefined;
    let canonicalUrl: string | undefined = undefined;
    const headings: string[] = [];
    const keywords: string[] = [];
    const evidenceList: string[] = [];

    if (html && html.length > 0) {
      // 1. Page Title
      const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
      if (titleMatch && titleMatch[1]) {
        pageTitle = this.decodeHtmlEntities(titleMatch[1].replace(/<[^>]+>/g, '')).trim();
        if (pageTitle) evidenceList.push(`Page Title: "${pageTitle}"`);
      }

      // 2. Meta Description
      const metaDescMatch =
        html.match(/<meta\b[^>]*\b(?:name|property)=["'](?:description|og:description)["'][^>]*\bcontent=["']([^"']*)["']/i) ||
        html.match(/<meta\b[^>]*\bcontent=["']([^"']*)["'][^>]*\b(?:name|property)=["'](?:description|og:description)["']/i);
      if (metaDescMatch && metaDescMatch[1]) {
        metaDescription = this.decodeHtmlEntities(metaDescMatch[1]).trim();
        if (metaDescription) evidenceList.push(`Meta Description: "${metaDescription.slice(0, 100)}..."`);
      }

      // 3. Canonical URL
      const canonicalMatch =
        html.match(/<link\b[^>]*\brel=["']canonical["'][^>]*\bhref=["']([^"']+)["']/i) ||
        html.match(/<link\b[^>]*\bhref=["']([^"']+)["'][^>]*\brel=["']canonical["']/i);
      if (canonicalMatch && canonicalMatch[1]) {
        canonicalUrl = this.decodeHtmlEntities(canonicalMatch[1]).trim();
        if (canonicalUrl) evidenceList.push(`Canonical URL: "${canonicalUrl}"`);
      }

      // 4. Headings H1 / H2
      const h1Matches = html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/gi) || [];
      h1Matches.slice(0, 2).forEach((h) => {
        const text = this.decodeHtmlEntities(h.replace(/<[^>]+>/g, '')).trim();
        if (text && text.length > 2 && text.length < 120) {
          headings.push(text);
          evidenceList.push(`H1 Heading: "${text}"`);
        }
      });

      const h2Matches = html.match(/<h2\b[^>]*>([\s\S]*?)<\/h2>/gi) || [];
      h2Matches.slice(0, 3).forEach((h) => {
        const text = this.decodeHtmlEntities(h.replace(/<[^>]+>/g, '')).trim();
        if (text && text.length > 2 && text.length < 100 && !headings.includes(text)) {
          headings.push(text);
        }
      });

      // 5. Keyword extraction
      const lowerHtml = html.toLowerCase();
      const candidateKeywords = [
        'security', 'authentication', 'api', 'pricing', 'checkout', 'cart',
        'shop', 'store', 'documentation', 'developer', 'saas', 'cloud',
        'hosting', 'domain', 'crypto', 'wallet', 'banking', 'payment',
        'blog', 'news', 'healthcare', 'medical', 'compliance', 'login',
        'compare', 'marketplace',
      ];
      candidateKeywords.forEach((kw) => {
        if (lowerHtml.includes(kw)) keywords.push(kw);
      });
    }

    // Classification Logic
    const pageText = `${pageTitle || ''} ${metaDescription || ''} ${headings.join(' ')} ${keywords.join(' ')}`.trim();
    const combinedText = `${pageText} ${finalUrl}`.toLowerCase();

    let websiteType = 'Corporate';
    let industry = 'Technology & Business';
    let primaryPurpose = 'Provides corporate information, service offerings, and organizational background.';
    let confidence = 0.75;

    if (pageText.length < 5) {
      websiteType = 'General Website';
      industry = 'Unknown / Low confidence';
      primaryPurpose = 'Standard web page with minimal or undisclosed textual content.';
      confidence = 0.35;
    }
    // E-Commerce
    else if (
      techs.some((t) => t.technology.includes('Shopify')) ||
      /cart|checkout|shop|store|buy\s+now|pricing|products|catalog|add\s+to\s+cart/i.test(combinedText)
    ) {
      websiteType = 'E-Commerce';
      industry = 'Retail & Consumer Goods';
      primaryPurpose = 'Online retail store or marketplace facilitating product purchases and catalog browsing.';
      confidence = 0.92;
    }
    // Developer / Documentation / API Platform
    else if (
      /developer|documentation|api\s+reference|docs|sdk|github|programming|python|javascript|library|code/i.test(combinedText)
    ) {
      websiteType = 'Developer Platform';
      industry = 'Software Engineering & Developer Tools';
      primaryPurpose = 'Provides technical documentation, developer APIs, programming resources, or software downloads.';
      confidence = 0.94;
    }
    // Comparison / Hosting / Marketplace
    else if (
      /compare|comparison|reviews|best\s+hosting|top\s+10|ratings|plans/i.test(combinedText) &&
      /hosting|domain|cloud|vpn|provider/i.test(combinedText)
    ) {
      websiteType = 'Comparison Marketplace';
      industry = 'Web Hosting & Domain Services';
      primaryPurpose = 'Helps users compare hosting, domain providers, and related technology services.';
      confidence = 0.91;
    }
    // SaaS / Cloud Application
    else if (
      /saas|platform|dashboard|sign\s+up\s+free|start\s+free\s+trial|workspace|features|integrations|workflow/i.test(combinedText)
    ) {
      websiteType = 'SaaS';
      industry = 'Cloud Software & Productivity';
      primaryPurpose = 'Cloud-based software application providing productivity, workflow, or business tools.';
      confidence = 0.88;
    }
    // News / Media / Blog
    else if (
      techs.some((t) => t.technology.includes('WordPress')) ||
      /news|daily|journal|magazine|blog|articles|editorial|breaking\s+news|press/i.test(combinedText)
    ) {
      websiteType = 'Blog/Media';
      industry = 'Media & Journalism';
      primaryPurpose = 'Publishes news articles, editorial opinions, or digital media content.';
      confidence = 0.89;
    }
    // Education / Encyclopedia / Reference
    else if (
      /encyclopedia|wikipedia|reference|university|academy|learning|course|tutorials|education/i.test(combinedText)
    ) {
      websiteType = 'Education';
      industry = 'Education & Reference';
      primaryPurpose = 'Provides free educational knowledge, reference material, or academic learning resources.';
      confidence = 0.94;
    }
    // Financial
    else if (
      /bank|banking|investing|crypto|wallet|exchange|loan|insurance|credit\s+card|fintech/i.test(combinedText)
    ) {
      websiteType = 'Financial';
      industry = 'Financial Services & Banking';
      primaryPurpose = 'Delivers banking, financial transaction services, investment, or fintech tools.';
      confidence = 0.87;
    }
    // Healthcare
    else if (/health|hospital|clinic|patient|medical|doctor|wellness|telehealth/i.test(combinedText)) {
      websiteType = 'Healthcare';
      industry = 'Healthcare & Medicine';
      primaryPurpose = 'Provides medical information, clinical services, or patient healthcare resources.';
      confidence = 0.88;
    }
    // Government
    else if (/\.gov\b|\.mil\b|government|ministry|official\s+portal|public\s+service/i.test(combinedText)) {
      websiteType = 'Government';
      industry = 'Public Sector & Government';
      primaryPurpose = 'Official government portal providing public services, policy records, and civic information.';
      confidence = 0.95;
    }
    // Informational / Reference Example Domain
    else if (/example\s+domain|iana|demonstrative/i.test(combinedText)) {
      websiteType = 'Documentation';
      industry = 'Internet Standards & Reference';
      primaryPurpose = 'Serves as an illustrative example domain for documentation and standards compliance.';
      confidence = 0.96;
    } else {
      confidence = 0.70;
      websiteType = 'Corporate';
      industry = 'Business & Commercial Services';
      primaryPurpose = 'Presents business capabilities, company background, and public organizational information.';
    }

    const confidenceLabel: 'High' | 'Medium' | 'Low' | 'Unknown' =
      confidence >= 0.85 ? 'High' : confidence >= 0.60 ? 'Medium' : confidence >= 0.40 ? 'Low' : 'Unknown';

    return {
      websiteType,
      industry,
      primaryPurpose,
      confidence,
      confidenceLabel,
      evidence: evidenceList,
      pageTitle,
      metaDescription,
      headings,
      keywords,
      canonicalUrl,
    };
  }

  /**
   * Main Website Scanner V2 Execution Pipeline.
   */
  public analyze(input: any): any {
    let target = input.target || 'https://example.com';
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = `https://${target}`;
    }

    let parsedUrl: URL;
    if (input.parsedUrl instanceof URL) {
      parsedUrl = input.parsedUrl;
    } else {
      try {
        parsedUrl = new URL(target);
      } catch {
        parsedUrl = new URL('https://example.com');
      }
    }

    let httpResult = input.httpResult;
    if (!httpResult && (input.statusCode !== undefined || input.responseHeaders || input.html !== undefined || input.finalUrl || input.redirects)) {
      const allHeaders: Record<string, string> = {};
      const rawCookies: string[] = [];
      if (input.responseHeaders) {
        Object.entries(input.responseHeaders).forEach(([k, v]) => {
          const lk = k.toLowerCase();
          if (lk === 'set-cookie') {
            if (Array.isArray(v)) {
              rawCookies.push(...v);
              allHeaders['set-cookie'] = v.join('; ');
            } else if (typeof v === 'string') {
              rawCookies.push(v);
              allHeaders['set-cookie'] = v;
            }
          } else {
            allHeaders[lk] = Array.isArray(v) ? (v as any[]).join(', ') : String(v);
          }
        });
      }

      const finalUrl = input.finalUrl || (input.redirects && input.redirects.length > 0 ? input.redirects[input.redirects.length - 1].to : target);
      const redirectCount = input.redirects?.length || 0;
      const redirectChain = (input.redirects || []).map((r: any) => ({ url: r.from || r.to, statusCode: r.statusCode }));

      httpResult = {
        statusCode: input.statusCode ?? 200,
        statusText: input.statusText || 'OK',
        contentType: allHeaders['content-type'] || 'text/html',
        contentLength: (input.html || '').length || undefined,
        server: allHeaders['server'],
        responseTimeMs: input.responseTimeMs || 80,
        finalUrl,
        redirectCount,
        redirectChain,
        securityHeaders: allHeaders,
        allHeaders,
        rawCookies,
        htmlSnippet: input.html || '',
        bodySnippet: input.html || '',
        details: 'HTTP analysis complete',
      };
    }

    let tlsResult = input.tlsResult;
    if (!tlsResult && input.tlsInfo) {
      tlsResult = {
        valid: input.tlsInfo.valid !== false,
        protocol: input.tlsInfo.protocol || 'TLSv1.3',
        issuer: input.tlsInfo.issuer || 'Standard CA',
        daysRemaining: input.tlsInfo.daysRemaining,
        details: input.tlsInfo.error ? `Certificate Error: ${input.tlsInfo.error}` : 'TLS certificate valid',
        error: input.tlsInfo.error,
      };
    }

    const dnsResult = input.dnsResult || {
      resolvedIps: ['93.184.216.34'],
      ipVersion: 'IPv4',
      dnsStatus: 'Domain syntax and DNS infrastructure resolved successfully',
      isPrivate: false,
    };

    const isHttpsTarget = (httpResult?.finalUrl ? httpResult.finalUrl.startsWith('https://') : target.startsWith('https://'));
    const effectiveHttps = input.effectiveHttps ?? isHttpsTarget;

    const findings: IScanFinding[] = [];
    const technicalEvidences: ISecurityEvidence[] = [];
    const positiveControls: Array<{ title: string; desc: string; evidence?: string; category?: string }> = [];
    const whyVerdict: string[] = [];
    const recommendations: string[] = [];
    const scoreContributors: IWebsiteScoreContributor[] = [];

    let riskScore = 0;
    let hardeningPoints = 0; // Capped at 15 max

    const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(parsedUrl.hostname);
    const hostname = parsedUrl.hostname.toLowerCase();

    // ── 1. SSRF & DNS Evaluation ─────────────────────────────────────────────
    if (dnsResult.isPrivate) {
      const ev: ISecurityEvidence = {
        source: 'dns',
        check: 'ssrf-prevention',
        observed: `Target destination resolved to private/internal network IP (${dnsResult.resolvedIps.join(', ') || '127.0.0.1'}).`,
        expected: 'Public globally routable IP address',
        location: hostname,
        confidence: 1.0,
      };
      technicalEvidences.push(ev);

      findings.push({
        id: 'finding-ssrf-blocked',
        category: 'Domain & Infrastructure',
        findingCategory: 'CONFIRMED_VULNERABILITY',
        severity: 'CRITICAL',
        confidence: 1.0,
        verificationStatus: 'CONFIRMED',
        title: 'Private / Internal Network Address (SSRF Blocked)',
        description: 'The target hostname resolves to a private, loopback, or reserved network range. Outbound requests are blocked to safeguard internal network boundaries.',
        evidence: `Host: ${hostname}, Resolved IP: ${dnsResult.resolvedIps.join(', ') || '127.0.0.1'}`,
        evidences: [ev],
        impact: 'Internal network services could be reached or probed if requests were permitted.',
        verification: 'DNS resolution confirmed local or private address range.',
        recommendation: 'Do NOT expose private internal services through public interfaces.',
        affectedComponent: hostname,
      });

      riskScore += 70;
      scoreContributors.push({
        findingId: 'finding-ssrf-blocked',
        category: 'SSRF & Infrastructure',
        title: 'Private / Loopback IP Target (SSRF Blocked)',
        severity: 'CRITICAL',
        contribution: 70,
        reason: 'Target resolves to a private or reserved network IP address.',
        evidence: `Resolved IP: ${dnsResult.resolvedIps.join(', ') || '127.0.0.1'}`,
        remediation: 'Do NOT expose internal services to public web scanning interfaces.',
      });
      whyVerdict.push('Destination resolves to a private/internal network IP address (SSRF blocked).');
    } else if (dnsResult.error) {
      const ev: ISecurityEvidence = {
        source: 'dns',
        check: 'dns-resolution',
        observed: `DNS resolution failed: ${dnsResult.error}`,
        expected: 'Valid DNS A/AAAA records',
        location: hostname,
        confidence: 1.0,
      };
      technicalEvidences.push(ev);

      findings.push({
        id: 'finding-dns-unresolvable',
        category: 'Domain & Infrastructure',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'MEDIUM',
        confidence: 1.0,
        verificationStatus: 'CONFIRMED',
        title: 'Unresolvable Domain Name',
        description: `The hostname does not resolve to active IP addresses in DNS (${dnsResult.error}).`,
        evidence: `DNS Error: ${dnsResult.error}`,
        evidences: [ev],
        recommendation: 'Verify domain registration and DNS record provisioning.',
        affectedComponent: hostname,
      });

      riskScore += 25;
      scoreContributors.push({
        findingId: 'finding-dns-unresolvable',
        category: 'DNS Resolution',
        title: 'DNS Resolution Failed',
        severity: 'MEDIUM',
        contribution: 25,
        reason: `Domain name could not be resolved via global DNS (${dnsResult.error}).`,
        evidence: dnsResult.error,
        remediation: 'Check domain DNS zone records and authoritative nameservers.',
      });
      whyVerdict.push(`Domain name could not be resolved via global DNS (${dnsResult.error}).`);
    } else {
      positiveControls.push({
        title: 'Valid Global DNS Resolution',
        desc: `Hostname resolved to globally routable IP address(es) (${dnsResult.resolvedIps.slice(0, 2).join(', ')}).`,
        evidence: `IPs: ${dnsResult.resolvedIps.join(', ')} (${dnsResult.ipVersion})`,
        category: 'dns',
      });
      technicalEvidences.push({
        source: 'dns',
        check: 'dns-resolution',
        observed: `Resolved ${dnsResult.resolvedIps.length} IP record(s): ${dnsResult.resolvedIps.join(', ')}`,
        confidence: 1.0,
      });
    }

    // ── 2. Transport & TLS Analysis ──────────────────────────────────────────
    if (!effectiveHttps && !isHttpsTarget) {
      const ev: ISecurityEvidence = {
        source: 'tls',
        check: 'https-transport-encryption',
        observed: 'Website communicates over unencrypted plaintext HTTP without TLS encryption.',
        expected: 'HTTPS with valid TLS certificate',
        location: target,
        confidence: 1.0,
      };
      technicalEvidences.push(ev);

      findings.push({
        id: 'finding-unencrypted-http',
        category: 'SSL/TLS',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'MEDIUM',
        confidence: 1.0,
        verificationStatus: 'CONFIRMED',
        title: 'Unencrypted Transport Protocol (Plaintext HTTP)',
        description: 'The website communicates over plain HTTP without TLS encryption. Credentials, session cookies, and transmitted data are vulnerable to network interception (MitM).',
        evidence: `Protocol: ${parsedUrl.protocol}`,
        evidences: [ev],
        impact: 'Network eavesdropping and active packet injection by on-path intermediaries.',
        verification: 'Direct HTTP connection negotiated without TLS handshake.',
        recommendation: 'Deploy an SSL/TLS certificate and configure HTTP-to-HTTPS redirection.',
        affectedComponent: 'Web Transport Layer',
      });

      riskScore += 25;
      scoreContributors.push({
        findingId: 'finding-unencrypted-http',
        category: 'Transport Security',
        title: 'Unencrypted Plaintext HTTP',
        severity: 'MEDIUM',
        contribution: 25,
        reason: 'Website communicates over unencrypted HTTP without TLS encryption.',
        evidence: `Protocol: ${parsedUrl.protocol}`,
        remediation: 'Deploy HTTPS and redirect cleartext HTTP traffic to HTTPS.',
      });
      whyVerdict.push('Plaintext HTTP is used without TLS encryption.');
    } else if (tlsResult) {
      if (tlsResult.valid === false || tlsResult.error) {
        const ev: ISecurityEvidence = {
          source: 'tls',
          check: 'tls-certificate-validity',
          observed: `Certificate validation failed: ${tlsResult.details}`,
          expected: 'Valid certificate matching hostname and trusted by public CA',
          location: hostname,
          confidence: 1.0,
        };
        technicalEvidences.push(ev);

        findings.push({
          id: 'finding-invalid-tls-cert',
          category: 'SSL/TLS',
          findingCategory: 'CONFIRMED_VULNERABILITY',
          severity: 'HIGH',
          confidence: 1.0,
          verificationStatus: 'CONFIRMED',
          title: 'Invalid / Expired SSL/TLS Certificate',
          description: `The SSL/TLS certificate presented by the host failed validation: ${tlsResult.details}`,
          evidence: tlsResult.error || tlsResult.details,
          evidences: [ev],
          impact: 'Browsers will display severe security warnings and reject secure connections.',
          verification: 'TLS handshake returned certificate verification error.',
          recommendation: 'Renew or reissue the SSL/TLS certificate with correct domain SANs.',
          affectedComponent: 'TLS Certificate',
        });

        riskScore += 35;
        scoreContributors.push({
          findingId: 'finding-invalid-tls-cert',
          category: 'SSL/TLS Certificate',
          title: 'Invalid or Expired TLS Certificate',
          severity: 'HIGH',
          contribution: 35,
          reason: `TLS certificate failed validation: ${tlsResult.details}`,
          evidence: tlsResult.error || tlsResult.details,
          remediation: 'Reissue or renew the SSL/TLS certificate through a trusted certificate authority.',
        });
        whyVerdict.push(`TLS certificate failed validation (${tlsResult.details}).`);
      } else {
        positiveControls.push({
          title: 'Active HTTPS & Valid TLS Certificate',
          desc: `Secure TLS connection established using ${tlsResult.protocol || 'TLS'}. Certificate issued by ${tlsResult.issuer || 'Trusted CA'}.`,
          evidence: `Expires in ${tlsResult.daysRemaining ?? 'N/A'} days (Valid until: ${tlsResult.validTo || 'Valid'})`,
          category: 'tls',
        });
        technicalEvidences.push({
          source: 'tls',
          check: 'tls-certificate-validity',
          observed: `Valid certificate issued by ${tlsResult.issuer || 'Public CA'}, expires in ${tlsResult.daysRemaining} days`,
          confidence: 1.0,
        });

        if (tlsResult.daysRemaining !== undefined && tlsResult.daysRemaining < 15) {
          const ev: ISecurityEvidence = {
            source: 'tls',
            check: 'certificate-expiration',
            observed: `Certificate is valid but expires in ${tlsResult.daysRemaining} days`,
            expected: 'Certificate validity exceeding 30 days',
            location: hostname,
            confidence: 1.0,
          };
          technicalEvidences.push(ev);

          findings.push({
            id: 'finding-cert-expiring-soon',
            category: 'SSL/TLS',
            findingCategory: 'HARDENING_RECOMMENDATION',
            severity: 'LOW',
            confidence: 1.0,
            verificationStatus: 'OBSERVED',
            title: 'SSL/TLS Certificate Expiring Soon',
            description: `The host TLS certificate is valid but expires in ${tlsResult.daysRemaining} day(s).`,
            evidence: `Valid until: ${tlsResult.validTo || 'Soon'}`,
            evidences: [ev],
            recommendation: 'Renew the SSL/TLS certificate before expiration to avoid service interruption.',
            affectedComponent: 'TLS Certificate',
          });

          hardeningPoints += 2;
          scoreContributors.push({
            findingId: 'finding-cert-expiring-soon',
            category: 'SSL/TLS Certificate',
            title: 'TLS Certificate Expiring Soon',
            severity: 'LOW',
            contribution: 2,
            reason: `Certificate is valid but expires in ${tlsResult.daysRemaining} days.`,
            evidence: `Expires on: ${tlsResult.validTo || 'Soon'}`,
            remediation: 'Renew the certificate before expiration.',
          });
          whyVerdict.push(`TLS certificate is valid but expires in ${tlsResult.daysRemaining} days.`);
        } else {
          whyVerdict.push('HTTPS is enabled with a valid TLS certificate.');
        }
      }
    }

    // ── 3. Redirect Analysis ────────────────────────────────────────────────
    if (httpResult && httpResult.redirectCount > 0) {
      const initialScheme = parsedUrl.protocol;
      const finalUrlStr = httpResult.finalUrl;
      let finalScheme = 'http:';
      try {
        finalScheme = new URL(finalUrlStr).protocol;
      } catch {
        finalScheme = initialScheme;
      }

      // HTTP to HTTPS Upgrade (Positive!)
      if (initialScheme === 'http:' && finalScheme === 'https:') {
        positiveControls.push({
          title: 'Automatic HTTP to HTTPS Upgrade',
          desc: 'The web server automatically redirected the initial plaintext HTTP request to secure HTTPS.',
          evidence: `Redirected to ${finalUrlStr}`,
          category: 'redirect',
        });
        technicalEvidences.push({
          source: 'redirect',
          check: 'http-to-https-upgrade',
          observed: `HTTP connection upgraded to HTTPS across ${httpResult.redirectCount} hop(s)`,
          confidence: 1.0,
        });
      }

      // HTTPS to HTTP Downgrade (Dangerous!)
      if (initialScheme === 'https:' && finalScheme === 'http:') {
        const ev: ISecurityEvidence = {
          source: 'redirect',
          check: 'https-to-http-downgrade',
          observed: `HTTPS initial connection was redirected to unencrypted HTTP (${finalUrlStr})`,
          expected: 'Preserve encrypted HTTPS transport',
          location: finalUrlStr,
          confidence: 1.0,
        };
        technicalEvidences.push(ev);

        findings.push({
          id: 'finding-https-downgrade',
          category: 'Redirect Analysis',
          findingCategory: 'SECURITY_WEAKNESS',
          severity: 'HIGH',
          confidence: 1.0,
          verificationStatus: 'CONFIRMED',
          title: 'HTTPS to Plaintext HTTP Downgrade Redirect',
          description: 'The server redirected a secure HTTPS request to an unencrypted HTTP destination, stripping transport security.',
          evidence: `Redirect chain: ${httpResult.redirectChain.map((h: any) => `${h.url} [${h.statusCode}]`).join(' -> ')} -> ${finalUrlStr}`,
          evidences: [ev],
          impact: 'Exposes authenticated requests or submitted data to network inspection.',
          verification: 'Observed Location header pointing to http:// scheme.',
          recommendation: 'Eliminate downgrade redirects; ensure all redirect destinations use HTTPS.',
          affectedComponent: 'Web Server Redirect Policy',
        });

        riskScore += 30;
        scoreContributors.push({
          findingId: 'finding-https-downgrade',
          category: 'Redirect Security',
          title: 'HTTPS to HTTP Downgrade Redirect',
          severity: 'HIGH',
          contribution: 30,
          reason: 'A secure HTTPS request was redirected to unencrypted HTTP (transport downgrade).',
          evidence: `Final Hop: ${finalUrlStr}`,
          remediation: 'Configure server redirection to always maintain HTTPS transport.',
        });
        whyVerdict.push('A secure HTTPS request was redirected to unencrypted HTTP (transport downgrade).');
      }

      // Cross-domain redirect (Informational observation, not an automatic critical vulnerability)
      try {
        const finalHost = new URL(finalUrlStr).hostname.toLowerCase();
        const initialClean = hostname.replace(/^www\./, '');
        const finalClean = finalHost.replace(/^www\./, '');
        if (initialClean !== finalClean && !initialClean.endsWith(`.${finalClean}`) && !finalClean.endsWith(`.${initialClean}`)) {
          technicalEvidences.push({
            source: 'redirect',
            check: 'cross-domain-redirect',
            observed: `URL redirected to an external domain (${finalHost})`,
            confidence: 0.95,
          });
          whyVerdict.push(`Redirects to external domain ${finalHost}.`);
        }
      } catch {
        // Ignore parse errors
      }
    } else if (httpResult?.error === 'MAX_REDIRECTS_EXCEEDED') {
      const ev: ISecurityEvidence = {
        source: 'redirect',
        check: 'redirect-loops',
        observed: 'Exceeded maximum redirect hop limit (5 hops). Potential circular loop.',
        expected: 'Direct resolution within 5 hops',
        location: target,
        confidence: 1.0,
      };
      technicalEvidences.push(ev);

      findings.push({
        id: 'finding-redirect-loop',
        category: 'Redirect Analysis',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'MEDIUM',
        confidence: 1.0,
        verificationStatus: 'CONFIRMED',
        title: 'Redirect Loop / Maximum Hops Exceeded',
        description: 'The target destination entered an excessive redirection chain exceeding 5 hops.',
        evidence: `Hops: ${httpResult.redirectChain.length}`,
        evidences: [ev],
        recommendation: 'Inspect web server rewrite and redirection rules to eliminate circular redirects.',
        affectedComponent: 'Routing & Rewrite Rules',
      });

      riskScore += 15;
      scoreContributors.push({
        findingId: 'finding-redirect-loop',
        category: 'Redirect Behavior',
        title: 'Redirect Loop / Maximum Hops Exceeded',
        severity: 'MEDIUM',
        contribution: 15,
        reason: 'Target entered an excessive or circular redirection chain exceeding safety limits.',
        evidence: `Hops followed: ${httpResult.redirectChain.length}`,
        remediation: 'Inspect web server redirect rules to eliminate circular loops.',
      });
      whyVerdict.push('Exceeded maximum redirect limit (possible circular redirect loop).');
    }

    // ── 4. HTTP Security Headers Analysis (Value-Aware) ──────────────────────
    const isHttpResponsive = Boolean(httpResult && httpResult.statusCode && !dnsResult.error && !dnsResult.isPrivate);
    const allHeaders = isHttpResponsive ? (httpResult?.allHeaders || {}) : {};
    const headerItems: NonNullable<IScanChecks['securityHeadersAnalysis']>['headers'] = [];

    const cspValue = allHeaders['content-security-policy'];
    let hasCspFrameAncestors = false;
    let hasStrictCsp = false;
    const hstsValue = allHeaders['strict-transport-security'];
    const xfoValue = allHeaders['x-frame-options'];
    let hasFrameProtection = false;
    const xctoValue = allHeaders['x-content-type-options'];
    const referrerValue = allHeaders['referrer-policy'];

    if (!isHttpResponsive) {
      whyVerdict.push('HTTP response headers could not be audited because the target server was unreachable.');
    } else {
      // CSP directive parser
      if (cspValue) {
        const lowerCsp = cspValue.toLowerCase();
        hasCspFrameAncestors = lowerCsp.includes('frame-ancestors');
        const hasUnsafeInline = lowerCsp.includes("'unsafe-inline'") && !lowerCsp.includes("'nonce-") && !lowerCsp.includes("'sha256-");
        const hasWildcard = lowerCsp.includes(' * ') || lowerCsp.includes('default-src *') || lowerCsp.includes('script-src *');

        if (hasUnsafeInline || hasWildcard) {
          headerItems.push({
            name: 'Content-Security-Policy',
            status: 'warning',
            value: cspValue.length > 80 ? `${cspValue.slice(0, 80)}...` : cspValue,
            explanation: "CSP is present but includes 'unsafe-inline' or wildcard sources, which reduces defense-in-depth against XSS.",
            recommendation: 'Refactor inline scripts to external bundles with cryptographic nonces/hashes.',
            severity: 'LOW',
          });

          const ev: ISecurityEvidence = {
            source: 'headers',
            check: 'content-security-policy',
            observed: `CSP contains permissive directive (${hasUnsafeInline ? "'unsafe-inline'" : 'wildcard *'})`,
            expected: 'Strict CSP with cryptographic nonces/hashes',
            location: 'Content-Security-Policy Header',
            confidence: 0.95,
          };
          technicalEvidences.push(ev);

          findings.push({
            id: 'finding-csp-permissive',
            category: 'Security Headers',
            findingCategory: 'HARDENING_RECOMMENDATION',
            severity: 'LOW',
            confidence: 0.90,
            verificationStatus: 'OBSERVED',
            title: 'Permissive Content-Security-Policy Directives',
            description: "Content-Security-Policy header contains 'unsafe-inline' or wildcard sources, reducing client-side defense-in-depth against Cross-Site Scripting (XSS).",
            evidence: `CSP: ${cspValue.length > 100 ? cspValue.slice(0, 100) + '...' : cspValue}`,
            evidences: [ev],
            recommendation: 'Deploy cryptographic nonces or hashes for inline scripts and restrict script-src origins.',
            affectedComponent: 'Content-Security-Policy',
          });

          hardeningPoints += 2;
          scoreContributors.push({
            findingId: 'finding-csp-permissive',
            category: 'Security Headers',
            title: 'Permissive CSP Directives',
            severity: 'LOW',
            contribution: 2,
            reason: "CSP header is present but contains 'unsafe-inline' or wildcard sources.",
            evidence: cspValue.slice(0, 80),
            remediation: 'Deploy strict CSP nonces or hashes for inline scripts.',
          });
        } else {
          hasStrictCsp = true;
          headerItems.push({
            name: 'Content-Security-Policy',
            status: 'present',
            value: cspValue.length > 80 ? `${cspValue.slice(0, 80)}...` : cspValue,
            explanation: 'Restricts authorized script, frame, and object sources to defend against Cross-Site Scripting (XSS).',
            recommendation: 'Maintain strict origin policies and review periodic policy violation reports.',
          });
          positiveControls.push({
            title: 'Content-Security-Policy (CSP) Deployed',
            desc: 'Enforces origin restrictions for scripts, objects, and framing to mitigate Cross-Site Scripting.',
            evidence: cspValue.slice(0, 60) + '...',
            category: 'headers',
          });
          technicalEvidences.push({
            source: 'headers',
            check: 'content-security-policy',
            observed: `Content-Security-Policy header active: ${cspValue.slice(0, 60)}...`,
            confidence: 1.0,
          });
        }
      } else {
        headerItems.push({
          name: 'Content-Security-Policy',
          status: 'missing',
          explanation: 'No Content-Security-Policy header observed. Browser-level defense-in-depth against XSS is reduced.',
          recommendation: 'Deploy a Content-Security-Policy header specifying authorized script and resource origins.',
          severity: 'LOW',
        });

        const ev: ISecurityEvidence = {
          source: 'headers',
          check: 'content-security-policy',
          observed: 'Content-Security-Policy header was not present in HTTP response headers.',
          expected: 'Content-Security-Policy header present',
          location: 'HTTP Response Headers',
          confidence: 1.0,
        };
        technicalEvidences.push(ev);

        findings.push({
          id: 'finding-csp-missing',
          category: 'Security Headers',
          findingCategory: 'HARDENING_RECOMMENDATION',
          severity: 'LOW',
          confidence: 1.0,
          verificationStatus: 'OBSERVED',
          title: 'Missing Content-Security-Policy (CSP) Header',
          description: 'The web server does not send a Content-Security-Policy header. Browsers will not enforce origin-level script execution restrictions.',
          evidence: 'Header Content-Security-Policy: Not present',
          evidences: [ev],
          impact: 'Reduced defense-in-depth against Cross-Site Scripting (XSS) if client-side injection occurs.',
          verification: 'Direct HTTP response inspection confirmed header absence.',
          recommendation: 'Deploy a Content-Security-Policy header specifying authorized script, frame, and style sources.',
          affectedComponent: 'HTTP Response Headers',
        });

        hardeningPoints += 2;
        scoreContributors.push({
          findingId: 'finding-csp-missing',
          category: 'Security Headers',
          title: 'Missing Content-Security-Policy Header',
          severity: 'LOW',
          contribution: 2,
          reason: 'No Content-Security-Policy header was detected in HTTP responses.',
          evidence: 'Header Content-Security-Policy: Not present',
          remediation: 'Deploy a suitable CSP specifying authorized script and resource origins.',
        });
        whyVerdict.push('Content-Security-Policy (CSP) was not observed.');
      }

      // Strict-Transport-Security (HSTS)
      if (hstsValue) {
        const maxAgeMatch = hstsValue.match(/max-age=(\d+)/i);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
        if (maxAge < 10368000) {
          headerItems.push({
            name: 'Strict-Transport-Security',
            status: 'warning',
            value: hstsValue,
            explanation: `HSTS is configured but max-age (${maxAge}s) is below the recommended 120 days (10,368,000s).`,
            recommendation: 'Increase max-age to at least 31536000 seconds (1 year) with includeSubDomains.',
            severity: 'LOW',
          });
          hardeningPoints += 1;
          scoreContributors.push({
            category: 'Security Headers',
            title: 'HSTS Max-Age Below Recommended Duration',
            severity: 'LOW',
            contribution: 1,
            reason: `HSTS max-age (${maxAge}s) is below recommended 120 days.`,
            evidence: hstsValue,
            remediation: 'Increase max-age to at least 31536000 with includeSubDomains.',
          });
        } else {
          headerItems.push({
            name: 'Strict-Transport-Security',
            status: 'present',
            value: hstsValue,
            explanation: 'Forces modern client browsers to communicate exclusively over encrypted HTTPS connections.',
            recommendation: 'Ensure includeSubDomains and preload are enabled once fully verified.',
          });
          positiveControls.push({
            title: 'Strict-Transport-Security (HSTS) Enabled',
            desc: `Enforces encrypted HTTPS connections across client browsers (max-age: ${maxAge}s).`,
            evidence: hstsValue,
            category: 'headers',
          });
          technicalEvidences.push({
            source: 'headers',
            check: 'strict-transport-security',
            observed: `HSTS active with max-age=${maxAge}`,
            confidence: 1.0,
          });
        }
      } else {
        headerItems.push({
          name: 'Strict-Transport-Security',
          status: 'missing',
          explanation: effectiveHttps
            ? 'Missing Strict-Transport-Security header on HTTPS website. Clients may attempt initial unencrypted HTTP connections.'
            : 'HSTS is not applicable on unencrypted HTTP.',
          recommendation: effectiveHttps
            ? 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains.'
            : 'Enforce HTTPS transport before configuring HSTS.',
          severity: effectiveHttps ? 'LOW' : 'INFO',
        });

        if (effectiveHttps) {
          const ev: ISecurityEvidence = {
            source: 'headers',
            check: 'strict-transport-security',
            observed: 'Strict-Transport-Security header was not present in HTTPS response.',
            expected: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
            location: 'HTTP Response Headers',
            confidence: 1.0,
          };
          technicalEvidences.push(ev);

          findings.push({
            id: 'finding-hsts-missing',
            category: 'Security Headers',
            findingCategory: 'HARDENING_RECOMMENDATION',
            severity: 'LOW',
            confidence: 1.0,
            verificationStatus: 'OBSERVED',
            title: 'Missing Strict-Transport-Security (HSTS) Header',
            description: 'The HTTPS website does not instruct client browsers to enforce HTTPS connections, permitting potential SSL-stripping on initial connections.',
            evidence: 'Header Strict-Transport-Security: Not present',
            evidences: [ev],
            impact: 'Clients making initial bookmarks/typed requests over HTTP may be subject to MitM downgrade.',
            verification: 'Direct HTTP response inspection confirmed header absence.',
            recommendation: 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains.',
            affectedComponent: 'HTTP Response Headers',
          });

          hardeningPoints += 2;
          scoreContributors.push({
            findingId: 'finding-hsts-missing',
            category: 'Security Headers',
            title: 'Missing Strict-Transport-Security (HSTS) Header',
            severity: 'LOW',
            contribution: 2,
            reason: 'HTTPS website does not send an HSTS header to enforce encrypted connections.',
            evidence: 'Header Strict-Transport-Security: Not present',
            remediation: 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains.',
          });
          whyVerdict.push('Strict-Transport-Security (HSTS) was not observed.');
        }
      }

      // Frame Protection: X-Frame-Options OR CSP frame-ancestors
      const hasXfoProtection = xfoValue && (xfoValue.toUpperCase().includes('DENY') || xfoValue.toUpperCase().includes('SAMEORIGIN'));
      hasFrameProtection = Boolean(hasXfoProtection || hasCspFrameAncestors);

      if (hasFrameProtection) {
        headerItems.push({
          name: 'X-Frame-Options / Frame-Ancestors',
          status: 'present',
          value: xfoValue || 'CSP frame-ancestors configured',
          explanation: 'Controls whether the site can be embedded within iframes, protecting against clickjacking UI redress attacks.',
          recommendation: 'Maintain SAMEORIGIN or frame-ancestors restrictions.',
        });
        positiveControls.push({
          title: 'Clickjacking / Frame Protection Active',
          desc: hasCspFrameAncestors
            ? 'Frame protection is actively enforced via CSP frame-ancestors directive.'
            : `Frame protection is enforced via X-Frame-Options: ${xfoValue}.`,
          evidence: xfoValue || 'CSP frame-ancestors',
          category: 'headers',
        });
        technicalEvidences.push({
          source: 'headers',
          check: 'frame-protection',
          observed: hasCspFrameAncestors ? 'CSP frame-ancestors active' : `X-Frame-Options: ${xfoValue}`,
          confidence: 1.0,
        });
      } else {
        headerItems.push({
          name: 'X-Frame-Options',
          status: 'missing',
          explanation: 'Neither X-Frame-Options nor CSP frame-ancestors was observed. Third-party sites could attempt iframe embedding.',
          recommendation: 'Configure X-Frame-Options: SAMEORIGIN or CSP frame-ancestors.',
          severity: 'LOW',
        });

        const ev: ISecurityEvidence = {
          source: 'headers',
          check: 'frame-protection',
          observed: 'Neither X-Frame-Options nor CSP frame-ancestors directive was present.',
          expected: "X-Frame-Options: SAMEORIGIN or CSP frame-ancestors: 'self'",
          location: 'HTTP Response Headers',
          confidence: 1.0,
        };
        technicalEvidences.push(ev);

        findings.push({
          id: 'finding-frame-protection-missing',
          category: 'Security Headers',
          findingCategory: 'HARDENING_RECOMMENDATION',
          severity: 'LOW',
          confidence: 1.0,
          verificationStatus: 'OBSERVED',
          title: 'Missing Clickjacking / Frame Protection Header',
          description: 'The website does not declare X-Frame-Options or CSP frame-ancestors to restrict iframe embedding by third-party domains.',
          evidence: 'Neither X-Frame-Options nor CSP frame-ancestors was detected',
          evidences: [ev],
          impact: 'Third-party sites may embed the website inside transparent iframes for UI redress.',
          verification: 'Header and CSP directive inspection confirmed neither control was declared.',
          recommendation: "Configure X-Frame-Options: SAMEORIGIN or declare CSP frame-ancestors 'self'.",
          affectedComponent: 'HTTP Response Headers',
        });

        hardeningPoints += 2;
        scoreContributors.push({
          findingId: 'finding-frame-protection-missing',
          category: 'Security Headers',
          title: 'Missing Frame Protection (Clickjacking Defense)',
          severity: 'LOW',
          contribution: 2,
          reason: 'Neither X-Frame-Options nor CSP frame-ancestors directive was declared.',
          evidence: 'Header X-Frame-Options: Not present',
          remediation: "Set X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'.",
        });
      }

      // X-Content-Type-Options
      if (xctoValue && xctoValue.toLowerCase().includes('nosniff')) {
        headerItems.push({
          name: 'X-Content-Type-Options',
          status: 'present',
          value: xctoValue,
          explanation: 'Prevents client browsers from MIME-sniffing a response away from the declared content-type.',
          recommendation: 'Maintain X-Content-Type-Options: nosniff across all static and dynamic responses.',
        });
        positiveControls.push({
          title: 'MIME-Type Sniffing Protection Enabled',
          desc: 'Enforces declared MIME types with X-Content-Type-Options: nosniff to prevent script execution via disguised assets.',
          evidence: xctoValue,
          category: 'headers',
        });
        technicalEvidences.push({
          source: 'headers',
          check: 'x-content-type-options',
          observed: 'X-Content-Type-Options: nosniff active',
          confidence: 1.0,
        });
      } else {
        headerItems.push({
          name: 'X-Content-Type-Options',
          status: 'missing',
          explanation: 'Missing nosniff directive allows browsers to attempt MIME-type guessing on downloaded assets.',
          recommendation: 'Add X-Content-Type-Options: nosniff header.',
          severity: 'LOW',
        });

        const ev: ISecurityEvidence = {
          source: 'headers',
          check: 'x-content-type-options',
          observed: 'X-Content-Type-Options header was not present.',
          expected: 'X-Content-Type-Options: nosniff',
          location: 'HTTP Response Headers',
          confidence: 1.0,
        };
        technicalEvidences.push(ev);

        findings.push({
          id: 'finding-xcto-missing',
          category: 'Security Headers',
          findingCategory: 'HARDENING_RECOMMENDATION',
          severity: 'LOW',
          confidence: 1.0,
          verificationStatus: 'OBSERVED',
          title: 'Missing X-Content-Type-Options Header',
          description: 'The web server does not declare X-Content-Type-Options: nosniff, allowing legacy browsers to execute non-executable MIME types as scripts.',
          evidence: 'Header X-Content-Type-Options: Not present',
          evidences: [ev],
          impact: 'Attacker-uploaded files (like images with script polyglots) might execute in vulnerable contexts.',
          verification: 'Direct HTTP response inspection confirmed header absence.',
          recommendation: 'Add X-Content-Type-Options: nosniff to all web server responses.',
          affectedComponent: 'HTTP Response Headers',
        });

        hardeningPoints += 1;
        scoreContributors.push({
          findingId: 'finding-xcto-missing',
          category: 'Security Headers',
          title: 'Missing X-Content-Type-Options: nosniff',
          severity: 'LOW',
          contribution: 1,
          reason: 'Header X-Content-Type-Options: nosniff was not detected in HTTP responses.',
          evidence: 'Header X-Content-Type-Options: Not present',
          remediation: 'Add X-Content-Type-Options: nosniff header.',
        });
      }

      // Referrer-Policy
      if (referrerValue) {
        headerItems.push({
          name: 'Referrer-Policy',
          status: 'present',
          value: referrerValue,
          explanation: 'Controls how much referrer information is included with requests made from your website.',
          recommendation: 'Maintain strict-origin-when-cross-origin or no-referrer.',
        });
        positiveControls.push({
          title: 'Referrer-Policy Configured',
          desc: `Controls cross-origin URL leakage with Referrer-Policy: ${referrerValue}.`,
          evidence: referrerValue,
          category: 'headers',
        });
        technicalEvidences.push({
          source: 'headers',
          check: 'referrer-policy',
          observed: `Referrer-Policy: ${referrerValue}`,
          confidence: 1.0,
        });
      } else {
        headerItems.push({
          name: 'Referrer-Policy',
          status: 'missing',
          explanation: 'No explicit Referrer-Policy declared. Browsers use standard default behavior.',
          recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin.',
          severity: 'LOW',
        });

        findings.push({
          id: 'finding-referrer-policy-missing',
          category: 'Security Headers',
          findingCategory: 'HARDENING_RECOMMENDATION',
          severity: 'LOW',
          confidence: 1.0,
          verificationStatus: 'OBSERVED',
          title: 'Missing Referrer-Policy Header',
          description: 'The web server does not explicitly specify a Referrer-Policy header to protect sensitive query parameters in outgoing links.',
          evidence: 'Header Referrer-Policy: Not present',
          recommendation: 'Set Referrer-Policy: strict-origin-when-cross-origin.',
          affectedComponent: 'HTTP Response Headers',
        });

        hardeningPoints += 1;
        scoreContributors.push({
          findingId: 'finding-referrer-policy-missing',
          category: 'Security Headers',
          title: 'Missing Referrer-Policy Header',
          severity: 'LOW',
          contribution: 1,
          reason: 'No explicit Referrer-Policy declared to protect query parameter leakage.',
          evidence: 'Header Referrer-Policy: Not present',
          remediation: 'Set Referrer-Policy: strict-origin-when-cross-origin.',
        });
      }

      // Permissions-Policy
      const permissionsValue = allHeaders['permissions-policy'] || allHeaders['feature-policy'];
      if (permissionsValue) {
        headerItems.push({
          name: 'Permissions-Policy',
          status: 'present',
          value: permissionsValue.length > 60 ? `${permissionsValue.slice(0, 60)}...` : permissionsValue,
          explanation: 'Restricts browser features like camera, microphone, and geolocation.',
          recommendation: 'Keep feature delegations restricted to necessary origins.',
        });
        positiveControls.push({
          title: 'Permissions-Policy Deployed',
          desc: 'Restricts powerful browser capabilities (camera, microphone, geolocation).',
          evidence: permissionsValue.slice(0, 40) + '...',
          category: 'headers',
        });
      } else {
        headerItems.push({
          name: 'Permissions-Policy',
          status: 'missing',
          explanation: 'Permissions-Policy header is absent. Browser hardware features are unrestricted by default policy.',
          recommendation: 'Configure Permissions-Policy: camera=(), microphone=(), geolocation=().',
          severity: 'LOW',
        });

        findings.push({
          id: 'finding-permissions-policy-missing',
          category: 'Security Headers',
          findingCategory: 'HARDENING_RECOMMENDATION',
          severity: 'LOW',
          confidence: 1.0,
          verificationStatus: 'OBSERVED',
          title: 'Missing Permissions-Policy Header',
          description: 'No Permissions-Policy header is declared to disable unnecessary browser hardware capabilities.',
          evidence: 'Header Permissions-Policy: Not present',
          recommendation: 'Configure Permissions-Policy to disable unused hardware interfaces (camera, geolocation, microphone).',
          affectedComponent: 'HTTP Response Headers',
        });

        hardeningPoints += 1;
        scoreContributors.push({
          findingId: 'finding-permissions-policy-missing',
          category: 'Security Headers',
          title: 'Missing Permissions-Policy Header',
          severity: 'LOW',
          contribution: 1,
          reason: 'No Permissions-Policy header declared to restrict browser hardware APIs.',
          evidence: 'Header Permissions-Policy: Not present',
          remediation: 'Configure Permissions-Policy: camera=(), microphone=(), geolocation=().',
        });
      }

      // COOP / CORP Cross-Origin Isolation
      const coopValue = allHeaders['cross-origin-opener-policy'];
      if (coopValue) {
        positiveControls.push({
          title: 'Cross-Origin Opener Policy (COOP) Active',
          desc: `Isolates the browsing context via COOP: ${coopValue}.`,
          evidence: coopValue,
          category: 'headers',
        });
      }

    }

    const presentHeadersCount = headerItems.filter((h: any) => h.status === 'present').length;
    const missingHeadersCount = headerItems.filter((h: any) => h.status === 'missing').length;
    const warningHeadersCount = headerItems.filter((h: any) => h.status === 'warning').length;

    const securityHeadersAnalysis: NonNullable<IScanChecks['securityHeadersAnalysis']> = {
      status: !isHttpResponsive ? 'neutral' : (missingHeadersCount >= 3 ? 'warning' : 'passed'),
      presentCount: presentHeadersCount,
      missingCount: missingHeadersCount,
      warningCount: warningHeadersCount,
      totalChecked: headerItems.length,
      headers: headerItems,
      details: !isHttpResponsive
        ? (dnsResult.error ? `Security headers could not be analyzed: Domain resolution failed (${dnsResult.error}).` : 'Security headers could not be analyzed: Target server was unreachable.')
        : `Analyzed ${headerItems.length} core security headers: ${presentHeadersCount} present, ${missingHeadersCount} missing or non-optimal.`,
    };

    // ── 5. Cookie Security Analysis (Deduplicated & Context-Aware) ───────────
    const rawCookies: string[] = httpResult?.rawCookies || [];
    const cookieTable: Array<{
      name: string;
      domain?: string;
      path: string;
      secure: boolean;
      httpOnly: boolean;
      sameSite: string;
      expires?: string;
      isPotentiallySensitive: boolean;
      assessment: string;
    }> = [];

    const legacyCookieItems: NonNullable<IScanChecks['cookiesAnalysis']>['cookies'] = [];

    let secureMissingCount = 0;
    let httpOnlyMissingCount = 0;
    let sameSiteMissingCount = 0;
    let sensitiveCookieIssues = 0;

    const sensitiveCookieRegex = /(session|auth|token|jwt|sid|login|id|user|account|phpsessid|jsessionid|connect\.sid)/i;

    for (const raw of rawCookies) {
      const parts: string[] = raw.split(';').map((p: string) => p.trim());
      if (parts.length === 0 || !parts[0]) continue;

      const [nameVal] = parts;
      const eqIdx = nameVal.indexOf('=');
      const name = eqIdx > -1 ? nameVal.slice(0, eqIdx).trim() : nameVal;
      const valueMasked = eqIdx > -1 ? `${nameVal.slice(eqIdx + 1, eqIdx + 4)}***` : undefined;

      const isSecure = parts.some((p: string) => /^secure$/i.test(p));
      const isHttpOnly = parts.some((p: string) => /^httponly$/i.test(p));
      const sameSitePart = parts.find((p: string) => /^samesite=/i.test(p));
      const sameSite = sameSitePart ? sameSitePart.split('=')[1]?.trim() : undefined;
      const domainPart = parts.find((p: string) => /^domain=/i.test(p));
      const domain = domainPart ? domainPart.split('=')[1]?.trim() : undefined;
      const pathPart = parts.find((p: string) => /^path=/i.test(p));
      const path = pathPart ? pathPart.split('=')[1]?.trim() : undefined;
      const expiresPart = parts.find((p: string) => /^expires=/i.test(p));
      const expires = expiresPart ? expiresPart.split('=')[1]?.trim() : undefined;

      const isPotentiallySensitive = sensitiveCookieRegex.test(name);
      const issues: string[] = [];

      if (!isSecure && effectiveHttps) {
        secureMissingCount++;
        issues.push('Missing Secure flag');
      }
      if (!isHttpOnly) {
        httpOnlyMissingCount++;
        if (isPotentiallySensitive) {
          issues.push('Missing HttpOnly on potentially sensitive cookie');
          sensitiveCookieIssues++;
        } else {
          issues.push('Missing HttpOnly flag');
        }
      }
      if (!sameSite || sameSite.toLowerCase() === 'none') {
        sameSiteMissingCount++;
        issues.push('SameSite not set or None');
      }

      let assessment = 'Secure baseline attributes configured.';
      if (issues.length > 0) {
        assessment = isPotentiallySensitive
          ? `Potentially sensitive cookie lacks: ${issues.join(', ')}.`
          : `Non-sensitive cookie lacks: ${issues.join(', ')}.`;
      }

      cookieTable.push({
        name,
        domain,
        path: path || '/',
        secure: isSecure,
        httpOnly: isHttpOnly,
        sameSite: sameSite || 'Not set',
        expires,
        isPotentiallySensitive,
        assessment,
      });

      legacyCookieItems.push({
        name,
        valueMasked,
        secure: isSecure,
        httpOnly: isHttpOnly,
        sameSite: sameSite || 'Not specified',
        domain,
        path: path || '/',
        isFlagged: issues.length > 0,
        issues: issues.length > 0 ? issues : undefined,
        details: `Secure: ${isSecure ? 'Yes' : 'No'}, HttpOnly: ${isHttpOnly ? 'Yes' : 'No'}, SameSite: ${sameSite || 'None'}`,
      });
    }

    // Consolidated Cookie Finding (No duplicate cards per cookie)
    if (cookieTable.length > 0) {
      if (sensitiveCookieIssues > 0) {
        const sensitiveCookies = cookieTable.filter((c) => c.isPotentiallySensitive && !c.httpOnly);
        const names = sensitiveCookies.map((c) => `'${c.name}'`).join(', ');

        const ev: ISecurityEvidence = {
          source: 'cookies',
          check: 'cookie-security-flags',
          observed: `Cookie(s) ${names} lack HttpOnly flag on client response.`,
          expected: 'Set-Cookie with HttpOnly and Secure attributes',
          location: 'Set-Cookie HTTP Response Headers',
          confidence: 0.85,
        };
        technicalEvidences.push(ev);

        findings.push({
          id: 'finding-cookie-httponly-sensitive',
          category: 'Cookie Security',
          findingCategory: 'SECURITY_WEAKNESS',
          severity: 'MEDIUM',
          confidence: 0.85,
          verificationStatus: 'PARTIALLY_VERIFIED',
          title: 'Sensitive Cookie Missing HttpOnly Flag',
          description: `Cookie(s) (${names}) appear potentially sensitive based on name/context but lack the HttpOnly attribute, making them accessible via JavaScript document.cookie (XSS data theft risk).`,
          evidence: `Set-Cookie: ${names} (HttpOnly missing)`,
          evidences: [ev],
          impact: 'In the event of an XSS vulnerability, malicious scripts can read session identifier values.',
          verification: 'Set-Cookie attribute inspection confirmed HttpOnly flag absence.',
          recommendation: 'Configure Set-Cookie with HttpOnly, Secure, and SameSite=Lax/Strict on all session identifiers.',
          affectedComponent: 'Session / Cookie Management',
        });

        riskScore += 15;
        scoreContributors.push({
          findingId: 'finding-cookie-httponly-sensitive',
          category: 'Cookie Security',
          title: 'Sensitive Cookie Missing HttpOnly Flag',
          severity: 'MEDIUM',
          contribution: 15,
          reason: `${sensitiveCookies.length} potentially sensitive cookie(s) lack HttpOnly flag.`,
          evidence: `Cookies: ${names}`,
          remediation: 'Add HttpOnly flag to all session and sensitive cookies.',
        });
        whyVerdict.push(`${sensitiveCookies.length} potentially sensitive cookie(s) lack the HttpOnly attribute.`);
      }

      if (secureMissingCount > 0 && effectiveHttps) {
        const insecureCookies = cookieTable.filter((c) => !c.secure);
        const names = insecureCookies.map((c) => `'${c.name}'`).slice(0, 3).join(', ');

        const ev: ISecurityEvidence = {
          source: 'cookies',
          check: 'cookie-secure-flag',
          observed: `${secureMissingCount} cookie(s) lack Secure flag on HTTPS transmission.`,
          expected: 'Set-Cookie with Secure attribute',
          location: 'Set-Cookie HTTP Response Headers',
          confidence: 0.90,
        };
        technicalEvidences.push(ev);

        findings.push({
          id: 'finding-cookie-secure-missing',
          category: 'Cookie Security',
          findingCategory: 'HARDENING_RECOMMENDATION',
          severity: 'LOW',
          confidence: 0.90,
          verificationStatus: 'OBSERVED',
          title: 'Cookie Security Attributes Missing (Missing Secure Flag)',
          description: `The website sets cookie(s) (${names}) without the Secure flag over an HTTPS connection.`,
          evidence: `Set-Cookie without Secure attribute (${secureMissingCount} cookie(s))`,
          evidences: [ev],
          impact: 'Cookies may be transmitted in cleartext if users follow unencrypted HTTP links to the same host.',
          verification: 'Set-Cookie inspection confirmed Secure flag absence.',
          recommendation: 'Add the Secure attribute to all Set-Cookie directives on HTTPS websites.',
          affectedComponent: 'Session / Cookie Management',
        });

        riskScore += 5;
        scoreContributors.push({
          findingId: 'finding-cookie-secure-missing',
          category: 'Cookie Security',
          title: 'Cookie Missing Secure Flag on HTTPS',
          severity: 'LOW',
          contribution: 5,
          reason: `${secureMissingCount} cookie(s) lack Secure flag over an HTTPS connection.`,
          evidence: `Cookies: ${names}`,
          remediation: 'Add Secure attribute to all Set-Cookie headers on HTTPS.',
        });
        whyVerdict.push(`${secureMissingCount} cookie(s) lack the Secure attribute.`);
      }

      if (secureMissingCount === 0 && httpOnlyMissingCount === 0) {
        positiveControls.push({
          title: 'Secure Cookie Hygiene',
          desc: `All ${cookieTable.length} observed cookie(s) enforce Secure and HttpOnly flags.`,
          evidence: `Cookies analyzed: ${cookieTable.length}`,
          category: 'cookies',
        });
      }
    } else {
      positiveControls.push({
        title: 'No Insecure Cookies Issued',
        desc: 'No cookies with missing security attributes were issued during initial passive request.',
        category: 'cookies',
      });
      whyVerdict.push('No insecure cookies were observed.');
    }

    const cookiesAnalysis: NonNullable<IScanChecks['cookiesAnalysis']> = {
      status: sensitiveCookieIssues > 0 || secureMissingCount > 0 ? 'warning' : cookieTable.length > 0 ? 'passed' : 'neutral',
      totalCookies: cookieTable.length,
      secureCookies: cookieTable.filter((c) => c.secure).length,
      httpOnlyCookies: cookieTable.filter((c) => c.httpOnly).length,
      sameSiteCookies: cookieTable.filter((c) => c.sameSite !== 'Not set').length,
      flaggedCookies: cookieTable.filter((c) => !c.secure || !c.httpOnly).length,
      cookies: legacyCookieItems,
      details: cookieTable.length > 0
        ? `Analyzed ${cookieTable.length} cookie(s): ${cookieTable.filter((c) => c.secure).length} Secure, ${cookieTable.filter((c) => c.httpOnly).length} HttpOnly.`
        : 'No cookies observed in initial response.',
    };

    // ── 6. HTML / DOM Analysis, Forms & Mixed Content ────────────────────────
    const html = httpResult?.htmlSnippet || '';
    let formsCount = 0;
    let passwordFormsCount = 0;
    let insecureFormsCount = 0;
    let externalFormActionsCount = 0;
    let mixedContentCount = 0;
    const mixedContentResources: string[] = [];
    const parsedForms: Array<{
      action: string;
      method: string;
      isExternal: boolean;
      isPlaintextHttp: boolean;
      hasPasswordField: boolean;
      fieldTypes: string[];
    }> = [];

    if (html && html.length > 0) {
      const formMatches = html.match(/<form\b[^>]*>/gi) || [];
      formsCount = formMatches.length;

      const passwordInputMatches = html.match(/<input\b[^>]*type=["']password["'][^>]*>/gi) || [];
      passwordFormsCount = passwordInputMatches.length;

      for (const formTag of formMatches) {
        const actionMatch = formTag.match(/action=["']([^"']*)["']/i);
        const action = actionMatch ? actionMatch[1].trim() : '';
        const methodMatch = formTag.match(/method=["']([^"']*)["']/i);
        const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
        const isPlaintextHttp = action.toLowerCase().startsWith('http://');

        let isExternal = false;
        if (action.startsWith('http://') || action.startsWith('https://')) {
          try {
            const actHost = new URL(action).hostname.toLowerCase();
            isExternal = actHost !== hostname && !actHost.endsWith(`.${hostname}`) && !hostname.endsWith(`.${actHost}`);
          } catch { }
        }
        if (isExternal) externalFormActionsCount++;

        const hasPassword = formTag.toLowerCase().includes('password') || /type=["']password["']/i.test(formTag);
        const fieldTypes: string[] = [];
        const typeMatches = Array.from(formTag.matchAll(/type=["']([^"']+)["']/gi)).map((m: any) => (m[1] as string).toLowerCase());
        typeMatches.forEach((t) => { if (!fieldTypes.includes(t)) fieldTypes.push(t); });

        parsedForms.push({
          action: action || '(same page)',
          method,
          isExternal,
          isPlaintextHttp,
          hasPasswordField: hasPassword,
          fieldTypes,
        });

        // Insecure plaintext form action on HTTPS webpage
        if (effectiveHttps && isPlaintextHttp) {
          insecureFormsCount++;
          const ev: ISecurityEvidence = {
            source: 'html',
            check: 'insecure-form-action',
            observed: `Form action points to unencrypted HTTP URL: "${action}" on an HTTPS webpage.`,
            expected: 'Form action pointing to https:// or relative path',
            location: formTag.slice(0, 100),
            confidence: 1.0,
          };
          technicalEvidences.push(ev);

          findings.push({
            id: 'finding-insecure-form-action',
            category: 'Web Content & Forms',
            findingCategory: 'CONFIRMED_VULNERABILITY',
            severity: 'HIGH',
            confidence: 1.0,
            verificationStatus: 'CONFIRMED',
            title: 'Insecure Plaintext HTTP Form Action on HTTPS Page',
            description: `The website renders an HTML form with an action submitting to unencrypted HTTP (${action}), exposing user data to cleartext interception.`,
            evidence: `Form action: ${action}`,
            evidences: [ev],
            impact: 'Form submissions (including credentials or sensitive inputs) transmitted in cleartext.',
            verification: 'Parsed HTML DOM form tag action attribute.',
            recommendation: 'Update all HTML form actions to submit strictly over encrypted HTTPS URLs.',
            affectedComponent: 'HTML Form Actions',
          });

          riskScore += 30;
          scoreContributors.push({
            findingId: 'finding-insecure-form-action',
            category: 'Forms & Authentication',
            title: 'Insecure Form Action Submitting over HTTP',
            severity: 'HIGH',
            contribution: 30,
            reason: `HTML form submits data to unencrypted HTTP URL (${action}).`,
            evidence: `Action: ${action}`,
            remediation: 'Update form action to submit over HTTPS.',
          });
          whyVerdict.push(`HTML form submitting data to unencrypted HTTP detected (${action}).`);
        }
      }

      // Plaintext password form over HTTP check
      if (passwordFormsCount > 0 && (!effectiveHttps || target.startsWith('http://'))) {
        insecureFormsCount++;
        const ev: ISecurityEvidence = {
          source: 'html',
          check: 'plaintext-password-form',
          observed: `Password input field detected on unencrypted HTTP page (${target}).`,
          expected: 'Password forms must only be served and submitted over secure HTTPS.',
          location: 'HTML Form Password Input',
          confidence: 1.0,
        };
        technicalEvidences.push(ev);

        findings.push({
          id: 'finding-plaintext-password-form',
          category: 'Web Content & Forms',
          findingCategory: 'CONFIRMED_VULNERABILITY',
          severity: 'HIGH',
          confidence: 1.0,
          verificationStatus: 'CONFIRMED',
          title: 'Plaintext Password Form Submission over Unencrypted HTTP',
          description: 'The website renders a password input on an unencrypted HTTP page or submits credentials over plaintext HTTP, exposing passwords to on-path interception.',
          evidence: `Password input on target: ${target}`,
          evidences: [ev],
          impact: 'Cleartext interception of user login credentials.',
          verification: 'Identified password input element served over unencrypted HTTP protocol.',
          recommendation: 'Enforce HTTPS transport across all login, authentication, and form endpoints.',
          affectedComponent: 'Authentication / HTML Forms',
        });

        riskScore += 40;
        scoreContributors.push({
          findingId: 'finding-plaintext-password-form',
          category: 'Forms & Authentication',
          title: 'Plaintext Password Input over Unencrypted HTTP',
          severity: 'HIGH',
          contribution: 40,
          reason: 'Password form input rendered on cleartext HTTP webpage.',
          evidence: `Target: ${target}`,
          remediation: 'Serve all login pages and credentials forms strictly over HTTPS.',
        });
        whyVerdict.push('Plaintext HTTP password input form detected.');
      }

      // Mixed Content Check on HTTPS
      if (effectiveHttps) {
        const scriptHttp = html.match(/<script\b[^>]*src=["'](http:\/\/[^"']+)["']/gi) || [];
        const linkHttp = html.match(/<link\b[^>]*href=["'](http:\/\/[^"']+)["']/gi) || [];
        const imgHttp = html.match(/<img\b[^>]*src=["'](http:\/\/[^"']+)["']/gi) || [];
        const iframeHttp = html.match(/<iframe\b[^>]*src=["'](http:\/\/[^"']+)["']/gi) || [];

        const allMixed = [...scriptHttp, ...linkHttp, ...imgHttp, ...iframeHttp];
        mixedContentCount = allMixed.length;

        allMixed.slice(0, 5).forEach((tag) => {
          const m = tag.match(/["'](http:\/\/[^"']+)["']/i);
          if (m && m[1]) mixedContentResources.push(m[1]);
        });

        if (mixedContentCount > 0) {
          const ev: ISecurityEvidence = {
            source: 'content',
            check: 'mixed-content',
            observed: `HTTPS page loads ${mixedContentCount} unencrypted HTTP asset(s). First observed: ${mixedContentResources[0]}`,
            expected: 'All asset URLs use https:// or relative paths',
            location: 'HTML Asset Tags',
            confidence: 1.0,
          };
          technicalEvidences.push(ev);

          findings.push({
            id: 'finding-mixed-content',
            category: 'Mixed Content',
            findingCategory: 'SECURITY_WEAKNESS',
            severity: 'MEDIUM',
            confidence: 1.0,
            verificationStatus: 'CONFIRMED',
            title: `Mixed Content Detected (${mixedContentCount} HTTP Asset${mixedContentCount > 1 ? 's' : ''})`,
            description: `The HTTPS website loads unencrypted HTTP asset(s) (${mixedContentResources[0] || 'http asset'}), which browsers may block or on-path attackers can tamper with.`,
            evidence: `Sample asset: ${mixedContentResources[0] || 'http asset'}`,
            evidences: [ev],
            impact: 'Passive or active mixed content can be intercepted or manipulated in transit.',
            verification: 'Parsed script/link/image tags in HTML DOM.',
            recommendation: 'Update all asset URLs to use HTTPS schemes or relative paths.',
            affectedComponent: 'HTML Resource Loader',
          });

          riskScore += 15;
          scoreContributors.push({
            findingId: 'finding-mixed-content',
            category: 'Mixed Content',
            title: `Mixed Content Detected (${mixedContentCount} HTTP Asset${mixedContentCount > 1 ? 's' : ''})`,
            severity: 'MEDIUM',
            contribution: 15,
            reason: `HTTPS webpage loads ${mixedContentCount} unencrypted HTTP resource(s).`,
            evidence: `Sample: ${mixedContentResources[0] || 'http asset'}`,
            remediation: 'Update resource links to use HTTPS or relative paths.',
          });
          whyVerdict.push(`${mixedContentCount} mixed HTTP asset(s) detected on HTTPS page.`);
        } else {
          positiveControls.push({
            title: 'No Mixed Content Detected',
            desc: 'All analyzed script, image, iframe, and stylesheet references on the HTTPS page use secure transport.',
            category: 'content',
          });
          technicalEvidences.push({
            source: 'content',
            check: 'mixed-content',
            observed: 'No mixed HTTP resources detected in HTML DOM.',
            confidence: 1.0,
          });
          whyVerdict.push('No mixed content was detected.');
        }
      }
    }

    const scriptTags = (html.match(/<script\b[^>]*>/gi) || []).length;
    const iframesCount = (html.match(/<iframe\b[^>]*>/gi) || []).length;

    const contentAnalysis: NonNullable<IScanChecks['contentAnalysis']> = {
      status: insecureFormsCount > 0 || mixedContentCount > 0 ? 'warning' : 'passed',
      formsCount,
      passwordFormsCount,
      insecureFormsCount,
      externalFormActionsCount,
      scriptsCount: scriptTags,
      externalScriptsCount: (html.match(/<script\b[^>]*src=["']https?:\/\/([^"'/]+)[^"']*["']/gi) || []).length,
      iframesCount,
      mixedContentCount,
      mixedContentResources: mixedContentResources.length > 0 ? mixedContentResources : undefined,
      details: `Analyzed HTML DOM: ${formsCount} form(s), ${scriptTags} script(s), ${iframesCount} iframe(s). ${mixedContentCount > 0 ? `${mixedContentCount} mixed-content asset(s).` : 'No mixed content.'}`,
    };

    // External resources breakdown
    const scriptsMatches = Array.from(html.matchAll(/<script\b[^>]*src=["']([^"']+)["']/gi)).map((m: any) => m[1] as string);
    const linkMatches = Array.from(html.matchAll(/<link\b[^>]*href=["']([^"']+)["']/gi)).map((m: any) => m[1] as string);
    const imgMatches = Array.from(html.matchAll(/<img\b[^>]*src=["']([^"']+)["']/gi)).map((m: any) => m[1] as string);
    const iframeMatches = Array.from(html.matchAll(/<iframe\b[^>]*src=["']([^"']+)["']/gi)).map((m: any) => m[1] as string);
    const externalDomainsSet = new Set<string>();
    [...scriptsMatches, ...linkMatches, ...imgMatches, ...iframeMatches].forEach((url) => {
      if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')) {
        try {
          const u = new URL(url.startsWith('//') ? `https:${url}` : url);
          if (u.hostname && u.hostname.toLowerCase() !== hostname) {
            externalDomainsSet.add(u.hostname.toLowerCase());
          }
        } catch { }
      }
    });

    const externalResources = {
      totalCount: scriptsMatches.length + linkMatches.length + imgMatches.length + iframeMatches.length,
      scriptsCount: scriptsMatches.length,
      externalScriptsCount: scriptsMatches.filter((s) => s.startsWith('http://') || s.startsWith('https://') || s.startsWith('//')).length,
      stylesheetsCount: linkMatches.length,
      imagesCount: imgMatches.length,
      iframesCount: iframeMatches.length,
      mixedContentCount,
      mixedContentResources: mixedContentResources.length > 0 ? mixedContentResources : [],
      externalDomains: Array.from(externalDomainsSet).slice(0, 15),
    };

    const formsAnalysis = {
      totalForms: formsCount,
      passwordForms: passwordFormsCount,
      insecureForms: insecureFormsCount,
      externalFormActions: externalFormActionsCount,
      forms: parsedForms,
    };

    // ── 7. Technical Error Leakage Detection ──────────────────────────────────
    const leakageCheck = this.detectTechnicalErrorLeakage(httpResult?.bodySnippet, allHeaders);
    if (leakageCheck.detected) {
      const ev: ISecurityEvidence = {
        source: 'content',
        check: 'error-information-leakage',
        observed: leakageCheck.leakEvidence[0] || 'Technical error / stack trace disclosure',
        expected: 'Generic sanitized user-friendly error page',
        location: 'HTTP Response Body',
        confidence: 0.95,
      };
      technicalEvidences.push(ev);

      findings.push({
        id: 'finding-error-leakage',
        category: 'Information Disclosure',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'MEDIUM',
        confidence: 0.95,
        verificationStatus: 'CONFIRMED',
        title: 'Technical Error or Stack Trace Information Disclosure',
        description: `The web server response exposes detailed internal error traces, framework diagnostics, or database error messages: ${leakageCheck.details}`,
        evidence: `Sample snippet: ${leakageCheck.leakEvidence[0] || 'Stack trace'}`,
        evidences: [ev],
        impact: 'Exposes database structure, internal filesystem paths, and framework versions to potential attackers.',
        verification: 'Identified technical stack trace / database error signature in response body.',
        recommendation: 'Disable debug mode in production and configure custom generic error handlers.',
        affectedComponent: 'Application Error Handler',
      });

      riskScore += 20;
      scoreContributors.push({
        findingId: 'finding-error-leakage',
        category: 'Information Disclosure',
        title: 'Technical Stack Trace / DB Error Disclosure',
        severity: 'MEDIUM',
        contribution: 20,
        reason: 'Server response exposed technical stack traces or database error messages.',
        evidence: leakageCheck.leakEvidence[0] || 'Stack trace',
        remediation: 'Configure generic sanitized error pages and disable debug mode in production.',
      });
      whyVerdict.push('Technical stack trace or database error disclosure observed in response.');
    } else {
      positiveControls.push({
        title: 'No Technical Stack Trace Leakage',
        desc: 'Server responses did not expose unhandled exceptions, database query errors, or internal file paths.',
        category: 'content',
      });
    }

    // ── 8. Technology Detection ──────────────────────────────────────────────
    const detectedTechnologies = this.detectTechnologies(allHeaders, html);

    // ── 9. Website Understanding ─────────────────────────────────────────────
    const understanding = this.analyzeWebsiteUnderstanding(html, httpResult?.finalUrl || target, detectedTechnologies);

    const websiteOverview: NonNullable<IScanChecks['websiteOverview']> = {
      pageTitle: understanding.pageTitle,
      metaDescription: understanding.metaDescription,
      category: understanding.websiteType,
      purpose: understanding.primaryPurpose,
      primaryFunction: understanding.primaryPurpose,
      contentSummary: understanding.metaDescription || understanding.primaryPurpose,
      websiteType: understanding.websiteType,
      confidence: understanding.confidenceLabel === 'High' ? 'High' : understanding.confidenceLabel === 'Medium' ? 'Medium' : 'Low',
      confidenceReason: `Classified based on ${understanding.evidence.length} observed signal(s) (Confidence: ${Math.round(understanding.confidence * 100)}%).`,
      evidence: {
        pageTitle: understanding.pageTitle,
        metaDescription: understanding.metaDescription,
        headings: understanding.headings,
        keywordsDetected: understanding.keywords,
        hasLoginForm: passwordFormsCount > 0,
        isSpaIndicator: html.includes('/_next/') || html.includes('/_nuxt/'),
      },
      observedBullets: understanding.evidence,
    };

    // ── 10. Risk Score Calculation (Weighted & Evidence-First) ───────────────
    // Cap hardening points at 15 max so missing headers don't cause high risk alone
    const cappedHardeningScore = Math.min(hardeningPoints, 15);
    riskScore += cappedHardeningScore;

    // Direct IP penalty
    if (isDirectIp && !dnsResult.isPrivate) {
      riskScore += 20;
      scoreContributors.push({
        category: 'Hostname Structure',
        title: 'Direct IP Hostname in Use',
        severity: 'MEDIUM',
        contribution: 20,
        reason: 'Host uses a direct IP address rather than a registered domain name.',
        evidence: `Direct IP: ${hostname}`,
        remediation: 'Use a standard registered domain name with proper certificate binding.',
      });
    }

    const rawScore = riskScore;
    riskScore = Math.min(Math.max(riskScore, 0), 100);

    const confirmedCount = findings.filter((f) => f.findingCategory === 'CONFIRMED_VULNERABILITY').length;
    const weaknessCount = findings.filter((f) => f.findingCategory === 'SECURITY_WEAKNESS').length;
    const hardeningCount = findings.filter((f) => f.findingCategory === 'HARDENING_RECOMMENDATION').length;
    const infoCount = findings.filter((f) => f.findingCategory === 'INFORMATIONAL').length;

    let riskLevel: 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' = 'SAFE';
    let classification: ScanResultClassification = 'Safe';

    if (riskScore >= 75 || confirmedCount >= 2) {
      riskLevel = 'CRITICAL';
      classification = 'Critical';
    } else if (riskScore >= 45 || confirmedCount >= 1) {
      riskLevel = 'HIGH';
      classification = 'High Risk';
    } else if (riskScore >= 25 || weaknessCount >= 2) {
      riskLevel = 'MODERATE';
      classification = 'Suspicious';
    } else if (riskScore >= 12 || weaknessCount >= 1 || (hardeningCount >= 4 && riskScore > 10)) {
      riskLevel = 'LOW';
      classification = 'Low Risk';
    } else {
      riskLevel = 'SAFE';
      classification = 'Safe';
    }

    if (confirmedCount === 0 && weaknessCount === 0) {
      whyVerdict.push('No confirmed exploitable vulnerability was established by this passive scan.');
    }

    // Recommendations builder
    if (dnsResult.isPrivate) {
      recommendations.push('Do NOT expose private internal services through public interfaces.');
    }
    if (!effectiveHttps) {
      recommendations.push('Deploy HTTPS across all web endpoints and redirect plaintext HTTP traffic to HTTPS.');
    }
    if (missingHeadersCount > 0) {
      recommendations.push('Implement missing security headers (e.g. Content-Security-Policy, HSTS, X-Content-Type-Options) to enhance browser-level defense.');
    }
    if (sensitiveCookieIssues > 0 || secureMissingCount > 0) {
      recommendations.push('Enforce Secure, HttpOnly, and SameSite attributes on all session and sensitive cookies.');
    }
    if (insecureFormsCount > 0) {
      recommendations.push('Update all form actions to submit data strictly over encrypted HTTPS URLs.');
    }
    if (mixedContentCount > 0) {
      recommendations.push('Eliminate mixed-content by ensuring all scripts, images, and styles use HTTPS URLs.');
    }
    if (recommendations.length === 0) {
      recommendations.push('Website demonstrates strong security posture across headers, transport encryption, and cookie hygiene.');
    }

    // ── 11. Threat Intelligence State ─────────────────────────────────────────
    const threatIntelligence = {
      status: 'NOT_CONFIGURED',
      provider: 'None Configured',
      result: 'Not Available',
      queried: false,
      message: 'Threat intelligence is not configured in this environment. External domain reputation was not evaluated.',
      details: 'No third-party threat intelligence provider is configured in this environment.',
    };

    // ── 12. Execution Outcome ─────────────────────────────────────────────────
    let executionOutcome: 'COMPLETED' | 'BLOCKED_BY_SSRF_POLICY' | 'TARGET_UNREACHABLE' | 'TIMEOUT' | 'DNS_FAILURE' | 'ANALYSIS_UNAVAILABLE' | 'FAILED' = 'COMPLETED';
    if (dnsResult.isPrivate || httpResult?.error === 'SSRF_BLOCKED') {
      executionOutcome = 'BLOCKED_BY_SSRF_POLICY';
    } else if (dnsResult.error) {
      executionOutcome = 'DNS_FAILURE';
    } else if (httpResult?.error === 'ETIMEDOUT') {
      executionOutcome = 'TIMEOUT';
    } else if (httpResult?.error) {
      executionOutcome = 'TARGET_UNREACHABLE';
    }

    // ── 13. Audit Checklist Matrix (12 Checks) ────────────────────────────────
    const auditChecks: IWebsiteAuditCheck[] = [
      {
        id: 'chk-protocol',
        checkId: 'transport-encryption',
        name: 'Protocol Security (HTTPS)',
        status: effectiveHttps ? 'PASS' : 'WARN',
        severity: effectiveHttps ? 'INFO' : 'MEDIUM',
        evidence: `Protocol: ${parsedUrl.protocol}`,
        explanation: effectiveHttps ? 'Target enforces TLS/HTTPS transport encryption.' : 'Target uses unencrypted HTTP protocol; data is transmitted in cleartext.',
      },
      {
        id: 'chk-dns',
        checkId: 'dns-resolution',
        name: 'DNS Resolution & SSRF Policy',
        status: dnsResult.isPrivate || dnsResult.error ? 'FAIL' : 'PASS',
        severity: dnsResult.isPrivate ? 'CRITICAL' : dnsResult.error ? 'MEDIUM' : 'INFO',
        evidence: dnsResult.resolvedIps.length > 0 ? `Resolved ${dnsResult.resolvedIps.length} record(s): ${dnsResult.resolvedIps.slice(0, 3).join(', ')}` : dnsResult.dnsStatus,
        explanation: dnsResult.isPrivate
          ? 'Hostname resolves to private/reserved IP address range (SSRF blocked).'
          : dnsResult.error
            ? `DNS resolution failed: ${dnsResult.error}`
            : 'Domain successfully resolved to active global infrastructure.',
      },
      {
        id: 'chk-tls',
        checkId: 'tls-validity',
        name: 'TLS Certificate Validity',
        status: !effectiveHttps ? 'UNAVAILABLE' : (tlsResult?.valid === false || tlsResult?.error) ? 'FAIL' : 'PASS',
        severity: !effectiveHttps ? 'INFO' : (tlsResult?.valid === false || tlsResult?.error) ? 'HIGH' : 'INFO',
        evidence: !effectiveHttps ? 'HTTPS not in use' : tlsResult?.details || 'Valid TLS certificate',
        explanation: !effectiveHttps
          ? 'TLS inspection not applicable on plain HTTP.'
          : tlsResult?.valid
            ? `Valid ${tlsResult.protocol || 'TLS'} connection. Certificate issued by ${tlsResult.issuer || 'Trusted CA'}.`
            : `TLS validation error: ${tlsResult?.error || 'Validation failure'}.`,
      },
      {
        id: 'chk-hsts',
        checkId: 'hsts-policy',
        name: 'Strict-Transport-Security (HSTS)',
        status: hstsValue ? (hstsValue.includes('max-age=') && parseInt(hstsValue.match(/max-age=(\d+)/i)?.[1] || '0', 10) < 10368000 ? 'WARN' : 'PASS') : effectiveHttps ? 'WARN' : 'NOT DETECTED',
        severity: hstsValue ? 'INFO' : effectiveHttps ? 'LOW' : 'INFO',
        evidence: hstsValue || 'Header Strict-Transport-Security: Not present',
        explanation: hstsValue
          ? `HSTS is active (${hstsValue.slice(0, 50)}).`
          : effectiveHttps
            ? 'HSTS header missing on HTTPS target; client transport downgrade protection is reduced.'
            : 'HSTS requires HTTPS transport.',
      },
      {
        id: 'chk-csp',
        checkId: 'csp-policy',
        name: 'Content-Security-Policy (CSP)',
        status: cspValue ? (hasStrictCsp ? 'PASS' : 'WARN') : 'WARN',
        severity: cspValue ? (hasStrictCsp ? 'INFO' : 'LOW') : 'LOW',
        evidence: cspValue ? (cspValue.length > 70 ? `${cspValue.slice(0, 70)}...` : cspValue) : 'Header Content-Security-Policy: Not present',
        explanation: cspValue
          ? (hasStrictCsp ? 'Strict Content-Security-Policy restricts script origins.' : "CSP contains permissive 'unsafe-inline' or wildcard directives.")
          : 'No Content-Security-Policy header detected in HTTP response.',
      },
      {
        id: 'chk-frame',
        checkId: 'frame-protection',
        name: 'Clickjacking / Frame Protection',
        status: hasFrameProtection ? 'PASS' : 'WARN',
        severity: hasFrameProtection ? 'INFO' : 'LOW',
        evidence: xfoValue ? `X-Frame-Options: ${xfoValue}` : hasCspFrameAncestors ? 'CSP frame-ancestors directive active' : 'Neither X-Frame-Options nor frame-ancestors detected',
        explanation: hasFrameProtection ? 'Iframe embedding restricted to defend against UI redress/clickjacking.' : 'Missing frame protection headers allows third-party iframe embedding.',
      },
      {
        id: 'chk-nosniff',
        checkId: 'mime-sniffing',
        name: 'MIME Sniffing Protection (nosniff)',
        status: xctoValue && xctoValue.toLowerCase().includes('nosniff') ? 'PASS' : 'WARN',
        severity: xctoValue && xctoValue.toLowerCase().includes('nosniff') ? 'INFO' : 'LOW',
        evidence: xctoValue ? `X-Content-Type-Options: ${xctoValue}` : 'Header X-Content-Type-Options: Not present',
        explanation: xctoValue && xctoValue.toLowerCase().includes('nosniff') ? 'MIME sniffing disabled via nosniff directive.' : 'Missing X-Content-Type-Options: nosniff directive.',
      },
      {
        id: 'chk-referrer',
        checkId: 'referrer-policy',
        name: 'Referrer Policy',
        status: referrerValue ? 'PASS' : 'WARN',
        severity: referrerValue ? 'INFO' : 'LOW',
        evidence: referrerValue ? `Referrer-Policy: ${referrerValue}` : 'Header Referrer-Policy: Not present',
        explanation: referrerValue ? `Referrer-Policy configured (${referrerValue}).` : 'No explicit Referrer-Policy declared; browser applies default policy.',
      },
      {
        id: 'chk-cookies',
        checkId: 'cookie-security',
        name: 'Cookie Security & Attributes',
        status: sensitiveCookieIssues > 0 ? 'FAIL' : secureMissingCount > 0 ? 'WARN' : 'PASS',
        severity: sensitiveCookieIssues > 0 ? 'MEDIUM' : secureMissingCount > 0 ? 'LOW' : 'INFO',
        evidence: cookieTable.length > 0 ? `Analyzed ${cookieTable.length} cookie(s): ${secureMissingCount} missing Secure, ${httpOnlyMissingCount} missing HttpOnly` : 'No cookies issued in initial response',
        explanation: sensitiveCookieIssues > 0
          ? `${sensitiveCookieIssues} sensitive cookie(s) lack HttpOnly flag.`
          : secureMissingCount > 0
            ? `${secureMissingCount} cookie(s) lack Secure flag on HTTPS.`
            : 'All analyzed cookies adhere to defensive flag standards.',
      },
      {
        id: 'chk-forms',
        checkId: 'form-security',
        name: 'Form & Credential Security',
        status: insecureFormsCount > 0 ? 'FAIL' : 'PASS',
        severity: insecureFormsCount > 0 ? 'HIGH' : 'INFO',
        evidence: `Forms analyzed: ${formsCount} (${passwordFormsCount} password form(s), ${insecureFormsCount} insecure submission(s))`,
        explanation: insecureFormsCount > 0 ? 'Forms detected submitting data or passwords over unencrypted HTTP.' : 'All analyzed forms use secure submission targets.',
      },
      {
        id: 'chk-mixed-content',
        checkId: 'mixed-content',
        name: 'Mixed Content Transport',
        status: mixedContentCount > 0 ? 'WARN' : 'PASS',
        severity: mixedContentCount > 0 ? 'MEDIUM' : 'INFO',
        evidence: mixedContentCount > 0 ? `${mixedContentCount} HTTP asset(s) on HTTPS page` : 'No mixed HTTP assets detected',
        explanation: mixedContentCount > 0
          ? `Detected ${mixedContentCount} unencrypted HTTP resource(s) loaded by an HTTPS webpage.`
          : 'All page assets load strictly over encrypted HTTPS transport.',
      },
      {
        id: 'chk-reputation',
        checkId: 'threat-reputation',
        name: 'Threat Intelligence & Reputation',
        status: 'UNAVAILABLE',
        severity: 'INFO',
        evidence: 'No third-party reputation provider configured in current environment',
        explanation: 'Threat intelligence provider is not configured. External reputation was not evaluated.',
      },
    ];

    // ── 14. Honest Limitations & Score Explanation ───────────────────────────
    const limitations = [
      'CyberWatch performs non-destructive website security analysis using observable network, transport, HTTP, and static page evidence.',
      'It does not perform intrusive penetration testing, execute arbitrary website code, or guarantee that a website is completely safe.',
      'Threat intelligence was not configured in this environment and external domain reputation was not evaluated.',
    ];

    const scoreExplanation: IWebsiteScoreExplanation = {
      summary: scoreContributors.length === 0
        ? 'No risk contributions were identified from the checks completed during this scan.'
        : `Risk score (${riskScore}/100) calculated from ${scoreContributors.length} observed indicator(s): ${scoreContributors.map((c) => `${c.title} (+${c.contribution})`).join(', ')}.`,
      rawScore,
      normalizedScore: riskScore,
      contributors: scoreContributors,
      limitations,
    };

    // Final WebsiteSecurityV2Analysis model
    const websiteSecurityV2: IWebsiteSecurityV2Analysis = {
      riskScore,
      riskLevel,
      confidence: 0.95,
      executionOutcome,
      counts: {
        confirmedVulnerabilities: confirmedCount,
        securityWeaknesses: weaknessCount,
        hardeningRecommendations: hardeningCount,
        informationalFindings: infoCount,
        total: findings.length,
      },
      whyVerdict: Array.from(new Set(whyVerdict)),
      whyThisVerdict: Array.from(new Set(whyVerdict)),
      scoreContributors,
      scoreExplanation,
      positiveControls,
      cookieSecuritySummary: {
        totalCookies: cookieTable.length,
        secureMissing: secureMissingCount,
        httpOnlyMissing: httpOnlyMissingCount,
        sameSiteMissing: sameSiteMissingCount,
        table: cookieTable,
      },
      technologyDetections: detectedTechnologies,
      websiteUnderstanding: {
        websiteType: understanding.websiteType,
        industry: understanding.industry,
        primaryPurpose: understanding.primaryPurpose,
        confidence: understanding.confidence,
        confidenceLabel: understanding.confidenceLabel,
        evidence: understanding.evidence,
        pageTitle: understanding.pageTitle,
        metaDescription: understanding.metaDescription,
        headings: understanding.headings,
        canonicalUrl: understanding.canonicalUrl,
      },
      technicalEvidence: technicalEvidences,
      errorLeakage: {
        detected: leakageCheck.detected,
        findings: leakageCheck.findings,
        details: leakageCheck.details,
      },
      threatIntelligence,
      formsAnalysis,
      externalResources,
      auditChecks,
      limitations,
    };

    const cookieAnalysisObj = {
      totalCookies: cookieTable.length,
      secureMissing: secureMissingCount,
      httpOnlyMissing: httpOnlyMissingCount,
      sameSiteMissing: sameSiteMissingCount,
      flaggedCookies: cookieTable.filter((c) => !c.secure || !c.httpOnly).length,
      cookies: cookieTable.map((c) => ({
        name: c.name,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite,
        expires: c.expires,
        isPotentiallySensitive: c.isPotentiallySensitive,
        isFlagged: !c.secure || !c.httpOnly,
        issues: !c.secure || !c.httpOnly ? [!c.secure ? 'Missing Secure' : '', !c.httpOnly ? 'Missing HttpOnly' : ''].filter(Boolean) : [],
        details: c.assessment,
      })),
      table: cookieTable,
    };

    return {
      websiteSecurityV2,
      findings,
      recommendations,
      riskScore,
      riskLevel,
      confidence: 0.95,
      executionOutcome,
      findingsCounts: websiteSecurityV2.counts,
      whyThisVerdict: websiteSecurityV2.whyVerdict,
      whyVerdict: websiteSecurityV2.whyVerdict,
      scoreContributors,
      scoreExplanation,
      positiveControls,
      cookieAnalysis: cookieAnalysisObj,
      cookiesAnalysis,
      technologyDetection: detectedTechnologies,
      websiteUnderstanding: websiteSecurityV2.websiteUnderstanding,
      classification,
      securityHeadersAnalysis,
      contentAnalysis,
      websiteOverview,
      auditChecks,
      threatIntelligence,
    };
  }
}

export const websiteScannerV2Service = new WebsiteScannerV2Service();

