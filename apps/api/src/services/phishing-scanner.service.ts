import { URL } from 'node:url';
import {
  IScanFinding,
  ISecurityEvidence,
  IPhishingSecurityAnalysis,
  IPhishingIndicator,
  IPhishingScoreContributor,
  IPhishingScoreExplanation,
  ScanResultClassification,
  FindingSeverity,
} from '../models/Scan';
import { deriveClassificationFromRiskScore, maskSensitiveUrl } from './scan.service';
import { DomainIntelligenceResult } from './domain-intelligence.service';

export interface PhishingScannerInput {
  target: string;
  normalizedTarget: string;
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
  threatIntelResult?: {
    status: 'Not Configured' | 'Queried' | 'Unavailable' | 'Clean' | 'Threat Detected';
    provider?: string;
    queried: boolean;
    result?: string;
    details: string;
  };
  domainIntelligence?: DomainIntelligenceResult;
}

export interface PhishingScannerResult {
  phishingSecurityAnalysis: IPhishingSecurityAnalysis;
  findings: IScanFinding[];
  recommendations: string[];
  riskScore: number;
  classification: ScanResultClassification;
  confidence: number;
  confidenceLabel: 'High' | 'Moderate' | 'Low' | 'Baseline';
  whyVerdict: string[];
  positiveSignals: Array<{ title: string; desc: string; category?: string }>;
  scoreContributors: IPhishingScoreContributor[];
  scoreExplanation: IPhishingScoreExplanation;
  indicators: IPhishingIndicator[];
  limitations: string[];
}

/**
 * Standard Brand Identity Dictionary
 * Maps well-known brands to their authorized registrable domains and key identification tokens.
 */
interface BrandIdentityDefinition {
  brandName: string;
  authorizedDomains: string[];
  identityKeywords: string[];
  loginKeywords: string[];
}

const KNOWN_BRAND_REGISTRY: BrandIdentityDefinition[] = [
  {
    brandName: 'PayPal',
    authorizedDomains: ['paypal.com', 'paypal-communication.com'],
    identityKeywords: ['paypal'],
    loginKeywords: ['paypal login', 'paypal account', 'verify paypal', 'paypal verification'],
  },
  {
    brandName: 'Microsoft',
    authorizedDomains: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'microsoftonline.com', 'azure.com'],
    identityKeywords: ['microsoft', 'outlook', 'office 365', 'onedrive', 'azure'],
    loginKeywords: ['sign in to your microsoft account', 'microsoft account', 'outlook login', 'office 365 login'],
  },
  {
    brandName: 'Google',
    authorizedDomains: ['google.com', 'accounts.google.com', 'gmail.com', 'youtube.com'],
    identityKeywords: ['google', 'gmail', 'google workspace', 'google drive'],
    loginKeywords: ['sign in - google accounts', 'sign in with google', 'google account verification'],
  },
  {
    brandName: 'Apple',
    authorizedDomains: ['apple.com', 'icloud.com'],
    identityKeywords: ['apple', 'icloud', 'apple id'],
    loginKeywords: ['sign in to apple id', 'manage your apple id', 'icloud sign in', 'verify apple id'],
  },
  {
    brandName: 'Meta / Facebook',
    authorizedDomains: ['facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'messenger.com'],
    identityKeywords: ['facebook', 'instagram', 'meta', 'whatsapp'],
    loginKeywords: ['log into facebook', 'instagram login', 'facebook security checkpoint'],
  },
  {
    brandName: 'Amazon',
    authorizedDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.ca', 'amazon.fr', 'amazon.jp', 'aws.amazon.com'],
    identityKeywords: ['amazon', 'amazon prime', 'aws'],
    loginKeywords: ['amazon sign-in', 'amazon prime verification', 'verify your amazon account'],
  },
  {
    brandName: 'Netflix',
    authorizedDomains: ['netflix.com'],
    identityKeywords: ['netflix'],
    loginKeywords: ['netflix sign in', 'update netflix payment', 'netflix membership verification'],
  },
  {
    brandName: 'Chase Bank',
    authorizedDomains: ['chase.com'],
    identityKeywords: ['chase bank', 'jpmorgan chase'],
    loginKeywords: ['sign in to chase online', 'chase verification', 'chase secure banking'],
  },
  {
    brandName: 'Bank of America',
    authorizedDomains: ['bankofamerica.com'],
    identityKeywords: ['bank of america', 'bofa'],
    loginKeywords: ['bank of america sign in', 'bofa verification', 'online banking access'],
  },
  {
    brandName: 'Wells Fargo',
    authorizedDomains: ['wellsfargo.com'],
    identityKeywords: ['wells fargo'],
    loginKeywords: ['wells fargo sign on', 'wells fargo verification'],
  },
  {
    brandName: 'MetaMask',
    authorizedDomains: ['metamask.io'],
    identityKeywords: ['metamask'],
    loginKeywords: ['unlock metamask wallet', 'import srp', 'wallet recovery phrase', 'secret recovery phrase'],
  },
  {
    brandName: 'Coinbase',
    authorizedDomains: ['coinbase.com'],
    identityKeywords: ['coinbase'],
    loginKeywords: ['sign in to coinbase', 'coinbase verification', 'unlock coinbase account'],
  },
  {
    brandName: 'Binance',
    authorizedDomains: ['binance.com', 'binance.us'],
    identityKeywords: ['binance'],
    loginKeywords: ['binance login', 'verify binance account', 'binance security verification'],
  },
  {
    brandName: 'Dropbox',
    authorizedDomains: ['dropbox.com'],
    identityKeywords: ['dropbox'],
    loginKeywords: ['sign in to dropbox', 'dropbox document share verification'],
  },
  {
    brandName: 'Adobe',
    authorizedDomains: ['adobe.com'],
    identityKeywords: ['adobe', 'creative cloud'],
    loginKeywords: ['adobe id sign in', 'adobe document cloud access'],
  },
  {
    brandName: 'DHL',
    authorizedDomains: ['dhl.com', 'dhl.de'],
    identityKeywords: ['dhl express', 'dhl tracking'],
    loginKeywords: ['dhl package verification', 'dhl delivery fee payment', 'dhl tracking sign in'],
  },
  {
    brandName: 'FedEx',
    authorizedDomains: ['fedex.com'],
    identityKeywords: ['fedex'],
    loginKeywords: ['fedex package delivery verification', 'fedex payment tracking'],
  },
];

export class PhishingScannerService {
  /**
   * Helper: extract registrable 2-level domain from hostname (e.g. "sub.example.co.uk" or "sub.example.com").
   */
  public extractRegistrableDomain(hostname: string): string {
    const cleanHost = hostname.toLowerCase().trim().replace(/^www\./, '');
    const parts = cleanHost.split('.');
    if (parts.length <= 2) return cleanHost;

    // Check for 2-level TLDs (e.g., co.uk, com.au, org.uk)
    const twoLevelTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'gov.uk', 'org.uk', 'ac.uk', 'edu.au'];
    const lastTwo = parts.slice(-2).join('.');
    if (twoLevelTlds.includes(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  /**
   * Helper: check if two hostnames belong to the same registrable domain.
   */
  public isSameRegistrableDomain(hostA: string, hostB: string): boolean {
    if (hostA.toLowerCase() === hostB.toLowerCase()) return true;
    const domA = this.extractRegistrableDomain(hostA);
    const domB = this.extractRegistrableDomain(hostB);
    return domA === domB;
  }

  /**
   * Helper: safe HTML text extractor.
   */
  public extractHtmlMetadata(html: string | undefined): {
    pageTitle?: string;
    metaDescription?: string;
    headings: string[];
    visibleSnippet: string;
  } {
    if (!html || typeof html !== 'string') {
      return { headings: [], visibleSnippet: '' };
    }

    // Page Title
    let pageTitle: string | undefined;
    const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
    if (titleMatch && titleMatch[1]) {
      pageTitle = titleMatch[1]
        .replace(/&amp;/g, '&')
        .replace(/&quot;/g, '"')
        .replace(/&#39;|&apos;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/\s+/g, ' ')
        .trim();
    }

    // Meta Description
    let metaDescription: string | undefined;
    const metaDescMatch =
      html.match(/<meta\b[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i) ||
      html.match(/<meta\b[^>]*content=["']([^"']*)["'][^>]*name=["']description["']/i) ||
      html.match(/<meta\b[^>]*property=["']og:description["'][^>]*content=["']([^"']*)["']/i);
    if (metaDescMatch && metaDescMatch[1]) {
      metaDescription = metaDescMatch[1].replace(/\s+/g, ' ').trim();
    }

    // Headings (h1, h2)
    const headings: string[] = [];
    const headingRegex = /<h[1-2]\b[^>]*>([\s\S]*?)<\/h[1-2]>/gi;
    let match: RegExpExecArray | null;
    while ((match = headingRegex.exec(html)) !== null) {
      const text = match[1].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
      if (text.length > 0 && text.length < 150 && !headings.includes(text)) {
        headings.push(text);
        if (headings.length >= 5) break;
      }
    }

    // Visible text snippet
    const bodyWithoutScripts = html
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
      .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
      .replace(/<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    const visibleSnippet = bodyWithoutScripts.slice(0, 1500);

    return {
      pageTitle,
      metaDescription,
      headings,
      visibleSnippet,
    };
  }

  /**
   * Main Phishing Scanner Analysis Engine
   */
  public analyze(input: PhishingScannerInput): PhishingScannerResult {
    const {
      target,
      normalizedTarget,
      parsedUrl,
      dnsResult,
      httpResult,
      tlsResult,
      effectiveHttps,
      threatIntelResult,
    } = input;

    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname;
    const search = parsedUrl.search;
    const fullNormalized = normalizedTarget.toLowerCase();
    const registrableDomain = this.extractRegistrableDomain(hostname);
    const hostParts = hostname.split('.');

    const findings: IScanFinding[] = [];
    const scoreContributors: IPhishingScoreContributor[] = [];
    const indicators: IPhishingIndicator[] = [];
    const positiveSignals: Array<{ title: string; desc: string; category?: string }> = [];
    const whyVerdict: string[] = [];
    const recommendations: string[] = [];
    const limitations: string[] = [
      'Analysis is passive and non-destructive. No credentials were submitted and no active exploitation was attempted.',
      'JavaScript-rendered single-page applications may contain dynamic lures that are not fully exposed in static HTML.',
      'Heuristic threat indicators reflect structural and deceptive patterns and are not calibrated statistical probabilities.',
    ];

    let rawScore = 0;

    const addContributor = (
      category: string,
      title: string,
      severity: FindingSeverity,
      points: number,
      reason: string,
      evidence?: string,
      remediation?: string,
      findingId?: string
    ) => {
      rawScore += points;
      scoreContributors.push({
        findingId,
        category,
        title,
        severity,
        contribution: points,
        reason,
        evidence,
        remediation,
      });
    };

    // ── 0. Handle Fatal Network & SSRF Exceptions ────────────────────────────
    if (dnsResult.isPrivate) {
      const blockedFinding: IScanFinding = {
        category: 'SSRF & Safety Policy',
        findingCategory: 'CONFIRMED_VULNERABILITY',
        severity: 'CRITICAL',
        title: 'Target Resolves to Private / Internal Network Address (SSRF Blocked)',
        description: `The destination hostname (${hostname}) resolves to a reserved, loopback, or private internal IP address (${dnsResult.resolvedIps.join(', ') || 'Internal IP'}). Analysis was blocked to protect internal infrastructure.`,
        evidence: `Resolved IP: ${dnsResult.resolvedIps.join(', ') || 'Private/Loopback'}`,
        impact: 'Requesting internal infrastructure exposes backend services to Server-Side Request Forgery (SSRF) exploitation.',
        recommendation: 'Do NOT scan internal, private, or metadata network IP addresses through public scanner endpoints.',
      };
      findings.push(blockedFinding);
      addContributor(
        'SSRF & Security Policy',
        'Private / Internal Address Target (SSRF Blocked)',
        'CRITICAL',
        80,
        'Destination resolves to private, loopback, or cloud metadata address blocked by SSRF policy.',
        dnsResult.resolvedIps.join(', ') || 'Internal IP',
        'Analyze only publicly accessible internet destinations.'
      );

      const riskScore = 80;
      const classification: ScanResultClassification = 'Critical';
      const explanation: IPhishingScoreExplanation = {
        summary: 'Target analysis blocked: Destination resolves to a private or internal IP address.',
        rawScore: 80,
        normalizedScore: 80,
        contributors: scoreContributors,
        positiveSignals: [],
        limitations,
      };

      const analysis: IPhishingSecurityAnalysis = {
        status: 'failed',
        executionOutcome: 'BLOCKED_BY_SSRF_POLICY',
        statusExplanation: 'Analysis blocked by CyberWatch SSRF protection policy.',
        confidence: 0,
        confidenceLabel: 'Baseline',
        riskScore,
        riskLevel: 'CRITICAL',
        details: 'Target resolves to a private or internal network address. Scan blocked by SSRF security policy.',
        summary: 'Target resolves to private network space. Phishing analysis could not proceed.',
        targetProfile: {
          originalUrl: maskSensitiveUrl(target),
          normalizedUrl: maskSensitiveUrl(normalizedTarget),
          finalUrl: maskSensitiveUrl(normalizedTarget),
          hostname,
          domain: registrableDomain,
          registrableDomain,
          isIpAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':'),
          isPunycode: hostname.includes('xn--'),
          subdomainCount: hostParts.length > 2 ? hostParts.length - 2 : 0,
          pathDepth: pathname.split('/').filter(Boolean).length,
          queryParamCount: search ? search.slice(1).split('&').length : 0,
        },
        redirectAnalysis: {
          totalHops: 0,
          hasCrossDomainRedirect: false,
          hasProtocolDowngrade: false,
          chain: [],
          assessment: 'No redirect inspection performed due to SSRF block.',
        },
        domainIdentityAnalysis: {
          detectedBrands: [],
          isLegitimateBrandDomain: false,
          impersonationDetected: false,
          homographDetected: false,
          punycodeLabels: [],
          suspiciousSubdomains: [],
          assessment: 'Domain identity inspection unavailable.',
        },
        pageIdentityAnalysis: {
          headings: [],
          identityConsistency: 'UNAVAILABLE',
          assessment: 'Page content unavailable due to SSRF block.',
        },
        credentialAnalysis: {
          hasLoginForm: false,
          hasPasswordField: false,
          hasUsernameOrEmailField: false,
          hasMfaField: false,
          formCount: 0,
          passwordFormCount: 0,
          insecureFormCount: 0,
          externalActionFormCount: 0,
          forms: [],
          assessment: 'Form inspection unavailable.',
        },
        socialEngineeringAnalysis: {
          urgencyKeywordsFound: [],
          securityAlertKeywordsFound: [],
          rewardKeywordsFound: [],
          isHeuristicSignal: false,
          assessment: 'Social engineering inspection unavailable.',
        },
        transportAnalysis: {
          usesHttps: effectiveHttps,
          assessment: 'Transport inspection blocked by SSRF policy.',
        },
        threatIntelligence: {
          status: 'Not Configured',
          queried: false,
          details: 'Threat intelligence was not configured for this scan.',
        },
        indicators: [],
        scoreContributors,
        scoreExplanation: explanation,
        positiveSignals: [],
        limitations,
        technicalDetails: {
          originalUrl: maskSensitiveUrl(target),
          finalUrl: maskSensitiveUrl(normalizedTarget),
          hostname,
          resolvedIps: dnsResult.resolvedIps,
          dnsStatus: dnsResult.dnsStatus,
        },
      };

      return {
        phishingSecurityAnalysis: analysis,
        findings,
        recommendations: ['Do NOT direct automated scanners toward internal network endpoints.'],
        riskScore,
        classification,
        confidence: 0,
        confidenceLabel: 'Baseline',
        whyVerdict: ['Target resolves to an internal network address (SSRF blocked).'],
        positiveSignals: [],
        scoreContributors,
        scoreExplanation: explanation,
        indicators: [],
        limitations,
      };
    }

    if (dnsResult.error) {
      const dnsFinding: IScanFinding = {
        category: 'DNS & Infrastructure',
        findingCategory: 'INFORMATIONAL',
        severity: 'MEDIUM',
        title: 'DNS Hostname Resolution Failed (Unresolvable Domain)',
        description: `The destination domain (${hostname}) could not be resolved in the global DNS hierarchy: ${dnsResult.error}.`,
        evidence: dnsResult.error,
        impact: 'Unresolvable domains cannot be reached by web clients or scanners.',
        recommendation: 'Verify the domain spelling and ensure authoritative DNS records are properly configured.',
      };
      findings.push(dnsFinding);
      addContributor(
        'DNS & Infrastructure',
        'DNS Hostname Resolution Failed',
        'MEDIUM',
        20,
        `Domain could not be resolved via DNS (${dnsResult.error}).`,
        dnsResult.error
      );

      const riskScore = 20;
      const classification: ScanResultClassification = 'Low Risk';
      const explanation: IPhishingScoreExplanation = {
        summary: `Target DNS resolution failed (${dnsResult.error}). Phishing analysis could not inspect page content.`,
        rawScore: 20,
        normalizedScore: 20,
        contributors: scoreContributors,
        positiveSignals: [],
        limitations,
      };

      const analysis: IPhishingSecurityAnalysis = {
        status: 'failed',
        executionOutcome: 'DNS_FAILURE',
        statusExplanation: `Domain name resolution failed (${dnsResult.error}).`,
        confidence: 0,
        confidenceLabel: 'Baseline',
        riskScore,
        riskLevel: 'LOW',
        details: `Analysis unavailable: Domain could not be resolved in DNS (${dnsResult.error}).`,
        summary: `DNS resolution failed (${dnsResult.error}). Destination is currently unresolvable.`,
        targetProfile: {
          originalUrl: maskSensitiveUrl(target),
          normalizedUrl: maskSensitiveUrl(normalizedTarget),
          finalUrl: maskSensitiveUrl(normalizedTarget),
          hostname,
          domain: registrableDomain,
          registrableDomain,
          isIpAddress: false,
          isPunycode: hostname.includes('xn--'),
          subdomainCount: hostParts.length > 2 ? hostParts.length - 2 : 0,
          pathDepth: pathname.split('/').filter(Boolean).length,
          queryParamCount: 0,
        },
        redirectAnalysis: {
          totalHops: 0,
          hasCrossDomainRedirect: false,
          hasProtocolDowngrade: false,
          chain: [],
          assessment: 'No redirect inspection performed due to DNS resolution failure.',
        },
        domainIdentityAnalysis: {
          detectedBrands: [],
          isLegitimateBrandDomain: false,
          impersonationDetected: false,
          homographDetected: false,
          punycodeLabels: [],
          suspiciousSubdomains: [],
          assessment: 'Domain is unresolvable.',
        },
        pageIdentityAnalysis: {
          headings: [],
          identityConsistency: 'UNAVAILABLE',
          assessment: 'Content inspection unavailable due to DNS resolution failure.',
        },
        credentialAnalysis: {
          hasLoginForm: false,
          hasPasswordField: false,
          hasUsernameOrEmailField: false,
          hasMfaField: false,
          formCount: 0,
          passwordFormCount: 0,
          insecureFormCount: 0,
          externalActionFormCount: 0,
          forms: [],
          assessment: 'Form inspection unavailable.',
        },
        socialEngineeringAnalysis: {
          urgencyKeywordsFound: [],
          securityAlertKeywordsFound: [],
          rewardKeywordsFound: [],
          isHeuristicSignal: false,
          assessment: 'Content inspection unavailable.',
        },
        transportAnalysis: {
          usesHttps: effectiveHttps,
          assessment: 'TLS inspection unavailable due to DNS resolution failure.',
        },
        threatIntelligence: {
          status: 'Not Configured',
          queried: false,
          details: 'Threat intelligence was not configured for this scan.',
        },
        indicators: [],
        scoreContributors,
        scoreExplanation: explanation,
        positiveSignals: [],
        limitations,
        technicalDetails: {
          originalUrl: maskSensitiveUrl(target),
          finalUrl: maskSensitiveUrl(normalizedTarget),
          hostname,
          resolvedIps: [],
          dnsStatus: dnsResult.dnsStatus,
        },
      };

      return {
        phishingSecurityAnalysis: analysis,
        findings,
        recommendations: ['Verify domain spelling and ensure authoritative DNS records are live.'],
        riskScore,
        classification,
        confidence: 0,
        confidenceLabel: 'Baseline',
        whyVerdict: [`DNS resolution failed for hostname ${hostname}.`],
        positiveSignals: [],
        scoreContributors,
        scoreExplanation: explanation,
        indicators: [],
        limitations,
      };
    }

    if (httpResult?.error === 'ETIMEDOUT' || (httpResult?.error && !httpResult.statusCode)) {
      const unreachableFinding: IScanFinding = {
        category: 'HTTP & Network',
        findingCategory: 'INFORMATIONAL',
        severity: 'LOW',
        title: 'Target Web Server Unreachable / Connection Timed Out',
        description: `Network connection to target web server failed (${httpResult.error || 'Connection timed out'}).`,
        evidence: httpResult.error || 'ETIMEDOUT',
        impact: 'Target cannot be reached over HTTP/HTTPS for page content analysis.',
        recommendation: 'Check server availability and firewall rules.',
      };
      findings.push(unreachableFinding);
      addContributor(
        'HTTP & Network',
        'Target Server Unreachable',
        'LOW',
        15,
        `Network connection to target failed (${httpResult.error || 'Timed out'}).`,
        httpResult.error || 'ETIMEDOUT'
      );

      const riskScore = 15;
      const classification: ScanResultClassification = 'Low Risk';
      const explanation: IPhishingScoreExplanation = {
        summary: 'Target server connection failed or timed out. Phishing assessment based solely on URL structure.',
        rawScore: 15,
        normalizedScore: 15,
        contributors: scoreContributors,
        positiveSignals: [],
        limitations,
      };

      const analysis: IPhishingSecurityAnalysis = {
        status: 'failed',
        executionOutcome: httpResult.error === 'ETIMEDOUT' ? 'TIMEOUT' : 'TARGET_UNREACHABLE',
        statusExplanation: `Connection to target failed (${httpResult.error || 'Timed out'}).`,
        confidence: 0,
        confidenceLabel: 'Baseline',
        riskScore,
        riskLevel: 'LOW',
        details: `Analysis unavailable: Target connection failed (${httpResult.error || 'Timed out'}).`,
        summary: `Target connection failed (${httpResult.error || 'Timed out'}). Full page analysis could not proceed.`,
        targetProfile: {
          originalUrl: maskSensitiveUrl(target),
          normalizedUrl: maskSensitiveUrl(normalizedTarget),
          finalUrl: maskSensitiveUrl(normalizedTarget),
          hostname,
          domain: registrableDomain,
          registrableDomain,
          isIpAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':'),
          isPunycode: hostname.includes('xn--'),
          subdomainCount: hostParts.length > 2 ? hostParts.length - 2 : 0,
          pathDepth: pathname.split('/').filter(Boolean).length,
          queryParamCount: search ? search.slice(1).split('&').length : 0,
        },
        redirectAnalysis: {
          totalHops: 0,
          hasCrossDomainRedirect: false,
          hasProtocolDowngrade: false,
          chain: [],
          assessment: 'No redirect inspection performed due to connection failure.',
        },
        domainIdentityAnalysis: {
          detectedBrands: [],
          isLegitimateBrandDomain: false,
          impersonationDetected: false,
          homographDetected: false,
          punycodeLabels: [],
          suspiciousSubdomains: [],
          assessment: 'Server unreachable for DOM inspection.',
        },
        pageIdentityAnalysis: {
          headings: [],
          identityConsistency: 'UNAVAILABLE',
          assessment: 'Content inspection unavailable due to network connection failure.',
        },
        credentialAnalysis: {
          hasLoginForm: false,
          hasPasswordField: false,
          hasUsernameOrEmailField: false,
          hasMfaField: false,
          formCount: 0,
          passwordFormCount: 0,
          insecureFormCount: 0,
          externalActionFormCount: 0,
          forms: [],
          assessment: 'Form inspection unavailable.',
        },
        socialEngineeringAnalysis: {
          urgencyKeywordsFound: [],
          securityAlertKeywordsFound: [],
          rewardKeywordsFound: [],
          isHeuristicSignal: false,
          assessment: 'Content inspection unavailable.',
        },
        transportAnalysis: {
          usesHttps: effectiveHttps,
          assessment: 'Server unreachable.',
        },
        threatIntelligence: {
          status: 'Not Configured',
          queried: false,
          details: 'Threat intelligence was not configured for this scan.',
        },
        indicators: [],
        scoreContributors,
        scoreExplanation: explanation,
        positiveSignals: [],
        limitations,
        technicalDetails: {
          originalUrl: maskSensitiveUrl(target),
          finalUrl: maskSensitiveUrl(normalizedTarget),
          hostname,
          resolvedIps: dnsResult.resolvedIps,
          dnsStatus: dnsResult.dnsStatus,
        },
      };

      return {
        phishingSecurityAnalysis: analysis,
        findings,
        recommendations: ['Verify target server availability and firewall reachability.'],
        riskScore,
        classification,
        confidence: 0,
        confidenceLabel: 'Baseline',
        whyVerdict: [`Connection to ${hostname} timed out or failed.`],
        positiveSignals: [],
        scoreContributors,
        scoreExplanation: explanation,
        indicators: [],
        limitations,
      };
    }

    // ── 1. URL & Domain Structure Inspection ────────────────────────────────
    const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
    const punycodeLabels = hostParts.filter((p) => p.startsWith('xn--'));
    const isPunycode = punycodeLabels.length > 0;
    const subdomainsList = isDirectIp ? [] : hostParts.length > 2 ? hostParts.slice(0, -2) : [];
    const pathDepth = pathname.split('/').filter(Boolean).length;
    const queryParamsCount = search ? search.slice(1).split('&').length : 0;

    // Direct IP Address Hostname
    if (isDirectIp) {
      const ipFinding: IScanFinding = {
        category: 'Domain & Hostname',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'HIGH',
        title: 'Direct IP Address Hostname Indicator',
        description: `Target URL specifies a raw IP address (${hostname}) instead of a registered domain name. Phishing campaigns frequently employ direct IP hosting to evade domain reputation tracking.`,
        evidence: `Host: ${hostname}`,
        impact: 'Direct IP hostnames bypass domain reputation filters and lack standard domain ownership verification.',
        recommendation: 'Exercise extreme caution when interacting with direct IP destinations. Legitimate organizations virtually always use registered domain names.',
      };
      findings.push(ipFinding);
      addContributor(
        'URL & Domain Structure',
        'Direct IP Address Hostname',
        'HIGH',
        25,
        'Direct numeric IP address used instead of registered domain name.',
        hostname,
        'Access services via verified domain names.'
      );
      indicators.push({
        id: 'ind-url-ip',
        category: 'URL_STRUCTURE',
        categoryLabel: 'URL & Domain Structure',
        name: 'Direct IP Hostname',
        status: 'FAIL',
        severity: 'HIGH',
        scoreContribution: 25,
        observed: `Target uses raw IP address ${hostname}`,
        explanation: 'Direct IP access bypasses domain-level reputation and SSL verification standards.',
        evidence: hostname,
      });
      whyVerdict.push(`Target uses a raw IP address (${hostname}) instead of a registered domain.`);
    } else {
      indicators.push({
        id: 'ind-url-ip',
        category: 'URL_STRUCTURE',
        categoryLabel: 'URL & Domain Structure',
        name: 'Registered Domain Name Format',
        status: 'PASS',
        scoreContribution: 0,
        observed: `Registered domain name (${hostname})`,
        explanation: 'Destination uses a standard registered domain name.',
      });
      positiveSignals.push({
        title: 'Standard Domain Name Structure',
        desc: `Target is addressed by registered domain name (${hostname}) rather than raw IP.`,
        category: 'Domain & Infrastructure',
      });
    }

    // Punycode / IDN Homograph
    if (isPunycode) {
      const punyFinding: IScanFinding = {
        category: 'Domain & Hostname',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'HIGH',
        title: 'Internationalized Domain Name (Punycode / Homograph Detected)',
        description: `The hostname contains Punycode encoded labels (${punycodeLabels.join(', ')}). Punycode allows international character sets which can visually mimic legitimate domain names in homograph phishing attacks.`,
        evidence: `Punycode labels: ${punycodeLabels.join(', ')}`,
        impact: 'Attackers use lookalike characters from international alphabets to trick users into believing they are visiting an authentic website.',
        recommendation: 'Inspect the decoded Unicode characters of the domain to ensure it is not mimicking a known brand.',
      };
      findings.push(punyFinding);
      addContributor(
        'URL & Domain Structure',
        'Punycode / IDN Homograph Label Detected',
        'HIGH',
        30,
        `Hostname contains punycode labels (${punycodeLabels.join(', ')}) with potential homograph visual spoofing risk.`,
        punycodeLabels.join(', '),
        'Verify authentic ASCII domain spelling.'
      );
      indicators.push({
        id: 'ind-url-punycode',
        category: 'URL_STRUCTURE',
        categoryLabel: 'URL & Domain Structure',
        name: 'Internationalized Domain Name (Punycode)',
        status: 'WARN',
        severity: 'HIGH',
        scoreContribution: 30,
        observed: `Punycode labels detected: ${punycodeLabels.join(', ')}`,
        explanation: 'Punycode enables internationalized homograph characters that can mimic legitimate brands.',
        evidence: punycodeLabels.join(', '),
      });
      whyVerdict.push(`Hostname utilizes Punycode labels (${punycodeLabels.join(', ')}) with homograph spoofing potential.`);
    } else {
      indicators.push({
        id: 'ind-url-punycode',
        category: 'URL_STRUCTURE',
        categoryLabel: 'URL & Domain Structure',
        name: 'Standard ASCII Domain Representation',
        status: 'PASS',
        scoreContribution: 0,
        observed: 'Standard ASCII character set with no punycode (xn--) encoding',
        explanation: 'Domain uses standard alphanumeric ASCII characters without internationalized homograph labels.',
      });
      positiveSignals.push({
        title: 'Standard ASCII Domain Representation',
        desc: 'Hostname does not contain Punycode (xn--) or homograph substitution labels.',
        category: 'Domain & Infrastructure',
      });
    }

    // URL Structural Obfuscation Patterns
    const structuralAnomalies: string[] = [];
    if (fullNormalized.includes('@')) {
      structuralAnomalies.push('Embedded userinfo credentials delimiter (@)');
    }
    if (fullNormalized.includes('%00')) {
      structuralAnomalies.push('Null-byte injection sequence (%00)');
    }
    if (fullNormalized.includes('..') || fullNormalized.includes('%2e%2e')) {
      structuralAnomalies.push('Path traversal sequence (..)');
    }
    if (pathname.includes('//')) {
      structuralAnomalies.push('Consecutive slashes (//) path obfuscation');
    }

    if (structuralAnomalies.length > 0) {
      const structFinding: IScanFinding = {
        category: 'URL Structure & Obfuscation',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'MEDIUM',
        title: 'Suspicious URL Structural Obfuscation Detected',
        description: `The URL contains structural obfuscation patterns commonly used in deceptive links: ${structuralAnomalies.join(', ')}.`,
        evidence: structuralAnomalies.join('; '),
        impact: 'Deceptive URL characters can mislead users or bypass basic URL parsing filters.',
        recommendation: 'Avoid clicking links containing embedded userinfo credentials (@) or null-byte characters.',
      };
      findings.push(structFinding);
      addContributor(
        'URL & Domain Structure',
        'Suspicious URL Structure Obfuscation',
        'MEDIUM',
        20,
        `Observed structural obfuscation: ${structuralAnomalies.join(', ')}.`,
        structuralAnomalies.join(', ')
      );
      indicators.push({
        id: 'ind-url-obfuscation',
        category: 'URL_STRUCTURE',
        categoryLabel: 'URL & Domain Structure',
        name: 'URL Structural Obfuscation',
        status: 'WARN',
        severity: 'MEDIUM',
        scoreContribution: 20,
        observed: structuralAnomalies.join(', '),
        explanation: 'Structural anomalies such as userinfo @ delimiters or path traversal sequences.',
        evidence: structuralAnomalies.join('; '),
      });
    } else {
      indicators.push({
        id: 'ind-url-obfuscation',
        category: 'URL_STRUCTURE',
        categoryLabel: 'URL & Domain Structure',
        name: 'Clean URL Structure',
        status: 'PASS',
        scoreContribution: 0,
        observed: 'Clean URL structure without embedded @ delimiters or path obfuscation',
        explanation: 'URL adheres to standard RFC formatting without deceptive delimiters.',
      });
    }

    // Subdomain Hierarchy Depth
    if (subdomainsList.length >= 4) {
      const subFinding: IScanFinding = {
        category: 'URL Structure',
        findingCategory: 'HARDENING_RECOMMENDATION',
        severity: 'LOW',
        title: 'Deep Multi-Tier Subdomain Nesting',
        description: `Hostname contains ${subdomainsList.length} subdomain levels (${subdomainsList.join('.')}). Attackers frequently stack multiple subdomains to mimic reputable domain prefixes.`,
        evidence: `Subdomains: ${subdomainsList.join('.')}`,
        impact: 'Deep subdomain nesting can obscure the true registrable domain on mobile or truncated browser address bars.',
        recommendation: 'Check the rightmost domain name before the top-level domain to confirm authentic ownership.',
      };
      findings.push(subFinding);
      addContributor(
        'URL & Domain Structure',
        'Deep Subdomain Nesting',
        'LOW',
        10,
        `Hostname contains ${subdomainsList.length} subdomain levels (${subdomainsList.join('.')}).`,
        subdomainsList.join('.')
      );
      indicators.push({
        id: 'ind-url-subdomains',
        category: 'URL_STRUCTURE',
        categoryLabel: 'URL & Domain Structure',
        name: 'Subdomain Nesting Depth',
        status: 'WARN',
        severity: 'LOW',
        scoreContribution: 10,
        observed: `${subdomainsList.length} subdomain levels (${subdomainsList.join('.')})`,
        explanation: 'Excessive subdomain depth can visually mask the authentic base domain.',
        evidence: subdomainsList.join('.'),
      });
    } else {
      indicators.push({
        id: 'ind-url-subdomains',
        category: 'URL_STRUCTURE',
        categoryLabel: 'URL & Domain Structure',
        name: 'Normal Subdomain Depth',
        status: 'PASS',
        scoreContribution: 0,
        observed: `${subdomainsList.length} subdomain levels`,
        explanation: 'Subdomain hierarchy depth is within standard single-tenant parameters.',
      });
    }

    // ── 2. Redirect Analysis Engine ─────────────────────────────────────────
    const redirectHops = httpResult?.redirectChain || [];
    const totalHops = httpResult?.redirectCount || 0;
    const finalUrl = httpResult?.finalUrl || normalizedTarget;
    let finalHostname = hostname;
    try {
      finalHostname = new URL(finalUrl).hostname.toLowerCase();
    } catch {}

    const isCrossDomainRedirect = totalHops > 0 && !this.isSameRegistrableDomain(hostname, finalHostname);
    const hasProtocolDowngrade =
      normalizedTarget.startsWith('https://') && finalUrl.startsWith('http://');

    if (isCrossDomainRedirect) {
      const redirFinding: IScanFinding = {
        category: 'Redirect Analysis',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'MEDIUM',
        title: 'Cross-Domain Redirection to External Destination',
        description: `The URL forwards users across distinct domain boundaries (${hostname} → ${finalHostname}) across ${totalHops} redirect hop(s).`,
        evidence: `Redirect path: ${hostname} → ${finalHostname} (${totalHops} hops)`,
        impact: 'Cross-domain redirects are used by attackers to lure victims through shorteners, compromised sites, or open redirectors toward phishing landing pages.',
        recommendation: 'Inspect intermediate redirect hops to verify whether the forwarding journey was authorized and intended.',
      };
      findings.push(redirFinding);
      addContributor(
        'Redirect Analysis',
        'Cross-Domain Redirection to External Destination',
        'MEDIUM',
        15,
        `URL forwards across distinct domain boundaries (${hostname} → ${finalHostname}).`,
        `Final destination: ${finalHostname}`
      );
      indicators.push({
        id: 'ind-redir-crossdomain',
        category: 'REDIRECT_BEHAVIOR',
        categoryLabel: 'Redirect Behavior',
        name: 'Cross-Domain Redirection',
        status: 'WARN',
        severity: 'MEDIUM',
        scoreContribution: 15,
        observed: `Redirects from ${hostname} to ${finalHostname} (${totalHops} hops)`,
        explanation: 'Forwarding users across distinct domain boundaries.',
        evidence: `${hostname} → ${finalHostname}`,
      });
      whyVerdict.push(`URL forwards across domain boundaries from ${hostname} to ${finalHostname}.`);
    } else if (totalHops > 0) {
      indicators.push({
        id: 'ind-redir-crossdomain',
        category: 'REDIRECT_BEHAVIOR',
        categoryLabel: 'Redirect Behavior',
        name: 'Same-Domain Redirection',
        status: 'PASS',
        scoreContribution: 0,
        observed: `Followed ${totalHops} hop(s) within the same organization domain (${finalHostname})`,
        explanation: 'Redirections remain confined within the authentic organization domain boundary.',
      });
      positiveSignals.push({
        title: 'Same-Domain Navigation Redirection',
        desc: `Followed ${totalHops} hop(s) safely within the primary domain boundary (${finalHostname}).`,
        category: 'Redirect Analysis',
      });
    } else {
      indicators.push({
        id: 'ind-redir-crossdomain',
        category: 'REDIRECT_BEHAVIOR',
        categoryLabel: 'Redirect Behavior',
        name: 'Direct Destination Navigation',
        status: 'PASS',
        scoreContribution: 0,
        observed: 'Direct target destination analyzed without intermediate multi-hop redirection chains',
        explanation: 'No intermediate URL shorteners or cross-domain forwarding steps.',
      });
      positiveSignals.push({
        title: 'Direct Navigation Target',
        desc: 'Direct target destination analyzed without intermediate multi-hop forwarding.',
        category: 'Redirect Analysis',
      });
    }

    if (hasProtocolDowngrade) {
      const downgradeFinding: IScanFinding = {
        category: 'Transport Security',
        findingCategory: 'CONFIRMED_VULNERABILITY',
        severity: 'HIGH',
        title: 'Insecure Protocol Downgrade (HTTPS to Plaintext HTTP)',
        description: 'The redirect journey transitioned from an encrypted HTTPS URL to an unencrypted plain HTTP destination.',
        evidence: `Redirect transition: HTTPS (${normalizedTarget}) → HTTP (${finalUrl})`,
        impact: 'Protocol downgrades remove transport layer security, making user sessions vulnerable to eavesdropping and manipulation.',
        recommendation: 'Ensure all redirections maintain HTTPS transport encryption throughout the entire navigation chain.',
      };
      findings.push(downgradeFinding);
      addContributor(
        'Transport Security',
        'Protocol Downgrade to Plaintext HTTP',
        'HIGH',
        25,
        'Navigation chain downgraded from secure HTTPS to plaintext HTTP.',
        finalUrl
      );
      indicators.push({
        id: 'ind-redir-downgrade',
        category: 'REDIRECT_BEHAVIOR',
        categoryLabel: 'Redirect Behavior',
        name: 'Transport Protocol Downgrade',
        status: 'FAIL',
        severity: 'HIGH',
        scoreContribution: 25,
        observed: 'Redirect chain downgraded connection from HTTPS to unencrypted HTTP',
        explanation: 'Insecure downgrade compromises session secrecy.',
        evidence: `${normalizedTarget} → ${finalUrl}`,
      });
    }

    // ── 3. HTML Content, Brand Deception & Credential Forms ──────────────────
    const html = httpResult?.htmlSnippet || '';
    const { pageTitle, metaDescription, headings, visibleSnippet } = this.extractHtmlMetadata(html);
    const pathAndQuery = `${pathname} ${search}`.toLowerCase();
    const textCorpus = `${pageTitle || ''} ${metaDescription || ''} ${headings.join(' ')} ${visibleSnippet} ${pathAndQuery}`.toLowerCase();

    // ── 3A. Brand Identification & Impersonation Analysis ───────────────────
    const detectedBrands: string[] = [];
    let impersonationBrand: BrandIdentityDefinition | null = null;
    let impersonationEvidenceStr: string | undefined;

    for (const brand of KNOWN_BRAND_REGISTRY) {
      // Check if page claims brand identity in Title, Headings, Login Keywords, or URL Path
      const titleMatchesBrand = pageTitle ? brand.identityKeywords.some((kw) => pageTitle.toLowerCase().includes(kw)) : false;
      const headingMatchesBrand = headings.some((h) => brand.identityKeywords.some((kw) => h.toLowerCase().includes(kw)));
      const pathMatchesBrand = brand.identityKeywords.some((kw) => pathAndQuery.includes(kw));
      const loginKwMatches = brand.loginKeywords.some((lkw) => textCorpus.includes(lkw)) || (pathMatchesBrand && (pathAndQuery.includes('login') || pathAndQuery.includes('verify') || pathAndQuery.includes('account')));

      if (titleMatchesBrand || headingMatchesBrand || loginKwMatches || pathMatchesBrand) {
        detectedBrands.push(brand.brandName);

        // Check if current domain is authorized for this brand
        const isAuthorizedDomain = brand.authorizedDomains.some(
          (ad) => hostname === ad || hostname.endsWith(`.${ad}`) || registrableDomain === ad
        );

        if (!isAuthorizedDomain) {
          // Verify if there is identity claim + credential/login context (not merely a neutral news mention)
          const hasLoginOrAccountContext =
            textCorpus.includes('login') ||
            textCorpus.includes('sign in') ||
            textCorpus.includes('password') ||
            textCorpus.includes('verify') ||
            textCorpus.includes('account') ||
            textCorpus.includes('wallet') ||
            textCorpus.includes('security') ||
            titleMatchesBrand ||
            pathMatchesBrand;

          if (hasLoginOrAccountContext) {
            impersonationBrand = brand;
            const matchedToken = brand.identityKeywords.find((kw) => pathAndQuery.includes(kw) || textCorpus.includes(kw)) || brand.brandName.toLowerCase();
            impersonationEvidenceStr = pathMatchesBrand
              ? `URL path/query contains ${brand.brandName} authentication token (${matchedToken}): "${pathAndQuery.trim()}", hosted on unverified domain "${hostname}".`
              : `Page displays ${brand.brandName} identity token (${matchedToken}) in title/content ("${pageTitle || brand.brandName}"), hosted on unverified domain "${hostname}".`;
            break;
          }
        }
      }
    }

    if (impersonationBrand && impersonationEvidenceStr) {
      const impFinding: IScanFinding = {
        category: 'Brand & Identity Impersonation',
        findingCategory: 'CONFIRMED_VULNERABILITY',
        severity: 'HIGH',
        title: `Potential Brand Impersonation (${impersonationBrand.brandName} Identity Mismatch)`,
        description: `The target page displays branding and identity claims associated with ${impersonationBrand.brandName} (Title: "${pageTitle || 'N/A'}"), but is hosted on an unverified domain (${hostname}) that does not correspond to the authentic organization (${impersonationBrand.authorizedDomains.join(', ')}).`,
        evidence: impersonationEvidenceStr,
        impact: 'Brand impersonation is a primary technique used in credential harvesting and identity deception campaigns.',
        recommendation: `Do NOT enter login credentials or personal data. Verify you are visiting the official ${impersonationBrand.brandName} portal (${impersonationBrand.authorizedDomains[0]}).`,
      };
      findings.push(impFinding);
      addContributor(
        'Domain & Brand Identity',
        `Brand Impersonation (${impersonationBrand.brandName} Mismatch)`,
        'HIGH',
        40,
        `Page presents ${impersonationBrand.brandName} identity claims on unauthorized host ${hostname}.`,
        impersonationEvidenceStr,
        `Verify official ${impersonationBrand.authorizedDomains[0]} address.`
      );
      indicators.push({
        id: 'ind-brand-impersonation',
        category: 'DOMAIN_IDENTITY',
        categoryLabel: 'Domain & Brand Identity',
        name: 'Brand & Identity Consistency',
        status: 'FAIL',
        severity: 'HIGH',
        scoreContribution: 40,
        observed: `Claimed: ${impersonationBrand.brandName} | Host: ${hostname}`,
        explanation: `Claimed brand identity does not match the registered domain (${impersonationBrand.authorizedDomains.join(', ')}).`,
        evidence: impersonationEvidenceStr,
      });
      whyVerdict.push(`Page presents ${impersonationBrand.brandName} brand identity on an unauthorized domain (${hostname}).`);
    } else if (detectedBrands.length > 0) {
      indicators.push({
        id: 'ind-brand-impersonation',
        category: 'DOMAIN_IDENTITY',
        categoryLabel: 'Domain & Brand Identity',
        name: 'Brand Identity Correspondence',
        status: 'PASS',
        scoreContribution: 0,
        observed: `Brand references (${detectedBrands.join(', ')}) correspond to authentic registered domain`,
        explanation: 'Page brand references match authentic first-party domain registrations.',
      });
      positiveSignals.push({
        title: 'Authentic Brand Domain Correspondence',
        desc: `Identified organization branding (${detectedBrands.join(', ')}) aligns with official registered domain space.`,
        category: 'Domain & Identity',
      });
    } else {
      indicators.push({
        id: 'ind-brand-impersonation',
        category: 'DOMAIN_IDENTITY',
        categoryLabel: 'Domain & Brand Identity',
        name: 'Brand Identity Consistency',
        status: 'PASS',
        scoreContribution: 0,
        observed: 'No deceptive third-party brand impersonation indicators identified',
        explanation: 'Page presents consistent domain identity without unauthorized trademark lures.',
      });
    }

    // ── 3B. Credential Collection & Form Destination Analysis ────────────────
    const formsList: Array<{
      action: string;
      method: string;
      isExternal: boolean;
      isPlaintext: boolean;
      hasPasswordField: boolean;
      hasUsernameField: boolean;
      actionHostname?: string;
    }> = [];

    let hasPasswordField = false;
    let hasUsernameOrEmailField = false;
    let hasMfaField = false;
    let passwordFormCount = 0;
    let insecureFormCount = 0;
    let externalActionFormCount = 0;

    if (html && html.length > 0) {
      // Inputs scan
      const passwordInputs = html.match(/<input\b[^>]*type=["']password["']/gi) || [];
      hasPasswordField = passwordInputs.length > 0;

      const userInputs = html.match(/<input\b[^>]*(?:name|id|type)=["'](?:username|user|email|login|account|identifier)["']/gi) || [];
      hasUsernameOrEmailField = userInputs.length > 0;

      const mfaInputs = html.match(/<input\b[^>]*(?:name|id|placeholder)=["'](?:otp|token|2fa|code|mfa|verification)["']/gi) || [];
      hasMfaField = mfaInputs.length > 0;

      // Forms scan
      const formMatches = html.match(/<form\b[^>]*>[\s\S]*?<\/form>/gi) || html.match(/<form\b[^>]*>/gi) || [];

      for (const formBlock of formMatches) {
        const actionMatch = formBlock.match(/action=["']([^"']*)["']/i);
        const methodMatch = formBlock.match(/method=["']([^"']*)["']/i);
        const actionRaw = actionMatch ? actionMatch[1].trim() : '';
        const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();

        const formHasPassword = /type=["']password["']/i.test(formBlock);
        const formHasUser = /(?:name|id|type)=["'](?:username|user|email|login|account)["']/i.test(formBlock);

        let isExternal = false;
        let isPlaintext = false;
        let actionHost: string | undefined;

        if (actionRaw.startsWith('http://') || actionRaw.startsWith('https://')) {
          try {
            const actionUrl = new URL(actionRaw);
            actionHost = actionUrl.hostname.toLowerCase();
            isExternal = !this.isSameRegistrableDomain(hostname, actionHost);
            isPlaintext = actionUrl.protocol === 'http:';
          } catch {}
        } else if (actionRaw.startsWith('//')) {
          try {
            const actionUrl = new URL(`https:${actionRaw}`);
            actionHost = actionUrl.hostname.toLowerCase();
            isExternal = !this.isSameRegistrableDomain(hostname, actionHost);
          } catch {}
        }

        if (formHasPassword) passwordFormCount++;
        if (isPlaintext || (!effectiveHttps && formHasPassword)) insecureFormCount++;
        if (isExternal && formHasPassword) externalActionFormCount++;

        formsList.push({
          action: actionRaw || '(self / current URL)',
          method,
          isExternal,
          isPlaintext,
          hasPasswordField: formHasPassword,
          hasUsernameField: formHasUser,
          actionHostname: actionHost,
        });
      }
    }

    // Evaluate Credential Findings
    const hasLoginForm = hasPasswordField || (hasUsernameOrEmailField && (textCorpus.includes('password') || textCorpus.includes('sign in')));

    // Case 1: Password input over unencrypted HTTP
    if (hasPasswordField && !effectiveHttps) {
      const httpPassFinding: IScanFinding = {
        category: 'Credential Collection & Transport',
        findingCategory: 'CONFIRMED_VULNERABILITY',
        severity: 'HIGH',
        title: 'Password Credential Collection Served Over Unencrypted HTTP',
        description: 'The target page presents a password credential input form over plain unencrypted HTTP. Any credentials entered can be intercepted in cleartext by network intermediaries.',
        evidence: 'HTML <input type="password"> served over unencrypted HTTP protocol',
        impact: 'Cleartext transmission of passwords facilitates credential harvesting and man-in-the-middle theft.',
        recommendation: 'Never enter passwords on unencrypted HTTP pages. Enforce HTTPS and TLS for all authentication forms.',
      };
      findings.push(httpPassFinding);
      addContributor(
        'Credential Collection',
        'Password Form on Unencrypted HTTP',
        'HIGH',
        35,
        'Password input served over unencrypted HTTP protocol.',
        'HTML password input over plaintext HTTP'
      );
      indicators.push({
        id: 'ind-cred-insecure',
        category: 'CREDENTIAL_COLLECTION',
        categoryLabel: 'Credential Collection',
        name: 'Insecure Credential Transport',
        status: 'FAIL',
        severity: 'HIGH',
        scoreContribution: 35,
        observed: 'Password input form hosted over unencrypted HTTP',
        explanation: 'Credentials submitted over unencrypted transport are exposed in cleartext.',
        evidence: 'Plaintext HTTP <input type="password">',
      });
      whyVerdict.push('Target page requests password credentials over an unencrypted HTTP connection.');
    }

    // Case 2: Credential form action submits to external/unrelated origin
    if (externalActionFormCount > 0) {
      const externalForms = formsList.filter((f) => f.isExternal && f.hasPasswordField);
      const extDestinations = externalForms.map((f) => f.actionHostname || f.action).join(', ');
      const extFinding: IScanFinding = {
        category: 'Credential Collection & Form Destinations',
        findingCategory: 'CONFIRMED_VULNERABILITY',
        severity: 'HIGH',
        title: 'Cross-Origin Destination: Credential Form Action Targets External / Third-Party Origin',
        description: `HTML authentication form specifies a cross-origin external submission action (${extDestinations}) that does not correspond to the hosting domain (${hostname}).`,
        evidence: `Form action destinations: ${extDestinations}`,
        impact: 'Credential forwarding to external origins is a hallmark of credential harvesting phishing portals.',
        recommendation: 'Do NOT submit login credentials on this form. Authentication forms must submit to first-party origins.',
      };
      findings.push(extFinding);
      addContributor(
        'Form Destinations',
        'Cross-Origin Credential Form Submits to External Origin',
        'HIGH',
        30,
        `Password form submits credentials to external endpoint (${extDestinations}).`,
        `Action: ${extDestinations}`
      );
      indicators.push({
        id: 'ind-form-external',
        category: 'FORM_DESTINATIONS',
        categoryLabel: 'Form Destinations',
        name: 'External Credential Submission',
        status: 'FAIL',
        severity: 'HIGH',
        scoreContribution: 30,
        observed: `Password form action points to external host: ${extDestinations}`,
        explanation: 'Form submits credentials to a different external origin than the hosting page.',
        evidence: extDestinations,
      });
      whyVerdict.push(`Authentication form posts credentials to an external origin (${extDestinations}).`);
    } else if (formsList.length > 0) {
      indicators.push({
        id: 'ind-form-external',
        category: 'FORM_DESTINATIONS',
        categoryLabel: 'Form Destinations',
        name: 'Same-Origin Form Submission',
        status: 'PASS',
        scoreContribution: 0,
        observed: `All ${formsList.length} form action(s) submit to same-origin first-party endpoints`,
        explanation: 'Form actions do not forward payloads to external third-party domains.',
      });
      positiveSignals.push({
        title: 'Same-Origin Form Action Submissions',
        desc: `All ${formsList.length} form action(s) submit safely to first-party same-origin endpoints.`,
        category: 'Form Destinations',
      });
    }

    // Case 3: Legitimate login page on HTTPS with same-origin submission
    if (hasLoginForm && effectiveHttps && externalActionFormCount === 0 && !impersonationBrand && !isDirectIp) {
      positiveSignals.push({
        title: 'Standard First-Party Login Architecture',
        desc: 'Authentication form is served over HTTPS and submits to first-party same-origin endpoints.',
        category: 'Credential Collection',
      });
      indicators.push({
        id: 'ind-cred-legit',
        category: 'CREDENTIAL_COLLECTION',
        categoryLabel: 'Credential Collection',
        name: 'First-Party Authentication Form',
        status: 'PASS',
        scoreContribution: 0,
        observed: 'Standard same-origin login form secured over TLS/HTTPS',
        explanation: 'Authentication inputs are served over HTTPS and submit to first-party endpoints.',
      });
    } else if (!hasLoginForm) {
      indicators.push({
        id: 'ind-cred-none',
        category: 'CREDENTIAL_COLLECTION',
        categoryLabel: 'Credential Collection',
        name: 'No Password Collection Inputs',
        status: 'PASS',
        scoreContribution: 0,
        observed: 'No password or credential harvesting input fields detected in static DOM',
        explanation: 'Page does not request sensitive password or authentication credentials.',
      });
      positiveSignals.push({
        title: 'Clean Credential Profile',
        desc: 'No password harvesting input fields or deceptive authentication lures detected in page DOM.',
        category: 'Credential Collection',
      });
    }

    // ── 4. Social Engineering & Urgency Indicators (Heuristic) ───────────────
    const urgencyKeywords = [
      'account suspended',
      'unauthorized login attempt',
      'verify within 24 hours',
      'action required immediately',
      'temporary suspension',
      'update your billing immediately',
      'security alert: unusual activity',
      'confirm your identity to prevent deletion',
    ];
    const matchedUrgency = urgencyKeywords.filter((kw) => textCorpus.includes(kw));

    const securityAlertKeywords = [
      'unauthorized access',
      'compromised account',
      'security notification',
      'locked account',
    ];
    const matchedSecurity = securityAlertKeywords.filter((kw) => textCorpus.includes(kw));

    const rewardKeywords = [
      'claim your prize',
      'you have won',
      'crypto airdrop claim',
      'free gift card reward',
    ];
    const matchedReward = rewardKeywords.filter((kw) => textCorpus.includes(kw));

    if (matchedUrgency.length > 0 || (matchedReward.length > 0 && hasLoginForm)) {
      const allLures = [...matchedUrgency, ...matchedReward];
      const lureFinding: IScanFinding = {
        category: 'Social Engineering & Urgency Signals',
        findingCategory: 'HARDENING_RECOMMENDATION',
        severity: impersonationBrand || externalActionFormCount > 0 ? 'HIGH' : 'LOW',
        title: 'Heuristic Social Engineering / Urgency Lure Patterns Detected',
        description: `The page contains high-urgency social engineering phrases commonly used in phishing lures: "${allLures.join('", "')}".`,
        evidence: `Matched phrases: ${allLures.join(', ')}`,
        impact: 'Urgent coercion language pressures victims into acting impulsively without verifying link authenticity.',
        recommendation: 'Be skeptical of unexpected messages claiming immediate account termination or urgent payment verification.',
      };
      findings.push(lureFinding);

      const lurePoints = impersonationBrand || externalActionFormCount > 0 ? 20 : 15;
      addContributor(
        'Social Engineering Indicators',
        'Urgent Social Engineering Language (Heuristic)',
        impersonationBrand || externalActionFormCount > 0 ? 'MEDIUM' : 'LOW',
        lurePoints,
        `Page contains urgency pressure phrases: ${allLures.join(', ')}.`,
        allLures.join(', ')
      );
      indicators.push({
        id: 'ind-social-urgency',
        category: 'SOCIAL_ENGINEERING',
        categoryLabel: 'Social Engineering Indicators',
        name: 'Urgency & Coercion Language',
        status: 'WARN',
        severity: 'LOW',
        scoreContribution: lurePoints,
        observed: `Matched urgency phrases: ${allLures.join(', ')}`,
        explanation: 'Heuristic indicator: High-pressure urgency language detected in visible page text.',
        evidence: allLures.join(', '),
      });
    } else {
      indicators.push({
        id: 'ind-social-urgency',
        category: 'SOCIAL_ENGINEERING',
        categoryLabel: 'Social Engineering Indicators',
        name: 'Social Engineering & Urgency Analysis',
        status: 'PASS',
        scoreContribution: 0,
        observed: 'No high-pressure urgency or deceptive coercive phrases detected',
        explanation: 'Page text does not exhibit high-pressure urgency or account suspension threats.',
      });
      positiveSignals.push({
        title: 'Neutral Content Profile',
        desc: 'Page content does not exhibit high-pressure account suspension or deceptive urgency lures.',
        category: 'Social Engineering',
      });
    }

    // ── 5. Transport Security & TLS Observations ────────────────────────────
    if (!effectiveHttps) {
      const httpFinding: IScanFinding = {
        category: 'Transport Security',
        findingCategory: 'SECURITY_WEAKNESS',
        severity: 'MEDIUM',
        title: 'Unencrypted Transport Protocol (Plaintext HTTP)',
        description: 'Communications with this destination are conducted over plain unencrypted HTTP, exposing all transmitted data to network eavesdropping.',
        evidence: `Protocol: ${parsedUrl.protocol}`,
        impact: 'Cleartext communications can be intercepted or modified by intermediaries on the network path.',
        recommendation: 'Enforce HTTPS transport encryption and implement HSTS.',
      };
      findings.push(httpFinding);
      addContributor(
        'Transport Security',
        'Unencrypted Plaintext HTTP Protocol',
        'MEDIUM',
        20,
        'Destination uses unencrypted plain HTTP transport.',
        `Protocol: ${parsedUrl.protocol}`
      );
      indicators.push({
        id: 'ind-transport-tls',
        category: 'TRANSPORT_SECURITY',
        categoryLabel: 'Transport Security & TLS',
        name: 'Transport Encryption',
        status: 'WARN',
        severity: 'MEDIUM',
        scoreContribution: 20,
        observed: 'Unencrypted HTTP protocol in use',
        explanation: 'Communications transmitted in cleartext without TLS encryption.',
        evidence: parsedUrl.protocol,
      });
      whyVerdict.push('Destination uses unencrypted HTTP transport.');
    } else if (tlsResult && (tlsResult.valid === false || tlsResult.error)) {
      const invalidTlsFinding: IScanFinding = {
        category: 'Transport Security',
        findingCategory: 'CONFIRMED_VULNERABILITY',
        severity: 'HIGH',
        title: 'Invalid / Untrusted SSL/TLS Certificate',
        description: `The SSL/TLS certificate presented by ${hostname} failed validation: ${tlsResult.details}`,
        evidence: tlsResult.error || tlsResult.details,
        impact: 'Untrusted certificates fail to guarantee server identity and expose sessions to interception.',
        recommendation: 'Obtain a valid SSL/TLS certificate issued by a recognized public Certificate Authority.',
      };
      findings.push(invalidTlsFinding);
      addContributor(
        'Transport Security',
        'Invalid / Untrusted SSL/TLS Certificate',
        'HIGH',
        25,
        `TLS certificate verification failed: ${tlsResult.details}`,
        tlsResult.error || tlsResult.details
      );
      indicators.push({
        id: 'ind-transport-tls',
        category: 'TRANSPORT_SECURITY',
        categoryLabel: 'Transport Security & TLS',
        name: 'SSL/TLS Certificate Validity',
        status: 'FAIL',
        severity: 'HIGH',
        scoreContribution: 25,
        observed: `Certificate validation failed: ${tlsResult.details}`,
        explanation: 'The SSL/TLS certificate presented by the server is invalid or untrusted.',
        evidence: tlsResult.details,
      });
      whyVerdict.push(`SSL/TLS certificate presented by ${hostname} failed trust validation.`);
    } else if (effectiveHttps) {
      indicators.push({
        id: 'ind-transport-tls',
        category: 'TRANSPORT_SECURITY',
        categoryLabel: 'Transport Security & TLS',
        name: 'Valid HTTPS Transport Encryption',
        status: 'PASS',
        scoreContribution: 0,
        observed: `Valid ${tlsResult?.protocol || 'TLS'} encryption active (Issuer: ${tlsResult?.issuer || 'Recognized CA'})`,
        explanation: 'Encrypted transport is active. Note: HTTPS verifies encryption, not business legitimacy.',
      });
      positiveSignals.push({
        title: 'HTTPS Transport Encryption Active',
        desc: `Valid TLS certificate (${tlsResult?.protocol || 'TLS'}) encrypts web traffic in transit.`,
        category: 'Transport Security',
      });
    }

    // ── 6. Threat Intelligence Feed Handling ─────────────────────────────────
    let threatIntelStatus: 'Not Configured' | 'Queried' | 'Unavailable' | 'Clean' | 'Threat Detected' = 'Not Configured';
    let threatIntelDetails = 'External threat intelligence feeds were not configured for this scan. Assessment is based on direct evidence.';

    if (threatIntelResult) {
      threatIntelStatus = threatIntelResult.status;
      threatIntelDetails = threatIntelResult.details;
      if (threatIntelResult.status === 'Threat Detected') {
        const tiFinding: IScanFinding = {
          category: 'Threat Intelligence',
          findingCategory: 'CONFIRMED_VULNERABILITY',
          severity: 'CRITICAL',
          title: `Threat Intelligence Feed Match (${threatIntelResult.provider || 'Configured Feed'})`,
          description: `Target was flagged as malicious/phishing by configured threat intelligence feed: ${threatIntelResult.details}`,
          evidence: threatIntelResult.details,
          impact: 'Known malicious classifications indicate high likelihood of active adversary infrastructure.',
          recommendation: 'Block this destination immediately across web proxies and endpoint security systems.',
        };
        findings.push(tiFinding);
        addContributor(
          'Threat Intelligence',
          `Threat Intelligence Match (${threatIntelResult.provider || 'Feed'})`,
          'CRITICAL',
          45,
          threatIntelResult.details,
          threatIntelResult.details
        );
        indicators.push({
          id: 'ind-ti-feed',
          category: 'THREAT_INTELLIGENCE',
          categoryLabel: 'Threat Intelligence',
          name: 'External Threat Feed Reputation',
          status: 'FAIL',
          severity: 'CRITICAL',
          scoreContribution: 45,
          observed: threatIntelResult.details,
          explanation: 'Target flagged by configured threat intelligence provider.',
          evidence: threatIntelResult.details,
        });
        whyVerdict.push(`Target flagged by external threat intelligence feed (${threatIntelResult.provider || 'Feed'}).`);
      }
    } else {
      indicators.push({
        id: 'ind-ti-feed',
        category: 'THREAT_INTELLIGENCE',
        categoryLabel: 'Threat Intelligence',
        name: 'External Threat Intelligence Feeds',
        status: 'NOT_CONFIGURED',
        scoreContribution: 0,
        observed: 'Threat Intelligence: Not Configured',
        explanation: 'No commercial external reputation feeds were configured; assessment is based on direct evidence.',
      });
    }

    // ── 7. Clean Baseline Finding for Zero-Finding Scans ─────────────────────
    if (findings.length === 0) {
      findings.push({
        category: 'Security Baseline & Verification',
        findingCategory: 'INFORMATIONAL',
        severity: 'INFO',
        title: 'Clean Phishing Security Profile',
        description: 'Target demonstrated standard URL formatting, valid TLS transport encryption, same-origin form handling, and no deceptive brand impersonation patterns.',
        evidence: `Inspected ${normalizedTarget}${httpResult?.statusCode ? ` (HTTP ${httpResult.statusCode})` : ''}`,
        impact: 'No immediate phishing indicators or deceptive mechanisms were observed.',
        recommendation: 'Continue practicing standard link verification and verifying SSL certificate domains before entering sensitive data.',
      });
      whyVerdict.push('No risk contributions were identified from the checks completed during this scan.');
    }

    // ── 8. Calculate Final Risk Score & Classification ───────────────────────
    const normalizedScore = Math.min(100, Math.max(0, rawScore));
    const hasCriticalFinding = findings.some((f) => f.severity === 'CRITICAL');
    const classification = deriveClassificationFromRiskScore(normalizedScore, hasCriticalFinding);

    // Heuristic Threat Indicator Confidence Rating
    let confidence = 0;
    if (normalizedScore > 0 || hasCriticalFinding) {
      let confidencePoints = 0;
      if (httpResult?.statusCode) confidencePoints += 35;
      if (effectiveHttps && tlsResult?.valid) confidencePoints += 25;
      if (html.length > 100) confidencePoints += 25;
      if (dnsResult.resolvedIps.length > 0) confidencePoints += 15;
      confidence = Math.min(100, Math.max(15, confidencePoints));
    }

    let confidenceLabel: 'High' | 'Moderate' | 'Low' | 'Baseline' = 'Baseline';
    if (confidence >= 80) confidenceLabel = 'High';
    else if (confidence >= 50) confidenceLabel = 'Moderate';
    else if (confidence >= 25) confidenceLabel = 'Low';

    // Summary statement
    let scoreSummaryText = 'No risk contributions were identified from the checks completed during this scan.';
    if (normalizedScore >= 75 || hasCriticalFinding) {
      scoreSummaryText = 'Multiple critical indicators associated with phishing, deceptive brand impersonation, or unencrypted credential collection were identified.';
    } else if (normalizedScore >= 50) {
      scoreSummaryText = 'High-risk indicators associated with suspicious URL structures, brand identity discrepancies, or external form submissions were detected.';
    } else if (normalizedScore >= 25) {
      scoreSummaryText = 'Moderate structural or transport indicators observed. Proceed with caution and verify destination authenticity.';
    } else if (normalizedScore >= 12) {
      scoreSummaryText = 'Minor structural observations noted, with no active deceptive credential lures detected.';
    }

    const scoreExplanation: IPhishingScoreExplanation = {
      summary: scoreSummaryText,
      rawScore,
      normalizedScore,
      contributors: scoreContributors,
      positiveSignals,
      limitations,
    };

    // Construct Final Recommendations
    if (normalizedScore >= 50 || hasCriticalFinding) {
      recommendations.push('Do NOT enter login credentials, passwords, or financial information on this destination.');
      recommendations.push('Verify the exact spelling of the domain in your browser address bar before interacting.');
      recommendations.push('Report suspicious deceptive links to your security team or service provider.');
    } else if (normalizedScore >= 25) {
      recommendations.push('Exercise caution before interacting with forms or downloading content.');
      recommendations.push('Verify domain ownership independently if this URL was received via an unsolicited communication.');
    } else {
      recommendations.push('No significant phishing indicators observed. Continue practicing standard link verification.');
      recommendations.push('Always confirm the browser address bar matches the intended destination domain before authenticating.');
    }

    const phishingSecurityAnalysis: IPhishingSecurityAnalysis = {
      status: normalizedScore >= 50 ? 'warning' : 'passed',
      executionOutcome: 'COMPLETED',
      statusExplanation: 'Comprehensive passive phishing security assessment completed.',
      confidence,
      confidenceLabel,
      riskScore: normalizedScore,
      riskLevel:
        classification === 'Critical'
          ? 'CRITICAL'
          : classification === 'High Risk'
          ? 'HIGH'
          : classification === 'Suspicious'
          ? 'MODERATE'
          : classification === 'Low Risk'
          ? 'LOW'
          : 'SAFE',
      details: scoreSummaryText,
      summary: scoreSummaryText,
      targetProfile: {
        originalUrl: maskSensitiveUrl(target),
        normalizedUrl: maskSensitiveUrl(normalizedTarget),
        finalUrl: maskSensitiveUrl(finalUrl),
        hostname,
        domain: registrableDomain,
        registrableDomain,
        isIpAddress: isDirectIp,
        isPunycode,
        subdomainCount: subdomainsList.length,
        pathDepth,
        queryParamCount: queryParamsCount,
      },
      redirectAnalysis: {
        totalHops,
        hasCrossDomainRedirect: isCrossDomainRedirect,
        hasProtocolDowngrade,
        chain: redirectHops.map((hop, idx) => ({
          hopNumber: idx + 1,
          sourceUrl: maskSensitiveUrl(hop.url),
          destinationUrl: maskSensitiveUrl(redirectHops[idx + 1]?.url || finalUrl),
          statusCode: hop.statusCode,
          statusText: hop.statusText,
          isCrossDomain: isCrossDomainRedirect,
          isDowngrade: false,
        })),
        assessment:
          totalHops > 0
            ? isCrossDomainRedirect
              ? `Followed ${totalHops} redirect hop(s) across distinct domain boundaries (${hostname} → ${finalHostname}).`
              : `Followed ${totalHops} redirect hop(s) within the same domain space (${finalHostname}).`
            : 'Direct navigation destination analyzed without intermediate redirect hops.',
      },
      domainIdentityAnalysis: {
        claimedBrand: impersonationBrand?.brandName,
        detectedBrands,
        isLegitimateBrandDomain: detectedBrands.length > 0 && !impersonationBrand,
        impersonationDetected: Boolean(impersonationBrand),
        impersonationEvidence: impersonationEvidenceStr,
        homographDetected: isPunycode,
        punycodeLabels,
        suspiciousSubdomains: subdomainsList,
        assessment: impersonationBrand
          ? `Potential brand impersonation detected: Page displays ${impersonationBrand.brandName} identity tokens on unauthorized host ${hostname}.`
          : 'Domain and page identity appear consistent with no third-party impersonation patterns.',
      },
      pageIdentityAnalysis: {
        pageTitle,
        metaDescription,
        headings,
        claimedIdentity: impersonationBrand?.brandName || (pageTitle ? pageTitle.slice(0, 50) : undefined),
        identityConsistency: impersonationBrand
          ? 'SUSPICIOUS_MISMATCH'
          : pageTitle
          ? 'CONSISTENT'
          : 'GENERIC_UNBRANDED',
        assessment: impersonationBrand
          ? `Page title "${pageTitle || ''}" claims ${impersonationBrand.brandName} identity on mismatched host ${hostname}.`
          : pageTitle
          ? `Page identity ("${pageTitle}") is consistent with first-party presentation.`
          : 'Page presents standard content without branded identity markers.',
      },
      credentialAnalysis: {
        hasLoginForm,
        hasPasswordField,
        hasUsernameOrEmailField,
        hasMfaField,
        formCount: formsList.length,
        passwordFormCount,
        insecureFormCount,
        externalActionFormCount,
        forms: formsList,
        assessment:
          hasPasswordField && !effectiveHttps
            ? 'CRITICAL: Password input form served over unencrypted HTTP.'
            : externalActionFormCount > 0
            ? 'HIGH: Authentication form submits credentials to an external origin.'
            : hasLoginForm
            ? 'Authentication form present on HTTPS with same-origin submission.'
            : 'No credential collection or password input fields detected.',
      },
      socialEngineeringAnalysis: {
        urgencyKeywordsFound: matchedUrgency,
        securityAlertKeywordsFound: matchedSecurity,
        rewardKeywordsFound: matchedReward,
        isHeuristicSignal: true,
        assessment:
          matchedUrgency.length > 0
            ? `Heuristic signal: High-pressure urgency phrases detected ("${matchedUrgency.join('", "')}").`
            : 'No high-pressure urgency or account coercion patterns detected in page text.',
      },
      transportAnalysis: {
        usesHttps: effectiveHttps,
        tlsValid: tlsResult ? tlsResult.valid : effectiveHttps,
        tlsProtocol: tlsResult?.protocol,
        issuer: tlsResult?.issuer,
        certificateExpired: tlsResult?.daysRemaining !== undefined && tlsResult.daysRemaining < 0,
        hostnameMatch: tlsResult ? tlsResult.valid !== false : undefined,
        assessment: !effectiveHttps
          ? 'Target uses unencrypted HTTP protocol.'
          : tlsResult?.valid === false
          ? `TLS certificate failed trust validation: ${tlsResult.details}`
          : `Secure HTTPS active with valid ${tlsResult?.protocol || 'TLS'} certificate.`,
      },
      threatIntelligence: {
        status: threatIntelStatus,
        provider: threatIntelResult?.provider,
        queried: Boolean(threatIntelResult?.queried),
        result: threatIntelResult?.result,
        details: threatIntelDetails,
      },
      indicators,
      scoreContributors,
      scoreExplanation,
      positiveSignals,
      limitations,
      technicalDetails: {
        originalUrl: maskSensitiveUrl(target),
        finalUrl: maskSensitiveUrl(finalUrl),
        hostname,
        resolvedIps: dnsResult.resolvedIps,
        httpStatus: httpResult?.statusCode,
        contentType: httpResult?.contentType,
        responseTimeMs: httpResult?.responseTimeMs,
        tlsVersion: tlsResult?.protocol,
        tlsCipher: tlsResult?.cipher,
        server: httpResult?.server,
        dnsStatus: dnsResult.dnsStatus,
      },
    };

    return {
      phishingSecurityAnalysis,
      findings,
      recommendations,
      riskScore: normalizedScore,
      classification,
      confidence,
      confidenceLabel,
      whyVerdict,
      positiveSignals,
      scoreContributors,
      scoreExplanation,
      indicators,
      limitations,
    };
  }
}

export const phishingScannerService = new PhishingScannerService();
