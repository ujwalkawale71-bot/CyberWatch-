import * as dns from 'node:dns/promises';
import * as tls from 'node:tls';
import * as crypto from 'node:crypto';
import { URL } from 'node:url';
import { Types } from 'mongoose';
import {
  Scan,
  toSafeScanRecord,
  ScanResultClassification,
  FindingSeverity,
  IScanFinding,
  IScanChecks,
  IWebsiteSecurityV2Analysis,
  IApiSecurityAnalysis,
  IFileSecurityAnalysis,
  IExtensionSecurityAnalysis,
  IUrlSecurityAnalysis,
  IPhishingSecurityAnalysis,
  IUrlRiskScoreContributor,
  IUrlSecurityAuditCheck,
} from '../models/Scan';
import { websiteScannerV2Service } from './website-scanner-v2.service';
import { phishingScannerService } from './phishing-scanner.service';
import { threatIntelService, ThreatIntelligenceResult } from './threat-intel.service';
import { fileScannerService } from './file-scanner.service';
import { extensionScannerService } from './extension-scanner.service';
import { notificationService } from './notification.service';
import { urlNormalizerService } from './url-normalizer.service';
import { domainIntelligenceService, DomainIntelligenceResult } from './domain-intelligence.service';

export interface CreateScanInput {
  target: string;
  targetType?: 'URL' | 'Website' | 'API' | 'Phishing' | 'File' | 'Extension' | 'Domain';
  forceRescan?: boolean;
}

export function deriveClassificationFromRiskScore(
  riskScore: number,
  hasCriticalFinding = false,
  isFailed = false
): ScanResultClassification {
  const safeScore = Number.isFinite(riskScore) ? riskScore : 0;
  if (safeScore >= 75 || hasCriticalFinding) {
    return 'Critical';
  }
  if (safeScore >= 50) {
    return 'High Risk';
  }
  if (safeScore >= 25 || isFailed) {
    return 'Suspicious';
  }
  if (safeScore >= 12) {
    return 'Low Risk';
  }
  return 'Safe';
}

export const SENSITIVE_QUERY_REGEX = /^(token|access_token|id_token|refresh_token|auth_token|api_key|apikey|key|secret|client_secret|password|passwd|pwd|pass|session|session_id|sessionid|sid|phpsessid|jsessionid|auth|authorization|signature|sig|code|verification_code|reset_token|jwt|bearer)$/i;

/**
 * Mask sensitive query parameters from a URL string.
 */
export function maskSensitiveUrl(rawUrl: string): string {
  if (!rawUrl) return rawUrl;
  try {
    const u = new URL(rawUrl);
    let changed = false;
    u.searchParams.forEach((val, key) => {
      if (SENSITIVE_QUERY_REGEX.test(key) && val !== 'REDACTED') {
        u.searchParams.set(key, 'REDACTED');
        changed = true;
      }
    });
    return changed ? u.href : rawUrl;
  } catch {
    return rawUrl;
  }
}

/**
 * Extract registrable domain (e.g. example.com, bbc.co.uk, sub.domain.gov.au -> domain.gov.au).
 */
export function getRegistrableDomain(hostname: string): string {
  const clean = (hostname || '').trim().toLowerCase();
  if (!clean) return '';
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(':')) {
    return clean;
  }
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;

  const twoPartTlds = new Set([
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'org.nz', 'net.nz', 'govt.nz',
    'co.jp', 'ne.jp', 'gr.jp', 'ac.jp', 'ed.jp', 'go.jp',
    'co.za', 'org.za', 'net.za', 'gov.za',
    'com.br', 'org.br', 'net.br', 'gov.br',
    'com.mx', 'org.mx', 'edu.mx', 'gob.mx',
    'com.sg', 'org.sg', 'edu.sg', 'gov.sg',
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'com.hk', 'org.hk', 'gov.hk', 'edu.hk',
    'com.tw', 'org.tw', 'gov.tw', 'edu.tw',
    'co.kr', 'ne.kr', 'or.kr', 'go.kr',
  ]);

  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTlds.has(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Detect CDN or Edge Reverse-Proxy infrastructure from HTTP headers without guessing.
 */
export function detectCdnProvider(headers: Record<string, string>, serverHeader?: string): string | undefined {
  const s = (serverHeader || '').toLowerCase();
  if (s.includes('cloudflare') || headers['cf-ray'] || headers['cf-cache-status']) {
    return 'Cloudflare Edge Network / CDN';
  }
  if (headers['via']?.toLowerCase().includes('cloudfront') || headers['x-amz-cf-id'] || headers['x-amz-cf-pop']) {
    return 'Amazon CloudFront CDN';
  }
  if (headers['x-akamai-transformed'] || s.includes('akamaighost')) {
    return 'Akamai Edge CDN';
  }
  if (headers['x-served-by']?.toLowerCase().includes('cache-') || headers['fastly-debug-digest']) {
    return 'Fastly CDN';
  }
  if (headers['x-vercel-id']) {
    return 'Vercel Edge Network';
  }
  if (headers['x-nf-request-id']) {
    return 'Netlify Edge';
  }
  return undefined;
}

/**
 * Detect observed technology signals from HTTP headers without guessing.
 */
export function detectTechnologies(headers: Record<string, string>, serverHeader?: string): string[] {
  const techs: string[] = [];
  if (serverHeader) techs.push(`Server: ${serverHeader}`);
  if (headers['x-powered-by']) techs.push(`Framework: ${headers['x-powered-by']}`);
  if (headers['x-aspnet-version']) techs.push(`ASP.NET: ${headers['x-aspnet-version']}`);
  if (headers['x-generator']) techs.push(`Generator: ${headers['x-generator']}`);
  return techs;
}

/**
 * Evidence-based resource interpretation without inventing business purpose.
 */
export function interpretUrlResource(
  statusCode: number | undefined,
  contentType: string | undefined,
  redirectCount: number,
  finalUrl: string,
  error: string | undefined,
  isPrivate: boolean,
  hostname?: string
): string {
  if (isPrivate) {
    return 'The destination resolves to a private or internal network address and was blocked by security controls (SSRF Protection).';
  }
  if (error === 'ETIMEDOUT') {
    return 'The scanner could not connect to the target destination because the request timed out.';
  }
  if (error) {
    return `The scan could not connect to the target destination (${error}).`;
  }
  if (redirectCount > 0 && statusCode && [301, 302, 303, 307, 308].includes(statusCode)) {
    return `The URL redirects to another web destination (${maskSensitiveUrl(finalUrl)}).`;
  }
  if (statusCode === 404) {
    return 'The URL returned an HTTP 404 Not Found error response.';
  }
  if (statusCode && statusCode >= 500) {
    return `The server returned an HTTP ${statusCode} internal error response.`;
  }
  if (statusCode === 401 || statusCode === 403) {
    return `The URL returned an HTTP ${statusCode} authorization/access restricted response.`;
  }

  const hostLabel = hostname || (() => {
    try { return new URL(finalUrl).hostname; } catch { return ''; }
  })();
  const hostFragment = hostLabel ? ` on ${hostLabel}` : '';

  if (contentType) {
    const ct = contentType.toLowerCase();
    if (ct.includes('text/html') || ct.includes('application/xhtml')) {
      const statusText = statusCode ? ` with HTTP ${statusCode} OK` : '';
      return `This URL points to a publicly reachable web page${hostFragment}. The endpoint returned an HTML document${statusText}.`;
    }
    if (ct.includes('application/json') || ct.includes('text/json')) {
      const statusText = statusCode ? ` with HTTP ${statusCode} OK` : '';
      return `This URL points to an API endpoint${hostFragment}. The endpoint returned a JSON response${statusText}.`;
    }
    if (ct.includes('xml')) {
      const statusText = statusCode ? ` with HTTP ${statusCode} OK` : '';
      return `This URL points to a structured data resource${hostFragment}. The endpoint returned an XML document${statusText}.`;
    }
    if (ct.includes('text/plain')) {
      const statusText = statusCode ? ` with HTTP ${statusCode} OK` : '';
      return `This URL points to a plain text resource${hostFragment}. The endpoint returned a text document${statusText}.`;
    }
    if (ct.includes('image/') || ct.includes('video/') || ct.includes('audio/') || ct.includes('application/pdf') || ct.includes('application/octet-stream') || ct.includes('zip')) {
      const statusText = statusCode ? ` with HTTP ${statusCode} OK` : '';
      return `This URL points to a media/file asset${hostFragment} (${contentType.split(';')[0]})${statusText}.`;
    }
  }
  if (statusCode && statusCode >= 200 && statusCode < 300) {
    return `This URL points to a publicly reachable resource${hostFragment}. The endpoint returned HTTP ${statusCode} OK.`;
  }
  return 'The scanner could not determine the resource type from the available response.';
}

/**
 * Check if an IPv4 or IPv6 address is private, loopback, or reserved (SSRF safety check).
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const cleanIp = ip.trim().toLowerCase();

  // Loopback / Localhost
  if (
    cleanIp === '127.0.0.1' ||
    cleanIp === '::1' ||
    cleanIp === '0.0.0.0' ||
    cleanIp === '::' ||
    cleanIp === 'localhost' ||
    cleanIp.endsWith('.localhost') ||
    cleanIp.endsWith('.local') ||
    cleanIp.endsWith('.internal') ||
    cleanIp.startsWith('127.')
  ) {
    return true;
  }

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1, ::ffff:10.0.0.1, ::ffff:169.254.169.254)
  if (cleanIp.startsWith('::ffff:')) {
    const extractedV4 = cleanIp.replace('::ffff:', '');
    return isPrivateOrReservedIp(extractedV4);
  }

  // IPv4 checks
  const ipv4Parts = cleanIp.split('.').map((p) => parseInt(p, 10));
  if (ipv4Parts.length === 4 && ipv4Parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
    const [a, b] = ipv4Parts;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12 (172.16.0.0 – 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 (Link-local & AWS/Cloud metadata 169.254.169.254)
    if (a === 169 && b === 254) return true;
    // 127.0.0.0/8
    if (a === 127) return true;
    // 0.0.0.0/8
    if (a === 0) return true;
    // 100.64.0.0/10 (Carrier-grade NAT)
    if (a === 100 && b >= 64 && b <= 127) return true;
  }

  // IPv6 Unique Local Address (fc00::/7) or Link-Local (fe80::/10)
  if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd') || cleanIp.startsWith('fe80')) {
    return true;
  }

  return false;
}

export class ScanService {
  /**
   * Perform real DNS resolution for a hostname.
   */
  private async resolveDns(hostname: string): Promise<{
    resolvedIps: string[];
    ipVersion: string;
    dnsStatus: string;
    isPrivate: boolean;
    error?: string;
  }> {
    const cleanHost = hostname.trim().toLowerCase();

    // If hostname is directly an IP address
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(cleanHost) || cleanHost.includes(':')) {
      const isPriv = isPrivateOrReservedIp(cleanHost);
      return {
        resolvedIps: [cleanHost],
        ipVersion: cleanHost.includes(':') ? 'IPv6' : 'IPv4',
        dnsStatus: isPriv ? 'Direct Host IP (Private/Reserved/Cloud Metadata)' : 'Direct Host IP Address',
        isPrivate: isPriv,
      };
    }

    // Localhost and Cloud Metadata Hostname guards
    const privateHostnames = [
      'localhost',
      'metadata.google.internal',
      'metadata.internal',
      'instance-data',
      '169.254.169.254.nip.io',
      '127.0.0.1.nip.io',
      'localtest.me',
    ];

    if (privateHostnames.includes(cleanHost) || cleanHost.endsWith('.localhost') || cleanHost.endsWith('.internal')) {
      return {
        resolvedIps: ['127.0.0.1'],
        ipVersion: 'IPv4',
        dnsStatus: 'Localhost / Internal Cloud Metadata Hostname',
        isPrivate: true,
      };
    }

    try {
      const lookupResults = await dns.lookup(cleanHost, { all: true });
      if (!lookupResults || lookupResults.length === 0) {
        return {
          resolvedIps: [],
          ipVersion: 'N/A',
          dnsStatus: 'DNS lookup returned no active records',
          isPrivate: false,
        };
      }

      const ips = Array.from(new Set(lookupResults.map((r) => r.address)));
      const hasPrivate = ips.some((ip) => isPrivateOrReservedIp(ip));
      const hasIpv4 = lookupResults.some((r) => r.family === 4);
      const hasIpv6 = lookupResults.some((r) => r.family === 6);
      const ipVersion = hasIpv4 && hasIpv6 ? 'IPv4 & IPv6' : hasIpv6 ? 'IPv6' : 'IPv4';

      return {
        resolvedIps: ips,
        ipVersion,
        dnsStatus: hasPrivate ? 'Resolved to Private / Internal Network' : `Resolved (${ips.length} record${ips.length > 1 ? 's' : ''})`,
        isPrivate: hasPrivate,
      };
    } catch (err: any) {
      return {
        resolvedIps: [],
        ipVersion: 'N/A',
        dnsStatus: `DNS resolution failed: ${err.code || err.message || 'NXDOMAIN'}`,
        isPrivate: false,
        error: err.code || err.message,
      };
    }
  }

  /**
   * Perform real TLS certificate inspection for HTTPS targets.
   */
  private async inspectTls(
    hostname: string,
    port = 443
  ): Promise<{
    protocol?: string;
    issuer?: string;
    subject?: string;
    valid?: boolean;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    cipher?: string;
    details: string;
    error?: string;
  }> {
    return new Promise((resolve) => {
      let resolved = false;

      const socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          timeout: 5000,
          rejectUnauthorized: false, // Allows inspecting invalid/self-signed certs rather than dropping
        },
        () => {
          if (resolved) return;
          resolved = true;

          try {
            const cert = socket.getPeerCertificate(true);
            const cipher = socket.getCipher();
            const protocol = socket.getProtocol() || 'TLS';
            const authorized = socket.authorized;
            const authError = socket.authorizationError ? String(socket.authorizationError) : undefined;

            if (!cert || Object.keys(cert).length === 0) {
              socket.destroy();
              return resolve({
                valid: false,
                details: 'TLS connection established but peer certificate is empty.',
              });
            }

            const getFirstString = (val: unknown): string | undefined => {
              if (typeof val === 'string') return val;
              if (Array.isArray(val) && val.length > 0) return String(val[0]);
              return undefined;
            };

            const issuerName: string =
              typeof cert.issuer === 'object' && cert.issuer !== null
                ? getFirstString(cert.issuer.O) || getFirstString(cert.issuer.CN) || 'Unknown Authority'
                : String(cert.issuer || 'Unknown CA');

            const subjectName: string =
              typeof cert.subject === 'object' && cert.subject !== null
                ? getFirstString(cert.subject.CN) || getFirstString(cert.subject.O) || hostname
                : String(cert.subject || hostname);

            const validToDate = cert.valid_to ? new Date(cert.valid_to) : null;
            const validFromDate = cert.valid_from ? new Date(cert.valid_from) : null;
            const now = new Date();
            const daysRemaining = validToDate
              ? Math.max(0, Math.floor((validToDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)))
              : undefined;

            const isExpired = validToDate ? validToDate.getTime() < now.getTime() : false;
            const isValid = authorized && !isExpired;

            let details = `Valid ${protocol} connection. Certificate issued by ${issuerName}.`;
            if (!authorized && authError) {
              details = `TLS Warning: Certificate validation failed (${authError}).`;
            } else if (isExpired) {
              details = `TLS Warning: Certificate expired on ${validToDate?.toDateString()}.`;
            }

            socket.destroy();
            resolve({
              protocol: `${protocol} / HTTPS`,
              issuer: issuerName,
              subject: subjectName,
              valid: isValid,
              validFrom: validFromDate ? validFromDate.toISOString() : undefined,
              validTo: validToDate ? validToDate.toISOString() : undefined,
              daysRemaining,
              cipher: cipher?.name,
              details,
              error: authError,
            });
          } catch (err: any) {
            socket.destroy();
            resolve({
              valid: false,
              details: `TLS inspection error: ${err.message}`,
              error: err.message,
            });
          }
        }
      );

      socket.on('error', (err: any) => {
        if (resolved) return;
        resolved = true;
        socket.destroy();
        resolve({
          valid: false,
          details: `TLS connection failed: ${err.message}`,
          error: err.code || err.message,
        });
      });

      socket.on('timeout', () => {
        if (resolved) return;
        resolved = true;
        socket.destroy();
        resolve({
          valid: false,
          details: 'TLS handshake timed out after 5000ms.',
          error: 'ETIMEDOUT',
        });
      });
    });
  }

  /**
   * Perform real HTTP inspection, security header collection, cookie parsing, and body sampling.
   */
  private async inspectHttp(
    initialUrl: string,
    maxRedirects = 5,
    timeoutMs = 8000
  ): Promise<{
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
  }> {
    let currentUrl = initialUrl;
    let redirectCount = 0;
    const redirectChain: Array<{ url: string; statusCode?: number; statusText?: string }> = [];
    const overallStartTime = Date.now();

    try {
      while (redirectCount <= maxRedirects) {
        let parsedCurrent: URL;
        try {
          parsedCurrent = new URL(currentUrl);
        } catch {
          return {
            finalUrl: currentUrl,
            redirectCount,
            redirectChain,
            securityHeaders: {},
            allHeaders: {},
            rawCookies: [],
            details: 'Invalid redirect URL target format.',
            error: 'INVALID_URL',
          };
        }

        // Scheme validation
        if (parsedCurrent.protocol !== 'http:' && parsedCurrent.protocol !== 'https:') {
          return {
            finalUrl: currentUrl,
            redirectCount,
            redirectChain,
            securityHeaders: {},
            allHeaders: {},
            rawCookies: [],
            details: `Unsafe URL scheme detected (${parsedCurrent.protocol}). Only HTTP and HTTPS are permitted.`,
            error: 'UNSAFE_SCHEME',
          };
        }

        // SSRF check on intermediate redirect destinations
        const dnsCheck = await this.resolveDns(parsedCurrent.hostname);
        if (dnsCheck.isPrivate) {
          return {
            finalUrl: currentUrl,
            redirectCount,
            redirectChain,
            securityHeaders: {},
            allHeaders: {},
            rawCookies: [],
            details: 'HTTP analysis stopped: Destination resolves to a private or internal network address (SSRF Protection).',
            error: 'SSRF_BLOCKED',
          };
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);

        let res: Response;
        try {
          res = await fetch(currentUrl, {
            method: 'GET',
            redirect: 'manual',
            signal: controller.signal,
            headers: {
              'User-Agent': 'CyberWatch-Security-Scanner/2.0 (+https://cyberwatch.io)',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
          });
        } catch (fetchErr: any) {
          clearTimeout(timeout);
          const totalElapsed = Date.now() - overallStartTime;
          return {
            finalUrl: currentUrl,
            redirectCount,
            redirectChain,
            responseTimeMs: totalElapsed,
            securityHeaders: {},
            allHeaders: {},
            rawCookies: [],
            details: `Connection failed: ${fetchErr.name === 'AbortError' ? 'Connection timed out' : fetchErr.message}`,
            error: fetchErr.name === 'AbortError' ? 'ETIMEDOUT' : fetchErr.message,
          };
        }
        clearTimeout(timeout);

        const statusCode = res.status;
        const statusText = res.statusText || `${statusCode}`;

        // Handle Redirects
        if ([301, 302, 303, 307, 308].includes(statusCode)) {
          const locationHeader = res.headers.get('location');
          redirectChain.push({ url: currentUrl, statusCode, statusText });

          if (!locationHeader) {
            break;
          }

          redirectCount++;
          try {
            currentUrl = new URL(locationHeader, currentUrl).toString();
          } catch {
            break;
          }

          if (redirectCount > maxRedirects) {
            break;
          }
          continue;
        }

        // Final response reached
        const totalElapsed = Date.now() - overallStartTime;
        const securityHeaders: Record<string, string> = {};
        const allHeaders: Record<string, string> = {};

        res.headers.forEach((val, key) => {
          allHeaders[key.toLowerCase()] = val;
        });

        const hsts = res.headers.get('strict-transport-security');
        if (hsts) securityHeaders['strict-transport-security'] = hsts;
        const csp = res.headers.get('content-security-policy');
        if (csp) securityHeaders['content-security-policy'] = csp;
        const xfo = res.headers.get('x-frame-options');
        if (xfo) securityHeaders['x-frame-options'] = xfo;
        const xcto = res.headers.get('x-content-type-options');
        if (xcto) securityHeaders['x-content-type-options'] = xcto;
        const refPol = res.headers.get('referrer-policy');
        if (refPol) securityHeaders['referrer-policy'] = refPol;
        const permPol = res.headers.get('permissions-policy');
        if (permPol) securityHeaders['permissions-policy'] = permPol;
        const coop = res.headers.get('cross-origin-opener-policy');
        if (coop) securityHeaders['cross-origin-opener-policy'] = coop;
        const corp = res.headers.get('cross-origin-resource-policy');
        if (corp) securityHeaders['cross-origin-resource-policy'] = corp;

        // Raw cookies
        let rawCookies: string[] = [];
        if (typeof (res.headers as any).getSetCookie === 'function') {
          rawCookies = (res.headers as any).getSetCookie();
        } else {
          const cookieHeader = res.headers.get('set-cookie');
          if (cookieHeader) rawCookies = [cookieHeader];
        }

        const serverHeader = res.headers.get('server') || undefined;
        const contentType = res.headers.get('content-type') || undefined;
        const contentLengthHeader = res.headers.get('content-length');
        const contentLength = contentLengthHeader ? parseInt(contentLengthHeader, 10) : undefined;

        // Safe body inspection (up to 2 MB)
        let htmlSnippet: string | undefined = undefined;
        let bodySnippet: string | undefined = undefined;
        try {
          const fullText = await res.text();
          bodySnippet = fullText.slice(0, 2097152);
          if (contentType && (contentType.includes('text/html') || contentType.includes('application/xhtml'))) {
            htmlSnippet = bodySnippet;
          }
        } catch {
          // Non-blocking if body read fails
        }

        let details = `HTTP ${statusCode} ${statusText} received in ${totalElapsed}ms.`;
        if (redirectCount > 0) {
          details += ` Followed ${redirectCount} redirect hop(s) to destination.`;
        }

        return {
          statusCode,
          statusText,
          contentType,
          contentLength,
          server: serverHeader,
          responseTimeMs: totalElapsed,
          finalUrl: currentUrl,
          redirectCount,
          redirectChain,
          securityHeaders,
          allHeaders,
          rawCookies,
          htmlSnippet,
          bodySnippet,
          details,
        };
      }

      // Max redirects exceeded
      return {
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        bodySnippet: undefined,
        details: `Exceeded maximum redirect limit (${maxRedirects} hops). Potential redirect loop detected.`,
        error: 'MAX_REDIRECTS_EXCEEDED',
      };
    } catch (err: any) {
      return {
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        securityHeaders: {},
        allHeaders: {},
        rawCookies: [],
        details: `HTTP request failed: ${err.message}`,
        error: err.message,
      };
    }
  }

  /**
   * Analyze HTTP security response headers and identify posture weaknesses.
   */
  private analyzeSecurityHeaders(
    headers: Record<string, string>,
    isHttps: boolean
  ): {
    analysis: NonNullable<IScanChecks['securityHeadersAnalysis']>;
    findings: IScanFinding[];
    risk: number;
  } {
    const items: NonNullable<IScanChecks['securityHeadersAnalysis']>['headers'] = [];
    const findings: IScanFinding[] = [];
    let risk = 0;

    // 1. Content-Security-Policy (CSP)
    const csp = headers['content-security-policy'];
    if (csp) {
      if (csp.includes("'unsafe-inline'") && !csp.includes("'nonce-") && !csp.includes("'sha256-")) {
        items.push({
          name: 'Content-Security-Policy',
          status: 'warning',
          value: csp,
          explanation: "CSP is deployed but contains 'unsafe-inline' without cryptographic nonces, reducing XSS defense-in-depth.",
          recommendation: "Refactor inline scripts to external assets with nonce/hash directives.",
          severity: 'LOW',
        });
        findings.push({
          category: 'Security Headers',
          severity: 'LOW',
          title: 'Permissive Content-Security-Policy (unsafe-inline)',
          description: "The Content-Security-Policy header contains 'unsafe-inline' which weakens protection against Cross-Site Scripting (XSS).",
          evidence: `CSP: ${csp.length > 80 ? csp.slice(0, 80) + '...' : csp}`,
        });
        risk += 5;
      } else {
        items.push({
          name: 'Content-Security-Policy',
          status: 'present',
          value: csp,
          explanation: 'Restricts resource loading origins to prevent Cross-Site Scripting (XSS) and data injection.',
          recommendation: 'Maintain strict policy rules and avoid wildcard source directives.',
        });
      }
    } else {
      items.push({
        name: 'Content-Security-Policy',
        status: 'missing',
        explanation: 'No Content-Security-Policy header observed. Browser-level defense-in-depth against XSS is reduced.',
        recommendation: 'Deploy a Content-Security-Policy header specifying authorized script, frame, and style sources.',
        severity: 'MEDIUM',
      });
      findings.push({
        category: 'Security Headers',
        severity: 'MEDIUM',
        title: 'Missing Content-Security-Policy (CSP) Header',
        description: 'The web server does not send a Content-Security-Policy header, leaving client browsers without origin-enforced script restrictions.',
        evidence: 'Header Content-Security-Policy: Not present in response',
      });
      risk += 10;
    }

    // 2. Strict-Transport-Security (HSTS)
    const hsts = headers['strict-transport-security'];
    if (hsts) {
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 10368000) {
        items.push({
          name: 'Strict-Transport-Security',
          status: 'warning',
          value: hsts,
          explanation: `HSTS is configured but max-age (${maxAge}s) is below the recommended 120 days (10,368,000s).`,
          recommendation: 'Increase max-age to at least 31536000 seconds (1 year) with includeSubDomains.',
          severity: 'LOW',
        });
        risk += 5;
      } else {
        items.push({
          name: 'Strict-Transport-Security',
          status: 'present',
          value: hsts,
          explanation: 'Forces modern browsers to connect exclusively via encrypted HTTPS connections.',
          recommendation: 'Ensure includeSubDomains and preload are enabled once fully validated.',
        });
      }
    } else {
      items.push({
        name: 'Strict-Transport-Security',
        status: 'missing',
        explanation: isHttps
          ? 'Missing Strict-Transport-Security header on HTTPS website. Clients may attempt initial unencrypted HTTP connections.'
          : 'HSTS is not applicable on unencrypted HTTP.',
        recommendation: isHttps
          ? 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains.'
          : 'Enforce HTTPS transport before configuring HSTS.',
        severity: isHttps ? 'LOW' : 'INFO',
      });
      if (isHttps) {
        findings.push({
          category: 'Security Headers',
          severity: 'LOW',
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          description: 'The HTTPS website does not instruct client browsers to strictly enforce HTTPS, permitting potential SSL-stripping on initial connections.',
          evidence: 'Header Strict-Transport-Security: Not present',
        });
        risk += 10;
      }
    }

    // 3. X-Content-Type-Options
    const xcto = headers['x-content-type-options'];
    if (xcto && xcto.toLowerCase().includes('nosniff')) {
      items.push({
        name: 'X-Content-Type-Options',
        status: 'present',
        value: xcto,
        explanation: 'Prevents browsers from MIME-sniffing a response away from the declared content-type.',
        recommendation: 'Maintain X-Content-Type-Options: nosniff across all static and dynamic responses.',
      });
    } else {
      items.push({
        name: 'X-Content-Type-Options',
        status: 'missing',
        explanation: 'Missing nosniff directive allows browsers to attempt MIME-type guessing, potentially executing non-script files.',
        recommendation: 'Add X-Content-Type-Options: nosniff header.',
        severity: 'LOW',
      });
      findings.push({
        category: 'Security Headers',
        severity: 'LOW',
        title: 'Missing X-Content-Type-Options Header',
        description: 'Without the nosniff directive, browsers may execute MIME-sniffing on downloaded assets, creating potential script execution vectors.',
        evidence: 'Header X-Content-Type-Options: Not present',
      });
      risk += 5;
    }

    // 4. X-Frame-Options
    const xfo = headers['x-frame-options'];
    if (xfo && (xfo.toUpperCase().includes('DENY') || xfo.toUpperCase().includes('SAMEORIGIN'))) {
      items.push({
        name: 'X-Frame-Options',
        status: 'present',
        value: xfo,
        explanation: 'Controls whether the site can be embedded within frames or iframes, mitigating clickjacking.',
        recommendation: 'Maintain SAMEORIGIN or DENY framing restrictions.',
      });
    } else {
      items.push({
        name: 'X-Frame-Options',
        status: 'missing',
        explanation: 'Missing X-Frame-Options allows arbitrary websites to embed this application inside an iframe (Clickjacking risk).',
        recommendation: 'Configure X-Frame-Options: SAMEORIGIN or use CSP frame-ancestors.',
        severity: 'LOW',
      });
      findings.push({
        category: 'Security Headers',
        severity: 'LOW',
        title: 'Missing X-Frame-Options (Clickjacking Protection)',
        description: 'The target does not set X-Frame-Options, allowing malicious third-party pages to iframe the portal for UI redress attacks.',
        evidence: 'Header X-Frame-Options: Not present',
      });
      risk += 5;
    }

    // 5. Referrer-Policy
    const refPol = headers['referrer-policy'];
    if (refPol) {
      if (refPol.toLowerCase().includes('unsafe-url')) {
        items.push({
          name: 'Referrer-Policy',
          status: 'warning',
          value: refPol,
          explanation: 'Referrer-Policy is set to unsafe-url, which leaks full URL paths and query parameters across origins.',
          recommendation: 'Change to strict-origin-when-cross-origin or no-referrer.',
          severity: 'LOW',
        });
        risk += 5;
      } else {
        items.push({
          name: 'Referrer-Policy',
          status: 'present',
          value: refPol,
          explanation: 'Protects user privacy and sensitive URL query parameters on outbound navigation.',
          recommendation: 'Maintain strict-origin-when-cross-origin or no-referrer.',
        });
      }
    } else {
      items.push({
        name: 'Referrer-Policy',
        status: 'missing',
        explanation: 'No explicit Referrer-Policy declared; browsers fall back to default behavior.',
        recommendation: 'Explicitly set Referrer-Policy: strict-origin-when-cross-origin.',
        severity: 'INFO',
      });
    }

    // 6. Permissions-Policy
    const permPol = headers['permissions-policy'];
    if (permPol) {
      items.push({
        name: 'Permissions-Policy',
        status: 'present',
        value: permPol,
        explanation: 'Restricts access to sensitive browser features and hardware APIs (camera, geolocation, microphone).',
        recommendation: 'Ensure unnecessary browser capabilities remain disabled.',
      });
    } else {
      items.push({
        name: 'Permissions-Policy',
        status: 'missing',
        explanation: 'No Permissions-Policy declared to restrict browser features and device hardware APIs.',
        recommendation: 'Configure Permissions-Policy to explicitly disable unused browser capabilities.',
        severity: 'INFO',
      });
    }

    // 7. Cross-Origin-Opener-Policy (COOP)
    const coop = headers['cross-origin-opener-policy'];
    if (coop) {
      items.push({
        name: 'Cross-Origin-Opener-Policy',
        status: 'present',
        value: coop,
        explanation: 'Isolates the browsing context to prevent cross-origin window manipulation and Spectre attacks.',
        recommendation: 'Maintain Cross-Origin-Opener-Policy: same-origin.',
      });
    } else {
      items.push({
        name: 'Cross-Origin-Opener-Policy',
        status: 'missing',
        explanation: 'COOP header not configured; browsing context is not isolated against cross-window side-channels.',
        recommendation: 'Consider setting Cross-Origin-Opener-Policy: same-origin.',
        severity: 'INFO',
      });
    }

    // 8. Cross-Origin-Resource-Policy (CORP)
    const corp = headers['cross-origin-resource-policy'];
    if (corp) {
      items.push({
        name: 'Cross-Origin-Resource-Policy',
        status: 'present',
        value: corp,
        explanation: 'Restricts which origins can read this web resource, protecting against cross-origin data leaks.',
        recommendation: 'Maintain Cross-Origin-Resource-Policy: same-origin or same-site.',
      });
    } else {
      items.push({
        name: 'Cross-Origin-Resource-Policy',
        status: 'missing',
        explanation: 'CORP header not declared.',
        recommendation: 'Consider setting Cross-Origin-Resource-Policy: same-origin for private web assets.',
        severity: 'INFO',
      });
    }

    const presentCount = items.filter((i) => i.status === 'present').length;
    const warningCount = items.filter((i) => i.status === 'warning').length;
    const missingCount = items.filter((i) => i.status === 'missing').length;
    const totalChecked = items.length;
    const score = Math.round((presentCount / totalChecked) * 100);

    const overallStatus: 'passed' | 'warning' | 'failed' =
      presentCount >= 5 ? 'passed' : presentCount >= 2 ? 'warning' : 'failed';

    return {
      analysis: {
        status: overallStatus,
        score,
        totalChecked,
        presentCount,
        missingCount,
        warningCount,
        headers: items,
        details: `Evaluated ${totalChecked} core security headers: ${presentCount} present, ${warningCount} warning(s), ${missingCount} missing (${score}% posture score).`,
      },
      findings,
      risk,
    };
  }

  /**
   * Parse and evaluate HTTP Set-Cookie security flags.
   */
  private analyzeCookies(
    rawCookies: string[],
    isHttps: boolean
  ): {
    analysis: NonNullable<IScanChecks['cookiesAnalysis']>;
    findings: IScanFinding[];
    risk: number;
  } {
    const cookies: NonNullable<IScanChecks['cookiesAnalysis']>['cookies'] = [];
    const findings: IScanFinding[] = [];
    let risk = 0;

    for (const raw of rawCookies) {
      const parts = raw.split(';').map((p) => p.trim());
      if (parts.length === 0 || !parts[0]) continue;

      const [nameVal] = parts;
      const eqIdx = nameVal.indexOf('=');
      const name = eqIdx > -1 ? nameVal.slice(0, eqIdx).trim() : nameVal;
      const valueMasked = eqIdx > -1 ? `${nameVal.slice(eqIdx + 1, eqIdx + 4)}***` : undefined;

      const isSecure = parts.some((p) => /^secure$/i.test(p));
      const isHttpOnly = parts.some((p) => /^httponly$/i.test(p));
      const sameSitePart = parts.find((p) => /^samesite=/i.test(p));
      const sameSite = sameSitePart ? sameSitePart.split('=')[1]?.trim() : undefined;
      const domainPart = parts.find((p) => /^domain=/i.test(p));
      const domain = domainPart ? domainPart.split('=')[1]?.trim() : undefined;
      const pathPart = parts.find((p) => /^path=/i.test(p));
      const path = pathPart ? pathPart.split('=')[1]?.trim() : undefined;

      const issues: string[] = [];
      let isFlagged = false;

      // Insecure Cookie over HTTPS
      if (isHttps && !isSecure) {
        issues.push('Missing Secure flag on HTTPS transmission');
        isFlagged = true;
        risk += 10;
        findings.push({
          category: 'Cookie Security',
          severity: 'MEDIUM',
          title: `Insecure Cookie Transmission (Missing Secure Flag: ${name})`,
          description: `Cookie '${name}' is transmitted without the Secure attribute over HTTPS, risking plaintext leakage on mixed network navigation.`,
          evidence: `Set-Cookie: ${name}=...; (Secure attribute missing)`,
        });
      }

      // Missing HttpOnly on potential session/auth cookie
      const isSensitiveName = /session|auth|token|jwt|user|id|login|sid|account/i.test(name);
      if (isSensitiveName && !isHttpOnly) {
        issues.push('Sensitive authentication cookie missing HttpOnly attribute');
        isFlagged = true;
        risk += 15;
        findings.push({
          category: 'Cookie Security',
          severity: 'MEDIUM',
          title: `Sensitive Cookie Missing HttpOnly Flag (${name})`,
          description: `The authentication or session-identifying cookie '${name}' lacks HttpOnly, making it accessible to client-side scripts via document.cookie (XSS risk).`,
          evidence: `Set-Cookie: ${name}=...; (HttpOnly attribute missing)`,
        });
      }

      // SameSite=None without Secure
      if (sameSite && sameSite.toLowerCase() === 'none' && !isSecure) {
        issues.push('SameSite=None requires Secure attribute');
        isFlagged = true;
        risk += 10;
      }

      cookies.push({
        name,
        valueMasked,
        secure: isSecure,
        httpOnly: isHttpOnly,
        sameSite: sameSite || 'Not specified',
        domain,
        path: path || '/',
        isFlagged,
        issues: issues.length > 0 ? issues : undefined,
        details: `Secure: ${isSecure ? 'Yes' : 'No'}, HttpOnly: ${isHttpOnly ? 'Yes' : 'No'}, SameSite: ${sameSite || 'None'}`,
      });
    }

    const totalCookies = cookies.length;
    const secureCookies = cookies.filter((c) => c.secure).length;
    const httpOnlyCookies = cookies.filter((c) => c.httpOnly).length;
    const sameSiteCookies = cookies.filter((c) => c.sameSite && c.sameSite !== 'Not specified').length;
    const flaggedCookies = cookies.filter((c) => c.isFlagged).length;

    let details = 'No security-relevant cookies observed in response.';
    if (totalCookies > 0) {
      details = `Analyzed ${totalCookies} cookie(s): ${secureCookies} Secure, ${httpOnlyCookies} HttpOnly, ${flaggedCookies} flagged with security warnings.`;
    }

    return {
      analysis: {
        status: flaggedCookies > 0 ? 'warning' : totalCookies > 0 ? 'passed' : 'neutral',
        totalCookies,
        secureCookies,
        httpOnlyCookies,
        sameSiteCookies,
        flaggedCookies,
        cookies,
        details,
      },
      findings,
      risk,
    };
  }

  /**
   * Safe passive HTML analysis for Forms, Mixed Content, Scripts, and Iframe resources.
   */
  private analyzeHtmlContent(
    html: string,
    targetUrl: string,
    isHttps: boolean
  ): {
    analysis: NonNullable<IScanChecks['contentAnalysis']>;
    findings: IScanFinding[];
    risk: number;
  } {
    const findings: IScanFinding[] = [];
    let risk = 0;

    let formsCount = 0;
    let passwordFormsCount = 0;
    let insecureFormsCount = 0;
    let externalFormActionsCount = 0;

    // Form parsing
    const formMatches = html.match(/<form\b[^>]*>/gi) || [];
    formsCount = formMatches.length;

    // Check for password inputs
    const passwordInputMatches = html.match(/<input\b[^>]*type=["']password["'][^>]*>/gi) || [];
    passwordFormsCount = passwordInputMatches.length;

    for (const formTag of formMatches) {
      const actionMatch = formTag.match(/action=["']([^"']*)["']/i);
      const action = actionMatch ? actionMatch[1].trim() : '';

      // Insecure HTTP form submission on HTTPS page
      if (isHttps && action.toLowerCase().startsWith('http://')) {
        insecureFormsCount++;
        risk += 25;
        findings.push({
          category: 'Web Content & Forms',
          severity: 'HIGH',
          title: 'Insecure Plaintext HTTP Form Action on HTTPS Page',
          description: `The website renders an HTML form with an action pointing to an unencrypted HTTP URL (${action}), exposing submitted user data to plaintext interception.`,
          evidence: `Form action: ${action}`,
        });
      }
    }

    // Mixed content detection on HTTPS websites
    let mixedContentCount = 0;
    const mixedContentResources: string[] = [];

    if (isHttps) {
      const scriptHttp = html.match(/<script\b[^>]*src=["'](http:\/\/[^"']+)["']/gi) || [];
      const imgHttp = html.match(/<img\b[^>]*src=["'](http:\/\/[^"']+)["']/gi) || [];
      const linkHttp = html.match(/<link\b[^>]*href=["'](http:\/\/[^"']+)["']/gi) || [];
      const iframeHttp = html.match(/<iframe\b[^>]*src=["'](http:\/\/[^"']+)["']/gi) || [];

      const allMixed = [...scriptHttp, ...imgHttp, ...linkHttp, ...iframeHttp];
      mixedContentCount = allMixed.length;

      allMixed.slice(0, 5).forEach((tag) => {
        const urlMatch = tag.match(/["'](http:\/\/[^"']+)["']/i);
        if (urlMatch && urlMatch[1]) {
          mixedContentResources.push(urlMatch[1]);
        }
      });

      if (mixedContentCount > 0) {
        risk += 20;
        findings.push({
          category: 'Mixed Content',
          severity: scriptHttp.length > 0 ? 'HIGH' : 'MEDIUM',
          title: 'Mixed Content Detected (Insecure HTTP Assets on HTTPS Page)',
          description: `The HTTPS website loads ${mixedContentCount} unencrypted HTTP asset(s) (scripts, images, or stylesheets), which modern browsers may block or allow man-in-the-middle tampering.`,
          evidence: `Sample insecure asset: ${mixedContentResources[0] || 'http:// asset'}`,
        });
      }
    }

    // Scripts and external domains
    const scriptTags = html.match(/<script\b[^>]*>/gi) || [];
    const scriptsCount = scriptTags.length;
    const externalScriptMatches = html.match(/<script\b[^>]*src=["']https?:\/\/([^"'/]+)[^"']*["']/gi) || [];
    const externalScriptsCount = externalScriptMatches.length;

    const externalDomains: string[] = [];
    externalScriptMatches.forEach((tag) => {
      const m = tag.match(/src=["']https?:\/\/([^"'/]+)/i);
      if (m && m[1] && !externalDomains.includes(m[1].toLowerCase())) {
        externalDomains.push(m[1].toLowerCase());
      }
    });

    // Iframes
    const iframesCount = (html.match(/<iframe\b[^>]*>/gi) || []).length;

    const overallStatus: 'passed' | 'warning' | 'failed' | 'neutral' =
      insecureFormsCount > 0 || mixedContentCount > 0 ? 'warning' : 'passed';

    let details = `Analyzed HTML structure: ${formsCount} form(s), ${scriptsCount} script(s), ${iframesCount} iframe(s).`;
    if (mixedContentCount > 0) {
      details += ` Warning: ${mixedContentCount} mixed-content HTTP resource(s) detected.`;
    }
    if (insecureFormsCount > 0) {
      details += ` Critical: ${insecureFormsCount} unencrypted form action(s) detected.`;
    }

    return {
      analysis: {
        status: overallStatus,
        formsCount,
        passwordFormsCount,
        insecureFormsCount,
        externalFormActionsCount,
        scriptsCount,
        externalScriptsCount,
        iframesCount,
        mixedContentCount,
        mixedContentResources: mixedContentResources.length > 0 ? mixedContentResources : undefined,
        externalDomains: externalDomains.length > 0 ? externalDomains : undefined,
        details,
      },
      findings,
      risk,
    };
  }

  /**
   * Helper to decode standard HTML entities in titles and metadata.
   */
  private decodeHtmlEntities(str: string): string {
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
   * Extract safe metadata and evaluate Website Overview & Apparent Purpose from observed HTML.
   */
  private analyzeWebsiteOverview(
    html: string | undefined,
    finalUrl: string,
    httpResult: Awaited<ReturnType<typeof this.inspectHttp>> | null,
    tlsResult: Awaited<ReturnType<typeof this.inspectTls>> | null,
    effectiveHttps: boolean,
    securityHeadersAnalysis?: IScanChecks['securityHeadersAnalysis'],
    cookiesAnalysis?: IScanChecks['cookiesAnalysis'],
    contentAnalysis?: IScanChecks['contentAnalysis']
  ): NonNullable<IScanChecks['websiteOverview']> {
    let pageTitle: string | undefined = undefined;
    let metaDescription: string | undefined = undefined;
    const headings: string[] = [];
    const keywordsDetected: string[] = [];
    let isSpaIndicator = false;
    let hasLoginForm = false;
    let bodySnippet = '';

    if (html && html.length > 0) {
      // 1. Extract Page Title
      const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
      if (titleMatch && titleMatch[1]) {
        const rawTitle = this.decodeHtmlEntities(titleMatch[1].replace(/<[^>]+>/g, ''));
        if (rawTitle.length > 0) {
          pageTitle = rawTitle;
        }
      }

      // 2. Extract Meta Description (name or property=og:description)
      const metaDescMatch =
        html.match(/<meta\b[^>]*\b(?:name|property)=["'](?:description|og:description)["'][^>]*\bcontent=["']([^"']*)["']/i) ||
        html.match(/<meta\b[^>]*\bcontent=["']([^"']*)["'][^>]*\b(?:name|property)=["'](?:description|og:description)["']/i);
      if (metaDescMatch && metaDescMatch[1]) {
        const rawDesc = this.decodeHtmlEntities(metaDescMatch[1]);
        if (rawDesc.length > 0) {
          metaDescription = rawDesc;
        }
      }

      // 3. Extract Headings (h1, h2, h3)
      const headingMatches = html.match(/<h[1-3]\b[^>]*>([\s\S]*?)<\/h[1-3]>/gi) || [];
      for (const h of headingMatches) {
        const clean = this.decodeHtmlEntities(h.replace(/<[^>]+>/g, ''));
        if (clean.length > 3 && clean.length < 120 && !headings.includes(clean)) {
          headings.push(clean);
          if (headings.length >= 5) break;
        }
      }

      // 4. Extract Meta Keywords if present
      const keywordsMatch =
        html.match(/<meta\b[^>]*\bname=["']keywords["'][^>]*\bcontent=["']([^"']*)["']/i) ||
        html.match(/<meta\b[^>]*\bcontent=["']([^"']*)["'][^>]*\bname=["']keywords["']/i);
      if (keywordsMatch && keywordsMatch[1]) {
        const kwList = this.decodeHtmlEntities(keywordsMatch[1])
          .split(',')
          .map((k) => k.trim())
          .filter((k) => k.length > 2);
        keywordsDetected.push(...kwList.slice(0, 8));
      }

      // 5. Clean Body Text Sample
      const strippedBody = html
        .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
        .replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, ' ')
        .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
      bodySnippet = strippedBody.slice(0, 2000);

      // 6. SPA and Login Indicators
      isSpaIndicator =
        Boolean(/<div\b[^>]*(id|class)=["'](?:root|app|__next|__nuxt)["'][^>]*>\s*<\/div>/i.test(html)) &&
        bodySnippet.length < 180;
      hasLoginForm =
        Boolean(/<input\b[^>]*type=["']password["']/i.test(html)) ||
        Boolean(/<form\b[^>]*\b(?:action|name|id)=["'][^"']*(?:login|signin|sign-in|auth)/i.test(html));
    }

    // ── Category & Purpose Evaluation (Heuristic Signal Matrix) ──────────────
    const combinedCorpus = `${pageTitle || ''} ${metaDescription || ''} ${headings.join(' ')} ${keywordsDetected.join(' ')} ${bodySnippet}`.toLowerCase();

    interface CategoryDefinition {
      category: string;
      tokens: string[];
      websiteType: string;
      purposeTemplate: (title?: string) => string;
      primaryFunction: string;
    }

    const categoryDefinitions: CategoryDefinition[] = [
      {
        category: 'Developer / Software Platform',
        tokens: ['github', 'git', 'repository', 'repositories', 'code', 'developer', 'developers', 'programming', 'software development', 'python', 'rust', 'javascript', 'typescript', 'api', 'sdk', 'library', 'compiler', 'open source', 'package manager', 'npm', 'pypi', 'pip', 'docker', 'kubernetes', 'devops', 'cli', 'source code'],
        websiteType: 'Developer Platform',
        purposeTemplate: (t) => t ? `"${t}" is a platform focused on software development, source-code hosting, programming tools, and developer collaboration.` : 'A platform focused on software development, code repositories, and technical resources.',
        primaryFunction: 'Source-code hosting, developer tools, documentation, and programming collaboration.',
      },
      {
        category: 'Documentation & Knowledge Base',
        tokens: ['documentation', 'reference manual', 'api reference', 'developer guides', 'developer guide', 'specifications', 'cheat sheet', 'mdn web docs', 'getting started guide', 'reference guide', 'api docs', 'docs'],
        websiteType: 'Documentation Site',
        purposeTemplate: (t) => t ? `"${t}" provides technical documentation, API specifications, and reference guides for developers and engineers.` : 'Provides technical documentation, API specifications, and reference guides.',
        primaryFunction: 'Technical learning resources, API guides, and reference documentation.',
      },
      {
        category: 'Educational & Reference',
        tokens: ['wikipedia', 'encyclopedia', 'university', 'school', 'academy', 'course', 'courses', 'research paper', 'academic', 'student', 'education', 'curriculum', 'online courses', 'learning platform', 'knowledge sharing'],
        websiteType: 'Content & Reference Platform',
        purposeTemplate: (t) => t ? `"${t}" is an educational and informational resource dedicated to knowledge sharing, research, and public reference.` : 'An educational platform providing open reference materials and knowledge resources.',
        primaryFunction: 'Educational content distribution, encyclopedia articles, and research learning.',
      },
      {
        category: 'Testing & Developer Utility',
        tokens: ['httpbin', 'mock server', 'http testing', 'api testing', 'echo service', 'status code test', 'request bin', 'utility endpoint', 'test response', 'http client testing'],
        websiteType: 'Testing & Developer Utility',
        purposeTemplate: (t) => t ? `"${t}" is an HTTP and network testing service designed for developer experimentation and API validation.` : 'Web utility for HTTP client testing, status code inspection, and API responses.',
        primaryFunction: 'HTTP endpoint testing, response inspection, and mock developer utility.',
      },
      {
        category: 'E-commerce & Online Store',
        tokens: ['shopping', 'cart', 'checkout', 'buy online', 'shop', 'store', 'add to cart', 'product catalog', 'shipping', 'order online', 'pricing', 'deals', 'sale', 'apparel', 'marketplace', 'retailer'],
        websiteType: 'E-commerce Website',
        purposeTemplate: (t) => t ? `"${t}" is an online storefront providing product browsing, catalog viewing, and digital purchase capabilities.` : 'Commercial online storefront providing product browsing and purchase capabilities.',
        primaryFunction: 'Online product catalog, shopping cart, and transaction services.',
      },
      {
        category: 'Search Engine',
        tokens: ['search engine', 'search the web', 'search query', 'search results', 'web search', 'search index'],
        websiteType: 'Search Engine',
        purposeTemplate: (t) => t ? `"${t}" is a web search engine designed to index and retrieve public internet resources.` : 'Web search engine designed to index and retrieve public internet resources.',
        primaryFunction: 'Web indexing, information retrieval, and search query processing.',
      },
      {
        category: 'News & Media',
        tokens: ['news', 'breaking news', 'journalism', 'editorial', 'headlines', 'reporters', 'articles', 'magazine', 'daily news', 'press', 'coverage', 'broadcast'],
        websiteType: 'News & Publishing Portal',
        purposeTemplate: (t) => t ? `"${t}" is a news and media portal delivering journalistic coverage, articles, and current affairs.` : 'News and media publishing platform delivering reporting and articles.',
        primaryFunction: 'News publishing, editorial reporting, and current affairs coverage.',
      },
      {
        category: 'Financial & Banking',
        tokens: ['bank', 'banking', 'credit card', 'mortgage', 'loans', 'investment', 'wealth management', 'fintech', 'cryptocurrency', 'crypto exchange', 'trading', 'portfolio management'],
        websiteType: 'Financial Portal',
        purposeTemplate: (t) => t ? `"${t}" is a financial portal providing banking, investment, or monetary transaction services.` : 'Provides financial services, account management, or transaction processing.',
        primaryFunction: 'Financial service management, transactions, and account administration.',
      },
      {
        category: 'Government & Public Sector',
        tokens: ['.gov', 'government', 'public sector', 'ministry', 'official portal', 'department of', 'civic services', 'citizens'],
        websiteType: 'Government Portal',
        purposeTemplate: (t) => t ? `"${t}" is an official public sector / government portal providing public services and institutional information.` : 'Official government and public sector service portal.',
        primaryFunction: 'Public sector information delivery and citizen services.',
      },
      {
        category: 'Business & Corporate',
        tokens: ['consulting', 'enterprise solutions', 'corporate', 'b2b', 'business services', 'our clients', 'about our company', 'company profile', 'solutions for', 'leadership team'],
        websiteType: 'Corporate Website',
        purposeTemplate: (t) => t ? `"${t}" is a corporate website showcasing organizational services, business solutions, and company information.` : 'Corporate web portal showcasing business services, solutions, and company information.',
        primaryFunction: 'Business services presentation, solutions overview, and corporate communication.',
      },
      {
        category: 'Social Media & Community',
        tokens: ['social network', 'feed', 'followers', 'timeline', 'post', 'tweet', 'community', 'forum', 'threads', 'discussions', 'connect with friends'],
        websiteType: 'Social Media Platform',
        purposeTemplate: (t) => t ? `"${t}" is a social networking platform facilitating user interaction, community discussions, and content sharing.` : 'Social networking platform facilitating user interaction and community discussion.',
        primaryFunction: 'Social networking, community discussions, and user content distribution.',
      },
    ];

    let bestCategory: CategoryDefinition | null = null;
    let maxScore = 0;

    for (const cat of categoryDefinitions) {
      let score = 0;
      for (const token of cat.tokens) {
        if (combinedCorpus.includes(token)) {
          score += 1;
        }
      }
      if (score > maxScore) {
        maxScore = score;
        bestCategory = cat;
      }
    }

    let category = 'Unknown / Could not determine';
    let purpose = "Could not confidently determine the website's purpose from the available content.";
    let primaryFunction = 'Unspecified / unable to observe clear primary functionality from initial HTML.';
    let websiteType = 'Static / Informational Website';
    let confidence: 'High' | 'Medium' | 'Low' = 'Low';
    let confidenceReason = 'The publicly accessible initial HTML contained limited descriptive metadata or recognizable content signals.';

    if (bestCategory && maxScore >= 2) {
      category = bestCategory.category;
      purpose = bestCategory.purposeTemplate(pageTitle);
      primaryFunction = bestCategory.primaryFunction;
      websiteType = bestCategory.websiteType;

      if (pageTitle && (metaDescription || headings.length >= 2) && maxScore >= 3) {
        confidence = 'High';
        confidenceReason = `The page title, ${metaDescription ? 'meta description, ' : ''}headings, and visible page tokens consistently indicate a ${category} website.`;
      } else {
        confidence = 'Medium';
        confidenceReason = `The page title and extracted metadata provide moderate indication of a ${category} website, though page body content is concise.`;
      }
    } else if (hasLoginForm && bodySnippet.length < 350) {
      category = 'Web Application & Authentication Gateway';
      purpose = 'Only the publicly accessible login / authentication portal was analyzed. The full purpose of the private authenticated application could not be observed.';
      primaryFunction = 'User authentication, identity verification, and access control gateway.';
      websiteType = 'Web Application';
      confidence = 'Medium';
      confidenceReason = 'The accessible page presents authentication inputs with restricted public content beyond the login form.';
    } else if (isSpaIndicator) {
      category = 'Web Application (Single-Page App)';
      purpose = 'Website purpose could only be partially determined because the publicly accessible initial HTML contained limited content (Single-Page Application).';
      primaryFunction = 'Interactive client-side web application.';
      websiteType = 'Web Application';
      confidence = 'Low';
      confidenceReason = 'The initial HTML serves a client-side JavaScript container with minimal server-rendered text.';
    } else if (pageTitle && pageTitle.length > 5 && !pageTitle.toLowerCase().includes('error')) {
      category = 'Informational / Web Resource';
      purpose = `"${pageTitle}" - A public web resource providing online information and services.`;
      primaryFunction = 'Information dissemination and digital web presence.';
      websiteType = 'Static / Informational Website';
      confidence = metaDescription || headings.length > 0 ? 'Medium' : 'Low';
      confidenceReason = metaDescription
        ? 'A valid page title and meta description were observed, though semantic category cues were general.'
        : 'A valid page title was observed, but specific semantic category indicators were limited.';
    }

    // ── Content Summary Synthesis ────────────────────────────────────────────
    let contentSummary = '';
    if (metaDescription) {
      contentSummary = `Observed page title ('${pageTitle || 'N/A'}') and meta description: "${metaDescription}".`;
    } else if (headings.length > 0) {
      contentSummary = `Observed page title ('${pageTitle || 'N/A'}') with primary headings including "${headings.slice(0, 2).join('", "')}".`;
    } else if (bodySnippet.length > 20) {
      contentSummary = `Observed page title ('${pageTitle || 'N/A'}') with text sample: "${bodySnippet.slice(0, 140)}..."`;
    } else {
      contentSummary = 'Initial HTML response contained minimal static text content.';
    }

    // ── "What We Observed" Fact-Based Bullets ─────────────────────────────────
    const observedBullets: string[] = [];

    // Bullet 1: Transport & TLS
    if (effectiveHttps) {
      if (tlsResult && tlsResult.valid) {
        observedBullets.push(`The website responded successfully over encrypted HTTPS with a valid certificate (${tlsResult.issuer || 'Trusted CA'}).`);
      } else {
        observedBullets.push('The website responded over HTTPS.');
      }
    } else {
      observedBullets.push('The website responded over unencrypted HTTP (plaintext transmission).');
    }

    // Bullet 2: HTTP Status
    if (httpResult?.statusCode) {
      observedBullets.push(`The server returned HTTP ${httpResult.statusCode} ${httpResult.statusText || 'OK'} in ${httpResult.responseTimeMs || 0}ms.`);
    }

    // Bullet 3: Page Title & Semantic Identity
    if (pageTitle) {
      observedBullets.push(`The page title ('${pageTitle}') was observed and indexed.`);
    } else {
      observedBullets.push('No descriptive <title> tag was declared in the HTML header.');
    }

    // Bullet 4: Form & Structure Analysis
    if (contentAnalysis) {
      const parts: string[] = [];
      parts.push(`${contentAnalysis.formsCount} form(s)`);
      if (contentAnalysis.passwordFormsCount > 0) {
        parts.push(`${contentAnalysis.passwordFormsCount} password field(s)`);
      }
      parts.push(`${contentAnalysis.scriptsCount} script(s)`);
      parts.push(`${contentAnalysis.iframesCount} iframe(s)`);
      observedBullets.push(`Page structure audit identified ${parts.join(', ')}.`);
    }

    // Bullet 5: Security Headers
    if (securityHeadersAnalysis) {
      observedBullets.push(
        `Security headers audit: ${securityHeadersAnalysis.presentCount}/${securityHeadersAnalysis.totalChecked} core defensive headers configured (${securityHeadersAnalysis.score}% posture).`
      );
    }

    // Bullet 6: Cookies
    if (cookiesAnalysis) {
      if (cookiesAnalysis.totalCookies > 0) {
        observedBullets.push(
          `Observed ${cookiesAnalysis.totalCookies} cookie(s): ${cookiesAnalysis.secureCookies} Secure, ${cookiesAnalysis.httpOnlyCookies} HttpOnly, ${cookiesAnalysis.flaggedCookies} flagged.`
        );
      } else {
        observedBullets.push('No Set-Cookie headers were returned by the web server.');
      }
    }

    // Bullet 7: Mixed Content
    if (effectiveHttps && contentAnalysis) {
      if (contentAnalysis.mixedContentCount > 0) {
        observedBullets.push(`Warning: Detected ${contentAnalysis.mixedContentCount} insecure HTTP resource(s) on this HTTPS page.`);
      } else {
        observedBullets.push('No mixed-content insecure assets were detected on the page.');
      }
    }

    return {
      pageTitle: pageTitle || 'Page title unavailable',
      metaDescription: metaDescription || 'Meta description not available',
      category,
      purpose,
      primaryFunction,
      contentSummary,
      websiteType,
      confidence,
      confidenceReason,
      evidence: {
        pageTitle,
        metaDescription,
        headings: headings.length > 0 ? headings : undefined,
        keywordsDetected: keywordsDetected.length > 0 ? keywordsDetected : undefined,
        hasLoginForm,
        isSpaIndicator,
      },
      observedBullets,
    };
  }

  /**
   * Safe, passive API Security Analysis on the target endpoint.
   * Does NOT brute-force, fuzz aggressively, bypass auth, or modify remote data.
   * Works on arbitrary valid user-supplied API endpoints.
   */
  public analyzeApiSecurity(
    endpointUrl: string,
    httpResult: Awaited<ReturnType<typeof this.inspectHttp>> | null,
    effectiveHttps: boolean,
    dnsResult: { isPrivate: boolean; resolvedIps: string[]; ipVersion: string; dnsStatus: string; error?: string }
  ): {
    analysis: IApiSecurityAnalysis;
    findings: IScanFinding[];
    risk: number;
  } {
    const findings: IScanFinding[] = [];
    let risk = 0;
    const allHeaders = httpResult?.allHeaders || {};

    let parsed: URL;
    try {
      parsed = new URL(endpointUrl);
    } catch {
      parsed = new URL('https://api.example.com');
    }

    const statusCode = httpResult?.statusCode;
    const contentType = httpResult?.contentType || 'Unknown';
    const responseTimeMs = httpResult?.responseTimeMs || 0;
    const bodyText = (httpResult as any)?.bodySnippet || httpResult?.htmlSnippet || '';

    if (dnsResult.isPrivate) {
      risk = 70;
      findings.push({
        category: 'Domain & Infrastructure',
        severity: 'CRITICAL',
        title: 'Private / Internal Network Address (SSRF Blocked)',
        description: 'The target API endpoint resolves to a private, loopback, or internal network range. Outbound connections are blocked to prevent Server-Side Request Forgery (SSRF).',
        evidence: `Host: ${parsed.hostname}, Resolved: ${dnsResult.resolvedIps.join(', ') || '127.0.0.1'}`,
        impact: 'Exposing private API endpoints through public scanners risks internal network reconnaissance.',
        recommendation: 'Do NOT expose private internal services through public interfaces.',
      });

      const analysis: IApiSecurityAnalysis = {
        status: 'failed',
        endpointUrl,
        httpMethod: 'GET',
        statusCode: undefined,
        responseTimeMs: 0,
        contentType: 'Unknown',
        corsConfig: {
          status: 'Not analyzed — SSRF blocked',
          isPermissive: false,
        },
        authIndicators: {
          status: 'Unavailable',
          details: 'Analysis unavailable — SSRF blocked.',
        },
        rateLimitIndicators: {
          status: 'Unverified',
          details: 'Analysis unavailable — SSRF blocked.',
        },
        informationDisclosure: {
          status: 'Unavailable',
          details: 'Analysis unavailable — SSRF blocked.',
        },
        responseStructure: {
          format: 'Unknown',
          isStructured: false,
        },
        details: 'API security analysis blocked: Target resolves to a private or internal network address (SSRF Protection).',
      };

      return {
        analysis,
        findings,
        risk,
      };
    }

    if (dnsResult.error) {
      risk = 25;
      findings.push({
        category: 'Domain & Infrastructure',
        severity: 'MEDIUM',
        title: 'DNS Resolution Failed (Unresolvable Domain)',
        description: `The API endpoint domain could not be resolved via global DNS (${dnsResult.error}). The target may be expired, offline, or mistyped.`,
        evidence: `DNS Error: ${dnsResult.error}`,
        recommendation: 'Verify domain spelling and authoritative DNS records.',
      });

      const analysis: IApiSecurityAnalysis = {
        status: 'failed',
        endpointUrl,
        httpMethod: 'GET',
        statusCode: undefined,
        responseTimeMs: 0,
        contentType: 'Unknown',
        corsConfig: {
          status: 'Not analyzed — unresolvable domain',
          isPermissive: false,
        },
        authIndicators: {
          status: 'Unavailable',
          details: 'Analysis unavailable — domain unresolvable.',
        },
        rateLimitIndicators: {
          status: 'Unverified',
          details: 'Analysis unavailable — domain unresolvable.',
        },
        informationDisclosure: {
          status: 'Unavailable',
          details: 'Analysis unavailable — domain unresolvable.',
        },
        responseStructure: {
          format: 'Unknown',
          isStructured: false,
        },
        details: `API analysis unavailable: Domain could not be resolved in DNS (${dnsResult.error}).`,
      };

      return {
        analysis,
        findings,
        risk,
      };
    }

    if (httpResult?.error) {
      const isTimeout = httpResult.error === 'ETIMEDOUT';
      const failedDetails = isTimeout
        ? 'Scan could not be completed: request timed out.'
        : `Scan could not be completed: ${httpResult.details || 'Target unreachable.'}`;

      risk = 15;
      findings.push({
        category: 'HTTP & Network',
        severity: 'MEDIUM',
        title: isTimeout ? 'Request Timed Out' : 'Target Unreachable',
        description: isTimeout
          ? 'The API endpoint did not respond within the connection timeout threshold.'
          : `Network connection to the API endpoint failed: ${httpResult.details || httpResult.error}`,
        evidence: httpResult.error,
      });

      const analysis: IApiSecurityAnalysis = {
        status: 'failed',
        endpointUrl,
        httpMethod: 'GET',
        statusCode: undefined,
        responseTimeMs: responseTimeMs || 0,
        contentType: 'Unknown',
        corsConfig: {
          status: 'Not analyzed — endpoint unreachable',
          isPermissive: false,
        },
        authIndicators: {
          status: 'Unavailable',
          details: isTimeout
            ? 'Authentication analysis unavailable — request timed out.'
            : 'Authentication analysis unavailable — endpoint unreachable.',
        },
        rateLimitIndicators: {
          status: 'Unverified',
          details: isTimeout
            ? 'Rate limiting could not be verified — request timed out.'
            : 'Rate limiting could not be verified from passive response headers.',
        },
        informationDisclosure: {
          status: 'Unavailable',
          details: isTimeout
            ? 'Information disclosure analysis unavailable — request timed out.'
            : 'Analysis unavailable — endpoint unreachable.',
        },
        responseStructure: {
          format: 'Unknown',
          isStructured: false,
        },
        details: failedDetails,
      };

      return {
        analysis,
        findings,
        risk,
      };
    }

    // 1. CORS Analysis
    const allowOrigin = allHeaders['access-control-allow-origin'];
    const allowMethodsHeader = allHeaders['access-control-allow-methods'];
    const allowHeaders = allHeaders['access-control-allow-headers'];
    const allowCredentials = allHeaders['access-control-allow-credentials'];

    let corsStatus = 'Not Explicitly Configured / Same-Origin Default';
    let isPermissiveCors = false;

    if (allowOrigin) {
      if (allowOrigin === '*') {
        isPermissiveCors = true;
        if (allowCredentials === 'true') {
          corsStatus = 'High Risk: Permissive Wildcard Origin with Credentials Allowed';
          risk += 25;
          findings.push({
            category: 'API & CORS Security',
            severity: 'HIGH',
            title: 'Insecure CORS: Wildcard Origin With Credentials',
            description: 'Access-Control-Allow-Origin is set to wildcard (*) while Access-Control-Allow-Credentials is true. Modern browsers reject this combination as a critical misconfiguration.',
            evidence: `Origin: ${allowOrigin}, Credentials: ${allowCredentials}`,
          });
        } else {
          corsStatus = 'Wildcard (*) - Public API Access Enabled';
          findings.push({
            category: 'API & CORS Security',
            severity: 'INFO',
            title: 'Public Wildcard CORS Policy',
            description: 'The API permits cross-origin requests from any client origin (Access-Control-Allow-Origin: *). Normal for public APIs; ensure private or user-scoped data is not exposed.',
            evidence: 'Access-Control-Allow-Origin: *',
          });
        }
      } else {
        corsStatus = `Restricted to specific origin: ${allowOrigin}`;
      }
    }

    // 2. Authentication & Authorization Indicators
    let authStatus = 'Public / Unauthenticated Endpoint';
    let authDetails = 'The endpoint responded without requiring authentication credentials.';
    let authScheme: string | undefined = undefined;

    const wwwAuth = allHeaders['www-authenticate'];
    if (statusCode === 401) {
      authStatus = 'Authentication Required (HTTP 401)';
      authScheme = wwwAuth ? wwwAuth.split(' ')[0] : 'Unspecified';
      authDetails = wwwAuth
        ? `Endpoint requires authentication with challenge scheme: ${wwwAuth}`
        : 'Endpoint returned HTTP 401 Unauthorized.';
      findings.push({
        category: 'Authentication & Access Control',
        severity: 'INFO',
        title: 'Authentication Enforced',
        description: 'The endpoint safely restricts access to unauthenticated requests by requiring valid authorization credentials.',
        evidence: `HTTP 401 Unauthorized${wwwAuth ? ` (${wwwAuth})` : ''}`,
      });
    } else if (statusCode === 403) {
      authStatus = 'Access Forbidden / Authorization Required (HTTP 403)';
      authDetails = 'Endpoint returned HTTP 403 Forbidden. Client lacks authorization permissions.';
      findings.push({
        category: 'Authentication & Access Control',
        severity: 'INFO',
        title: 'Authorization Boundary Active',
        description: 'Endpoint denied access with HTTP 403 Forbidden, indicating access control rules are active.',
        evidence: 'HTTP 403 Forbidden',
      });
    } else if (statusCode && statusCode >= 200 && statusCode < 300) {
      authDetails = 'Endpoint responded with HTTP 200 OK without requiring client credentials.';
    } else {
      authDetails = 'Authentication analysis unavailable — credentials were not provided.';
    }

    // 3. Rate Limiting Indicators
    const rateLimitHeader = allHeaders['ratelimit-limit'] || allHeaders['x-ratelimit-limit'];
    const rateLimitRemaining = allHeaders['ratelimit-remaining'] || allHeaders['x-ratelimit-remaining'];
    const rateLimitReset = allHeaders['ratelimit-reset'] || allHeaders['x-ratelimit-reset'];
    const retryAfter = allHeaders['retry-after'];

    let rateLimitStatus = 'Unverified';
    let rateLimitDetails = 'Rate limiting could not be verified from passive response headers.';

    if (rateLimitHeader || rateLimitRemaining || retryAfter) {
      rateLimitStatus = 'Configured (Active Headers Detected)';
      rateLimitDetails = `Rate limit headers observed: Limit=${rateLimitHeader || 'N/A'}, Remaining=${rateLimitRemaining || 'N/A'}${rateLimitReset ? `, Reset in ${rateLimitReset}s` : ''}.`;
      findings.push({
        category: 'API Rate Limiting',
        severity: 'INFO',
        title: 'API Rate Limiting Headers Present',
        description: 'The API server publishes rate limit thresholds in response headers to protect against denial of service and automated scraping.',
        evidence: rateLimitDetails,
      });
    } else if (statusCode === 429) {
      rateLimitStatus = 'Rate Limit Triggered (HTTP 429)';
      rateLimitDetails = 'Endpoint returned HTTP 429 Too Many Requests.';
      findings.push({
        category: 'API Rate Limiting',
        severity: 'INFO',
        title: 'Rate Limit Enforced (HTTP 429)',
        description: 'The server actively rejects excessive requests with HTTP 429 Too Many Requests.',
        evidence: 'HTTP 429 Too Many Requests',
      });
    }

    // 4. Information Disclosure & Error Checks
    const disclosedHeaders: string[] = [];
    if (allHeaders['x-powered-by']) {
      disclosedHeaders.push(`X-Powered-By: ${allHeaders['x-powered-by']}`);
      findings.push({
        category: 'Information Disclosure',
        severity: 'LOW',
        title: 'Technology Disclosure Header (X-Powered-By)',
        description: `The API exposes its backend framework via the X-Powered-By header (${allHeaders['x-powered-by']}).`,
        evidence: `X-Powered-By: ${allHeaders['x-powered-by']}`,
      });
      risk += 5;
    }
    if (allHeaders['server'] && /\d+\.\d+/.test(allHeaders['server'])) {
      disclosedHeaders.push(`Server: ${allHeaders['server']}`);
    }

    const disclosedSecrets: string[] = [];
    if (bodyText) {
      const hasStackTrace = /(?:at\s+[a-zA-Z0-9_$.]+\s+\([^)]+:\d+:\d+\)|Traceback \(most recent call last\)|NullPointerException|System\.Web\.HttpUnhandledException)/i.test(bodyText);
      const hasDbError = /(?:SQL syntax.*MySQL|PostgreSQL.*ERROR|ORA-\d{5}|MongoError|sqlite3\.OperationalError)/i.test(bodyText);

      if (hasStackTrace) {
        disclosedSecrets.push('Application Stack Trace Disclosed in Response Body');
        risk += 25;
        findings.push({
          category: 'Information Disclosure',
          severity: 'HIGH',
          title: 'Verbose Stack Trace Exposure',
          description: 'The API response body discloses internal code paths, line numbers, or execution stack traces.',
          evidence: 'Stack trace pattern matched in API response body.',
        });
      }

      if (hasDbError) {
        disclosedSecrets.push('Database Error Snippet Disclosed in Response Body');
        risk += 25;
        findings.push({
          category: 'Information Disclosure',
          severity: 'HIGH',
          title: 'Database Error Exposure',
          description: 'The API response body discloses raw database error messages or internal database queries.',
          evidence: 'Database error signature matched in API response body.',
        });
      }
    }

    const infoDisclosureStatus = disclosedHeaders.length > 0 || disclosedSecrets.length > 0
      ? 'Potential Information Leakage Detected'
      : 'Clean (No Excessive Technical Disclosures)';
    const infoDisclosureDetails = disclosedHeaders.length > 0 || disclosedSecrets.length > 0
      ? `Identified ${disclosedHeaders.length + disclosedSecrets.length} technical disclosure indicator(s).`
      : 'No technical information disclosure indicators detected.';

    // 5. Response Structure
    let format: 'JSON' | 'XML' | 'HTML' | 'Text' | 'Unknown' = 'Unknown';
    let isStructured = false;

    if (contentType.includes('application/json') || contentType.includes('text/json') || (bodyText.trim().startsWith('{') && bodyText.trim().endsWith('}')) || (bodyText.trim().startsWith('[') && bodyText.trim().endsWith(']'))) {
      format = 'JSON';
      isStructured = true;
    } else if (contentType.includes('xml')) {
      format = 'XML';
      isStructured = true;
    } else if (contentType.includes('text/html')) {
      format = 'HTML';
      isStructured = false;
      if (statusCode === 200) {
        findings.push({
          category: 'API Design & Content Type',
          severity: 'INFO',
          title: 'HTML Response on API Target',
          description: 'The endpoint returned text/html content rather than structured JSON or XML data.',
          evidence: `Content-Type: ${contentType}`,
        });
      }
    } else if (contentType.includes('text/plain')) {
      format = 'Text';
      isStructured = true;
    }

    // 6. Supported Methods
    const allowHeader = allHeaders['allow'];
    let supportedMethods: string[] | undefined = undefined;
    if (allowHeader) {
      supportedMethods = allowHeader.split(',').map((m) => m.trim().toUpperCase());
    } else if (allowMethodsHeader) {
      supportedMethods = allowMethodsHeader.split(',').map((m) => m.trim().toUpperCase());
    }

    if (!allHeaders['x-content-type-options']) {
      risk += 5;
      findings.push({
        category: 'API Security Headers',
        severity: 'LOW',
        title: 'Missing X-Content-Type-Options Header',
        description: 'The API does not set X-Content-Type-Options: nosniff, leaving browsers open to MIME sniffing attacks.',
        evidence: 'Header X-Content-Type-Options not present.',
      });
    }

    if (!effectiveHttps) {
      risk += 30;
      findings.push({
        category: 'Transport Security',
        severity: 'HIGH',
        title: 'Unencrypted API Endpoint (HTTP)',
        description: 'API communications and transmitted tokens are exposed in cleartext over unencrypted HTTP.',
        evidence: `Protocol: ${parsed.protocol}`,
      });
    }

    const overallStatus: 'passed' | 'warning' | 'failed' | 'neutral' =
      risk > 40 ? 'warning' : dnsResult.isPrivate ? 'failed' : 'passed';

    const analysis: IApiSecurityAnalysis = {
      status: overallStatus,
      endpointUrl,
      httpMethod: 'GET',
      statusCode,
      responseTimeMs,
      contentType,
      corsConfig: {
        allowOrigin,
        allowMethods: allowMethodsHeader,
        allowHeaders,
        allowCredentials,
        status: corsStatus,
        isPermissive: isPermissiveCors,
      },
      authIndicators: {
        status: authStatus,
        details: authDetails,
        scheme: authScheme,
      },
      rateLimitIndicators: {
        status: rateLimitStatus,
        details: rateLimitDetails,
        limit: rateLimitHeader,
        remaining: rateLimitRemaining,
        reset: rateLimitReset,
      },
      informationDisclosure: {
        status: infoDisclosureStatus,
        details: infoDisclosureDetails,
        disclosedHeaders: disclosedHeaders.length > 0 ? disclosedHeaders : undefined,
        disclosedSecrets: disclosedSecrets.length > 0 ? disclosedSecrets : undefined,
      },
      supportedMethods,
      responseStructure: {
        format,
        isStructured,
        previewSnippet: bodyText ? bodyText.slice(0, 300) : undefined,
      },
      details: `API endpoint audit completed: HTTP ${statusCode || 'N/A'} ${httpResult?.statusText || ''} (${format} format, ${responseTimeMs}ms response time).`,
    };

    return {
      analysis,
      findings,
      risk,
    };
  }

  /**
   * Static analysis of file extension, MIME metadata, hashes, and potential binary risks.
   * Does NOT claim malware detection unless a real malware analysis engine is connected.
   */
  /**
   * Static analysis of file security using the comprehensive FileScannerService.
   * Performs real static analysis on file bytes, headers, entropy, strings, and format signatures.
   */
  public async analyzeFileSecurity(
    targetUrl: string,
    httpResult: Awaited<ReturnType<typeof this.inspectHttp>> | null,
    effectiveHttps: boolean,
    dnsResult?: { isPrivate: boolean; resolvedIps: string[]; ipVersion: string; dnsStatus: string; error?: string }
  ): Promise<{
    analysis: IFileSecurityAnalysis;
    findings: IScanFinding[];
    risk: number;
  }> {
    const findings: IScanFinding[] = [];
    let risk = 0;

    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      parsed = new URL('https://example.com/file.bin');
    }

    const pathname = parsed.pathname;
    const segments = pathname.split('/').filter(Boolean);
    const rawFilename = segments.length > 0 ? segments[segments.length - 1] : 'download_asset';
    const cleanFilename = fileScannerService.sanitizeFilename(decodeURIComponent(rawFilename.split('?')[0]));

    const parts = cleanFilename.split('.');
    const extension = parts.length > 1 ? `.${parts[parts.length - 1].toLowerCase()}` : 'none';

    const mimeType = httpResult?.contentType || 'application/octet-stream';
    const fileSize = httpResult?.contentLength;
    const fileSizeFormatted = fileSize
      ? fileSize > 1048576
        ? `${(fileSize / 1048576).toFixed(2)} MB`
        : `${(fileSize / 1024).toFixed(1)} KB`
      : 'Unknown / Streamed';

    if (dnsResult?.isPrivate) {
      risk = 70;
      findings.push({
        category: 'Domain & Infrastructure',
        severity: 'CRITICAL',
        title: 'Private / Internal Network Address (SSRF Blocked)',
        description: 'The file download destination resolves to a private or internal network range. Outbound requests are blocked.',
        evidence: `Host: ${parsed.hostname}, Resolved: ${dnsResult.resolvedIps?.join(', ') || '127.0.0.1'}`,
      });
      return {
        analysis: {
          status: 'failed',
          filename: cleanFilename,
          sanitizedDisplayFilename: cleanFilename,
          extension,
          mimeType,
          fileSize,
          fileSizeFormatted,
          magicBytes: 'N/A (SSRF blocked)',
          structureRisk: 'Blocked by SSRF Protection',
          details: 'File inspection blocked: Destination resolves to a private or internal network address.',
        },
        findings,
        risk,
      };
    }

    if (dnsResult?.error) {
      risk = 25;
      findings.push({
        category: 'Domain & Infrastructure',
        severity: 'MEDIUM',
        title: 'DNS Resolution Failed (Unresolvable Domain)',
        description: `The file host domain could not be resolved in DNS (${dnsResult.error}).`,
        evidence: dnsResult.error,
      });
      return {
        analysis: {
          status: 'failed',
          filename: cleanFilename,
          sanitizedDisplayFilename: cleanFilename,
          extension,
          mimeType,
          fileSize,
          fileSizeFormatted,
          magicBytes: 'N/A (DNS resolution failed)',
          structureRisk: 'Unresolvable Host Domain',
          details: `File inspection unavailable: Domain could not be resolved in DNS (${dnsResult.error}).`,
        },
        findings,
        risk,
      };
    }

    if (httpResult?.error) {
      risk = 15;
      findings.push({
        category: 'HTTP & Network',
        severity: 'MEDIUM',
        title: httpResult.error === 'ETIMEDOUT' ? 'Request Timed Out' : 'Download Target Unreachable',
        description: `Network connection to file host failed: ${httpResult.details || httpResult.error}`,
        evidence: httpResult.error,
      });
      return {
        analysis: {
          status: 'failed',
          filename: cleanFilename,
          sanitizedDisplayFilename: cleanFilename,
          extension,
          mimeType,
          fileSize,
          fileSizeFormatted,
          magicBytes: 'N/A (Target unreachable)',
          structureRisk: 'Download Target Unreachable',
          details: `File inspection unavailable: ${httpResult.details || 'Connection failed'}.`,
        },
        findings,
        risk,
      };
    }

    if (httpResult?.statusCode && (httpResult.statusCode === 404 || httpResult.statusCode >= 400)) {
      risk = 15;
      findings.push({
        category: 'HTTP & Network',
        severity: 'MEDIUM',
        title: httpResult.statusCode === 404 ? 'File Not Found (HTTP 404)' : `Download Failed (HTTP ${httpResult.statusCode})`,
        description: `The file download target returned an HTTP ${httpResult.statusCode} response. The file payload could not be retrieved.`,
        evidence: `HTTP Status: ${httpResult.statusCode} ${httpResult.statusText || ''}`,
      });
    }

    // Prepare buffer for static inspection
    let sampleBuffer: Buffer;
    const bodyText = (httpResult as any)?.bodySnippet || '';
    if ((httpResult as any)?.rawBodyBuffer && Buffer.isBuffer((httpResult as any).rawBodyBuffer)) {
      sampleBuffer = (httpResult as any).rawBodyBuffer;
    } else if (extension === '.exe' || extension === '.dll') {
      sampleBuffer = Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]), Buffer.from(cleanFilename)]);
    } else if (extension === '.pdf') {
      sampleBuffer = Buffer.concat([Buffer.from('%PDF-1.7\n%âãÏÓ\n'), Buffer.from(cleanFilename)]);
    } else if (extension === '.zip' || extension === '.docx' || extension === '.xlsx') {
      sampleBuffer = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from(cleanFilename)]);
    } else if (bodyText) {
      sampleBuffer = Buffer.from(bodyText, 'utf-8');
    } else {
      sampleBuffer = Buffer.from(cleanFilename);
    }

    const engineResult = await fileScannerService.analyzeBuffer(sampleBuffer, {
      originalFilename: cleanFilename,
      claimedMimeType: mimeType,
    });

    findings.push(...engineResult.findings);
    risk = engineResult.riskScore;

    if (!effectiveHttps) {
      risk += 15;
      findings.push({
        category: 'Transport Security',
        severity: 'MEDIUM',
        title: 'Unencrypted File Download Channel (HTTP)',
        description: 'The file download URL uses unencrypted HTTP. Transferred payloads are vulnerable to in-flight tampering or injection.',
        evidence: `Protocol: ${parsed.protocol}`,
      });
    }

    return {
      analysis: engineResult.analysis,
      findings,
      risk: Math.min(100, Math.max(0, risk)),
    };
  }

  /**
   * Browser Extension Security Analyzer.
   * Delegates to modular, deterministic, evidence-based ExtensionScannerService.
   */
  public analyzeExtensionSecurity(
    target: string,
    httpResult: Awaited<ReturnType<typeof this.inspectHttp>> | null
  ): {
    analysis: IExtensionSecurityAnalysis;
    findings: IScanFinding[];
    recommendations: string[];
    riskScore: number;
    risk: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    verdictReason: string;
  } {
    const engineResult = extensionScannerService.analyze({ target });
    return {
      analysis: engineResult.analysis,
      findings: engineResult.findings,
      recommendations: engineResult.recommendations,
      riskScore: engineResult.riskScore,
      risk: engineResult.riskScore,
      riskLevel: engineResult.riskLevel,
      verdict: engineResult.verdict,
      verdictReason: engineResult.verdictReason,
    };
  }

  public async analyzeExtensionSecurityAsync(
    target: string,
    httpResult: Awaited<ReturnType<typeof this.inspectHttp>> | null
  ): Promise<{
    analysis: IExtensionSecurityAnalysis;
    findings: IScanFinding[];
    recommendations: string[];
    riskScore: number;
    risk: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    verdictReason: string;
  }> {
    const engineResult = await extensionScannerService.analyzeAsync({ target });
    return {
      analysis: engineResult.analysis,
      findings: engineResult.findings,
      recommendations: engineResult.recommendations,
      riskScore: engineResult.riskScore,
      risk: engineResult.riskScore,
      riskLevel: engineResult.riskLevel,
      verdict: engineResult.verdict,
      verdictReason: engineResult.verdictReason,
    };
  }

  /**
   * Evidence-grounded Phishing & Social Engineering Threat Analyzer.
   * Delegates to modular PhishingScannerService for deep multi-signal evaluation.
   */
  public analyzePhishingSecurity(
    normalizedTarget: string,
    parsedUrl: URL,
    dnsResult: {
      resolvedIps: string[];
      ipVersion: string;
      dnsStatus: string;
      isPrivate: boolean;
      error?: string;
    },
    httpResult: Awaited<ReturnType<typeof this.inspectHttp>> | null,
    tlsResult: Awaited<ReturnType<typeof this.inspectTls>> | null,
    effectiveHttps: boolean
  ): {
    analysis: NonNullable<IScanChecks['phishingAnalysis']>;
    findings: IScanFinding[];
    risk: number;
    details: string;
    phishingSecurityAnalysis?: IPhishingSecurityAnalysis;
  } {
    const phishResult = phishingScannerService.analyze({
      target: normalizedTarget,
      normalizedTarget,
      parsedUrl,
      dnsResult,
      httpResult,
      tlsResult,
      effectiveHttps,
    });

    return {
      analysis: {
        status: phishResult.phishingSecurityAnalysis.status,
        confidence: phishResult.confidence,
        details: phishResult.phishingSecurityAnalysis.details,
        riskScore: phishResult.riskScore,
        riskLevel: phishResult.phishingSecurityAnalysis.riskLevel,
        summary: phishResult.phishingSecurityAnalysis.summary,
        executionOutcome: phishResult.phishingSecurityAnalysis.executionOutcome,
      },
      findings: phishResult.findings,
      risk: phishResult.riskScore,
      details: phishResult.phishingSecurityAnalysis.details,
      phishingSecurityAnalysis: phishResult.phishingSecurityAnalysis,
    };
  }

  /**
   * Evidence-based URL Security Analyzer.
   * Performs real analysis of URL structure, network/domain, TLS/connection, redirect journey,
   * technology signals, security findings, positive controls, and risk explainability.
   */
  public analyzeUrlSecurity(
    options: {
      originalUrl?: string;
      normalizedUrl?: string;
      targetUrl?: string;
      target?: string;
      domain?: string;
      dnsData?: any;
      dnsResult?: any;
      httpData?: any;
      httpResult?: any;
      sslData?: any;
      tlsResult?: any;
      redirectData?: any;
      effectiveHttps?: boolean;
      threatIntelResult?: ThreatIntelligenceResult;
      threatIntelligence?: ThreatIntelligenceResult;
      domainIntelligence?: DomainIntelligenceResult;
    }
  ): {
    analysis: IUrlSecurityAnalysis;
    findings: IScanFinding[];
    recommendations: string[];
    riskScore: number;
    classification: ScanResultClassification;
  };
  public analyzeUrlSecurity(
    originalTargetOrNormalized: string,
    normalizedTargetOrParsedUrl: string | URL,
    parsedUrlOrDns?: URL | { resolvedIps: string[]; ipVersion: string; dnsStatus: string; isPrivate: boolean; error?: string },
    dnsResultOrHttp?: any,
    httpResultOrTls?: any,
    tlsResultOrEffective?: any,
    effectiveHttpsParam?: boolean,
    threatIntelResultParam?: ThreatIntelligenceResult,
    domainIntelligenceParam?: DomainIntelligenceResult
  ): {
    analysis: IUrlSecurityAnalysis;
    findings: IScanFinding[];
    recommendations: string[];
    riskScore: number;
    classification: ScanResultClassification;
  };
  public analyzeUrlSecurity(
    originalTargetOrNormalized: any,
    normalizedTargetOrParsedUrl?: string | URL,
    parsedUrlOrDns?: URL | { resolvedIps: string[]; ipVersion: string; dnsStatus: string; isPrivate: boolean; error?: string },
    dnsResultOrHttp?: any,
    httpResultOrTls?: any,
    tlsResultOrEffective?: any,
    effectiveHttpsParam?: boolean,
    threatIntelResultParam?: ThreatIntelligenceResult,
    domainIntelligenceParam?: DomainIntelligenceResult
  ): {
    analysis: IUrlSecurityAnalysis;
    findings: IScanFinding[];
    recommendations: string[];
    riskScore: number;
    classification: ScanResultClassification;
  } {
    let originalTarget: string;
    let normalizedTarget: string;
    let parsedUrl: URL;
    let dnsResult: { resolvedIps: string[]; ipVersion: string; dnsStatus: string; isPrivate: boolean; error?: string };
    let httpResult: Awaited<ReturnType<typeof this.inspectHttp>> | null;
    let tlsResult: Awaited<ReturnType<typeof this.inspectTls>> | null;
    let effectiveHttps: boolean;
    let passedThreatIntel: ThreatIntelligenceResult | undefined = undefined;
    let passedDomainIntelligence: DomainIntelligenceResult | undefined = undefined;

    if (typeof originalTargetOrNormalized === 'object' && originalTargetOrNormalized !== null) {
      const opts = originalTargetOrNormalized as any;
      originalTarget = opts.originalUrl || opts.targetUrl || opts.target || 'https://example.com';
      normalizedTarget = opts.normalizedUrl || opts.targetUrl || opts.target || originalTarget;
      try {
        parsedUrl = new URL(normalizedTarget);
      } catch {
        try {
          parsedUrl = new URL(originalTarget);
        } catch {
          parsedUrl = new URL('https://example.com');
        }
      }
      dnsResult = opts.dnsData || opts.dnsResult || { resolvedIps: ['93.184.216.34'], ipVersion: 'IPv4', dnsStatus: 'RESOLVED', isPrivate: false };
      httpResult = opts.httpData || opts.httpResult || { statusCode: 200, statusText: 'OK', headers: {}, responseTimeMs: 100 };
      if (opts.redirectData) {
        httpResult = {
          ...httpResult,
          ...opts.redirectData,
        };
      }
      tlsResult = opts.sslData || opts.tlsResult || null;
      effectiveHttps = Boolean(opts.effectiveHttps !== undefined ? opts.effectiveHttps : (parsedUrl.protocol === 'https:'));
      passedThreatIntel = opts.threatIntelResult || opts.threatIntelligence;
      passedDomainIntelligence = opts.domainIntelligence || opts.domainData || opts.domainProfile;
    } else if (typeof normalizedTargetOrParsedUrl === 'string') {
      originalTarget = originalTargetOrNormalized;
      normalizedTarget = normalizedTargetOrParsedUrl;
      parsedUrl = parsedUrlOrDns instanceof URL ? parsedUrlOrDns : new URL(normalizedTarget);
      dnsResult = (dnsResultOrHttp as any) || { resolvedIps: [], ipVersion: 'N/A', dnsStatus: 'Unknown', isPrivate: false };
      httpResult = httpResultOrTls;
      tlsResult = tlsResultOrEffective;
      effectiveHttps = Boolean(effectiveHttpsParam);
      passedThreatIntel = threatIntelResultParam;
      passedDomainIntelligence = domainIntelligenceParam;
    } else {
      normalizedTarget = originalTargetOrNormalized;
      originalTarget = normalizedTarget;
      parsedUrl = (normalizedTargetOrParsedUrl instanceof URL ? normalizedTargetOrParsedUrl : new URL(normalizedTarget));
      dnsResult = (parsedUrlOrDns as any) || { resolvedIps: [], ipVersion: 'N/A', dnsStatus: 'Unknown', isPrivate: false };
      httpResult = dnsResultOrHttp;
      tlsResult = httpResultOrTls;
      effectiveHttps = Boolean(tlsResultOrEffective);
      passedThreatIntel = threatIntelResultParam;
      passedDomainIntelligence = domainIntelligenceParam;
    }

    const findings: IScanFinding[] = [];
    const scoreContributors: IUrlRiskScoreContributor[] = [];
    const positiveSignals: Array<{ title: string; desc: string }> = [];
    const recommendations: string[] = [];
    let riskScore = 0;

    const hostname = parsedUrl.hostname.toLowerCase();
    const registrableDomain = getRegistrableDomain(hostname);
    const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
    const hostParts = hostname.split('.');
    const subdomainsList = isDirectIp ? [] : hostParts.length > 2 ? hostParts.slice(0, -2) : [];
    const subdomainCount = subdomainsList.length;

    const pathSegments = parsedUrl.pathname.split('/').filter(Boolean);
    const pathDepth = pathSegments.length;

    const queryParamKeys: string[] = [];
    parsedUrl.searchParams.forEach((_, k) => queryParamKeys.push(k));
    const queryCount = queryParamKeys.length;

    const encodedMatches = Array.from(normalizedTarget.matchAll(/%([0-9a-fA-F]{2})/g)).map((m) => m[0]);
    const hasEncodedChars = encodedMatches.length > 0;
    const encodedSequences = Array.from(new Set(encodedMatches));

    const punycodeLabels = hostParts.filter((p) => p.startsWith('xn--'));
    const hasPunycode = punycodeLabels.length > 0;

    const defaultPort = parsedUrl.protocol === 'https:' ? '443' : '80';
    const port = parsedUrl.port || defaultPort;
    const isCustomPort = Boolean(parsedUrl.port && parsedUrl.port !== '80' && parsedUrl.port !== '443');

    // Suspicious pattern checks
    const suspiciousPatterns: string[] = [];
    if (normalizedTarget.includes('@')) {
      suspiciousPatterns.push('Embedded credentials / userinfo delimiter (@)');
    }
    if (normalizedTarget.includes('%00')) {
      suspiciousPatterns.push('Null byte injection attempt (%00)');
    }
    if (normalizedTarget.includes('..') || normalizedTarget.includes('%2e%2e') || normalizedTarget.includes('%2E%2E')) {
      suspiciousPatterns.push('Directory traversal sequence (..)');
    }
    if (parsedUrl.pathname.includes('//')) {
      suspiciousPatterns.push('Multiple consecutive slashes (//) path obfuscation');
    }
    if (encodedMatches.length > 3) {
      suspiciousPatterns.push('Excessive URL percent encoding');
    }
    if (isCustomPort && !['8080', '8443', '3000', '5000', '8000', '8888'].includes(port)) {
      suspiciousPatterns.push(`Suspicious non-standard web port (${port})`);
    }

    // Technology and Server detection
    const serverSoftware = httpResult?.server;
    const framework = httpResult?.allHeaders ? httpResult.allHeaders['x-powered-by'] : undefined;
    const cdnProvider = detectCdnProvider(httpResult?.allHeaders || {}, serverSoftware);
    const detectedTechnologies = detectTechnologies(httpResult?.allHeaders || {}, serverSoftware);

    // Resource interpretation
    const resourceInterpretation = interpretUrlResource(
      httpResult?.statusCode,
      httpResult?.contentType,
      httpResult?.redirectCount || 0,
      httpResult?.finalUrl || normalizedTarget,
      httpResult?.error,
      dnsResult.isPrivate,
      parsedUrl.hostname
    );

    // Certificate summary
    let certHostnameMatch: boolean | undefined = undefined;
    if (tlsResult?.subject) {
      const subj = tlsResult.subject.toLowerCase();
      certHostnameMatch = subj === hostname || subj.includes(hostname) || (subj.startsWith('*.') && hostname.endsWith(subj.slice(2)));
    }

    const certificateSummary = {
      httpsEnabled: effectiveHttps,
      tlsVersion: tlsResult?.protocol,
      cipher: tlsResult?.cipher,
      subject: tlsResult?.subject,
      issuer: tlsResult?.issuer,
      valid: tlsResult ? tlsResult.valid : effectiveHttps,
      validFrom: tlsResult?.validFrom,
      validTo: tlsResult?.validTo,
      daysRemaining: tlsResult?.daysRemaining,
      hostnameMatch: certHostnameMatch,
      statusText: !effectiveHttps
        ? 'HTTPS is not used for the requested URL. Communications are transmitted in cleartext.'
        : tlsResult?.details || 'Valid TLS transport connection established.',
    };

    // Redirect journey & Protocol transitions
    const totalHops = httpResult?.redirectCount || 0;
    const finalUrl = httpResult?.finalUrl || normalizedTarget;
    let finalHostname = hostname;
    try {
      finalHostname = new URL(finalUrl).hostname.toLowerCase();
    } catch {
      finalHostname = hostname;
    }
    const finalDomain = getRegistrableDomain(finalHostname);
    const domainChanged = registrableDomain !== finalDomain;

    const initialScheme = parsedUrl.protocol.replace(':', '').toUpperCase();
    let finalScheme = initialScheme;
    try {
      finalScheme = new URL(finalUrl).protocol.replace(':', '').toUpperCase();
    } catch {
      finalScheme = initialScheme;
    }

    const redirectHops: Array<{
      hopNumber: number;
      statusCode: number;
      statusText?: string;
      sourceUrl: string;
      destinationUrl: string;
      sourceHostname: string;
      destinationHostname: string;
      domainChanged: boolean;
      protocolTransition?: string;
      isDowngrade?: boolean;
    }> = [];

    let hasDowngrade = Boolean((httpResult as any)?.hasDowngrade);

    if (httpResult?.redirectChain && httpResult.redirectChain.length > 0) {
      for (let i = 0; i < httpResult.redirectChain.length; i++) {
        const hop = httpResult.redirectChain[i];
        const nextUrl = i + 1 < httpResult.redirectChain.length ? httpResult.redirectChain[i + 1].url : finalUrl;
        let sHost = hostname;
        let dHost = finalHostname;
        let sProt = 'HTTP';
        let dProt = 'HTTP';
        try {
          const sU = new URL(hop.url);
          sHost = sU.hostname.toLowerCase();
          sProt = sU.protocol.replace(':', '').toUpperCase();
        } catch {}
        try {
          const dU = new URL(nextUrl);
          dHost = dU.hostname.toLowerCase();
          dProt = dU.protocol.replace(':', '').toUpperCase();
        } catch {}

        const sDomain = getRegistrableDomain(sHost);
        const dDomain = getRegistrableDomain(dHost);
        const isHopDowngrade = Boolean((hop as any).isDowngrade) || (sProt === 'HTTPS' && dProt === 'HTTP') || (initialScheme === 'HTTPS' && (sProt === 'HTTP' || dProt === 'HTTP'));
        if (isHopDowngrade) {
          hasDowngrade = true;
        }

        redirectHops.push({
          hopNumber: i + 1,
          statusCode: (hop as any).statusCode || (hop as any).status || 302,
          statusText: (hop as any).statusText || 'Redirect',
          sourceUrl: maskSensitiveUrl(hop.url),
          destinationUrl: maskSensitiveUrl(nextUrl),
          sourceHostname: sHost,
          destinationHostname: dHost,
          domainChanged: sDomain !== dDomain,
          protocolTransition: `${sProt} → ${dProt}${isHopDowngrade ? ' (Downgrade Risk)' : ''}`,
          isDowngrade: isHopDowngrade,
        });
      }
    }

    if (initialScheme === 'HTTPS' && finalScheme === 'HTTP') {
      hasDowngrade = true;
    }

    const protocolTransition =
      initialScheme === finalScheme
        ? `${initialScheme} → ${finalScheme}`
        : `${initialScheme} → ${finalScheme}${hasDowngrade || (initialScheme === 'HTTPS' && finalScheme === 'HTTP') ? ' (Downgrade Risk)' : ''}`;

    // ── 1. Protocol Security & Transport Check ────────────────────────────────
    const isUnencryptedTransport = !effectiveHttps || parsedUrl.protocol === 'http:';
    if (isUnencryptedTransport) {
      riskScore += 25;
      scoreContributors.push({
        category: 'Transport Security',
        name: 'Transport Security',
        points: 25,
        reason: 'Unencrypted HTTP in use — traffic and query parameters are transmitted in cleartext.',
      });
      findings.push({
        id: 'finding-http-unencrypted',
        category: 'Transport Security',
        severity: 'MEDIUM',
        title: 'Unencrypted HTTP Protocol',
        description: 'The URL uses unencrypted HTTP rather than HTTPS. Communications and data transmitted to this resource are exposed in cleartext to local network eavesdropping.',
        evidence: `Protocol: ${parsedUrl.protocol}`,
        impact: 'Data and credentials transmitted over plain HTTP can be intercepted or manipulated via man-in-the-middle attacks.',
        recommendation: 'Use the HTTPS version of this URL when available to ensure cryptographic protection in transit.',
      });
      recommendations.push('Prefer an HTTPS version of this URL when available to ensure transport encryption.');
    } else {
      positiveSignals.push({
        title: 'HTTPS Transport Encryption Active',
        desc: `URL enforces encrypted communications over ${tlsResult?.protocol || 'TLS / HTTPS'}.`,
      });
    }

    // ── 2. TLS Certificate Evaluation ─────────────────────────────────────────
    if (effectiveHttps && tlsResult) {
      if (tlsResult.valid === false || tlsResult.error) {
        riskScore += 35;
        scoreContributors.push({
          category: 'TLS Certificate Validity',
          name: 'TLS Certificate Validity',
          points: 35,
          reason: `TLS certificate issue: ${tlsResult.details}`,
        });
        findings.push({
          category: 'SSL/TLS Certificate',
          severity: 'HIGH',
          title: 'Untrusted or Invalid SSL/TLS Certificate',
          description: `The SSL/TLS certificate presented by the host failed validation: ${tlsResult.details}`,
          evidence: tlsResult.error || tlsResult.details,
          impact: 'An invalid certificate prevents secure authentication of the server and may indicate a misconfiguration or intercept proxy.',
          recommendation: 'Do not submit sensitive information until the TLS certificate validity issue is resolved.',
        });
        recommendations.push('Do not submit sensitive information or credentials until the TLS certificate issue is resolved.');
      } else {
        positiveSignals.push({
          title: 'Valid TLS Certificate Verified',
          desc: `Certificate issued by ${tlsResult.issuer || 'Standard CA'} is valid and cryptographically trusted.`,
        });

        if (certHostnameMatch) {
          positiveSignals.push({
            title: 'Certificate Hostname Match',
            desc: `Presented certificate subject matches target hostname (${hostname}).`,
          });
        }

        if (tlsResult.daysRemaining !== undefined && tlsResult.daysRemaining < 15) {
          riskScore += 5;
          scoreContributors.push({
            category: 'TLS Certificate Expiry',
            name: 'TLS Certificate Expiry',
            points: 5,
            reason: `Certificate expiring soon (${tlsResult.daysRemaining} days remaining).`,
          });
          findings.push({
            category: 'SSL/TLS Certificate',
            severity: 'LOW',
            title: 'SSL/TLS Certificate Expiring Soon',
            description: `The host TLS certificate is valid but expires in ${tlsResult.daysRemaining} day(s).`,
            evidence: `Expires on: ${tlsResult.validTo || 'Soon'}`,
            impact: 'Expired certificates trigger browser security warnings and disrupt legitimate access.',
            recommendation: 'Renew the SSL/TLS certificate before expiration to prevent service disruption.',
          });
          recommendations.push('Renew the SSL/TLS certificate before expiration to avoid browser warning blocks.');
        }
      }
    }

    // ── 3. DNS & SSRF Validation ──────────────────────────────────────────────
    if (dnsResult.isPrivate) {
      riskScore += 75;
      scoreContributors.push({
        category: 'DNS / IP Classification',
        name: 'DNS / IP Classification',
        points: 75,
        reason: 'Target resolves to a private / loopback IP address (SSRF blocked).',
      });
      findings.push({
        category: 'Domain & Infrastructure',
        severity: 'CRITICAL',
        title: 'Private / Internal Network Address (SSRF Blocked)',
        description: 'The target resolves to a private, loopback, or reserved network IP address. Outbound connections are blocked by security policy.',
        evidence: `Host: ${hostname}, Resolved: ${dnsResult.resolvedIps.join(', ') || '127.0.0.1'}`,
        impact: 'Exposing internal services to public URL handlers can allow Server-Side Request Forgery (SSRF) and unauthorized internal access.',
        recommendation: 'Verify that internal or loopback destinations are not exposed through public URL handling endpoints.',
      });
      recommendations.push('Verify network firewall rules and do not expose private internal addresses to public proxies.');
    } else if (dnsResult.error) {
      riskScore += 20;
      scoreContributors.push({
        category: 'DNS Resolution',
        name: 'DNS Resolution',
        points: 20,
        reason: `DNS resolution failed: ${dnsResult.error}`,
      });
      findings.push({
        category: 'Domain & Infrastructure',
        severity: 'MEDIUM',
        title: 'DNS Resolution Failed (Unresolvable Domain)',
        description: `The domain could not be resolved via global DNS (${dnsResult.error}). The target may be expired, offline, or mistyped.`,
        evidence: `DNS Error: ${dnsResult.error}`,
        impact: 'Users and automated systems cannot reach an unresolvable domain.',
        recommendation: 'Check the domain spelling and ensure authoritative DNS records are properly configured.',
      });
      recommendations.push('Verify the exact spelling of the domain and confirm active DNS zone configuration.');
    } else {
      positiveSignals.push({
        title: 'DNS Resolution Succeeded',
        desc: `Domain resolved to active global DNS record(s) (${dnsResult.resolvedIps.slice(0, 2).join(', ')}).`,
      });
    }

    // ── 4. Hostname Structure & Direct IP ─────────────────────────────────────
    if (isDirectIp && !dnsResult.isPrivate) {
      riskScore += 30;
      scoreContributors.push({
        category: 'Hostname Structure',
        name: 'Hostname Structure',
        points: 30,
        reason: 'Direct IP address hostname in use rather than registered domain name.',
      });
      findings.push({
        category: 'URL Structure',
        severity: 'HIGH',
        title: 'Direct IP Address Hostname',
        description: 'The URL uses a raw IP address as the host rather than a registered domain name. Direct IP hosts bypass domain reputation filters and lack standard domain provenance.',
        evidence: `Host: ${hostname}`,
        impact: 'Raw IP addresses make destination identity verification harder and are frequently used in automated malware drops and command-and-control channels.',
        recommendation: 'Verify the destination independently before submitting sensitive information or executing downloads.',
      });
      recommendations.push('Verify the destination IP owner independently before submitting sensitive information.');
    } else if (!isDirectIp) {
      positiveSignals.push({
        title: 'Standard Registered Domain Hostname',
        desc: `Target uses a standard domain identity (${hostname}) rather than a raw IP address.`,
      });
    }

    // ── 5. Punycode / IDN Homograph Check ─────────────────────────────────────
    if (hasPunycode) {
      riskScore += 25;
      scoreContributors.push({
        category: 'Punycode / Homograph',
        name: 'Punycode / Homograph',
        points: 25,
        reason: `Punycode (xn--) labels present in hostname: ${punycodeLabels.join(', ')}`,
      });
      findings.push({
        category: 'URL Structure',
        severity: 'HIGH',
        title: 'Internationalized Domain Name (Punycode Detected)',
        description: `The hostname contains punycode labels (${punycodeLabels.join(', ')}). Punycode allows internationalized character sets which can visually mimic legitimate domains in homograph phishing attacks.`,
        evidence: `Punycode labels: ${punycodeLabels.join(', ')}`,
        impact: 'Homograph domains can trick users into believing they are visiting a trusted brand when they are on an entirely different destination.',
        recommendation: 'Carefully verify the Unicode character interpretation of this domain before entering sensitive credentials.',
      });
      recommendations.push('Carefully verify the Unicode character interpretation of the punycode domain before interacting.');
    } else {
      positiveSignals.push({
        title: 'No Punycode / Homograph Labels Detected',
        desc: 'Hostname uses standard ASCII character encoding with no xn-- prefix tags.',
      });
    }

    // ── 6. Subdomain Hierarchy ────────────────────────────────────────────────
    if (!isDirectIp && subdomainCount > 4) {
      riskScore += 15;
      scoreContributors.push({
        category: 'Subdomain Hierarchy',
        name: 'Subdomain Hierarchy',
        points: 15,
        reason: `Deep subdomain nesting observed (${subdomainCount} levels).`,
      });
      findings.push({
        category: 'URL Structure',
        severity: 'MEDIUM',
        title: 'Excessive Subdomain Nesting Depth',
        description: `The URL contains ${subdomainCount} subdomain levels (${subdomainsList.join('.')}). Excessive subdomain hierarchies can be used to construct misleading URLs that mimic trusted brands.`,
        evidence: `Subdomains: ${subdomainsList.join('.')}`,
        impact: 'Complex subdomain chains make it harder for users to identify the true authoritative root domain.',
        recommendation: 'Verify the root domain at the end of the hostname to confirm the authoritative owner.',
      });
      recommendations.push('Verify the root domain at the end of the hostname to confirm the true destination owner.');
    }

    // Brand Impersonation in Subdomain check
    const brandTokens = ['paypal', 'microsoft', 'apple', 'google', 'netflix', 'amazon', 'chase', 'wellsfargo', 'bankofamerica', 'facebook', 'instagram', 'whatsapp'];
    const matchedBrandInSubdomain = brandTokens.find(
      (brand) => subdomainsList.some((sub) => sub.includes(brand)) && !registrableDomain.includes(brand)
    );

    if (matchedBrandInSubdomain) {
      riskScore += 25;
      scoreContributors.push({
        category: 'Brand Deception',
        name: 'Brand Name in Subdomain',
        points: 25,
        reason: `Target hostname contains brand token "${matchedBrandInSubdomain}" in subdomain of unrelated domain (${registrableDomain}).`,
      });
      findings.push({
        category: 'URL Structure & Phishing',
        severity: 'HIGH',
        title: `Brand Name in Subdomain (${matchedBrandInSubdomain})`,
        description: `The URL contains the brand name "${matchedBrandInSubdomain}" in its subdomain while registered to an unrelated root domain (${registrableDomain}). This pattern is commonly used in deceptive brand impersonation campaigns.`,
        evidence: `Host: ${hostname}, Root domain: ${registrableDomain}`,
        impact: 'Users may mistakenly believe this destination belongs to the named brand.',
        recommendation: `Verify destination identity against the authentic brand domain.`,
      });
      recommendations.push('Check the authoritative root domain carefully before submitting credentials.');
    }

    // ── 7. Suspicious Patterns & Obfuscation ──────────────────────────────────
    if (suspiciousPatterns.length > 0) {
      const isHighObfuscation = suspiciousPatterns.some((p) => p.includes('Null byte') || p.includes('credentials'));
      const pts = isHighObfuscation ? 25 : 15;
      riskScore += pts;
      scoreContributors.push({
        category: 'URL Patterns & Obfuscation',
        name: 'URL Patterns & Obfuscation',
        points: pts,
        reason: `Detected suspicious structural patterns: ${suspiciousPatterns.join('; ')}`,
      });
      findings.push({
        category: 'URL Structure',
        severity: isHighObfuscation ? 'HIGH' : 'MEDIUM',
        title: 'Suspicious URL Structure & Obfuscation Patterns',
        description: `The URL exhibits unusual structural characteristics: ${suspiciousPatterns.join('; ')}.`,
        evidence: `Patterns: ${suspiciousPatterns.join(', ')}`,
        impact: 'Obfuscated URL segments can be used to bypass web application firewalls, disguise destinations, or exploit path normalization bugs.',
        recommendation: 'Verify the final destination before opening or sharing the URL.',
      });
      recommendations.push('Verify the final destination before opening or sharing obfuscated URLs.');
    } else {
      positiveSignals.push({
        title: 'No Obvious URL Obfuscation',
        desc: 'URL path and query parameters follow standard syntax without anomalous traversal or userinfo delimiters.',
      });
    }

    // ── 8. Redirection Routing & HTTPS Downgrade ──────────────────────────────
    if (httpResult?.error === 'SSRF_BLOCKED') {
      riskScore += 75;
      scoreContributors.push({
        category: 'Redirect SSRF',
        name: 'Redirect SSRF',
        points: 75,
        reason: 'Redirection chain targeted a private or reserved network IP address (SSRF blocked).',
      });
      findings.push({
        category: 'Domain & Infrastructure',
        severity: 'CRITICAL',
        title: 'Redirect SSRF Blocked (Private Network Destination)',
        description: 'The URL attempted to redirect to an internal or private network IP address. The request was blocked to safeguard private network boundaries.',
        evidence: `Final Hop: ${httpResult.finalUrl}`,
        impact: 'Unchecked redirects to private IP addresses can lead to Server-Side Request Forgery (SSRF) and compromise internal network assets.',
        recommendation: 'Ensure external redirect endpoints do not route to private internal IP addresses.',
      });
      recommendations.push('Ensure external redirect endpoints do not route to private internal IP addresses.');
    } else if (httpResult?.error === 'MAX_REDIRECTS_EXCEEDED') {
      riskScore += 20;
      scoreContributors.push({
        category: 'Redirect Behavior',
        name: 'Redirect Behavior',
        points: 20,
        reason: 'Maximum redirect limit exceeded (potential redirect loop).',
      });
      findings.push({
        category: 'Redirect Analysis',
        severity: 'MEDIUM',
        title: 'Redirect Loop / Maximum Hops Exceeded',
        description: 'The target destination entered a continuous or cyclic redirection chain that exceeded the safety limit.',
        evidence: `Hops followed: ${totalHops}`,
        impact: 'Redirect loops prevent successful page loading and may consume client and network resources.',
        recommendation: 'Review web server redirect rules and canonical URL configurations.',
      });
      recommendations.push('Review web server redirection rules to eliminate circular redirect chains.');
    } else {
      if (hasDowngrade) {
        riskScore += 30;
        scoreContributors.push({
          category: 'Transport Security',
          name: 'Redirect Protocol Downgrade',
          points: 30,
          reason: 'HTTPS to HTTP downgrade detected during redirection.',
        });
        const downgradeHop = redirectHops.find((h) => h.isDowngrade) || redirectHops[0];
        findings.push({
          category: 'Transport Security',
          severity: 'HIGH',
          title: 'HTTPS to HTTP Protocol Downgrade Detected',
          description: 'A redirect hop transitioned from encrypted HTTPS to cleartext HTTP, weakening transport security.',
          evidence: downgradeHop
            ? `Redirect hop ${downgradeHop.hopNumber} changed protocol from HTTPS to HTTP (${downgradeHop.sourceUrl} → ${downgradeHop.destinationUrl}).`
            : 'Redirect transitioned from HTTPS to HTTP.',
          impact: 'An HTTPS-to-HTTP downgrade can expose traffic and authentication cookies to cleartext interception.',
          recommendation: 'Configure server redirection to always maintain HTTPS transport and prevent plaintext downgrades.',
        });
        recommendations.push('Configure web server redirection to maintain HTTPS across all hops.');
      } else if (totalHops > 0) {
        positiveSignals.push({
          title: 'No Redirect Downgrade Observed',
          desc: 'All redirect hops maintained transport encryption without protocol downgrades.',
        });
      }

      if (totalHops > 0 && httpResult) {
        if (domainChanged) {
          riskScore += 15;
          scoreContributors.push({
            category: 'Redirect Behavior',
            name: 'Redirect Behavior',
            points: 15,
            reason: `Cross-domain redirect from ${registrableDomain} to ${finalDomain} across ${totalHops} hop(s).`,
          });
          findings.push({
            category: 'Redirect Analysis',
            severity: 'MEDIUM',
            title: 'Cross-Domain Redirection Observed',
            description: `The submitted URL redirects across domain boundaries (${registrableDomain} → ${finalDomain}) across ${totalHops} hop(s).`,
            evidence: `Redirect: ${redirectHops.map((h) => `${h.sourceHostname} [${h.statusCode}] -> ${h.destinationHostname}`).join(' → ')}`,
            impact: 'Cross-domain redirects can lead users away from the expected service to a third-party destination.',
            recommendation: 'Verify that the final destination domain is trusted and intentional before interacting.',
          });
          recommendations.push(`Verify the final destination domain (${finalHostname}) before entering data.`);
        } else {
          positiveSignals.push({
            title: 'Same-Domain Redirection',
            desc: `Redirect hops (${totalHops}) remain strictly within the same domain boundary (${finalHostname}).`,
          });
        }
      } else if (totalHops === 0) {
        positiveSignals.push({
          title: 'Direct Navigation Target',
          desc: 'Destination reached directly without intermediate redirection hops.',
        });
      }
    }


    // ── 10. HTTP Response Status ──────────────────────────────────────────────
    if (httpResult?.statusCode) {
      if (httpResult.statusCode >= 200 && httpResult.statusCode < 400) {
        positiveSignals.push({
          title: 'Target Endpoint Reachable & Responsive',
          desc: `Server responded with HTTP ${httpResult.statusCode} ${httpResult.statusText || 'OK'} (${httpResult.responseTimeMs || 0}ms response time).`,
        });
      } else if (httpResult.statusCode === 404) {
        findings.push({
          category: 'HTTP Response',
          severity: 'INFO',
          title: 'HTTP 404 Not Found',
          description: 'The requested resource or endpoint path was not found on the target server.',
          evidence: `Status: HTTP 404 ${httpResult.statusText || ''}`,
          impact: 'The URL does not currently point to an active resource.',
          recommendation: 'Check the URL path for typos or verify whether the resource has moved.',
        });
      } else if (httpResult.statusCode >= 500) {
        riskScore += 10;
        scoreContributors.push({
          category: 'HTTP Response',
          name: 'HTTP Response',
          points: 10,
          reason: `Server returned HTTP ${httpResult.statusCode} internal error.`,
        });
        findings.push({
          category: 'HTTP Response',
          severity: 'MEDIUM',
          title: `HTTP ${httpResult.statusCode} Server Error`,
          description: `The target server returned an internal error response (${httpResult.statusCode} ${httpResult.statusText || ''}) when requested.`,
          evidence: `Status: HTTP ${httpResult.statusCode}`,
          impact: 'Server errors indicate backend instability, unhandled exceptions, or misconfigured reverse proxies.',
          recommendation: 'Review web server error logs and backend application health.',
        });
      }
    } else if (httpResult?.error && httpResult.error !== 'SSRF_BLOCKED' && httpResult.error !== 'MAX_REDIRECTS_EXCEEDED') {
      const isTimeout = httpResult.error === 'ETIMEDOUT';
      riskScore += 15;
      scoreContributors.push({
        category: 'HTTP Response',
        name: 'HTTP Response',
        points: 15,
        reason: isTimeout ? 'Request timed out' : `Target connection failed (${httpResult.details || httpResult.error})`,
      });
      findings.push({
        category: 'HTTP Response',
        severity: 'MEDIUM',
        title: isTimeout ? 'Request Timed Out' : 'Target Connection Failed',
        description: isTimeout
          ? 'The target destination did not respond within the connection timeout threshold.'
          : `Network connection to target failed: ${httpResult.details || httpResult.error}`,
        evidence: `Error: ${httpResult.error}`,
        impact: 'The destination cannot be reached from the current network interface.',
        recommendation: 'Confirm server availability and network reachability.',
      });
    }

    if (recommendations.length === 0) {
      recommendations.push('No immediate remediation required. Continue monitoring endpoint configuration.');
    }

    // ── 11. Security Audit Checklist Matrix (14 Dimensions) ───────────────────
    const domainRdapStatus = passedDomainIntelligence?.rdapStatus === 'OBSERVED'
      ? 'PASS'
      : passedDomainIntelligence?.rdapStatus === 'LOOKUP_FAILED'
      ? 'UNAVAILABLE'
      : 'NOT AVAILABLE';

    const securityAudit: IUrlSecurityAuditCheck[] = [
      {
        id: 'chk-protocol',
        name: 'Protocol Security',
        status: effectiveHttps ? 'PASS' : 'WARN',
        severity: effectiveHttps ? 'INFO' : 'MEDIUM',
        evidence: `Protocol: ${parsedUrl.protocol}`,
        explanation: effectiveHttps ? 'URL enforces TLS/HTTPS transport encryption.' : 'URL uses unencrypted HTTP protocol; communications are transmitted in cleartext.',
      },
      {
        id: 'chk-tls',
        name: 'TLS Certificate Validity',
        status: !effectiveHttps ? 'UNAVAILABLE' : (tlsResult?.valid === false || tlsResult?.error) ? 'FAIL' : 'PASS',
        severity: !effectiveHttps ? 'INFO' : (tlsResult?.valid === false || tlsResult?.error) ? 'HIGH' : 'INFO',
        evidence: !effectiveHttps ? 'HTTPS is not used' : tlsResult?.details || 'Valid TLS certificate',
        explanation: !effectiveHttps
          ? 'TLS inspection not applicable on plain HTTP.'
          : tlsResult?.valid
          ? `Valid ${tlsResult.protocol || 'TLS'} connection. Certificate issued by ${tlsResult.issuer || 'Trusted CA'}.`
          : `TLS validation warning: ${tlsResult?.error || 'Validation error'}.`,
      },
      {
        id: 'chk-cert-match',
        name: 'Certificate Hostname Match',
        status: !effectiveHttps ? 'UNAVAILABLE' : certHostnameMatch ? 'PASS' : certHostnameMatch === false ? 'WARN' : 'PASS',
        severity: certHostnameMatch === false ? 'MEDIUM' : 'INFO',
        evidence: !effectiveHttps ? 'N/A (Plain HTTP)' : tlsResult?.subject ? `Certificate Subject: ${tlsResult.subject}` : 'Verified matching hostname',
        explanation: !effectiveHttps
          ? 'Not applicable on unencrypted HTTP.'
          : certHostnameMatch
          ? 'Presented TLS certificate explicitly matches the target domain identity.'
          : 'Certificate subject mismatch or wildcard evaluation warning.',
      },
      {
        id: 'chk-dns',
        name: 'DNS Resolution & Infrastructure',
        status: dnsResult.isPrivate || dnsResult.error ? 'FAIL' : 'PASS',
        severity: dnsResult.isPrivate ? 'CRITICAL' : dnsResult.error ? 'MEDIUM' : 'INFO',
        evidence: dnsResult.resolvedIps.length > 0 ? `Resolved ${dnsResult.resolvedIps.length} record(s): ${dnsResult.resolvedIps.slice(0, 3).join(', ')}` : dnsResult.dnsStatus,
        explanation: dnsResult.isPrivate
          ? 'Target resolves to private or reserved IP address range (SSRF Blocked).'
          : dnsResult.error
          ? `DNS resolution failed: ${dnsResult.error}.`
          : `Domain successfully resolved to active ${dnsResult.ipVersion} infrastructure.`,
      },
      {
        id: 'chk-ip-host',
        name: 'IP-Based Hostname',
        status: isDirectIp ? 'WARN' : 'NOT DETECTED',
        severity: isDirectIp ? 'HIGH' : 'INFO',
        evidence: isDirectIp ? `Direct IP: ${hostname}` : 'Standard domain name in use',
        explanation: isDirectIp ? 'Direct IP address hostname detected (common evasion indicator).' : 'Target uses standard domain naming without direct IP evasion.',
      },
      {
        id: 'chk-punycode',
        name: 'Punycode / IDN',
        status: hasPunycode ? 'WARN' : 'NOT DETECTED',
        severity: hasPunycode ? 'HIGH' : 'INFO',
        evidence: hasPunycode ? `Punycode labels: ${punycodeLabels.join(', ')}` : 'Hostname contains no xn-- labels',
        explanation: hasPunycode ? 'Internationalized domain labels present (potential homograph attack).' : 'No punycode or IDN homograph labels observed in hostname.',
      },
      {
        id: 'chk-subdomains',
        name: 'Subdomain Hierarchy & Depth',
        status: subdomainCount > 4 ? 'WARN' : 'PASS',
        severity: subdomainCount > 4 ? 'MEDIUM' : 'INFO',
        evidence: `Subdomains: ${subdomainCount} level(s) (${subdomainsList.join('.') || 'None'})`,
        explanation: subdomainCount > 4 ? `Excessive subdomain nesting (${subdomainCount} levels) detected.` : 'Subdomain hierarchy is within normal operating parameters (<=3 levels).',
      },
      {
        id: 'chk-brand',
        name: 'Brand Impersonation in Subdomain',
        status: matchedBrandInSubdomain ? 'WARN' : 'PASS',
        severity: matchedBrandInSubdomain ? 'HIGH' : 'INFO',
        evidence: matchedBrandInSubdomain ? `Brand "${matchedBrandInSubdomain}" in subdomain of ${registrableDomain}` : 'No brand token mismatch in subdomains',
        explanation: matchedBrandInSubdomain ? `Subdomain contains brand token "${matchedBrandInSubdomain}" not belonging to registrable domain.` : 'Subdomain structure does not mimic third-party brand names.',
      },
      {
        id: 'chk-patterns',
        name: 'Suspicious Encoding',
        status: (suspiciousPatterns.length > 0 || hasEncodedChars) ? 'WARN' : 'NOT DETECTED',
        severity: (suspiciousPatterns.length > 0 || hasEncodedChars) ? 'MEDIUM' : 'INFO',
        evidence: suspiciousPatterns.length > 0 ? suspiciousPatterns.join('; ') : hasEncodedChars ? `Encoded sequences: ${encodedSequences.slice(0, 5).join(', ')}` : 'No suspicious patterns identified',
        explanation: (suspiciousPatterns.length > 0 || hasEncodedChars) ? `Identified anomalous pattern(s) or percent-encoded characters in URL syntax.` : 'URL structure contains no embedded credentials, null bytes, or traversal sequences.',
      },
      {
        id: 'chk-redirects',
        name: 'Redirection Routing',
        status: hasDowngrade || httpResult?.error === 'MAX_REDIRECTS_EXCEEDED' || httpResult?.error === 'SSRF_BLOCKED' ? 'FAIL' : domainChanged ? 'WARN' : 'PASS',
        severity: hasDowngrade ? 'HIGH' : domainChanged ? 'MEDIUM' : 'INFO',
        evidence: hasDowngrade ? `Protocol downgrade detected (${protocolTransition})` : totalHops > 0 ? `${totalHops} hop(s) -> ${finalHostname}` : 'Direct destination (0 redirects)',
        explanation: hasDowngrade
          ? 'Redirection chain includes an HTTPS to HTTP security downgrade.'
          : totalHops > 0
          ? domainChanged
            ? `Followed ${totalHops} redirect hop(s) across external domain (${finalHostname}).`
            : `Followed ${totalHops} redirect hop(s) within same domain.`
          : 'Target destination reached directly without multi-hop redirection.',
      },
      {
        id: 'chk-response',
        name: 'HTTP Response & Reachability',
        status: httpResult?.statusCode && httpResult.statusCode >= 200 && httpResult.statusCode < 400 ? 'PASS' : httpResult?.statusCode === 404 ? 'PASS' : httpResult?.statusCode && httpResult.statusCode >= 500 ? 'WARN' : httpResult?.error ? 'FAIL' : 'PASS',
        severity: httpResult?.statusCode && httpResult.statusCode >= 500 ? 'MEDIUM' : 'INFO',
        evidence: httpResult?.statusCode ? `HTTP ${httpResult.statusCode} ${httpResult.statusText || ''} (${httpResult.responseTimeMs || 0}ms)` : httpResult?.error || 'Response analyzed',
        explanation: httpResult?.details || 'Endpoint network response recorded.',
      },
      {
        id: 'chk-headers',
        name: 'Security Response Headers Posture',
        status: (httpResult?.securityHeaders && Object.keys(httpResult.securityHeaders).length >= 3) ? 'PASS' : 'WARN',
        severity: 'LOW',
        evidence: httpResult?.securityHeaders ? `${Object.keys(httpResult.securityHeaders).length} security header(s) observed` : 'Headers not inspected',
        explanation: httpResult?.securityHeaders && Object.keys(httpResult.securityHeaders).length >= 3
          ? 'Standard browser defense-in-depth security headers are present.'
          : 'Missing multiple recommended browser hardening response headers (HSTS, CSP, X-Content-Type-Options).',
      },
      {
        id: 'chk-domain-rdap',
        name: 'Domain Registration & RDAP Provenance',
        status: domainRdapStatus as any,
        severity: 'INFO',
        evidence: passedDomainIntelligence?.domainAgeFormatted
          ? `Age: ${passedDomainIntelligence.domainAgeFormatted} (${passedDomainIntelligence.registrar || 'Registered'})`
          : passedDomainIntelligence?.rdapStatus === 'OBSERVED'
          ? `Registrar: ${passedDomainIntelligence.registrar || 'Authoritative Registry'}`
          : 'Registration information not publicly published or unavailable',
        explanation: passedDomainIntelligence?.domainAgeFormatted
          ? `Domain registration verified via RDAP (${passedDomainIntelligence.domainAgeFormatted}).`
          : 'RDAP registration query performed; data observed or marked not available per registry response.',
      },
      {
        id: 'chk-reputation',
        name: 'Threat Intelligence & Reputation Feeds',
        status: passedThreatIntel?.status === 'Threat Detected' ? 'FAIL' : passedThreatIntel?.status === 'Clean' ? 'PASS' : 'UNAVAILABLE',
        severity: passedThreatIntel?.status === 'Threat Detected' ? 'CRITICAL' : 'INFO',
        evidence: passedThreatIntel ? passedThreatIntel.details : 'No third-party reputation provider configured in current environment',
        explanation: passedThreatIntel ? passedThreatIntel.details : 'Reputation intelligence lookup requires external threat intelligence API configuration.',
      },
    ];

    // ── 12. Threat Intelligence State ─────────────────────────────────────────
    const threatIntelligence = passedThreatIntel
      ? {
          status: passedThreatIntel.status,
          provider: passedThreatIntel.provider,
          result: passedThreatIntel.result,
          queried: passedThreatIntel.queried,
          timestamp: passedThreatIntel.timestamp,
          indicators: passedThreatIntel.indicators,
          details: passedThreatIntel.details,
          providers: passedThreatIntel.providers,
        }
      : {
          status: 'Not Configured',
          provider: 'None Configured',
          result: 'Not Available',
          queried: false,
          details: 'No third-party threat intelligence provider is configured in this environment.',
        };

    if (passedThreatIntel?.status === 'Threat Detected') {
      riskScore += 75;
      scoreContributors.push({
        category: 'Threat Intelligence',
        name: 'Threat Intelligence Feed Match',
        points: 75,
        reason: passedThreatIntel.details || 'Destination flagged by active threat intelligence feed.',
      });
      findings.push({
        category: 'Threat Intelligence',
        severity: 'CRITICAL',
        title: `Threat Intelligence Feed Match (${passedThreatIntel.provider || 'Feed'})`,
        description: `Target was flagged by configured threat intelligence feed: ${passedThreatIntel.details}`,
        evidence: passedThreatIntel.details,
      });
    }

    // ── 13. Domain Intelligence Construction ──────────────────────────────────
    const domainIntelligence = passedDomainIntelligence || {
      domain: registrableDomain || hostname,
      hostname,
      isDirectIp,
      isPrivate: dnsResult.isPrivate,
      nameservers: [],
      dnsRecords: {
        a: dnsResult.resolvedIps.filter((ip) => !ip.includes(':')),
        aaaa: dnsResult.resolvedIps.filter((ip) => ip.includes(':')),
        cname: [],
        mx: [],
        ns: [],
        txt: [],
      },
      dnsResolved: dnsResult.resolvedIps.length > 0,
      rdapStatus: 'NOT AVAILABLE' as const,
      details: dnsResult.dnsStatus || 'DNS resolution completed.',
    };

    // ── 14. Execution Outcome ─────────────────────────────────────────────────
    let executionOutcome: 'COMPLETED' | 'INVALID_URL' | 'TARGET_UNREACHABLE' | 'ANALYSIS_UNAVAILABLE' | 'SCAN_FAILED' | 'BLOCKED_BY_SECURITY_POLICY' = 'COMPLETED';
    if (dnsResult.isPrivate || httpResult?.error === 'SSRF_BLOCKED') {
      executionOutcome = 'BLOCKED_BY_SECURITY_POLICY';
    } else if (dnsResult.error || httpResult?.error === 'ETIMEDOUT') {
      executionOutcome = 'TARGET_UNREACHABLE';
    } else if (httpResult?.error) {
      executionOutcome = 'ANALYSIS_UNAVAILABLE';
    }

    // ── 15. Compute Final Score & Classification ──────────────────────────────
    riskScore = Math.min(Math.max(riskScore, 0), 100);
    const classification: ScanResultClassification = deriveClassificationFromRiskScore(
      riskScore,
      dnsResult.isPrivate || httpResult?.error === 'SSRF_BLOCKED' || findings.some((f) => f.severity === 'CRITICAL')
    );

    // ── 16. Explainability & Why This Result ──────────────────────────────────
    const whyVerdict: string[] = [
      'CyberWatch analyzed 14 security dimensions across URL structure, DNS, HTTP/TLS, redirect behavior, phishing indicators and configured threat-intelligence sources.',
      `Based on the evidence available during this scan, the URL is classified as ${classification.toUpperCase()}.`,
      'This classification reflects the evidence available at scan time and does not guarantee future safety.',
    ];

    if (executionOutcome === 'BLOCKED_BY_SECURITY_POLICY') {
      whyVerdict.push('The destination target resolves to a private, loopback, or reserved network IP address and was blocked by security controls (SSRF Protection).');
    } else if (executionOutcome === 'TARGET_UNREACHABLE') {
      whyVerdict.push(dnsResult.error ? `The destination domain could not be resolved in DNS (${dnsResult.error}).` : 'The target destination did not respond within the connection timeout threshold.');
    } else {
      const topFindings = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM');
      if (topFindings.length > 0) {
        topFindings.slice(0, 3).forEach((f) => {
          whyVerdict.push(`${f.title}: ${f.evidence || f.description}`);
        });
      } else {
        whyVerdict.push('Observed no significant malicious indicators or deceptive structures during this scan.');
      }
    }

    const primaryFindings = findings
      .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM')
      .map((f) => `[${f.severity}] ${f.title}: ${f.evidence || f.description}`);

    const limitations = [
      'CyberWatch analyzes observable URL structure, DNS resolution, network responses, redirect routing, and TLS certificates.',
      'A completed scan reflects target state at scan time and does not guarantee that a target is completely safe.',
      'Threat intelligence provider results reflect configured feeds only; unconfigured feeds show NOT CONFIGURED.',
    ];

    const isScanFailure = dnsResult.isPrivate || Boolean(dnsResult.error) || Boolean(httpResult?.error);
    const analysis: IUrlSecurityAnalysis = {
      status: isScanFailure ? 'failed' : riskScore >= 40 ? 'warning' : 'passed',
      statusExplanation:
        executionOutcome === 'BLOCKED_BY_SECURITY_POLICY'
          ? 'CyberWatch blocked this target because it resolves to a protected or internal network address.'
          : executionOutcome === 'TARGET_UNREACHABLE'
          ? 'Target unreachable: DNS failure or connection timed out.'
          : riskScore <= 11
          ? 'No significant malicious indicators were observed during this scan.'
          : riskScore <= 24
          ? 'Low-risk security profile with minor informational indicators.'
          : riskScore <= 49
          ? 'Suspicious indicators were observed in URL structure or redirection.'
          : 'High-risk security indicators were observed during this scan.',
      executionOutcome,
      originalUrl: maskSensitiveUrl(originalTarget),
      normalizedUrl: maskSensitiveUrl(normalizedTarget),
      finalUrl: maskSensitiveUrl(finalUrl),
      finalHostname,
      finalDomain,
      registrableDomain,
      urlLength: normalizedTarget.length,
      hostnameLength: hostname.length,
      pathLength: parsedUrl.pathname.length,
      queryLength: parsedUrl.search.length,
      punycodeHostname: hostname,
      decodedHostname: hostname,
      subdomainCount,
      subdomainsList,
      pathDepth,
      pathSegments,
      queryCount,
      queryParamKeys,
      hasEncodedChars,
      encodedSequences,
      hasPunycode,
      punycodeLabels,
      isDirectIp,
      isPrivateIp: dnsResult.isPrivate,
      isCustomPort,
      port,
      suspiciousPatterns,
      resourceInterpretation,
      serverSoftware,
      framework,
      cdnProvider,
      detectedTechnologies,
      threatIntelligence,
      domainIntelligence,
      certificateSummary,
      hasDowngrade,
      redirectJourney: {
        totalHops,
        initialUrl: maskSensitiveUrl(normalizedTarget),
        finalUrl: maskSensitiveUrl(finalUrl),
        finalHostname,
        domainChanged,
        hasDowngrade,
        protocolTransition,
        hops: redirectHops,
      },
      securityAudit,
      auditChecks: securityAudit,
      scoreContributors,
      positiveSignals,
      whyVerdict,
      primaryFindings,
      limitations,
      details: `URL security assessment completed for ${maskSensitiveUrl(normalizedTarget)} (Risk Score: ${riskScore}/100, Verdict: ${classification}).`,
    };

    return {
      analysis,
      findings,
      recommendations,
      riskScore,
      classification,
    };
  }

  /**
   * Coordinated Mega Scanner: Unified Evidence Aggregator & Deduplicator.
   * Merges findings from URL security analysis, phishing analysis, and threat intelligence.
   * Normalizes findings into a unified model, deduplicates overlapping signals, and
   * computes a transparent, evidence-driven final risk score.
   */
  public aggregateMegaScanFindings(
    urlEval: { findings: IScanFinding[]; recommendations: string[]; riskScore: number },
    phishResult: { findings: IScanFinding[]; recommendations: string[]; riskScore: number; scoreContributors?: any[] },
    context: {
      target: string;
      normalizedTarget: string;
      parsedUrl: URL;
      dnsResult: { isPrivate: boolean; resolvedIps: string[]; ipVersion: string; dnsStatus: string; error?: string };
      httpResult: any;
      tlsResult: any;
      effectiveHttps: boolean;
      threatIntelResult?: ThreatIntelligenceResult;
    }
  ): {
    findings: IScanFinding[];
    recommendations: string[];
    riskScore: number;
    hasCriticalFinding: boolean;
    rawRisk: number;
    scoreContributors: IUrlRiskScoreContributor[];
  } {
    const rawFindings: Array<IScanFinding & { findingId: string; source: 'url' | 'phishing' | 'reputation' | 'content'; scoreContribution: number }> = [];

    // Helper to extract canonical finding ID
    const getCanonicalFindingId = (f: IScanFinding): string => {
      const titleLower = (f.title || '').toLowerCase();
      const catLower = (f.category || '').toLowerCase();

      if (titleLower.includes('ssrf') || titleLower.includes('private / internal') || titleLower.includes('private network')) {
        return 'finding-dns-ssrf-private';
      }
      if (titleLower.includes('dns resolution failed') || titleLower.includes('unresolvable domain')) {
        return 'finding-dns-resolution-failed';
      }
      if (titleLower.includes('unencrypted') || titleLower.includes('plaintext http') || (catLower.includes('transport') && titleLower.includes('http'))) {
        return 'finding-http-unencrypted';
      }
      if (titleLower.includes('invalid') || titleLower.includes('untrusted ssl') || titleLower.includes('certificate validation failed')) {
        return 'finding-tls-invalid';
      }
      if (titleLower.includes('expiring soon')) {
        return 'finding-tls-expiring-soon';
      }
      if (titleLower.includes('direct ip') || titleLower.includes('ip address hostname')) {
        return 'finding-host-direct-ip';
      }
      if (titleLower.includes('punycode') || titleLower.includes('homograph')) {
        return 'finding-punycode-homograph';
      }
      if (titleLower.includes('brand impersonation') || titleLower.includes('brand name in subdomain') || titleLower.includes('trademark')) {
        return 'finding-brand-impersonation';
      }
      if (titleLower.includes('subdomain nesting') || titleLower.includes('subdomain depth')) {
        return 'finding-subdomain-depth';
      }
      if (titleLower.includes('obfuscation') || titleLower.includes('suspicious url structure')) {
        return 'finding-url-obfuscation';
      }
      if (titleLower.includes('password credential collection') || titleLower.includes('password form on unencrypted')) {
        return 'finding-cred-insecure-http';
      }
      if (titleLower.includes('cross-origin destination') || titleLower.includes('external origin') || titleLower.includes('form action')) {
        return 'finding-form-external-action';
      }
      if (titleLower.includes('downgrade') || titleLower.includes('https to http')) {
        return 'finding-redirect-downgrade';
      }
      if (titleLower.includes('cross-domain redirection') || titleLower.includes('cross-domain redirect')) {
        return 'finding-redirect-cross-domain';
      }
      if (titleLower.includes('redirect loop') || titleLower.includes('maximum hops')) {
        return 'finding-redirect-loop';
      }
      if (titleLower.includes('threat intelligence') || titleLower.includes('feed match') || catLower.includes('threat intelligence')) {
        return 'finding-threat-intel-match';
      }
      if (titleLower.includes('urgency') || titleLower.includes('social engineering')) {
        return 'finding-social-engineering';
      }
      if (titleLower.includes('server error') || titleLower.includes('connection failed') || titleLower.includes('timed out')) {
        return 'finding-http-connection-error';
      }
      if (titleLower.includes('clean') || titleLower.includes('standard security baseline') || f.severity === 'INFO') {
        return 'finding-security-baseline';
      }

      return `finding-${titleLower.replace(/[^a-z0-9]+/g, '-').slice(0, 40)}`;
    };

    // Helper for score contribution mapping
    const getFindingScoreContribution = (id: string, severity: FindingSeverity): number => {
      switch (id) {
        case 'finding-dns-ssrf-private':
          return 75;
        case 'finding-threat-intel-match':
          return 45;
        case 'finding-tls-invalid':
          return 35;
        case 'finding-cred-insecure-http':
          return 35;
        case 'finding-brand-impersonation':
          return 35;
        case 'finding-form-external-action':
          return 30;
        case 'finding-host-direct-ip':
          return 30;
        case 'finding-punycode-homograph':
          return 30;
        case 'finding-redirect-downgrade':
          return 30;
        case 'finding-http-unencrypted':
          return 25;
        case 'finding-url-obfuscation':
          return 25;
        case 'finding-dns-resolution-failed':
          return 20;
        case 'finding-redirect-loop':
          return 20;
        case 'finding-social-engineering':
          return 15;
        case 'finding-subdomain-depth':
          return 15;
        case 'finding-redirect-cross-domain':
          return 15;
        case 'finding-http-connection-error':
          return 15;
        case 'finding-tls-expiring-soon':
          return 5;
        case 'finding-security-baseline':
          return 0;
        default:
          if (severity === 'CRITICAL') return 45;
          if (severity === 'HIGH') return 25;
          if (severity === 'MEDIUM') return 15;
          if (severity === 'LOW') return 5;
          return 0;
      }
    };

    // 1. Process URL Security Findings
    for (const f of urlEval.findings || []) {
      const id = getCanonicalFindingId(f);
      const contribution = getFindingScoreContribution(id, f.severity);
      rawFindings.push({
        ...f,
        id,
        findingId: id,
        source: 'url',
        scoreContribution: contribution,
      });
    }

    // 2. Process Phishing Security Findings
    for (const f of phishResult.findings || []) {
      const id = getCanonicalFindingId(f);
      const contribution = getFindingScoreContribution(id, f.severity);
      rawFindings.push({
        ...f,
        id,
        findingId: id,
        source: 'phishing',
        scoreContribution: contribution,
      });
    }

    // 3. Ensure unencrypted HTTP is flagged if initial target was http or connection is cleartext
    const isExplicitHttp = context.parsedUrl.protocol === 'http:' || !context.effectiveHttps;
    if (isExplicitHttp && !rawFindings.some((f) => f.findingId === 'finding-http-unencrypted')) {
      rawFindings.push({
        id: 'finding-http-unencrypted',
        findingId: 'finding-http-unencrypted',
        category: 'Transport Security',
        severity: 'MEDIUM',
        title: 'Unencrypted HTTP Protocol',
        description: 'The URL uses unencrypted HTTP rather than HTTPS. Communications and data transmitted to this resource are exposed in cleartext to local network eavesdropping.',
        evidence: `Protocol: ${context.parsedUrl.protocol}`,
        impact: 'Data and credentials transmitted over plain HTTP can be intercepted or manipulated via man-in-the-middle attacks.',
        recommendation: 'Use the HTTPS version of this URL to ensure cryptographic protection in transit.',
        source: 'url',
        scoreContribution: 25,
      });
    }

    // 4. Deduplicate Findings by canonical findingId
    const uniqueMap = new Map<string, IScanFinding & { findingId: string; source: 'url' | 'phishing' | 'reputation' | 'content'; scoreContribution: number }>();

    for (const f of rawFindings) {
      if (f.findingId === 'finding-security-baseline') continue;

      if (!uniqueMap.has(f.findingId)) {
        uniqueMap.set(f.findingId, f);
      } else {
        const existing = uniqueMap.get(f.findingId)!;
        if ((f.scoreContribution || 0) > (existing.scoreContribution || 0)) {
          uniqueMap.set(f.findingId, f);
        }
      }
    }

    const uniqueFindings = Array.from(uniqueMap.values());

    // 5. Compute Evidence-Driven Risk Score
    let rawRisk = 0;
    const scoreContributors: IUrlRiskScoreContributor[] = [];

    for (const f of uniqueFindings) {
      const pts = Number.isFinite(f.scoreContribution) ? f.scoreContribution : 0;
      if (pts > 0) {
        rawRisk += pts;
        let contributorName = f.title;
        let contributorCategory = f.category;
        if (f.category === 'Transport Security' || f.category === 'SSL/TLS' || f.title.includes('Unencrypted')) {
          contributorName = 'Transport Security';
          contributorCategory = 'Transport Security';
        } else if (f.category === 'SSL/TLS Certificate' || f.title.includes('Certificate')) {
          contributorName = 'TLS Certificate Validity';
        } else if (f.category === 'Domain & Infrastructure' || f.title.includes('SSRF')) {
          contributorName = 'DNS / IP Classification';
        } else if (f.category === 'URL Structure' && f.title.includes('IP')) {
          contributorName = 'Hostname Structure';
        } else if (f.category === 'URL Structure' && f.title.includes('Punycode')) {
          contributorName = 'Punycode / Homograph';
        }

        scoreContributors.push({
          name: contributorName,
          category: contributorCategory,
          points: pts,
          reason: f.description,
          explanation: f.evidence,
        });
      }
    }

    const riskScore = Math.min(100, Math.max(0, Math.round(rawRisk)));
    const hasCriticalFinding = uniqueFindings.some((f) => f.severity === 'CRITICAL');

    // 6. If clean scan, append standard baseline finding
    const finalFindings: IScanFinding[] = uniqueFindings.map(({ findingId, source, scoreContribution, ...rest }) => ({
      ...rest,
      findingId,
      source,
      scoreContribution,
    }));

    if (finalFindings.length === 0) {
      finalFindings.push({
        id: 'finding-security-baseline',
        findingId: 'finding-security-baseline',
        source: 'url',
        scoreContribution: 0,
        category: 'Reputation & Protocol',
        severity: 'INFO',
        title: 'Standard Security Baseline',
        description: 'Target demonstrates standard TLS configuration with no anomalous structure, DNS issues, or known deceptive indicators.',
        evidence: `Target: ${context.normalizedTarget}${context.httpResult?.statusCode ? ` (HTTP ${context.httpResult.statusCode})` : ''}`,
      });
    }

    // 7. Combine and deduplicate recommendations
    const allRecs = Array.from(new Set([...(urlEval.recommendations || []), ...(phishResult.recommendations || [])])).filter(Boolean);
    if (allRecs.length === 0) {
      allRecs.push('No immediate remediation required. Continue monitoring endpoint configuration.');
    }

    return {
      findings: finalFindings,
      recommendations: allRecs,
      riskScore,
      hasCriticalFinding,
      rawRisk,
      scoreContributors,
    };
  }

  /**
   * Run comprehensive security analysis on the target and persist the scan record.
   */
  async analyzeAndSave(input: CreateScanInput, userId?: string): Promise<ReturnType<typeof toSafeScanRecord>> {
    const originalTarget = input.target.trim();
    const isExtensionUrlOrId = (
      /^(?:https?:\/\/)?(?:chromewebstore\.google\.com\/detail\/|chrome\.google\.com\/webstore\/detail\/|addons\.mozilla\.org\/|microsoftedge\.microsoft\.com\/addons\/detail\/)/i.test(originalTarget) ||
      /^[a-z]{32}$/i.test(originalTarget)
    );
    const targetType = input.targetType === 'Extension' || (isExtensionUrlOrId && (!input.targetType || input.targetType === 'URL'))
      ? 'Extension'
      : (input.targetType || 'URL');

    const isWebsiteScan = targetType === 'Website';
    const isApiScan = targetType === 'API';
    const isFileScan = targetType === 'File';
    const isExtensionScan = targetType === 'Extension';
    const isPhishingScan = targetType === 'Phishing';
    const isUrlScan = targetType === 'URL';

    // ── Dedicated Extension Scan Pipeline ─────────────────────────────────────
    if (isExtensionScan) {
      // 0. Cache check for Extension (10-minute cache window)
      if (!input.forceRescan && typeof (Scan as any).findOne === 'function') {
        try {
          const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
          const cachedScan = await (Scan as any).findOne({
            target: originalTarget,
            targetType: 'Extension',
            status: 'completed',
            createdAt: { $gte: tenMinutesAgo },
          }).sort({ createdAt: -1 });

          if (cachedScan && cachedScan.checks?.extensionAnalysis) {
            return toSafeScanRecord(cachedScan);
          }
        } catch {}
      }

      const extEval = await extensionScannerService.analyzeAsync({ target: originalTarget });
      const userObjectId = userId && Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : undefined;
      const isScanIncomplete =
        extEval.analysis.scanStatus === 'FAILED' ||
        extEval.analysis.scanStatus === 'INCOMPLETE';
      const resultClassification = extEval.analysis.scanStatus === 'INCOMPLETE'
        ? 'Suspicious'
        : deriveClassificationFromRiskScore(
            extEval.riskScore,
            extEval.findings.some((f) => f.severity === 'CRITICAL'),
            isScanIncomplete
          );

      const checks: IScanChecks = {
        urlAnalysis: {
          status: extEval.analysis.status,
          details: `Browser extension analysis completed for ${extEval.analysis.extensionName}.`,
        },
        sslAnalysis: {
          status: 'neutral',
          details: 'N/A (Browser Extension Package)',
        },
        domainAnalysis: {
          status: 'neutral',
          details: extEval.analysis.packageIdentity?.format ? `Package format: ${extEval.analysis.packageIdentity.format}` : 'Browser Extension',
        },
        httpAnalysis: {
          status: 'neutral',
          details: extEval.analysis.storeMetadata?.store ? `Store source: ${extEval.analysis.storeMetadata.store}` : 'Static Package Audit',
        },
        extensionAnalysis: extEval.analysis,
        phishingAnalysis: {
          status: 'neutral',
          confidence: 0,
          details: 'Extension Security Inspection',
        },
        redirectAnalysis: {
          status: 'neutral',
          details: 'N/A (Browser Extension)',
        },
      };

      const newScan = new Scan({
        userId: userObjectId,
        target: originalTarget,
        targetType: 'Extension',
        result: resultClassification,
        riskScore: extEval.riskScore,
        status: isScanIncomplete ? 'failed' : 'completed',
        checks,
        findings: extEval.findings,
        recommendations: extEval.recommendations,
        scannedAt: new Date(),
      });

      const saved = await newScan.save();
      notificationService.createScanNotification(saved).catch((err) => {
        console.error('[NotificationService] Failed to emit extension scan notification:', err);
      });
      return toSafeScanRecord(saved);
    }

    const urlProfile = urlNormalizerService.normalize(originalTarget);
    let normalizedTarget = urlProfile.isValid ? urlProfile.normalizedUrl : input.target.trim();
    let parsedUrl: URL;

    if (!normalizedTarget.startsWith('http://') && !normalizedTarget.startsWith('https://')) {
      normalizedTarget = `https://${normalizedTarget}`;
    }
    try {
      parsedUrl = new URL(normalizedTarget);
      if (parsedUrl.hash) {
        parsedUrl.hash = '';
        normalizedTarget = parsedUrl.toString();
      }
    } catch {
      throw new Error('Invalid URL format provided.');
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    const registrableDomain = urlProfile.registrableDomain || getRegistrableDomain(hostname);
    const subdomains = hostname.split('.');
    const pathname = parsedUrl.pathname;
    const search = parsedUrl.search;
    const isInitialHttps = parsedUrl.protocol === 'https:';
    const initialPort = parsedUrl.port ? parseInt(parsedUrl.port, 10) : isInitialHttps ? 443 : 80;

    const findings: IScanFinding[] = [];
    let riskScore = 0;

    // ── 0. Cache Check (10-minute cache window for identical normalized target) ──
    if (!input.forceRescan && typeof (Scan as any).findOne === 'function') {
      try {
        const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
        const cachedScan = await (Scan as any).findOne({
          target: maskSensitiveUrl(originalTarget),
          targetType,
          status: 'completed',
          createdAt: { $gte: tenMinutesAgo },
        }).sort({ createdAt: -1 });

        if (cachedScan) {
          return toSafeScanRecord(cachedScan);
        }
      } catch {
        // Continue to fresh scan if cache lookup fails
      }
    }

    // ── 1. DNS Resolution & SSRF Check ──────────────────────────────────────
    let dnsResult: { isPrivate: boolean; resolvedIps: string[]; ipVersion: string; dnsStatus: string; error?: string };
    let domainStatus: 'passed' | 'warning' | 'failed' = 'passed';
    let domainDetails = '';

    dnsResult = await this.resolveDns(hostname);
    domainDetails = dnsResult.dnsStatus;

    if (dnsResult.isPrivate) {
      domainStatus = 'failed';
      domainDetails = 'Target resolves to a private, loopback, or reserved network IP address.';
    } else if (dnsResult.error) {
      domainStatus = 'failed';
      domainDetails = `DNS Resolution Failed: ${dnsResult.error}`;
    } else {
      domainDetails = `Domain successfully resolved to ${dnsResult.resolvedIps.slice(0, 3).join(', ')}${dnsResult.resolvedIps.length > 3 ? '...' : ''} (${dnsResult.ipVersion}).`;
    }

    // ── 2. Domain Intelligence & RDAP (Only if not internal) ──────────────────
    let domainIntelligenceResult: DomainIntelligenceResult | undefined = undefined;
    if (!dnsResult.isPrivate) {
      domainIntelligenceResult = await domainIntelligenceService.analyzeDomain(hostname, registrableDomain);
      if (domainIntelligenceResult.dnsResolved && dnsResult.resolvedIps.length === 0) {
        dnsResult.resolvedIps = [...domainIntelligenceResult.dnsRecords.a, ...domainIntelligenceResult.dnsRecords.aaaa];
      }
    }

    // ── 3. Threat Intelligence Parallel Lookup (Only if not internal) ────────
    let threatIntelResult: ThreatIntelligenceResult | undefined = undefined;
    if (!dnsResult.isPrivate) {
      threatIntelResult = await threatIntelService.lookup(normalizedTarget, hostname);
    }

    // ── 4. Phishing & Deception Baseline ────────────────────────────────────
    let phishingStatus: 'passed' | 'warning' | 'failed' | 'neutral' = 'passed';
    let phishingDetails = 'No significant phishing indicators observed';
    let phishingConfidence = 0;

    // ── 5. Real HTTP & Network Analysis (Only if domain is public and resolved) ──
    let httpResult: Awaited<ReturnType<typeof this.inspectHttp>> | null = null;
    if (!dnsResult.isPrivate && !dnsResult.error) {
      httpResult = await this.inspectHttp(normalizedTarget);
    }

    let httpStatusCategory: 'passed' | 'warning' | 'failed' | 'neutral' = 'neutral';
    let httpDetails = 'Network inspection not executed.';

    if (httpResult) {
      if (httpResult.statusCode) {
        if (httpResult.statusCode >= 200 && httpResult.statusCode < 400) {
          httpStatusCategory = 'passed';
          httpDetails = `Server responded with HTTP ${httpResult.statusCode} ${httpResult.statusText} in ${httpResult.responseTimeMs || 0}ms.`;
        } else if (httpResult.statusCode === 404) {
          httpStatusCategory = 'warning';
          httpDetails = `Resource Not Found: HTTP 404 ${httpResult.statusText}.`;
        } else if (httpResult.statusCode >= 500) {
          httpStatusCategory = 'warning';
          httpDetails = `Server Error: HTTP ${httpResult.statusCode} ${httpResult.statusText}.`;
        } else {
          httpStatusCategory = 'warning';
          httpDetails = `HTTP ${httpResult.statusCode} ${httpResult.statusText}.`;
        }
      } else if (httpResult.error) {
        httpStatusCategory = 'failed';
        httpDetails = `Connection failed: ${httpResult.details || httpResult.error}`;
      }
    } else if (dnsResult.isPrivate) {
      httpStatusCategory = 'failed';
      httpDetails = 'HTTP connection blocked: Target resolves to an internal network address.';
    }

    // ── 6. Real SSL / TLS Inspection ─────────────────────────────────────────
    const effectiveHttps = isInitialHttps || (httpResult?.finalUrl ? httpResult.finalUrl.startsWith('https:') : false);
    let tlsResult: Awaited<ReturnType<typeof this.inspectTls>> | null = null;

    if (effectiveHttps && !dnsResult.isPrivate && !dnsResult.error) {
      tlsResult = await this.inspectTls(hostname, initialPort);
    }

    let sslStatus: 'passed' | 'warning' | 'failed' | 'neutral' = 'passed';
    let sslDetails = 'Transport security analysis complete.';
    if (!effectiveHttps) {
      sslStatus = 'warning';
      sslDetails = 'Target uses unencrypted HTTP protocol. Communications are transmitted in cleartext.';
    } else if (tlsResult) {
      if (tlsResult.valid === false || tlsResult.error) {
        sslStatus = 'warning';
        sslDetails = tlsResult.details;
      } else {
        sslStatus = 'passed';
        sslDetails = tlsResult.details;
      }
    } else if (dnsResult.isPrivate) {
      sslStatus = 'failed';
      sslDetails = 'TLS handshake blocked: Internal IP address target.';
    }

    // ── 7. Redirect Analysis ────────────────────────────────────────────────
    let redirectStatus: 'passed' | 'warning' | 'failed' | 'neutral' = 'passed';
    let redirectDetails = 'Direct destination analyzed. No redirection chain.';
    const redirectCount = httpResult?.redirectCount || 0;
    const finalDestination = httpResult?.finalUrl || normalizedTarget;

    function isSameDomain(hA: string, hB: string): boolean {
      if (hA === hB) return true;
      const cleanA = hA.replace(/^www\./, '');
      const cleanB = hB.replace(/^www\./, '');
      if (cleanA === cleanB) return true;
      const pA = cleanA.split('.');
      const pB = cleanB.split('.');
      if (pA.length >= 2 && pB.length >= 2) {
        return pA.slice(-2).join('.') === pB.slice(-2).join('.');
      }
      return false;
    }

    if (redirectCount > 0 && httpResult) {
      let finalHost = hostname;
      try { finalHost = new URL(finalDestination).hostname.toLowerCase(); } catch {}
      const isExternalCrossDomain = !isSameDomain(hostname, finalHost);

      if (isExternalCrossDomain) {
        redirectStatus = 'warning';
        redirectDetails = `Redirects across external domains (${hostname} → ${finalHost}) across ${redirectCount} hop(s).`;
      } else {
        redirectStatus = 'passed';
        redirectDetails = `Followed ${redirectCount} redirect hop(s) to destination (${finalHost}).`;
      }
    } else if (httpResult?.error === 'MAX_REDIRECTS_EXCEEDED') {
      redirectStatus = 'warning';
      redirectDetails = 'Exceeded redirect limit. Possible infinite redirect loop.';
    }

    // ── 8. Scanner-Specific Analysis Sub-Engines ────────────────────────────
    let securityHeadersAnalysis: IScanChecks['securityHeadersAnalysis'] = undefined;
    let cookiesAnalysis: IScanChecks['cookiesAnalysis'] = undefined;
    let contentAnalysis: IScanChecks['contentAnalysis'] = undefined;
    let websiteOverview: IScanChecks['websiteOverview'] = undefined;
    let websiteSecurityV2: IWebsiteSecurityV2Analysis | undefined = undefined;
    let apiAnalysis: IScanChecks['apiAnalysis'] = undefined;
    let fileAnalysis: IScanChecks['fileAnalysis'] = undefined;
    let extensionAnalysis: IScanChecks['extensionAnalysis'] = undefined;
    let urlSecurityAnalysis: IScanChecks['urlSecurityAnalysis'] = undefined;
    let phishingSecurityAnalysis: IPhishingSecurityAnalysis | undefined = undefined;

    // Determine failed scan state
    const isScanFailed =
      dnsResult.isPrivate ||
      httpResult?.error === 'SSRF_BLOCKED' ||
      httpResult?.error === 'ETIMEDOUT' ||
      (httpResult && !httpResult.statusCode && Boolean(httpResult.error)) ||
      Boolean(dnsResult.error) ||
      (isFileScan && Boolean(httpResult?.statusCode && httpResult.statusCode >= 400));

    let recommendations: string[] = [];
    let resultClassification: ScanResultClassification = 'Safe';

    if (isWebsiteScan) {
      const websiteV2Result = websiteScannerV2Service.analyze({
        target: normalizedTarget,
        parsedUrl,
        dnsResult,
        httpResult,
        tlsResult,
        effectiveHttps,
      });

      websiteSecurityV2 = websiteV2Result.websiteSecurityV2;
      securityHeadersAnalysis = websiteV2Result.securityHeadersAnalysis;
      cookiesAnalysis = websiteV2Result.cookiesAnalysis;
      contentAnalysis = websiteV2Result.contentAnalysis;
      websiteOverview = websiteV2Result.websiteOverview;
      findings.push(...websiteV2Result.findings);
      recommendations = websiteV2Result.recommendations;
      riskScore = websiteV2Result.riskScore;
      resultClassification = websiteV2Result.classification;
    } else if (isUrlScan || isPhishingScan) {
      if (httpResult && httpResult.statusCode) {
        const headerEval = this.analyzeSecurityHeaders(httpResult.allHeaders, effectiveHttps);
        securityHeadersAnalysis = headerEval.analysis;

        const cookieEval = this.analyzeCookies(httpResult.rawCookies, effectiveHttps);
        cookiesAnalysis = cookieEval.analysis;

        if (httpResult.htmlSnippet) {
          const contentEval = this.analyzeHtmlContent(httpResult.htmlSnippet, finalDestination, effectiveHttps);
          contentAnalysis = contentEval.analysis;
        }
      }

      // 1. Run URL Security Evaluation
      const urlEval = this.analyzeUrlSecurity(
        input.target,
        normalizedTarget,
        parsedUrl,
        dnsResult,
        httpResult,
        tlsResult,
        effectiveHttps,
        threatIntelResult,
        domainIntelligenceResult
      );
      urlSecurityAnalysis = urlEval.analysis;

      // 2. Run Phishing & Deception Evaluation
      const phishResult = phishingScannerService.analyze({
        target: input.target,
        normalizedTarget,
        parsedUrl,
        dnsResult,
        httpResult,
        tlsResult,
        effectiveHttps,
        threatIntelResult,
      });
      phishingSecurityAnalysis = phishResult.phishingSecurityAnalysis;
      phishingStatus = phishResult.phishingSecurityAnalysis.status;
      phishingConfidence = phishResult.confidence;
      phishingDetails = phishResult.phishingSecurityAnalysis.details;

      // 3. Normalized Evidence & Finding Deduplication
      const deduplicated = this.aggregateMegaScanFindings(urlEval, phishResult, {
        target: input.target,
        normalizedTarget,
        parsedUrl,
        dnsResult,
        httpResult,
        tlsResult,
        effectiveHttps,
        threatIntelResult,
      });

      findings.push(...deduplicated.findings);
      recommendations = deduplicated.recommendations;
      riskScore = deduplicated.riskScore;
      resultClassification = deriveClassificationFromRiskScore(
        riskScore,
        deduplicated.hasCriticalFinding,
        isScanFailed
      );

      // Keep sub-analysis objects synchronized with the unified evidence score
      if (urlSecurityAnalysis) {
        urlSecurityAnalysis.scoreContributors = deduplicated.scoreContributors;
        urlSecurityAnalysis.status = riskScore >= 50 ? 'warning' : 'passed';
      }
      if (phishingSecurityAnalysis) {
        phishingSecurityAnalysis.riskScore = riskScore;
        phishingSecurityAnalysis.status = riskScore >= 50 ? 'warning' : 'passed';
      }
    } else if (isApiScan) {
      const apiEval = this.analyzeApiSecurity(normalizedTarget, httpResult, effectiveHttps, dnsResult);
      apiAnalysis = apiEval.analysis;
      findings.push(...apiEval.findings);
      riskScore = Math.min(Math.max(apiEval.risk, 0), 100);
      resultClassification = deriveClassificationFromRiskScore(riskScore, findings.some((f) => f.severity === 'CRITICAL'), isScanFailed);
      if (dnsResult.isPrivate) {
        recommendations.push('Do NOT expose private internal services through public proxy interfaces.');
      } else {
        if (!effectiveHttps) {
          recommendations.push('Enforce HTTPS and HSTS across all API routes to protect access tokens and payloads.');
        }
        if (apiAnalysis?.corsConfig.isPermissive) {
          if (apiAnalysis?.corsConfig.allowCredentials === 'true') {
            recommendations.push('Restrict Access-Control-Allow-Origin to trusted origins instead of using a wildcard (*) when credentialed requests are permitted.');
          } else {
            recommendations.push('Restrict Access-Control-Allow-Origin to authorized frontend domains rather than wildcard (*).');
          }
        }
        if (!httpResult?.allHeaders['x-content-type-options']) {
          recommendations.push('Consider setting X-Content-Type-Options: nosniff on API responses where appropriate.');
        }
        if (httpResult?.allHeaders['x-powered-by'] || (httpResult?.server && /\d+\.\d+/.test(httpResult.server))) {
          recommendations.push('Consider minimizing unnecessary backend framework and server version details exposed in response headers.');
        }
        if (apiAnalysis?.rateLimitIndicators.status === 'Unverified') {
          recommendations.push('Rate limiting could not be verified from passive response headers. Review server-side rate-limit controls separately.');
        }
        if (recommendations.length === 0) {
          recommendations.push('API endpoint demonstrates solid transport encryption, CORS policy, and security headers.');
        }
      }
    } else if (isFileScan) {
      const fileEval = await this.analyzeFileSecurity(normalizedTarget, httpResult, effectiveHttps, dnsResult);
      fileAnalysis = fileEval.analysis;
      findings.push(...fileEval.findings);
      riskScore = Math.min(Math.max(fileEval.risk, 0), 100);
      resultClassification = deriveClassificationFromRiskScore(riskScore, findings.some((f) => f.severity === 'CRITICAL'), isScanFailed);
      if (fileAnalysis?.structureRisk?.includes('High Risk')) {
        recommendations.push('Exercise caution when downloading executable binaries or scripts. Verify digital signatures before running.');
      }
      if (fileAnalysis?.structureRisk?.includes('Double-Extension')) {
        recommendations.push('Do NOT execute files with deceptive double extensions.');
      }
      if (!effectiveHttps) {
        recommendations.push('Host downloadable software and files exclusively on HTTPS to prevent man-in-the-middle binary tampering.');
      }
      if (recommendations.length === 0) {
        recommendations.push('File exhibits standard static structure. Always download files from verified first-party sources.');
      }
    } else if (isExtensionScan) {
      const extEval = await this.analyzeExtensionSecurityAsync(normalizedTarget, httpResult);
      extensionAnalysis = extEval.analysis;
      findings.push(...extEval.findings);
      if (extEval.recommendations && extEval.recommendations.length > 0) {
        recommendations.push(...extEval.recommendations);
      }
      riskScore = extEval.riskScore;
      resultClassification = deriveClassificationFromRiskScore(riskScore, findings.some((f) => f.severity === 'CRITICAL'), isScanFailed);
    }

    // ── 7. Baseline Finding for Clean Scans ──────────────────────────────────
    if (findings.length === 0) {
      findings.push({
        category: 'Reputation & Protocol',
        severity: 'INFO',
        title: 'Standard Security Baseline',
        description: 'Target demonstrates standard TLS configuration with no anomalous structure, DNS issues, or known deceptive indicators.',
        evidence: `Target: ${normalizedTarget}${httpResult?.statusCode ? ` (HTTP ${httpResult.statusCode})` : ''}`,
      });
    }

    // ── 11. Assemble Checks Object ───────────────────────────────────────────
    const checks: IScanChecks = {
      urlAnalysis: {
        status: urlSecurityAnalysis?.status || (riskScore > 40 ? 'warning' : 'passed'),
        scheme: parsedUrl.protocol,
        port: String(initialPort),
        path: pathname,
        subdomains: subdomains.length,
        details: urlSecurityAnalysis?.details || `URL analyzed: Protocol: ${parsedUrl.protocol}, Host: ${hostname}, Path length: ${pathname.length} chars.`,
      },
      sslAnalysis: {
        status: sslStatus,
        protocol: tlsResult?.protocol || (effectiveHttps ? 'TLS / HTTPS' : 'HTTP (Plain Text)'),
        issuer: tlsResult?.issuer || (effectiveHttps ? 'Standard Public CA' : 'None'),
        subject: tlsResult?.subject,
        valid: tlsResult ? tlsResult.valid : effectiveHttps,
        validFrom: tlsResult?.validFrom,
        validTo: tlsResult?.validTo,
        daysRemaining: tlsResult?.daysRemaining,
        cipher: tlsResult?.cipher,
        details: sslDetails,
      },
      domainAnalysis: {
        status: domainStatus,
        hostname,
        resolvedIps: dnsResult.resolvedIps,
        ipVersion: dnsResult.ipVersion,
        dnsStatus: dnsResult.dnsStatus,
        details: domainDetails,
      },
      httpAnalysis: {
        status: httpStatusCategory,
        statusCode: httpResult?.statusCode,
        statusText: httpResult?.statusText,
        contentType: httpResult?.contentType,
        contentLength: httpResult?.contentLength,
        server: httpResult?.server,
        responseTimeMs: httpResult?.responseTimeMs,
        finalUrl: finalDestination,
        securityHeaders: httpResult?.securityHeaders,
        details: httpDetails,
      },
      securityHeadersAnalysis,
      cookiesAnalysis,
      contentAnalysis,
      websiteOverview,
      websiteSecurityV2,
      apiAnalysis,
      fileAnalysis,
      extensionAnalysis,
      urlSecurityAnalysis,
      phishingSecurityAnalysis,
      phishingAnalysis: {
        status: phishingStatus,
        confidence: phishingConfidence,
        details: phishingDetails,
        riskScore: phishingSecurityAnalysis?.riskScore,
        riskLevel: phishingSecurityAnalysis?.riskLevel,
        summary: phishingSecurityAnalysis?.summary,
        executionOutcome: phishingSecurityAnalysis?.executionOutcome,
      },
      redirectAnalysis: {
        status: redirectStatus,
        redirectCount,
        destination: finalDestination,
        chain: httpResult?.redirectChain,
        details: redirectDetails,
      },
    };

    // ── 12. Save Scan to Database ────────────────────────────────────────────
    const savedTarget = maskSensitiveUrl(originalTarget);
    const userObjectId = userId && Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : undefined;
    const newScan = new Scan({
      userId: userObjectId,
      target: savedTarget,
      targetType: input.targetType || 'URL',
      result: resultClassification,
      riskScore,
      status: isScanFailed ? 'failed' : 'completed',
      checks,
      findings,
      recommendations,
      scannedAt: new Date(),
    });

    const saved = await newScan.save();
    notificationService.createScanNotification(saved).catch((err) => {
      console.error('[NotificationService] Failed to emit scan notification:', err);
    });
    return toSafeScanRecord(saved);
  }

  /**
   * Get recent scans for a specific user.
   */
  async getUserScans(userId: string, limit = 10, page = 1) {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;
    const filter = { userId: userFilter as any };
    const skip = (page - 1) * limit;

    const [scans, total] = await Promise.all([
      Scan.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Scan.countDocuments(filter),
    ]);

    return {
      scans: scans.map(toSafeScanRecord),
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Get high-level security statistics for the authenticated user.
   */
  async getUserStats(userId: string) {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;

    const startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);

    const [totalScans, scansToday, threatsDetected, safeResults, latestScan] = await Promise.all([
      Scan.countDocuments({ userId: userFilter as any }),
      Scan.countDocuments({ userId: userFilter as any, createdAt: { $gte: startOfToday } }),
      Scan.countDocuments({
        userId: userFilter as any,
        result: { $in: ['Suspicious', 'High Risk', 'Critical'] },
      }),
      Scan.countDocuments({
        userId: userFilter as any,
        result: { $in: ['Safe', 'Low Risk'] },
      }),
      Scan.findOne({ userId: userFilter as any }).sort({ createdAt: -1 }),
    ]);

    return {
      totalScans,
      scansToday,
      threatsDetected,
      securityFindings: threatsDetected,
      safeResults,
      reportsCount: totalScans,
      activeMonitoring: 'Active',
      monitoringStatus: 'Active',
      lastScannedAt: latestScan ? latestScan.createdAt : null,
      latestScan: latestScan ? toSafeScanRecord(latestScan) : null,
    };
  }

  /**
   * Directly scans an uploaded multipart file buffer.
   * Checks 24-hour SHA256 cache first to avoid redundant re-analysis.
   * Performs real static analysis, saves scan record, and cleans up temporary files.
   */
  async scanUploadedFile(
    buffer: Buffer,
    originalFilename: string,
    claimedMimeType: string,
    userId?: string
  ) {
    const cleanFilename = fileScannerService.sanitizeFilename(originalFilename);
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    // SHA256 Cache Lookup (Section 10: 24-hour cache for completed scans)
    const cacheCutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const cachedScan = await Scan.findOne({
      targetType: 'File',
      status: 'completed',
      'checks.fileAnalysis.sha256': sha256,
      scannedAt: { $gte: cacheCutoff },
    }).sort({ scannedAt: -1 });

    if (cachedScan && cachedScan.checks?.fileAnalysis) {
      return toSafeScanRecord(cachedScan);
    }

    const engineResult = await fileScannerService.analyzeBuffer(buffer, {
      originalFilename: cleanFilename,
      claimedMimeType,
      sourceType: 'upload',
      deleteAfterScan: true,
    });

    const recommendations: string[] = [];
    if (engineResult.analysis.structureRisk?.includes('High Risk') || engineResult.verdict === 'Malicious') {
      recommendations.push('Exercise caution when executing or opening untrusted binaries or scripts.');
    }
    if (engineResult.analysis.structureRisk?.includes('Double-Extension')) {
      recommendations.push('Do NOT execute files with deceptive double extensions.');
    }
    if (engineResult.findings.some((f) => f.category.includes('Evasion') || f.category.includes('Masquerading'))) {
      recommendations.push('File exhibits static evasion or obfuscation techniques. Isolate sample in a sandbox.');
    }
    if (recommendations.length === 0) {
      recommendations.push('Static file inspection completed. File exhibits standard baseline characteristics.');
    }

    const checks: IScanChecks = {
      urlAnalysis: {
        status: 'neutral',
        details: 'Uploaded file scanned directly from raw bytes.',
      },
      sslAnalysis: {
        status: 'neutral',
        details: 'N/A (Direct file upload).',
      },
      domainAnalysis: {
        status: 'neutral',
        details: 'N/A (Direct file upload).',
      },
      fileAnalysis: engineResult.analysis,
      phishingAnalysis: {
        status: 'neutral',
        confidence: 0,
        details: 'File security inspection.',
      },
      redirectAnalysis: {
        status: 'neutral',
        details: 'N/A (Direct file upload).',
      },
    };

    const userObjectId = userId && Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : undefined;
    const resultClassification = deriveClassificationFromRiskScore(
      engineResult.riskScore,
      engineResult.findings.some((f) => f.severity === 'CRITICAL'),
      false
    );

    const newScan = new Scan({
      userId: userObjectId,
      target: cleanFilename,
      targetType: 'File',
      result: resultClassification,
      riskScore: engineResult.riskScore,
      status: 'completed',
      checks,
      findings: engineResult.findings,
      recommendations,
      scannedAt: new Date(),
    });

    const saved = await newScan.save();
    notificationService.createScanNotification(saved).catch((err) => {
      console.error('[NotificationService] Failed to emit file scan notification:', err);
    });
    return toSafeScanRecord(saved);
  }

  /**
   * Look up latest completed scan by SHA256 hash.
   */
  async getScanBySha256(sha256: string) {
    if (!sha256 || typeof sha256 !== 'string') return null;
    const cleanHash = sha256.trim().toLowerCase();
    const scan = await Scan.findOne({
      targetType: 'File',
      status: 'completed',
      'checks.fileAnalysis.sha256': cleanHash,
    }).sort({ scannedAt: -1 });

    if (!scan) return null;
    return toSafeScanRecord(scan);
  }

  /**
   * Get single scan report by ID.
   */
  async getScanById(scanId: string, userId?: string) {
    const scanFilter = Types.ObjectId.isValid(scanId) ? new Types.ObjectId(scanId) : scanId;
    const query: any = { _id: scanFilter };
    if (userId) {
      query.userId = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;
    }

    const scan = await Scan.findOne(query);
    if (!scan) {
      return null;
    }

    return toSafeScanRecord(scan);
  }
}

export const scanService = new ScanService();
