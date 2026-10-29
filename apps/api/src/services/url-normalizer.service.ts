import { URL } from 'node:url';
import { getRegistrableDomain, isPrivateOrReservedIp, maskSensitiveUrl } from './scan.service';

export interface NormalizedUrlProfile {
  isValid: boolean;
  validationError?: string;

  originalUrl: string;
  normalizedUrl: string;
  scheme: 'http' | 'https' | string;
  hostname: string;
  registrableDomain: string;
  port: string;
  isCustomPort: boolean;
  path: string;
  query: string;
  fragment: string;
  username?: string;
  hasPassword: boolean;

  punycodeHostname: string;
  decodedHostname: string;

  urlLength: number;
  hostnameLength: number;
  pathLength: number;
  queryLength: number;
  subdomainCount: number;
  subdomainsList: string[];
  pathSegments: string[];
  pathDepth: number;
  queryParams: Record<string, string>;
  queryParamKeys: string[];
  queryCount: number;

  // Detections & Heuristic Signals
  isMalformed: boolean;
  hasEmbeddedCredentials: boolean;
  isDirectIp: boolean;
  isPrivateIp: boolean;
  hasPunycode: boolean;
  isUnicodeHostname: boolean;
  excessiveSubdomains: boolean;
  excessiveUrlLength: boolean;
  hasSuspiciousEncoding: boolean;
  encodedSequences: string[];
  hasNestedUrls: boolean;
  nestedUrls: string[];
  redirectParameters: string[];
  suspiciousQueryParams: string[];
  suspiciousPatterns: string[];
}

export class UrlNormalizerService {
  /**
   * Safe URL normalization & deep structural analysis.
   */
  public normalize(rawUrl: string): NormalizedUrlProfile {
    const originalUrl = (rawUrl || '').trim();
    if (!originalUrl) {
      return this.createInvalidProfile(originalUrl, 'Empty or undefined URL input.');
    }

    let candidateUrl = originalUrl;

    // Check for schema presence
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(candidateUrl)) {
      // If starts with "//", prepend "https:"
      if (candidateUrl.startsWith('//')) {
        candidateUrl = `https:${candidateUrl}`;
      } else {
        candidateUrl = `https://${candidateUrl}`;
      }
    }

    let parsed: URL;
    try {
      parsed = new URL(candidateUrl);
    } catch (err: any) {
      return this.createInvalidProfile(originalUrl, `Malformed URL syntax: ${err.message}`);
    }

    // Only HTTP and HTTPS are permitted for web/URL scanning
    const scheme = parsed.protocol.replace(':', '').toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return this.createInvalidProfile(originalUrl, `Unsupported protocol scheme "${scheme}:". Only HTTP and HTTPS are permitted.`);
    }

    // Extract raw components before redaction
    const username = parsed.username ? decodeURIComponent(parsed.username) : undefined;
    const hasPassword = Boolean(parsed.password);
    const fragment = parsed.hash ? parsed.hash.slice(1) : '';

    // Remove userinfo and hash for the normalized network URL
    parsed.username = '';
    parsed.password = '';
    const rawFragment = parsed.hash;
    parsed.hash = '';

    const normalizedUrl = parsed.toString();
    const hostname = parsed.hostname.toLowerCase();
    const registrableDomain = getRegistrableDomain(hostname);

    const defaultPort = scheme === 'https' ? '443' : '80';
    const port = parsed.port || defaultPort;
    const isCustomPort = Boolean(parsed.port && parsed.port !== '80' && parsed.port !== '443');

    const path = parsed.pathname || '/';
    const query = parsed.search ? parsed.search.slice(1) : '';

    // Subdomains breakdown
    const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
    const isPrivateIp = isDirectIp ? isPrivateOrReservedIp(hostname) : isPrivateOrReservedIp(hostname);

    const hostParts = hostname.split('.');
    const subdomainsList = isDirectIp
      ? []
      : hostParts.length > 2
      ? hostParts.slice(0, registrableDomain ? -registrableDomain.split('.').length : -2)
      : [];
    const subdomainCount = subdomainsList.length;

    // Path analysis
    const pathSegments = path.split('/').filter(Boolean);
    const pathDepth = pathSegments.length;

    // Query analysis
    const queryParams: Record<string, string> = {};
    const queryParamKeys: string[] = [];
    parsed.searchParams.forEach((val, key) => {
      queryParams[key] = val;
      queryParamKeys.push(key);
    });
    const queryCount = queryParamKeys.length;

    // Punycode & Unicode detection
    const punycodeLabels = hostParts.filter((p) => p.startsWith('xn--'));
    const hasPunycode = punycodeLabels.length > 0;
    const isUnicodeHostname = /[^\u0000-\u007F]/.test(originalUrl);
    const punycodeHostname = hostname;
    let decodedHostname = hostname;
    try {
      // Decode punycode if applicable
      decodedHostname = new URL(candidateUrl).hostname;
    } catch {}

    // Encoded character extraction
    const encodedMatches = Array.from(originalUrl.matchAll(/%([0-9a-fA-F]{2})/g)).map((m) => m[0]);
    const encodedSequences = Array.from(new Set(encodedMatches));
    const hasSuspiciousEncoding = encodedMatches.length > 4 || originalUrl.includes('%25');

    // Nested URLs detection (e.g. ?url=https:// or /https:// inside path/query)
    const nestedUrls: string[] = [];
    const nestedMatches = originalUrl.match(/https?%3A%2F%2F[^\s&"']+|https?:\/\/[^\s&"']+/gi) || [];
    if (nestedMatches.length > 1) {
      nestedMatches.slice(1).forEach((u) => nestedUrls.push(decodeURIComponent(u)));
    }

    // Redirect parameter detection
    const redirectParamKeys = ['url', 'redirect', 'next', 'dest', 'destination', 'target', 'r', 'out', 'link', 'goto', 'return', 'forward'];
    const redirectParameters = queryParamKeys.filter((k) => redirectParamKeys.includes(k.toLowerCase()));

    // Suspicious query params (credentials, sessions)
    const sensitiveParamKeys = ['token', 'access_token', 'password', 'passwd', 'pwd', 'session', 'session_id', 'auth', 'key', 'secret', 'jwt'];
    const suspiciousQueryParams = queryParamKeys.filter((k) => sensitiveParamKeys.includes(k.toLowerCase()));

    // Suspicious patterns
    const suspiciousPatterns: string[] = [];
    if (username || hasPassword || originalUrl.includes('@')) {
      suspiciousPatterns.push('Embedded credentials in URL userinfo (@)');
    }
    if (originalUrl.includes('%00')) {
      suspiciousPatterns.push('Null byte (%00) injection pattern');
    }
    if (path.includes('..') || originalUrl.includes('%2e%2e') || originalUrl.includes('%2E%2E')) {
      suspiciousPatterns.push('Directory traversal sequence (..)');
    }
    if (path.includes('//')) {
      suspiciousPatterns.push('Multiple consecutive slashes (//) path obfuscation');
    }
    if (hasSuspiciousEncoding) {
      suspiciousPatterns.push(`Excessive percent-encoding (${encodedMatches.length} sequences)`);
    }
    if (isCustomPort && !['8080', '8443', '3000', '5000', '8000', '8888'].includes(port)) {
      suspiciousPatterns.push(`Non-standard web port (${port})`);
    }
    if (nestedUrls.length > 0) {
      suspiciousPatterns.push(`Nested destination URL detected in parameters (${nestedUrls[0]})`);
    }
    if (hasPunycode) {
      suspiciousPatterns.push(`Punycode IDN homograph label (${punycodeLabels.join(', ')})`);
    }

    return {
      isValid: true,
      originalUrl,
      normalizedUrl,
      scheme,
      hostname,
      registrableDomain,
      port,
      isCustomPort,
      path,
      query,
      fragment: rawFragment ? rawFragment.slice(1) : fragment,
      username,
      hasPassword,

      punycodeHostname,
      decodedHostname,

      urlLength: originalUrl.length,
      hostnameLength: hostname.length,
      pathLength: path.length,
      queryLength: query.length,
      subdomainCount,
      subdomainsList,
      pathSegments,
      pathDepth,
      queryParams,
      queryParamKeys,
      queryCount,

      isMalformed: false,
      hasEmbeddedCredentials: Boolean(username || hasPassword || originalUrl.includes('@')),
      isDirectIp,
      isPrivateIp,
      hasPunycode,
      isUnicodeHostname,
      excessiveSubdomains: subdomainCount > 3,
      excessiveUrlLength: originalUrl.length > 120,
      hasSuspiciousEncoding,
      encodedSequences,
      hasNestedUrls: nestedUrls.length > 0,
      nestedUrls,
      redirectParameters,
      suspiciousQueryParams,
      suspiciousPatterns,
    };
  }

  private createInvalidProfile(originalUrl: string, error: string): NormalizedUrlProfile {
    return {
      isValid: false,
      validationError: error,
      originalUrl: originalUrl || '',
      normalizedUrl: originalUrl || '',
      scheme: 'invalid',
      hostname: '',
      registrableDomain: '',
      port: '0',
      isCustomPort: false,
      path: '',
      query: '',
      fragment: '',
      hasPassword: false,
      punycodeHostname: '',
      decodedHostname: '',
      urlLength: (originalUrl || '').length,
      hostnameLength: 0,
      pathLength: 0,
      queryLength: 0,
      subdomainCount: 0,
      subdomainsList: [],
      pathSegments: [],
      pathDepth: 0,
      queryParams: {},
      queryParamKeys: [],
      queryCount: 0,
      isMalformed: true,
      hasEmbeddedCredentials: false,
      isDirectIp: false,
      isPrivateIp: false,
      hasPunycode: false,
      isUnicodeHostname: false,
      excessiveSubdomains: false,
      excessiveUrlLength: false,
      hasSuspiciousEncoding: false,
      encodedSequences: [],
      hasNestedUrls: false,
      nestedUrls: [],
      redirectParameters: [],
      suspiciousQueryParams: [],
      suspiciousPatterns: ['Malformed or invalid URL syntax'],
    };
  }
}

export const urlNormalizerService = new UrlNormalizerService();
