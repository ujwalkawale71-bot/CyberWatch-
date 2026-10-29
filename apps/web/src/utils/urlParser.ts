export interface ParsedTargetUrl {
  fullUrl: string;
  protocol: string;
  scheme: string;
  hostname: string;
  hostnameLength: number;
  domain: string;
  subdomain: string;
  tld: string;
  port: string;
  path: string;
  pathname: string;
  pathDepth: number;
  search: string;
  queryParameters: Array<{ key: string; value: string }>;
  queryParamKeys: string[];
  queryCount: number;
  fragment: string;
  urlLength: number;
  isIpAddress: boolean;
  subdomainCount: number;
  hasPercentEncoding: boolean;
  isPunycode: boolean;
}

export const SENSITIVE_PARAM_REGEX = /^(token|access_token|id_token|refresh_token|auth_token|api_key|apikey|key|secret|client_secret|password|passwd|pwd|pass|session|session_id|sessionid|sid|phpsessid|jsessionid|auth|authorization|signature|sig|code|verification_code|reset_token|jwt|bearer)$/i;

export function maskSensitiveValue(key: string, value: string): string {
  if (SENSITIVE_PARAM_REGEX.test(key)) {
    return 'REDACTED';
  }
  return value;
}

/**
 * Mask sensitive query parameters from a URL string.
 */
export function maskUrlString(rawUrl: string): string {
  if (!rawUrl) return rawUrl;
  try {
    let normalized = rawUrl.trim();
    const hasScheme = normalized.startsWith('http://') || normalized.startsWith('https://');
    if (!hasScheme) {
      normalized = `https://${normalized}`;
    }
    const u = new URL(normalized);
    let changed = false;
    u.searchParams.forEach((val, key) => {
      if (SENSITIVE_PARAM_REGEX.test(key) && val !== 'REDACTED') {
        u.searchParams.set(key, 'REDACTED');
        changed = true;
      }
    });
    if (!changed) return rawUrl;
    return hasScheme ? u.href : u.href.replace(/^https?:\/\//, '');
  } catch {
    return rawUrl;
  }
}

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
 * Safely parse a target URL string into verified constituent parts.
 * Masks sensitive query parameters (tokens, keys, passwords, session ids).
 */
export function parseTargetUrl(rawUrl: string): ParsedTargetUrl {
  let normalized = rawUrl.trim();
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
    normalized = `https://${normalized}`;
  }

  try {
    const urlObj = new URL(normalized);
    const hostname = urlObj.hostname.toLowerCase();
    const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');

    const hostParts = hostname.split('.');
    let tld = 'N/A';
    let domain = hostname;
    let subdomain = 'None';
    let subCount = 0;

    if (!isIpAddress && hostParts.length >= 2) {
      domain = getRegistrableDomain(hostname);
      const domParts = domain.split('.');
      tld = `.${domParts.slice(1).join('.')}`;
      if (hostname !== domain) {
        subdomain = hostname.slice(0, -(domain.length + 1));
        subCount = subdomain.split('.').length;
      }
    }

    const queryParams: Array<{ key: string; value: string }> = [];
    const queryParamKeys: string[] = [];
    const maskedSearchParams = new URLSearchParams();

    urlObj.searchParams.forEach((value, key) => {
      queryParamKeys.push(key);
      const maskedVal = maskSensitiveValue(key, value);
      queryParams.push({ key, value: maskedVal });
      maskedSearchParams.append(key, maskedVal);
    });

    const maskedSearch = queryParams.length > 0 ? `?${maskedSearchParams.toString()}` : '';
    const maskedUrlObj = new URL(urlObj.href);
    maskedUrlObj.search = maskedSearch;

    const defaultPort = urlObj.protocol === 'https:' ? '443' : '80';
    const port = urlObj.port || defaultPort;
    const pathSegments = urlObj.pathname.split('/').filter(Boolean);
    const pathDepth = pathSegments.length;
    const hasPercentEncoding = /%[0-9a-fA-F]{2}/.test(urlObj.href);
    const isPunycode = hostname.includes('xn--');

    return {
      fullUrl: maskedUrlObj.href,
      protocol: urlObj.protocol.replace(':', '').toUpperCase(),
      scheme: urlObj.protocol,
      hostname,
      hostnameLength: hostname.length,
      domain,
      subdomain,
      tld,
      port,
      path: urlObj.pathname || '/',
      pathname: urlObj.pathname || '/',
      pathDepth,
      search: maskedSearch,
      queryParameters: queryParams,
      queryParamKeys,
      queryCount: queryParams.length,
      fragment: urlObj.hash || 'None',
      urlLength: maskedUrlObj.href.length,
      isIpAddress,
      subdomainCount: isIpAddress ? 0 : subCount,
      hasPercentEncoding,
      isPunycode,
    };
  } catch {
    const isHttp = rawUrl.startsWith('http://');
    return {
      fullUrl: maskUrlString(rawUrl),
      protocol: isHttp ? 'HTTP' : 'HTTPS',
      scheme: isHttp ? 'http:' : 'https:',
      hostname: rawUrl,
      hostnameLength: rawUrl.length,
      domain: rawUrl,
      subdomain: 'None',
      tld: 'N/A',
      port: isHttp ? '80' : '443',
      path: '/',
      pathname: '/',
      pathDepth: 0,
      search: '',
      queryParameters: [],
      queryParamKeys: [],
      queryCount: 0,
      fragment: 'None',
      urlLength: rawUrl.length,
      isIpAddress: false,
      subdomainCount: 0,
      hasPercentEncoding: false,
      isPunycode: false,
    };
  }
}
