import { NormalizedIndicator, ThreatIntelIndicatorType } from '@cyberwatch/shared';
import { isIP } from 'net';

/**
 * Normalizes, categorizes, and validates security indicators (URL, Domain, IPv4/6, Hashes, Extension IDs).
 * Also defangs / refangs common security feed notations (e.g. hxxps://, [.]).
 */
export class IndicatorNormalizer {
  /**
   * Refangs / standardizes defanged security text.
   */
  public static refang(input: string): string {
    if (!input || typeof input !== 'string') return '';
    let cleaned = input.trim();

    // Remove wrapping quotes/brackets
    cleaned = cleaned.replace(/^["'`<(\[]+|[>"'`\])]+$/g, '');

    // Refang protocol
    cleaned = cleaned.replace(/^hxxps:\/\//i, 'https://');
    cleaned = cleaned.replace(/^hxxp:\/\//i, 'http://');
    cleaned = cleaned.replace(/^fxp:\/\//i, 'ftp://');

    // Refang bracketed dots, colons, slashes
    cleaned = cleaned.replace(/\[\.\]|\(\.\)|\[dot\]|\(dot\)/gi, '.');
    cleaned = cleaned.replace(/\[:\]|\(:\)|\[colon\]|\(colon\)/gi, ':');
    cleaned = cleaned.replace(/\[\/\]|\(\/\)|\[slash\]|\(slash\)/gi, '/');

    return cleaned.trim();
  }

  /**
   * Evaluates if an IPv4 address is in a private/loopback/link-local/multicast/reserved space.
   */
  public static isPrivateOrReservedIPv4(ip: string): boolean {
    const parts = ip.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some(isNaN)) return false;

    const [a, b] = parts;
    // 0.0.0.0/8
    if (a === 0) return true;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 169.254.0.0/16 (Link-local)
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12 (172.16.0.0 – 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 224.0.0.0/4 (Multicast / Reserved)
    if (a >= 224) return true;

    return false;
  }

  /**
   * Evaluates if an IPv6 address is in a private/loopback/link-local/reserved space.
   */
  public static isPrivateOrReservedIPv6(ip: string): boolean {
    const lower = ip.toLowerCase().trim();
    if (lower === '::1' || lower === '::' || lower === '0:0:0:0:0:0:0:1' || lower === '0:0:0:0:0:0:0:0') {
      return true;
    }
    // fc00::/7 (Unique Local)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    // fe80::/10 (Link-Local)
    if (lower.startsWith('fe80') || lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
      return true;
    }
    return false;
  }

  /**
   * Primary indicator normalization and classification method.
   */
  public static normalize(rawInput: string): NormalizedIndicator {
    if (!rawInput || typeof rawInput !== 'string' || !rawInput.trim()) {
      return {
        raw: rawInput || '',
        type: 'DOMAIN',
        canonical: '',
        normalized: '',
        display: '',
        isValid: false,
        validationError: 'Indicator cannot be empty.',
      };
    }

    const refanged = this.refang(rawInput);

    // 1. MD5 Hash check (32 hex characters)
    if (/^[a-fA-F0-9]{32}$/.test(refanged)) {
      const canonical = refanged.toLowerCase();
      return {
        raw: rawInput,
        type: 'HASH_MD5',
        canonical,
        normalized: canonical,
        display: canonical,
        isValid: true,
        metadata: { hashType: 'MD5' },
      };
    }

    // 2. SHA-1 Hash check (40 hex characters)
    if (/^[a-fA-F0-9]{40}$/.test(refanged)) {
      const canonical = refanged.toLowerCase();
      return {
        raw: rawInput,
        type: 'HASH_SHA1',
        canonical,
        normalized: canonical,
        display: canonical,
        isValid: true,
        metadata: { hashType: 'SHA1' },
      };
    }

    // 3. SHA-256 Hash check (64 hex characters)
    if (/^[a-fA-F0-9]{64}$/.test(refanged)) {
      const canonical = refanged.toLowerCase();
      return {
        raw: rawInput,
        type: 'HASH_SHA256',
        canonical,
        normalized: canonical,
        display: canonical,
        isValid: true,
        metadata: { hashType: 'SHA256' },
      };
    }

    // 4. Chrome / Edge Extension ID (32 alphabetic characters [a-p]{32})
    if (/^[a-pA-P]{32}$/.test(refanged)) {
      const canonical = refanged.toLowerCase();
      return {
        raw: rawInput,
        type: 'EXTENSION_ID',
        canonical,
        normalized: canonical,
        display: canonical,
        isValid: true,
        metadata: { extensionStore: 'Chrome' },
      };
    }

    // 4b. Firefox Extension ID ({guid} or name@domain)
    if (
      /^\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\}$/.test(refanged) ||
      /^[\w.-]+@[\w.-]+$/.test(refanged)
    ) {
      const canonical = refanged.trim();
      return {
        raw: rawInput,
        type: 'EXTENSION_ID',
        canonical,
        normalized: canonical,
        display: canonical,
        isValid: true,
        metadata: { extensionStore: 'Firefox' },
      };
    }

    // 5. IP Address Check (IPv4 / IPv6)
    const ipVersion = isIP(refanged);
    if (ipVersion === 4) {
      const isPrivate = this.isPrivateOrReservedIPv4(refanged);
      return {
        raw: rawInput,
        type: 'IP',
        canonical: refanged,
        normalized: refanged,
        display: refanged,
        isValid: true,
        isPrivate,
        metadata: { ipVersion: 'IPv4' },
      };
    }

    if (ipVersion === 6) {
      const canonical = refanged.toLowerCase();
      const isPrivate = this.isPrivateOrReservedIPv6(canonical);
      return {
        raw: rawInput,
        type: 'IP',
        canonical,
        normalized: canonical,
        display: canonical,
        isValid: true,
        isPrivate,
        metadata: { ipVersion: 'IPv6' },
      };
    }

    // 6. URL check
    // If it starts with http:// or https:// or ftp:// or contains a path/query after a slash
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(refanged);
    const hasPathOrQuery = !hasScheme && refanged.includes('/') && !refanged.endsWith('/');

    if (hasScheme || hasPathOrQuery) {
      const candidateUrl = hasScheme ? refanged : `http://${refanged}`;
      try {
        const parsed = new URL(candidateUrl);
        // Ensure host is valid
        if (!parsed.hostname || parsed.hostname.includes(' ')) {
          throw new Error('Invalid URL hostname');
        }

        const hostname = parsed.hostname.toLowerCase();
        const hostIpVer = isIP(hostname);
        const isPrivate =
          hostIpVer === 4
            ? this.isPrivateOrReservedIPv4(hostname)
            : hostIpVer === 6
            ? this.isPrivateOrReservedIPv6(hostname)
            : hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal');

        // Check for extension store URLs (Chrome Web Store, Edge Addons, AMO)
        if (hostname.includes('chromewebstore.google.com') || hostname.includes('chrome.google.com')) {
          const match = parsed.pathname.match(/\/detail\/(?:[^\/]+\/)?([a-p]{32})/i);
          if (match && match[1]) {
            const extId = match[1].toLowerCase();
            return {
              raw: rawInput,
              type: 'EXTENSION_ID',
              canonical: extId,
              normalized: extId,
              display: `${extId} (from Chrome Web Store URL)`,
              isValid: true,
              metadata: { extensionStore: 'Chrome' },
            };
          }
        }

        const canonical = parsed.toString();
        return {
          raw: rawInput,
          type: 'URL',
          canonical,
          normalized: canonical,
          display: canonical,
          isValid: true,
          isPrivate,
          metadata: {
            hostname,
            domain: hostname,
            path: parsed.pathname + parsed.search,
          },
        };
      } catch (err: any) {
        // Fall through to domain or rejection
      }
    }

    // 7. Domain / FQDN check
    const cleanDomain = refanged.replace(/\/+$/, '').toLowerCase();

    // Domain regex supporting labels with letters, numbers, hyphens, and standard TLDs or punycode
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

    if (domainRegex.test(cleanDomain) && !cleanDomain.includes('..')) {
      const isPunycode = cleanDomain.includes('xn--');
      const parts = cleanDomain.split('.');
      const registrableDomain = parts.slice(-2).join('.');
      const isPrivate = cleanDomain === 'localhost' || cleanDomain.endsWith('.local') || cleanDomain.endsWith('.internal');

      return {
        raw: rawInput,
        type: 'DOMAIN',
        canonical: cleanDomain,
        normalized: cleanDomain,
        display: cleanDomain,
        isValid: true,
        isPrivate,
        metadata: {
          domain: cleanDomain,
          hostname: cleanDomain,
          registrableDomain,
        },
      };
    }

    // 8. If none matched, mark invalid
    return {
      raw: rawInput,
      type: 'DOMAIN',
      canonical: refanged,
      normalized: refanged,
      display: rawInput,
      isValid: false,
      validationError: `Unable to recognize indicator format. Please provide a valid URL, domain, IPv4/IPv6, MD5/SHA1/SHA256 hash, or extension ID.`,
    };
  }
}
