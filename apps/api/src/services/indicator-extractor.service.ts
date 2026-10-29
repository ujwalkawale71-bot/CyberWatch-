import { IndicatorNormalizer } from '../utils/indicator-normalizer';
import { ExtractedIndicator } from '@cyberwatch/shared';

export class IndicatorExtractorService {
  /**
   * Deterministically extracts indicators from actual scanner inputs and execution results.
   * NEVER invents indicators or extracts phantom values.
   */
  public static extractFromScanner(
    scannerType: 'URL' | 'Website' | 'API' | 'Phishing' | 'File' | 'Extension',
    target: string,
    scanResult?: any
  ): ExtractedIndicator[] {
    const extracted: ExtractedIndicator[] = [];
    const seen = new Set<string>();

    const addIndicator = (raw: string | undefined, contextSource: string, isPrimary = false) => {
      if (!raw || typeof raw !== 'string' || !raw.trim()) return;
      const normalized = IndicatorNormalizer.normalize(raw.trim());
      if (!normalized.isValid) return;

      const key = `${normalized.type}:${normalized.canonical}`;
      if (seen.has(key)) return;
      seen.add(key);

      extracted.push({
        originalValue: raw.trim(),
        normalizedValue: normalized.canonical,
        type: normalized.type,
        contextSource,
        isPrimary,
      });
    };

    // 1. Primary target input
    addIndicator(target, `${scannerType} Scanner Target`, true);

    if (!scanResult) return extracted;

    // 2. Scanner-specific extraction
    if (scannerType === 'URL' || scannerType === 'Phishing' || scannerType === 'API') {
      const urlSec = scanResult.checks?.urlSecurityAnalysis || scanResult.analysis || scanResult;
      if (urlSec?.finalUrl && urlSec.finalUrl !== target) {
        addIndicator(urlSec.finalUrl, 'Resolved Final URL');
      }
      if (urlSec?.finalHostname) {
        addIndicator(urlSec.finalHostname, 'Resolved Final Hostname');
      }
      if (urlSec?.registrableDomain) {
        addIndicator(urlSec.registrableDomain, 'Registrable Domain');
      }
      const domain = scanResult.checks?.domainAnalysis;
      if (domain?.resolvedIps && Array.isArray(domain.resolvedIps)) {
        for (const ip of domain.resolvedIps) {
          addIndicator(ip, 'Resolved Host IP');
        }
      }
      if (urlSec?.redirectJourney?.hops && Array.isArray(urlSec.redirectJourney.hops)) {
        for (const hop of urlSec.redirectJourney.hops) {
          addIndicator(hop.url, 'Redirect Journey Hop URL');
          addIndicator(hop.hostname, 'Redirect Hop Domain');
        }
      }
    } else if (scannerType === 'Website') {
      const webSec = scanResult.checks?.websiteAnalysis || scanResult.analysis || scanResult;
      if (webSec?.canonicalUrl && webSec.canonicalUrl !== target) {
        addIndicator(webSec.canonicalUrl, 'Website Canonical URL');
      }
      if (webSec?.domain) {
        addIndicator(webSec.domain, 'Website Target Domain');
      }
      if (webSec?.externalResources?.externalDomains && Array.isArray(webSec.externalResources.externalDomains)) {
        for (const d of webSec.externalResources.externalDomains.slice(0, 10)) {
          addIndicator(d, 'Discovered External Resource Domain');
        }
      }
    } else if (scannerType === 'File') {
      const fileSec = scanResult.checks?.fileAnalysis || scanResult.analysis || scanResult;
      if (fileSec?.sha256) {
        addIndicator(fileSec.sha256, 'File SHA-256 Checksum', true);
      }
      if (fileSec?.sha1) {
        addIndicator(fileSec.sha1, 'File SHA-1 Checksum');
      }
      if (fileSec?.md5) {
        addIndicator(fileSec.md5, 'File MD5 Checksum');
      }
    } else if (scannerType === 'Extension') {
      const extSec = scanResult.checks?.extensionAnalysis || scanResult.analysis || scanResult;
      if (extSec?.extensionId) {
        addIndicator(extSec.extensionId, 'Extension Store Identifier', true);
      }
      if (extSec?.packageIdentity?.sha256) {
        addIndicator(extSec.packageIdentity.sha256, 'Extension Package SHA-256');
      }
      if (extSec?.packageIdentity?.md5) {
        addIndicator(extSec.packageIdentity.md5, 'Extension Package MD5');
      }
    }

    return extracted;
  }
}
