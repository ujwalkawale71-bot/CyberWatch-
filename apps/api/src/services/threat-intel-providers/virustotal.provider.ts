import {
  NormalizedIndicator,
  ThreatIntelIndicatorType,
  ThreatIntelProviderResult,
  ThreatIntelCategory,
  ThreatIntelEvidenceItem,
  ThreatIntelRelatedIndicator,
} from '@cyberwatch/shared';
import { ThreatIntelligenceProvider, sanitizeMetadata } from './base.provider';
import { env } from '../../config/env';

export class VirusTotalProvider implements ThreatIntelligenceProvider {
  public readonly id = 'virustotal';
  public readonly name = 'VirusTotal';
  public readonly supportedTypes: ThreatIntelIndicatorType[] = [
    'URL',
    'DOMAIN',
    'IP',
    'HASH_MD5',
    'HASH_SHA1',
    'HASH_SHA256',
  ];

  public isConfigured(): boolean {
    const key = process.env.VIRUSTOTAL_API_KEY || env.VIRUSTOTAL_API_KEY;
    return Boolean(key && key.trim().length > 0);
  }

  public async lookup(indicator: NormalizedIndicator): Promise<ThreatIntelProviderResult> {
    const apiKey = (process.env.VIRUSTOTAL_API_KEY || env.VIRUSTOTAL_API_KEY || '').trim();
    const now = new Date().toISOString();

    if (!this.isConfigured() || !apiKey) {
      return {
        providerId: this.id,
        providerName: this.name,
        configured: false,
        status: 'NOT_CONFIGURED',
        reputation: 'NOT_CONFIGURED',
        queryType: indicator.type,
        timestamp: now,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: 'VirusTotal API key is not configured in this environment.',
      };
    }

    if (indicator.isPrivate) {
      return {
        providerId: this.id,
        providerName: this.name,
        configured: true,
        status: 'SUCCESS',
        reputation: 'INFORMATIONAL',
        queryType: indicator.type,
        timestamp: now,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: 'Target indicator resides in private/reserved network space. External VirusTotal lookup skipped for SSRF safety.',
      };
    }

    // Build endpoint based on indicator type
    let endpoint = '';
    if (indicator.type === 'URL') {
      const urlId = Buffer.from(indicator.canonical)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    } else if (indicator.type === 'DOMAIN') {
      endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator.canonical)}`;
    } else if (indicator.type === 'IP') {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator.canonical)}`;
    } else if (
      indicator.type === 'HASH_MD5' ||
      indicator.type === 'HASH_SHA1' ||
      indicator.type === 'HASH_SHA256'
    ) {
      endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator.canonical)}`;
    } else {
      return {
        providerId: this.id,
        providerName: this.name,
        configured: true,
        status: 'FAILED',
        reputation: 'UNKNOWN',
        queryType: indicator.type,
        timestamp: now,
        errorCategory: 'UNSUPPORTED_TYPE',
        errorMessage: `VirusTotal does not support indicator type ${indicator.type}`,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: `Indicator type ${indicator.type} is not supported by VirusTotal API.`,
      };
    }

    const startTime = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    try {
      const res = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'x-apikey': apiKey,
          Accept: 'application/json',
        },
        signal: controller.signal,
      });

      clearTimeout(timer);
      const responseTimeMs = Date.now() - startTime;

      if (res.status === 404) {
        return {
          providerId: this.id,
          providerName: this.name,
          configured: true,
          status: 'SUCCESS',
          reputation: 'NO_MATCH',
          queryType: indicator.type,
          responseTimeMs,
          timestamp: now,
          detectionSummary: {
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
          },
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: 'Target indicator was not found in the VirusTotal intelligence database (no malicious records submitted).',
        };
      }

      if (res.status === 429) {
        return {
          providerId: this.id,
          providerName: this.name,
          configured: true,
          status: 'RATE_LIMITED',
          reputation: 'UNAVAILABLE',
          queryType: indicator.type,
          responseTimeMs,
          timestamp: now,
          errorCategory: 'RATE_LIMITED',
          errorMessage: 'VirusTotal API rate limit reached.',
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: 'VirusTotal rate limit exceeded for the configured API key.',
        };
      }

      if (!res.ok) {
        return {
          providerId: this.id,
          providerName: this.name,
          configured: true,
          status: 'FAILED',
          reputation: 'UNAVAILABLE',
          queryType: indicator.type,
          responseTimeMs,
          timestamp: now,
          errorCategory: 'API_ERROR',
          errorMessage: `VirusTotal API error (HTTP ${res.status})`,
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: `VirusTotal returned HTTP status ${res.status}.`,
        };
      }

      const body = (await res.json()) as any;
      const attributes = body.data?.attributes || {};
      const stats = attributes.last_analysis_stats || {};
      const maliciousCount = Number(stats.malicious) || 0;
      const suspiciousCount = Number(stats.suspicious) || 0;
      const harmlessCount = Number(stats.harmless) || 0;
      const undetectedCount = Number(stats.undetected) || 0;
      const totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount;

      const categories: ThreatIntelCategory[] = [];
      if (attributes.categories && typeof attributes.categories === 'object') {
        for (const val of Object.values(attributes.categories) as string[]) {
          if (val && !categories.includes(val)) {
            categories.push(val);
          }
        }
      }

      const threatLabel =
        attributes.popular_threat_classification?.suggested_threat_label ||
        attributes.meaningful_name ||
        attributes.type_description;
      if (threatLabel && !categories.includes(threatLabel)) {
        categories.push(threatLabel);
      }

      const reputation =
        maliciousCount >= 3
          ? 'MALICIOUS'
          : maliciousCount > 0 || suspiciousCount > 0
          ? 'SUSPICIOUS'
          : 'NO_MATCH';

      const evidence: ThreatIntelEvidenceItem[] = [];

      // Extract high-confidence detection engines
      const analysisResults = attributes.last_analysis_results || {};
      const flaggedVendors: string[] = [];
      for (const [vendor, data] of Object.entries(analysisResults) as [string, any][]) {
        if (data && (data.category === 'malicious' || data.category === 'suspicious')) {
          flaggedVendors.push(`${vendor} (${data.result || data.category})`);
        }
      }

      if (maliciousCount > 0 || suspiciousCount > 0) {
        evidence.push({
          id: `vt-det-${Date.now()}`,
          indicator: indicator.display,
          indicatorType: indicator.type,
          provider: this.name,
          evidenceType: 'Engine Detection Flag',
          category: threatLabel || (categories[0] ?? 'Malware'),
          severity: maliciousCount >= 3 ? 'HIGH' : 'MEDIUM',
          confidence: maliciousCount >= 5 ? 'HIGH' : 'MEDIUM',
          value: `${maliciousCount} / ${totalEngines} security vendors flagged indicator`,
          description: `VirusTotal multi-engine analysis flagged this indicator. Engines: ${flaggedVendors.slice(0, 5).join(', ')}${flaggedVendors.length > 5 ? ` +${flaggedVendors.length - 5} more` : ''}.`,
          firstSeen: attributes.first_submission_date
            ? new Date(attributes.first_submission_date * 1000).toISOString()
            : undefined,
          lastSeen: attributes.last_analysis_date
            ? new Date(attributes.last_analysis_date * 1000).toISOString()
            : undefined,
          sourceReference: `https://www.virustotal.com/gui/${indicator.type.toLowerCase().includes('hash') ? 'file' : indicator.type.toLowerCase()}/${indicator.canonical}`,
          timestamp: now,
        });
      }

      // Related Indicators extraction
      const relatedIndicators: ThreatIntelRelatedIndicator[] = [];
      if (attributes.last_dns_records && Array.isArray(attributes.last_dns_records)) {
        for (const record of attributes.last_dns_records.slice(0, 5)) {
          if (record.value) {
            relatedIndicators.push({
              indicator: record.value,
              type: record.type === 'A' || record.type === 'AAAA' ? 'IP' : 'DOMAIN',
              relationship: `DNS ${record.type} record`,
              source: this.name,
            });
          }
        }
      }

      if (attributes.network) {
        relatedIndicators.push({
          indicator: attributes.network,
          type: 'INFRASTRUCTURE',
          relationship: `Subnet / Autonomous System (${attributes.as_owner || 'ASN'})`,
          source: this.name,
        });
      }

      const firstSeen = attributes.first_submission_date
        ? new Date(attributes.first_submission_date * 1000).toISOString()
        : undefined;
      const lastSeen = attributes.last_analysis_date
        ? new Date(attributes.last_analysis_date * 1000).toISOString()
        : undefined;

      return {
        providerId: this.id,
        providerName: this.name,
        configured: true,
        status: 'SUCCESS',
        reputation,
        queryType: indicator.type,
        responseTimeMs,
        timestamp: now,
        detectionSummary: {
          malicious: maliciousCount,
          suspicious: suspiciousCount,
          harmless: harmlessCount,
          undetected: undetectedCount,
          total: totalEngines,
        },
        categories,
        evidence,
        relatedIndicators,
        firstSeen,
        lastSeen,
        lastAnalysisDate: lastSeen,
        details:
          maliciousCount > 0
            ? `VirusTotal reports ${maliciousCount} of ${totalEngines} security vendors flagged this indicator as malicious.`
            : `VirusTotal multi-engine consensus reports 0 malicious detections across ${totalEngines} security vendors.`,
        sanitizedRawMetadata: sanitizeMetadata({
          stats,
          reputation: attributes.reputation,
          tags: attributes.tags,
          threatLabel,
        }),
      };
    } catch (err: any) {
      clearTimeout(timer);
      const isTimeout = err.name === 'AbortError';
      return {
        providerId: this.id,
        providerName: this.name,
        configured: true,
        status: isTimeout ? 'TIMEOUT' : 'FAILED',
        reputation: 'UNAVAILABLE',
        queryType: indicator.type,
        responseTimeMs: Date.now() - startTime,
        timestamp: now,
        errorCategory: isTimeout ? 'TIMEOUT' : 'NETWORK_ERROR',
        errorMessage: isTimeout ? 'VirusTotal API request timed out.' : err.message,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: `VirusTotal lookup failed: ${err.message}`,
      };
    }
  }
}
