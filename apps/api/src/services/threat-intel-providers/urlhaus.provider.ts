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

export class URLhausProvider implements ThreatIntelligenceProvider {
  public readonly id = 'urlhaus';
  public readonly name = 'URLhaus (abuse.ch)';
  public readonly supportedTypes: ThreatIntelIndicatorType[] = [
    'URL',
    'DOMAIN',
    'HASH_SHA256',
    'HASH_MD5',
  ];

  public isConfigured(): boolean {
    // URLhaus has open threat feeds and can optionally use an API key if provided
    return true;
  }

  public async lookup(indicator: NormalizedIndicator): Promise<ThreatIntelProviderResult> {
    const apiKey = (process.env.URLHAUS_API_KEY || (env as any).URLHAUS_API_KEY || '').trim();
    const now = new Date().toISOString();

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
        details: 'Target indicator resides in private/reserved network space. External URLhaus lookup skipped for SSRF safety.',
      };
    }

    let endpoint = '';
    const bodyParams = new URLSearchParams();

    if (indicator.type === 'URL') {
      endpoint = 'https://urlhaus-api.abuse.ch/v1/url/';
      bodyParams.append('url', indicator.canonical);
    } else if (indicator.type === 'DOMAIN') {
      endpoint = 'https://urlhaus-api.abuse.ch/v1/host/';
      bodyParams.append('host', indicator.canonical);
    } else if (indicator.type === 'HASH_SHA256') {
      endpoint = 'https://urlhaus-api.abuse.ch/v1/payload/';
      bodyParams.append('sha256_hash', indicator.canonical);
    } else if (indicator.type === 'HASH_MD5') {
      endpoint = 'https://urlhaus-api.abuse.ch/v1/payload/';
      bodyParams.append('md5_hash', indicator.canonical);
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
        errorMessage: `URLhaus does not support indicator type ${indicator.type}`,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: `Indicator type ${indicator.type} is not supported by URLhaus.`,
      };
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    };
    if (apiKey) {
      headers['Auth-Key'] = apiKey;
    }

    const startTime = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: bodyParams.toString(),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const responseTimeMs = Date.now() - startTime;

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
          errorMessage: `URLhaus API error (HTTP ${res.status})`,
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: `URLhaus API returned HTTP status ${res.status}.`,
        };
      }

      const data = (await res.json()) as any;
      const queryStatus = data.query_status;

      if (queryStatus === 'no_results' || queryStatus === 'not_found') {
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
            total: 0,
          },
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: 'Target indicator was not found in the URLhaus active malware feed.',
        };
      }

      if (queryStatus === 'ok') {
        const threat = data.threat || 'Malware';
        const urlStatus = data.url_status || 'online';
        const tags = Array.isArray(data.tags) ? data.tags : [];
        const categories: ThreatIntelCategory[] = ['Malware'];

        if (threat && !categories.includes(threat)) categories.push(threat);
        for (const tag of tags) {
          if (tag && !categories.includes(tag)) categories.push(tag);
        }

        const evidence: ThreatIntelEvidenceItem[] = [];
        evidence.push({
          id: `urlhaus-${Date.now()}`,
          indicator: indicator.display,
          indicatorType: indicator.type,
          provider: this.name,
          evidenceType: 'Active Malware Feed Match',
          category: threat,
          severity: 'HIGH',
          confidence: 'HIGH',
          value: `Listed in URLhaus Malware Feed (${urlStatus.toUpperCase()})`,
          description: `URLhaus lists this target as an active malware distribution point (${threat}). Reporter: ${data.reporter || 'Anonymous'}. Status: ${urlStatus}.`,
          firstSeen: data.date_added || undefined,
          sourceReference: data.urlhaus_reference || 'https://urlhaus.abuse.ch',
          timestamp: now,
        });

        const relatedIndicators: ThreatIntelRelatedIndicator[] = [];
        if (data.payloads && Array.isArray(data.payloads)) {
          for (const p of data.payloads.slice(0, 5)) {
            if (p.response_sha256) {
              relatedIndicators.push({
                indicator: p.response_sha256,
                type: 'HASH_SHA256',
                relationship: `Delivered Payload (${p.file_type || 'Executable'})`,
                source: this.name,
                firstSeen: p.firstseen,
              });
            }
          }
        }

        if (data.host) {
          relatedIndicators.push({
            indicator: data.host,
            type: 'DOMAIN',
            relationship: 'Hosting Server',
            source: this.name,
          });
        }

        return {
          providerId: this.id,
          providerName: this.name,
          configured: true,
          status: 'SUCCESS',
          reputation: 'MALICIOUS',
          queryType: indicator.type,
          responseTimeMs,
          timestamp: now,
          detectionSummary: {
            malicious: 1,
            total: 1,
          },
          categories,
          evidence,
          relatedIndicators,
          firstSeen: data.date_added || undefined,
          lastSeen: data.last_online || undefined,
          details: `URLhaus database confirms indicator is an active malware delivery endpoint (${threat}).`,
          sanitizedRawMetadata: sanitizeMetadata({
            queryStatus: data.query_status,
            id: data.id,
            threat: data.threat,
            urlStatus: data.url_status,
            tags: data.tags,
            reporter: data.reporter,
            dateAdded: data.date_added,
          }),
        };
      }

      return {
        providerId: this.id,
        providerName: this.name,
        configured: true,
        status: 'SUCCESS',
        reputation: 'NO_MATCH',
        queryType: indicator.type,
        responseTimeMs,
        timestamp: now,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: `URLhaus query status: ${queryStatus || 'no results'}.`,
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
        errorMessage: isTimeout ? 'URLhaus request timed out.' : err.message,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: `URLhaus lookup failed: ${err.message}`,
      };
    }
  }
}
