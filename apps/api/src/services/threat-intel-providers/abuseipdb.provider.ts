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

export class AbuseIPDBProvider implements ThreatIntelligenceProvider {
  public readonly id = 'abuseipdb';
  public readonly name = 'AbuseIPDB';
  public readonly supportedTypes: ThreatIntelIndicatorType[] = ['IP'];

  public isConfigured(): boolean {
    const key = process.env.ABUSEIPDB_API_KEY || (env as any).ABUSEIPDB_API_KEY;
    return Boolean(key && key.trim().length > 0);
  }

  public async lookup(indicator: NormalizedIndicator): Promise<ThreatIntelProviderResult> {
    const apiKey = (process.env.ABUSEIPDB_API_KEY || (env as any).ABUSEIPDB_API_KEY || '').trim();
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
        details: 'AbuseIPDB API key is not configured in this environment.',
      };
    }

    if (indicator.type !== 'IP') {
      return {
        providerId: this.id,
        providerName: this.name,
        configured: true,
        status: 'FAILED',
        reputation: 'UNKNOWN',
        queryType: indicator.type,
        timestamp: now,
        errorCategory: 'UNSUPPORTED_TYPE',
        errorMessage: 'AbuseIPDB only supports IP address indicators.',
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: 'AbuseIPDB only supports IPv4 and IPv6 lookups.',
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
        details: 'Target IP resides in private/reserved network space. External AbuseIPDB lookup skipped for SSRF safety.',
      };
    }

    const startTime = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    try {
      const endpoint = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator.canonical)}&maxAgeInDays=90&verbose`;
      const res = await fetch(endpoint, {
        method: 'GET',
        headers: {
          Key: apiKey,
          Accept: 'application/json',
        },
        signal: controller.signal,
      });

      clearTimeout(timer);
      const responseTimeMs = Date.now() - startTime;

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
          errorMessage: 'AbuseIPDB API rate limit exceeded.',
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: 'AbuseIPDB API rate limit exceeded.',
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
          errorMessage: `AbuseIPDB API error (HTTP ${res.status})`,
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: `AbuseIPDB returned HTTP status ${res.status}.`,
        };
      }

      const body = (await res.json()) as any;
      const data = body.data || {};
      const score = Number(data.abuseConfidenceScore) || 0;
      const totalReports = Number(data.totalReports) || 0;
      const distinctUsers = Number(data.numDistinctUsers) || 0;

      const categories: ThreatIntelCategory[] = [];
      if (score >= 20 || totalReports > 0) {
        categories.push('Malicious Infrastructure');
        categories.push('Botnet');
      }

      const reputation =
        score >= 50
          ? 'MALICIOUS'
          : score > 0 || totalReports > 0
          ? 'SUSPICIOUS'
          : 'NO_MATCH';

      const evidence: ThreatIntelEvidenceItem[] = [];
      if (totalReports > 0 || score > 0) {
        evidence.push({
          id: `abuseipdb-${Date.now()}`,
          indicator: indicator.display,
          indicatorType: 'IP',
          provider: this.name,
          evidenceType: 'Crowdsourced Abuse Report',
          category: 'Malicious Infrastructure',
          severity: score >= 50 ? 'HIGH' : score >= 20 ? 'MEDIUM' : 'LOW',
          confidence: score >= 50 ? 'HIGH' : score >= 20 ? 'MEDIUM' : 'LOW',
          value: `Abuse Confidence Score: ${score}% (${totalReports} reports by ${distinctUsers} reporters)`,
          description: `AbuseIPDB database contains ${totalReports} reports submitted within the last 90 days. ISP: ${data.isp || 'Unknown'} (${data.countryCode || 'Unknown country'}).`,
          lastSeen: data.lastReportedAt || undefined,
          sourceReference: `https://www.abuseipdb.com/check/${encodeURIComponent(indicator.canonical)}`,
          timestamp: now,
        });
      }

      const relatedIndicators: ThreatIntelRelatedIndicator[] = [];
      if (data.domain) {
        relatedIndicators.push({
          indicator: data.domain,
          type: 'DOMAIN',
          relationship: 'Associated Domain Name',
          source: this.name,
        });
      }
      if (data.isp) {
        relatedIndicators.push({
          indicator: data.isp,
          type: 'INFRASTRUCTURE',
          relationship: `Internet Service Provider (${data.usageType || 'Commercial'})`,
          source: this.name,
        });
      }

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
          malicious: score >= 50 ? totalReports : 0,
          suspicious: score > 0 && score < 50 ? totalReports : 0,
          total: totalReports,
        },
        categories,
        evidence,
        relatedIndicators,
        lastSeen: data.lastReportedAt || undefined,
        details:
          totalReports > 0
            ? `AbuseIPDB reported ${totalReports} abuse report(s) with an abuse confidence rating of ${score}%.`
            : `AbuseIPDB reports 0 abuse records for this IP in the last 90 days.`,
        sanitizedRawMetadata: sanitizeMetadata({
          ipAddress: data.ipAddress,
          isPublic: data.isPublic,
          ipVersion: data.ipVersion,
          isWhitelisted: data.isWhitelisted,
          abuseConfidenceScore: data.abuseConfidenceScore,
          countryCode: data.countryCode,
          usageType: data.usageType,
          isp: data.isp,
          domain: data.domain,
          totalReports: data.totalReports,
          numDistinctUsers: data.numDistinctUsers,
          lastReportedAt: data.lastReportedAt,
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
        errorMessage: isTimeout ? 'AbuseIPDB request timed out.' : err.message,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: `AbuseIPDB lookup failed: ${err.message}`,
      };
    }
  }
}
