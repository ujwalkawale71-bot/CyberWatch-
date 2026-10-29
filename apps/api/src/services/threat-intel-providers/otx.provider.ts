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

export class AlienVaultOTXProvider implements ThreatIntelligenceProvider {
  public readonly id = 'otx';
  public readonly name = 'AlienVault OTX';
  public readonly supportedTypes: ThreatIntelIndicatorType[] = [
    'DOMAIN',
    'IP',
    'URL',
    'HASH_MD5',
    'HASH_SHA1',
    'HASH_SHA256',
  ];

  public isConfigured(): boolean {
    const key = process.env.OTX_API_KEY || (env as any).OTX_API_KEY;
    return Boolean(key && key.trim().length > 0);
  }

  public async lookup(indicator: NormalizedIndicator): Promise<ThreatIntelProviderResult> {
    const apiKey = (process.env.OTX_API_KEY || (env as any).OTX_API_KEY || '').trim();
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
        details: 'AlienVault OTX API key is not configured in this environment.',
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
        details: 'Target indicator resides in private/reserved network space. External OTX lookup skipped for SSRF safety.',
      };
    }

    let section = '';
    if (indicator.type === 'IP') {
      section = indicator.metadata?.ipVersion === 'IPv6' ? 'IPv6' : 'IPv4';
    } else if (indicator.type === 'DOMAIN') {
      section = 'domain';
    } else if (indicator.type === 'URL') {
      section = 'url';
    } else if (
      indicator.type === 'HASH_MD5' ||
      indicator.type === 'HASH_SHA1' ||
      indicator.type === 'HASH_SHA256'
    ) {
      section = 'file';
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
        errorMessage: `AlienVault OTX does not support indicator type ${indicator.type}`,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: `Indicator type ${indicator.type} is not supported by AlienVault OTX.`,
      };
    }

    const endpoint = `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(indicator.canonical)}/general`;
    const startTime = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    try {
      const res = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'X-OTX-API-KEY': apiKey,
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
            total: 0,
          },
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: 'AlienVault OTX has no threat pulses or IOC records for this indicator.',
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
          errorMessage: `AlienVault OTX API error (HTTP ${res.status})`,
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: `AlienVault OTX API returned status ${res.status}.`,
        };
      }

      const data = (await res.json()) as any;
      const pulseInfo = data.pulse_info || {};
      const pulseCount = Number(pulseInfo.count) || 0;
      const pulses = Array.isArray(pulseInfo.pulses) ? pulseInfo.pulses : [];

      const categories: ThreatIntelCategory[] = [];
      const evidence: ThreatIntelEvidenceItem[] = [];
      const relatedIndicators: ThreatIntelRelatedIndicator[] = [];

      for (const pulse of pulses.slice(0, 5)) {
        const pulseTags = Array.isArray(pulse.tags) ? pulse.tags : [];
        for (const tag of pulseTags) {
          if (tag && !categories.includes(tag)) categories.push(tag);
        }

        evidence.push({
          id: `otx-pulse-${pulse.id || Date.now()}`,
          indicator: indicator.display,
          indicatorType: indicator.type,
          provider: this.name,
          evidenceType: 'Community Threat Pulse',
          category: pulse.adversary || pulseTags[0] || 'Threat Activity',
          severity: pulseCount >= 3 ? 'HIGH' : 'MEDIUM',
          confidence: pulseCount >= 3 ? 'HIGH' : 'MEDIUM',
          value: pulse.name || 'Threat Pulse Match',
          description: `Associated with OTX pulse "${pulse.name}" authored by ${pulse.author_name || 'Community'}. Tags: ${pulseTags.slice(0, 4).join(', ') || 'None'}.`,
          firstSeen: pulse.created || undefined,
          lastSeen: pulse.modified || undefined,
          sourceReference: pulse.id ? `https://otx.alienvault.com/pulse/${pulse.id}` : undefined,
          timestamp: now,
        });

        if (pulse.name) {
          relatedIndicators.push({
            indicator: pulse.name,
            type: 'THREAT_PULSE',
            relationship: 'AlienVault Security Pulse',
            source: this.name,
            firstSeen: pulse.created,
          });
        }
      }

      if (data.country_name) {
        relatedIndicators.push({
          indicator: data.country_name,
          type: 'INFRASTRUCTURE',
          relationship: `Geographic Hosting Country (${data.asn || 'ASN'})`,
          source: this.name,
        });
      }

      const reputation =
        pulseCount >= 3
          ? 'MALICIOUS'
          : pulseCount > 0
          ? 'SUSPICIOUS'
          : 'NO_MATCH';

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
          malicious: pulseCount,
          total: pulseCount,
        },
        categories,
        evidence,
        relatedIndicators,
        details:
          pulseCount > 0
            ? `AlienVault OTX identified ${pulseCount} threat intelligence pulse(s) referencing this indicator.`
            : `AlienVault OTX reports 0 threat pulses for this target.`,
        sanitizedRawMetadata: sanitizeMetadata({
          pulseCount,
          countryName: data.country_name,
          asn: data.asn,
          validation: data.validation,
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
        errorMessage: isTimeout ? 'AlienVault OTX request timed out.' : err.message,
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: `AlienVault OTX lookup failed: ${err.message}`,
      };
    }
  }
}
