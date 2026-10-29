import { env } from '../config/env';

export interface ThreatIntelligenceProviderEntry {
  provider: string;
  status: 'MATCH' | 'NO MATCH' | 'NOT CONFIGURED' | 'UNAVAILABLE' | 'RATE_LIMITED' | 'ERROR';
  queried: boolean;
  queryTimeMs?: number;
  result: string;
  threatCategories?: string[];
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW' | 'N/A';
  details: string;
  sourceTimestamp?: string;
  stats?: {
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
    timeout?: number;
    totalEngines?: number;
  };
}

export interface ThreatIntelligenceResult {
  status: 'Not Configured' | 'Queried' | 'Unavailable' | 'Clean' | 'Threat Detected';
  provider: string;
  queried: boolean;
  result: string;
  timestamp?: string;
  indicators?: string[];
  details: string;
  providers?: ThreatIntelligenceProviderEntry[];
}

export class ThreatIntelService {
  /**
   * Check configured threat intelligence providers for a given target URL.
   * Only queries providers that have valid API credentials configured.
   * NEVER generates fake detections — unconfigured providers show NOT CONFIGURED.
   */
  async lookup(targetUrl: string, hostname?: string): Promise<ThreatIntelligenceResult> {
    const googleKey = (env.GOOGLE_WEB_RISK_API_KEY || env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.GOOGLE_WEB_RISK_API_KEY || process.env.GOOGLE_SAFE_BROWSING_API_KEY || '').trim();
    const vtKey = (env.VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY || '').trim();
    const urlhausKey = (env.URLHAUS_API_KEY || process.env.URLHAUS_API_KEY || '').trim();
    const otxKey = (env.OTX_API_KEY || process.env.OTX_API_KEY || process.env.ALIENVAULT_OTX_API_KEY || '').trim();

    const providerEntries: ThreatIntelligenceProviderEntry[] = [];
    const queryPromises: Promise<ThreatIntelligenceProviderEntry>[] = [];

    // 1. Google Safe Browsing / Web Risk
    if (googleKey) {
      queryPromises.push(this.queryGoogleSafeBrowsing(targetUrl, googleKey));
    } else {
      providerEntries.push({
        provider: 'Google Web Risk / Safe Browsing',
        status: 'NOT CONFIGURED',
        queried: false,
        queryTimeMs: 0,
        result: 'Not Configured',
        confidence: 'N/A',
        details: 'Google Safe Browsing / Web Risk API key is not configured in this environment.',
      });
    }

    // 2. VirusTotal
    if (vtKey) {
      queryPromises.push(this.queryVirusTotal(targetUrl, vtKey));
    } else {
      providerEntries.push({
        provider: 'VirusTotal',
        status: 'NOT CONFIGURED',
        queried: false,
        queryTimeMs: 0,
        result: 'Not Configured',
        confidence: 'N/A',
        details: 'VirusTotal API key is not configured in this environment.',
      });
    }

    // 3. URLhaus
    if (urlhausKey) {
      queryPromises.push(this.queryUrlhaus(targetUrl, urlhausKey));
    } else {
      providerEntries.push({
        provider: 'URLhaus (abuse.ch)',
        status: 'NOT CONFIGURED',
        queried: false,
        queryTimeMs: 0,
        result: 'Not Configured',
        confidence: 'N/A',
        details: 'URLhaus threat feed integration is not configured.',
      });
    }

    // 4. AlienVault OTX
    if (otxKey) {
      const effectiveHost = hostname || (() => {
        try {
          return new URL(targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`).hostname.toLowerCase();
        } catch {
          return targetUrl.toLowerCase();
        }
      })();
      queryPromises.push(this.queryAlienVaultOtx(effectiveHost, otxKey));
    } else {
      providerEntries.push({
        provider: 'AlienVault OTX',
        status: 'NOT CONFIGURED',
        queried: false,
        queryTimeMs: 0,
        result: 'Not Configured',
        confidence: 'N/A',
        details: 'AlienVault OTX API key is not configured.',
      });
    }

    // Await all configured provider queries concurrently
    if (queryPromises.length > 0) {
      const results = await Promise.allSettled(queryPromises);
      for (const res of results) {
        if (res.status === 'fulfilled') {
          providerEntries.push(res.value);
        }
      }
    }

    // Sort provider entries consistently
    const providerOrder = ['Google Web Risk / Safe Browsing', 'VirusTotal', 'URLhaus (abuse.ch)', 'AlienVault OTX'];
    providerEntries.sort((a, b) => {
      const idxA = providerOrder.indexOf(a.provider);
      const idxB = providerOrder.indexOf(b.provider);
      return (idxA >= 0 ? idxA : 99) - (idxB >= 0 ? idxB : 99);
    });

    const configuredCount = providerEntries.filter((p) => p.status !== 'NOT CONFIGURED').length;
    const matches = providerEntries.filter((p) => p.status === 'MATCH');
    const errors = providerEntries.filter((p) => p.status === 'UNAVAILABLE' || p.status === 'ERROR');

    if (configuredCount === 0) {
      return {
        status: 'Not Configured',
        provider: 'None Configured',
        queried: false,
        result: 'Not Configured',
        details: 'No third-party threat intelligence providers are configured in this environment.',
        providers: providerEntries,
      };
    }

    if (matches.length > 0) {
      const allIndicators = matches.flatMap((m) => m.threatCategories || []);
      const matchProviders = matches.map((m) => m.provider).join(', ');
      return {
        status: 'Threat Detected',
        provider: matchProviders,
        queried: true,
        result: `Threat Flagged by ${matchProviders}`,
        timestamp: new Date().toISOString(),
        indicators: allIndicators,
        details: `Active threat match detected by ${matchProviders}: ${matches.map((m) => m.details).join('; ')}`,
        providers: providerEntries,
      };
    }

    if (configuredCount > 0 && configuredCount === errors.length) {
      return {
        status: 'Unavailable',
        provider: 'Configured Providers',
        queried: true,
        result: 'Lookup Unavailable',
        timestamp: new Date().toISOString(),
        details: 'Configured threat intelligence provider lookups timed out or returned errors.',
        providers: providerEntries,
      };
    }

    return {
      status: 'Clean',
      provider: providerEntries.filter((p) => p.status === 'NO MATCH').map((p) => p.provider).join(', ') || 'Configured Sources',
      queried: true,
      result: 'No Known Threat Match',
      timestamp: new Date().toISOString(),
      details: 'No known threat match was observed from the configured threat intelligence sources.',
      providers: providerEntries,
    };
  }

  /**
   * Query Google Safe Browsing Lookup API v4 / Web Risk
   */
  private async queryGoogleSafeBrowsing(targetUrl: string, apiKey: string): Promise<ThreatIntelligenceProviderEntry> {
    const startTime = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    try {
      const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
      const payload = {
        client: {
          clientId: 'cyberwatch-threat-scanner',
          clientVersion: '2.0.0',
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: targetUrl }],
        },
      };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const queryTimeMs = Date.now() - startTime;

      if (!res.ok) {
        return {
          provider: 'Google Web Risk / Safe Browsing',
          status: 'UNAVAILABLE',
          queried: true,
          queryTimeMs,
          result: `API Error (HTTP ${res.status})`,
          confidence: 'N/A',
          details: `Google Safe Browsing API returned HTTP ${res.status}.`,
          sourceTimestamp: new Date().toISOString(),
        };
      }

      const data = await res.json() as any;
      const matches = data.matches || [];

      if (matches.length > 0) {
        const threatTypes = matches.map((m: any) => m.threatType).filter(Boolean);
        return {
          provider: 'Google Web Risk / Safe Browsing',
          status: 'MATCH',
          queried: true,
          queryTimeMs,
          result: `MATCH (${threatTypes.join(', ')})`,
          threatCategories: threatTypes,
          confidence: 'HIGH',
          details: `Google Web Risk identified this target as an active threat: ${threatTypes.join(', ')}.`,
          sourceTimestamp: new Date().toISOString(),
        };
      }

      return {
        provider: 'Google Web Risk / Safe Browsing',
        status: 'NO MATCH',
        queried: true,
        queryTimeMs,
        result: 'NO MATCH',
        confidence: 'HIGH',
        details: 'No known threat match was observed from Google Safe Browsing.',
        sourceTimestamp: new Date().toISOString(),
      };
    } catch (err: any) {
      clearTimeout(timer);
      const queryTimeMs = Date.now() - startTime;
      return {
        provider: 'Google Web Risk / Safe Browsing',
        status: 'UNAVAILABLE',
        queried: true,
        queryTimeMs,
        result: 'Lookup Timeout / Network Error',
        confidence: 'N/A',
        details: `Lookup failed: ${err.message}`,
      };
    }
  }

  /**
   * Query VirusTotal URL v3 API
   */
  private async queryVirusTotal(targetUrl: string, apiKey: string): Promise<ThreatIntelligenceProviderEntry> {
    const startTime = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    try {
      const urlId = Buffer.from(targetUrl).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

      const res = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'x-apikey': apiKey,
          'Accept': 'application/json',
        },
        signal: controller.signal,
      });

      clearTimeout(timer);
      const queryTimeMs = Date.now() - startTime;

      if (res.status === 404) {
        return {
          provider: 'VirusTotal',
          status: 'NO MATCH',
          queried: true,
          queryTimeMs,
          result: '0 / 0 (Unseen Target)',
          confidence: 'MEDIUM',
          details: 'Target URL is not currently listed in VirusTotal threat intelligence database.',
          sourceTimestamp: new Date().toISOString(),
        };
      }

      if (!res.ok) {
        return {
          provider: 'VirusTotal',
          status: 'UNAVAILABLE',
          queried: true,
          queryTimeMs,
          result: `API Error (HTTP ${res.status})`,
          confidence: 'N/A',
          details: `VirusTotal API returned HTTP ${res.status}.`,
          sourceTimestamp: new Date().toISOString(),
        };
      }

      const data = await res.json() as any;
      const stats = data.data?.attributes?.last_analysis_stats;
      const totalEngines = stats
        ? (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)
        : 0;

      const lastAnalysisDate = data.data?.attributes?.last_analysis_date
        ? new Date(data.data.attributes.last_analysis_date * 1000).toISOString()
        : new Date().toISOString();

      if (stats && stats.malicious > 0) {
        const threatCategories = stats.malicious >= 5 ? ['MALICIOUS', 'KNOWN_THREAT'] : ['SUSPICIOUS'];
        return {
          provider: 'VirusTotal',
          status: 'MATCH',
          queried: true,
          queryTimeMs,
          result: `${stats.malicious} / ${totalEngines || 90} malicious detections`,
          threatCategories,
          confidence: stats.malicious >= 3 ? 'HIGH' : 'MEDIUM',
          details: `VirusTotal reported ${stats.malicious} security vendor(s) flagged this target URL as malicious.`,
          sourceTimestamp: lastAnalysisDate,
          stats: {
            malicious: stats.malicious,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            timeout: stats.timeout || 0,
            totalEngines,
          },
        };
      }

      return {
        provider: 'VirusTotal',
        status: 'NO MATCH',
        queried: true,
        queryTimeMs,
        result: `0 / ${totalEngines || 90} malicious detections`,
        confidence: 'HIGH',
        details: 'VirusTotal security engines reported zero malicious detections for this target.',
        sourceTimestamp: lastAnalysisDate,
        stats: stats ? {
          malicious: 0,
          suspicious: stats.suspicious || 0,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0,
          timeout: stats.timeout || 0,
          totalEngines,
        } : undefined,
      };
    } catch (err: any) {
      clearTimeout(timer);
      const queryTimeMs = Date.now() - startTime;
      return {
        provider: 'VirusTotal',
        status: 'UNAVAILABLE',
        queried: true,
        queryTimeMs,
        result: 'Lookup Timeout / Error',
        confidence: 'N/A',
        details: `VirusTotal lookup timed out or failed: ${err.message}`,
      };
    }
  }

  /**
   * Query URLhaus API
   */
  private async queryUrlhaus(targetUrl: string, _apiKey: string): Promise<ThreatIntelligenceProviderEntry> {
    const startTime = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    try {
      const endpoint = 'https://urlhaus-api.abuse.ch/v1/url/';
      const body = new URLSearchParams();
      body.append('url', targetUrl);

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const queryTimeMs = Date.now() - startTime;

      if (!res.ok) {
        return {
          provider: 'URLhaus (abuse.ch)',
          status: 'UNAVAILABLE',
          queried: true,
          queryTimeMs,
          result: `API Error (HTTP ${res.status})`,
          confidence: 'N/A',
          details: `URLhaus API returned HTTP ${res.status}.`,
        };
      }

      const data = await res.json() as any;
      if (data.query_status === 'ok' && data.url_status === 'online') {
        const tags = Array.isArray(data.tags) ? data.tags : [data.threat || 'Malware'];
        return {
          provider: 'URLhaus (abuse.ch)',
          status: 'MATCH',
          queried: true,
          queryTimeMs,
          result: `MATCH (${data.threat || 'Malware'})`,
          threatCategories: tags,
          confidence: 'HIGH',
          details: `URLhaus database lists this target as an active malware distribution URL (${data.threat || 'Malware'}).`,
          sourceTimestamp: data.date_added || new Date().toISOString(),
        };
      }

      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'NO MATCH',
        queried: true,
        queryTimeMs,
        result: 'NO MATCH',
        confidence: 'HIGH',
        details: 'Target URL is not listed in the URLhaus active malware feed.',
        sourceTimestamp: new Date().toISOString(),
      };
    } catch (err: any) {
      clearTimeout(timer);
      const queryTimeMs = Date.now() - startTime;
      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'UNAVAILABLE',
        queried: true,
        queryTimeMs,
        result: 'Lookup Timeout / Error',
        confidence: 'N/A',
        details: `URLhaus lookup failed: ${err.message}`,
      };
    }
  }

  /**
   * Query AlienVault OTX
   */
  private async queryAlienVaultOtx(hostname: string, apiKey: string): Promise<ThreatIntelligenceProviderEntry> {
    const startTime = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    try {
      const endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(hostname)}/general`;
      const res = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'X-OTX-API-KEY': apiKey,
          'Accept': 'application/json',
        },
        signal: controller.signal,
      });

      clearTimeout(timer);
      const queryTimeMs = Date.now() - startTime;

      if (!res.ok) {
        return {
          provider: 'AlienVault OTX',
          status: 'UNAVAILABLE',
          queried: true,
          queryTimeMs,
          result: `API Error (HTTP ${res.status})`,
          confidence: 'N/A',
          details: `AlienVault OTX returned HTTP ${res.status}.`,
        };
      }

      const data = await res.json() as any;
      const pulseCount = data.pulse_info?.count || 0;

      if (pulseCount > 0) {
        return {
          provider: 'AlienVault OTX',
          status: 'MATCH',
          queried: true,
          queryTimeMs,
          result: `MATCH (${pulseCount} Threat Pulses)`,
          threatCategories: ['THREAT_PULSE'],
          confidence: 'HIGH',
          details: `AlienVault OTX associated ${pulseCount} threat pulse(s) with this target.`,
          sourceTimestamp: new Date().toISOString(),
        };
      }

      return {
        provider: 'AlienVault OTX',
        status: 'NO MATCH',
        queried: true,
        queryTimeMs,
        result: 'NO MATCH',
        confidence: 'HIGH',
        details: 'No threat pulses associated with domain in AlienVault OTX.',
        sourceTimestamp: new Date().toISOString(),
      };
    } catch (err: any) {
      clearTimeout(timer);
      const queryTimeMs = Date.now() - startTime;
      return {
        provider: 'AlienVault OTX',
        status: 'UNAVAILABLE',
        queried: true,
        queryTimeMs,
        result: 'Lookup Timeout / Error',
        confidence: 'N/A',
        details: `AlienVault OTX lookup failed: ${err.message}`,
      };
    }
  }
}

export const threatIntelService = new ThreatIntelService();
