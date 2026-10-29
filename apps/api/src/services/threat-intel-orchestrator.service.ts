import { randomUUID } from 'crypto';
import {
  NormalizedIndicator,
  ThreatIntelAnalysisReport,
  ThreatIntelCategory,
  ThreatIntelConfidence,
  ThreatIntelEvidenceItem,
  ThreatIntelProviderResult,
  ThreatIntelRelatedIndicator,
  ThreatIntelReputation,
} from '@cyberwatch/shared';
import { IndicatorNormalizer } from '../utils/indicator-normalizer';
import {
  ThreatIntelligenceProvider,
  VirusTotalProvider,
  AbuseIPDBProvider,
  URLhausProvider,
  AlienVaultOTXProvider,
  MalwareBazaarProvider,
} from './threat-intel-providers';
import { ThreatIntel } from '../models/ThreatIntel';
import { env } from '../config/env';

interface CacheEntry {
  report: ThreatIntelAnalysisReport;
  expiresAt: number;
}

export class ThreatIntelOrchestrator {
  private providers: ThreatIntelligenceProvider[] = [];
  private cache: Map<string, CacheEntry> = new Map();
  private cacheTtlMs: number;

  constructor() {
    this.cacheTtlMs =
      (parseInt(process.env.THREAT_INTELLIGENCE_CACHE_TTL_SECONDS || '', 10) || 3600) * 1000;

    // Register all supported provider adapters
    this.registerProvider(new VirusTotalProvider());
    this.registerProvider(new AbuseIPDBProvider());
    this.registerProvider(new URLhausProvider());
    this.registerProvider(new AlienVaultOTXProvider());
    this.registerProvider(new MalwareBazaarProvider());
  }

  public registerProvider(provider: ThreatIntelligenceProvider): void {
    // Avoid duplicate IDs
    this.providers = this.providers.filter((p) => p.id !== provider.id);
    this.providers.push(provider);
  }

  public getRegisteredProviders(): ThreatIntelligenceProvider[] {
    return this.providers;
  }

  public getConfiguredProvidersMetadata() {
    return this.providers.map((p) => ({
      id: p.id,
      name: p.name,
      configured: p.isConfigured(),
      supportedTypes: p.supportedTypes,
    }));
  }

  /**
   * Main entry point for Threat Intelligence analysis.
   */
  public async analyze(
    rawIndicator: string,
    options: { forceRefresh?: boolean; userId?: string } = {}
  ): Promise<ThreatIntelAnalysisReport> {
    const normalized = IndicatorNormalizer.normalize(rawIndicator);

    // 1. If invalid input, return structured validation error
    if (!normalized.isValid) {
      return {
        analysisId: `ti_${randomUUID()}`,
        indicator: rawIndicator || '',
        indicatorType: normalized.type,
        normalizedIndicator: normalized.normalized,
        canonicalValue: normalized.canonical,
        displayValue: normalized.display,
        status: 'ERROR',
        overallReputation: 'UNKNOWN',
        confidence: 'UNKNOWN',
        confidenceExplanation: 'Indicator failed syntax and structural validation rules.',
        recommendation: normalized.validationError || 'Please submit a valid security indicator.',
        threatCategories: [],
        providersChecked: 0,
        providersTotal: 0,
        providers: [],
        evidence: [],
        relatedIndicators: [],
        createdAt: new Date().toISOString(),
      };
    }

    const cacheKey = `ti:${normalized.type}:${normalized.canonical}`;

    // 2. Cache check
    if (!options.forceRefresh) {
      const cached = this.cache.get(cacheKey);
      if (cached && cached.expiresAt > Date.now()) {
        return {
          ...cached.report,
          cached: true,
        };
      }
    }

    // 3. Select compatible providers for this indicator type
    const compatibleProviders = this.providers.filter((p) =>
      p.supportedTypes.includes(normalized.type)
    );

    // 4. Query providers in parallel with safe error isolation
    const lookupPromises = compatibleProviders.map(async (provider) => {
      try {
        return await provider.lookup(normalized);
      } catch (err: any) {
        const res: ThreatIntelProviderResult = {
          providerId: provider.id,
          providerName: provider.name,
          configured: provider.isConfigured(),
          status: 'FAILED',
          reputation: 'UNAVAILABLE',
          queryType: normalized.type,
          timestamp: new Date().toISOString(),
          errorCategory: 'UNEXPECTED_ERROR',
          errorMessage: err.message || 'Unknown provider error',
          categories: [],
          evidence: [],
          relatedIndicators: [],
          details: `Provider encountered unhandled exception: ${err.message}`,
        };
        return res;
      }
    });

    const settledResults = await Promise.allSettled(lookupPromises);
    const providerResults: ThreatIntelProviderResult[] = settledResults.map((s, idx) => {
      if (s.status === 'fulfilled') {
        return s.value;
      }
      const provider = compatibleProviders[idx];
      return {
        providerId: provider?.id || 'unknown',
        providerName: provider?.name || 'Unknown Provider',
        configured: provider?.isConfigured() || false,
        status: 'FAILED',
        reputation: 'UNAVAILABLE',
        queryType: normalized.type,
        timestamp: new Date().toISOString(),
        errorCategory: 'PROMISE_REJECTED',
        errorMessage: String(s.reason),
        categories: [],
        evidence: [],
        relatedIndicators: [],
        details: 'Lookup promise was rejected.',
      };
    });

    // 5. Aggregate metrics and deduplicate evidence
    const report = this.synthesizeReport(
      normalized,
      providerResults,
      compatibleProviders.length,
      options.userId
    );

    // 6. Cache the synthesized report
    this.cache.set(cacheKey, {
      report,
      expiresAt: Date.now() + this.cacheTtlMs,
    });

    // 7. Persist to MongoDB asynchronously (non-blocking)
    this.persistAnalysis(report, options.userId).catch(() => {});

    return report;
  }

  /**
   * Synthesizes individual provider results into a unified Threat Intelligence report.
   */
  private synthesizeReport(
    indicator: NormalizedIndicator,
    providerResults: ThreatIntelProviderResult[],
    providersTotal: number,
    userId?: string
  ): ThreatIntelAnalysisReport {
    const analysisId = `ti_${randomUUID()}`;
    const now = new Date().toISOString();

    const configuredCount = providerResults.filter((p) => p.configured).length;
    const successCount = providerResults.filter((p) => p.status === 'SUCCESS').length;
    const failedCount = providerResults.filter(
      (p) => p.status === 'FAILED' || p.status === 'TIMEOUT'
    ).length;

    // Aggregate detections
    let flaggedCount = 0;
    let totalEnginesQueried = 0;
    let providersWithDetections = 0;

    const allCategories: ThreatIntelCategory[] = [];
    const allEvidence: ThreatIntelEvidenceItem[] = [];
    const allRelatedIndicators: ThreatIntelRelatedIndicator[] = [];

    const timestamps: { firstSeen: string[]; lastSeen: string[]; analysisDates: string[] } = {
      firstSeen: [],
      lastSeen: [],
      analysisDates: [],
    };

    for (const pr of providerResults) {
      if (pr.detectionSummary) {
        if (pr.detectionSummary.malicious > 0) {
          flaggedCount += pr.detectionSummary.malicious;
          providersWithDetections += 1;
        }
        if (pr.detectionSummary.total) {
          totalEnginesQueried += pr.detectionSummary.total;
        }
      }

      for (const cat of pr.categories) {
        if (cat && !allCategories.includes(cat)) {
          allCategories.push(cat);
        }
      }

      for (const ev of pr.evidence) {
        allEvidence.push(ev);
      }

      for (const rel of pr.relatedIndicators) {
        // Deduplicate related indicators by indicator value + type
        if (!allRelatedIndicators.some((r) => r.indicator === rel.indicator && r.type === rel.type)) {
          allRelatedIndicators.push(rel);
        }
      }

      if (pr.firstSeen) timestamps.firstSeen.push(pr.firstSeen);
      if (pr.lastSeen) timestamps.lastSeen.push(pr.lastSeen);
      if (pr.lastAnalysisDate) timestamps.analysisDates.push(pr.lastAnalysisDate);
    }

    // Determine overall status
    let status: ThreatIntelAnalysisReport['status'] = 'NO_MATCH';
    let overallReputation: ThreatIntelReputation = 'NO_MATCH';

    const hasMaliciousMatch = providerResults.some((p) => p.reputation === 'MALICIOUS');
    const hasSuspiciousMatch = providerResults.some((p) => p.reputation === 'SUSPICIOUS');

    if (configuredCount === 0) {
      status = 'NOT_CONFIGURED';
      overallReputation = 'NOT_CONFIGURED';
    } else if (successCount === 0 && failedCount > 0) {
      status = 'UNAVAILABLE';
      overallReputation = 'UNAVAILABLE';
    } else if (hasMaliciousMatch) {
      status = 'MATCH_FOUND';
      overallReputation = 'MALICIOUS';
    } else if (hasSuspiciousMatch) {
      status = 'MATCH_FOUND';
      overallReputation = 'SUSPICIOUS';
    } else if (failedCount > 0 && successCount > 0) {
      status = 'PARTIAL';
      overallReputation = 'NO_MATCH';
    } else if (indicator.isPrivate) {
      status = 'NO_MATCH';
      overallReputation = 'INFORMATIONAL';
    } else {
      status = 'NO_MATCH';
      overallReputation = 'NO_MATCH';
    }

    // Confidence Calculation Rules
    let confidence: ThreatIntelConfidence = 'UNKNOWN';
    let confidenceExplanation = '';

    if (status === 'NOT_CONFIGURED') {
      confidence = 'UNKNOWN';
      confidenceExplanation = 'No threat intelligence providers are configured in this environment.';
    } else if (status === 'UNAVAILABLE') {
      confidence = 'UNKNOWN';
      confidenceExplanation = 'All configured intelligence sources timed out or were unreachable.';
    } else if (hasMaliciousMatch) {
      if (providersWithDetections >= 2 || flaggedCount >= 3) {
        confidence = 'HIGH';
        confidenceExplanation = `Multiple independent intelligence engines (${providersWithDetections} sources / ${flaggedCount} vendor flags) corroborated malicious activity.`;
      } else {
        confidence = 'MEDIUM';
        confidenceExplanation = 'Single provider flagged malicious activity; corroboration from secondary sources is pending or unconfirmed.';
      }
    } else if (hasSuspiciousMatch) {
      confidence = 'MEDIUM';
      confidenceExplanation = 'Moderate abuse or suspicious flags detected without unanimous consensus.';
    } else if (successCount >= 2) {
      confidence = 'HIGH';
      confidenceExplanation = `High confidence across ${successCount} verified intelligence providers reporting zero active threat flags.`;
    } else if (successCount === 1) {
      confidence = 'MEDIUM';
      confidenceExplanation = 'Evaluated against one configured intelligence provider.';
    } else {
      confidence = 'LOW';
      confidenceExplanation = 'Limited provider coverage available for this indicator.';
    }

    // Recommendations
    let recommendation = '';
    if (overallReputation === 'MALICIOUS') {
      recommendation =
        'Treat this indicator as high risk and avoid interaction until independently verified.';
    } else if (overallReputation === 'SUSPICIOUS') {
      recommendation =
        'Review the associated evidence and investigate related indicators with elevated caution.';
    } else if (overallReputation === 'INFORMATIONAL') {
      recommendation =
        'This indicator belongs to a private/reserved network range. Threat intelligence lookups are intentionally scoped to public infrastructure.';
    } else if (status === 'NO_MATCH') {
      recommendation =
        'No matching threat intelligence was returned by the checked providers. This does not guarantee that the indicator is safe.';
    } else if (status === 'PARTIAL') {
      recommendation =
        'Partial intelligence available. Some external sources could not be reached; exercise standard vigilance.';
    } else if (status === 'NOT_CONFIGURED') {
      recommendation =
        'Threat intelligence sources are not configured. Configure API keys in your environment (.env) to enable multi-source enrichment.';
    } else {
      recommendation =
        'Threat intelligence could not be retrieved from the configured providers at this time.';
    }

    // Temporal Sorting
    const sortedFirstSeen = timestamps.firstSeen.sort();
    const sortedLastSeen = timestamps.lastSeen.sort();
    const firstSeen = sortedFirstSeen[0];
    const lastSeen = sortedLastSeen[sortedLastSeen.length - 1];
    const lastAnalysisDate = timestamps.analysisDates.sort().reverse()[0] || now;

    // Scanner correlation mapping
    let suggestedScanner: 'url' | 'website' | 'phishing' | 'file' | 'extension' | 'api' | undefined;
    let contextNote: string | undefined;

    if (indicator.type === 'URL') {
      suggestedScanner = 'url';
      contextNote = 'You can run a full CyberWatch URL or Phishing scan to audit TLS, redirects, and content.';
    } else if (indicator.type === 'DOMAIN') {
      suggestedScanner = 'website';
      contextNote = 'You can run a CyberWatch Website Security scan to audit security headers, cookies, and TLS posture.';
    } else if (
      indicator.type === 'HASH_MD5' ||
      indicator.type === 'HASH_SHA1' ||
      indicator.type === 'HASH_SHA256'
    ) {
      suggestedScanner = 'file';
      contextNote = 'Submit the file payload to CyberWatch File Security Scanner for deep static and dynamic inspection.';
    } else if (indicator.type === 'EXTENSION_ID' || indicator.type === 'EXTENSION_HASH') {
      suggestedScanner = 'extension';
      contextNote = 'Audit this extension with the CyberWatch Browser Extension Scanner for permission and code safety.';
    }

    return {
      analysisId,
      indicator: indicator.raw,
      indicatorType: indicator.type,
      normalizedIndicator: indicator.normalized,
      canonicalValue: indicator.canonical,
      displayValue: indicator.display,
      status,
      overallReputation,
      confidence,
      confidenceExplanation,
      recommendation,
      detectionSummary: {
        flaggedCount,
        totalEnginesQueried,
        providersWithDetections,
      },
      threatCategories: allCategories,
      providersChecked: providerResults.length,
      providersTotal,
      providers: providerResults,
      evidence: allEvidence,
      relatedIndicators: allRelatedIndicators,
      temporalData: {
        firstSeen,
        lastSeen,
        lastAnalysisDate,
        recentActivitySummary:
          firstSeen && lastSeen
            ? `Indicator observed active from ${new Date(firstSeen).toLocaleDateString()} to ${new Date(lastSeen).toLocaleDateString()}.`
            : undefined,
      },
      correlationWithCyberWatch: {
        targetMatchesExistingScanner: Boolean(suggestedScanner),
        suggestedScanner,
        contextNote,
      },
      createdAt: now,
      cached: false,
    };
  }

  /**
   * Retrieves an existing analysis by ID from MongoDB.
   */
  public async getAnalysisById(analysisId: string): Promise<ThreatIntelAnalysisReport | null> {
    try {
      const record = await ThreatIntel.findOne({ analysisId }).lean();
      if (!record) return null;
      return record as unknown as ThreatIntelAnalysisReport;
    } catch {
      return null;
    }
  }

  /**
   * Lists historical indicators analyzed and stored in MongoDB.
   * Supports filtering by type, status, provider, and search string.
   */
  public async listIndicators(params: {
    type?: string;
    status?: string;
    provider?: string;
    search?: string;
    page?: number;
    limit?: number;
  } = {}): Promise<{ items: any[]; total: number; page: number; limit: number }> {
    try {
      const page = Math.max(1, params.page || 1);
      const limit = Math.min(100, Math.max(1, params.limit || 20));
      const skip = (page - 1) * limit;

      const query: Record<string, any> = {};

      if (params.type && params.type !== 'ALL') {
        query.indicatorType = params.type.toUpperCase();
      }

      if (params.status && params.status !== 'ALL') {
        query.status = params.status.toUpperCase();
      }

      if (params.provider && params.provider !== 'ALL') {
        query['providers.providerId'] = params.provider.toLowerCase();
      }

      if (params.search && params.search.trim()) {
        const regex = new RegExp(params.search.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
        query.$or = [{ indicator: regex }, { canonicalValue: regex }, { displayValue: regex }];
      }

      const [records, total] = await Promise.all([
        ThreatIntel.find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        ThreatIntel.countDocuments(query),
      ]);

      const items = (records || []).map((r: any) => ({
        id: String(r._id || r.analysisId),
        analysisId: r.analysisId,
        indicator: r.displayValue || r.indicator,
        indicatorType: r.indicatorType,
        status: r.status,
        overallReputation: r.overallReputation,
        confidence: r.confidence,
        evidenceCount: Array.isArray(r.evidence) ? r.evidence.length : 0,
        sourcesCount: r.providersChecked || (Array.isArray(r.providers) ? r.providers.length : 0),
        sources: Array.isArray(r.providers) ? r.providers.map((p: any) => p.providerName || p.providerId) : [],
        firstSeen: r.temporalData?.firstSeen,
        lastSeen: r.temporalData?.lastSeen,
        lastAnalysisDate: r.temporalData?.lastAnalysisDate || r.createdAt,
        createdAt: r.createdAt,
      }));

      return { items, total, page, limit };
    } catch {
      return { items: [], total: 0, page: 1, limit: 20 };
    }
  }

  /**
   * Persists report to MongoDB with error isolation.
   */
  private async persistAnalysis(report: ThreatIntelAnalysisReport, userId?: string): Promise<void> {
    try {
      await ThreatIntel.create({
        ...report,
        userId,
      });
    } catch (err) {
      // MongoDB might not be running in isolated test environments; continue gracefully
    }
  }
}

export const threatIntelOrchestrator = new ThreatIntelOrchestrator();

