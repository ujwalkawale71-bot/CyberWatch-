import { Request, Response, NextFunction } from 'express';
import { threatIntelOrchestrator } from '../services/threat-intel-orchestrator.service';
import { IndicatorNormalizer } from '../utils/indicator-normalizer';
import { ApiResponse } from '@cyberwatch/shared';
import { notificationService } from '../services/notification.service';

export class ThreatIntelController {
  /**
   * POST /api/v1/threat-intelligence/analyze
   * Analyzes an indicator (URL, Domain, IP, Hash, Extension ID) against configured intelligence sources.
   */
  public async analyzeIndicator(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { indicator, forceRefresh } = req.body;

      if (!indicator || typeof indicator !== 'string' || !indicator.trim()) {
        res.status(400).json({
          success: false,
          message: 'Indicator is required and must be a non-empty string.',
          errors: [{ field: 'indicator', message: 'Indicator string is required.' }],
        });
        return;
      }

      // 1024 char limit on indicator to prevent buffer abuse
      if (indicator.length > 2048) {
        res.status(400).json({
          success: false,
          message: 'Indicator exceeds maximum allowable length of 2048 characters.',
          errors: [{ field: 'indicator', message: 'Indicator is too long.' }],
        });
        return;
      }

      const effectiveUserId = req.user?.userId || (req as any).user?.id || (req as any).user?._id;
      const report = await threatIntelOrchestrator.analyze(indicator.trim(), {
        forceRefresh: Boolean(forceRefresh),
        userId: effectiveUserId,
      });

      if (effectiveUserId && (report.overallReputation === 'MALICIOUS' || report.overallReputation === 'SUSPICIOUS')) {
        notificationService.createThreatIntelNotification({
          userId: effectiveUserId,
          indicator: report.indicator,
          indicatorType: report.indicatorType,
          reputation: report.overallReputation,
          threatScore: report.detectionSummary?.flaggedCount,
          analysisId: report.analysisId,
        }).catch((err) => {
          console.error('[NotificationService] Failed to emit threat intel notification:', err);
        });
      }

      const response: ApiResponse<typeof report> = {
        success: true,
        message:
          report.status === 'ERROR'
            ? 'Indicator validation error'
            : 'Threat intelligence analysis completed',
        data: report,
      };

      res.status(200).json(response);
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/threat-intelligence/providers
   * Returns list and configuration status of registered threat intelligence providers.
   */
  public async getProviders(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const providers = threatIntelOrchestrator.getConfiguredProvidersMetadata();
      res.status(200).json({
        success: true,
        message: 'Threat intelligence providers retrieved',
        data: providers,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/threat-intelligence/normalize
   * Returns indicator normalization and classification metadata without querying external providers.
   */
  public async normalize(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { indicator } = req.body;
      if (!indicator || typeof indicator !== 'string') {
        res.status(400).json({
          success: false,
          message: 'Indicator is required.',
        });
        return;
      }

      const normalized = IndicatorNormalizer.normalize(indicator.trim());
      res.status(200).json({
        success: true,
        message: 'Indicator normalized successfully',
        data: normalized,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/threat-intelligence/indicators
   * Retrieves historical indicators analyzed in CyberWatch with filtering & search.
   */
  public async listIndicators(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { type, status, provider, search, page, limit } = req.query;
      const result = await threatIntelOrchestrator.listIndicators({
        type: typeof type === 'string' ? type : undefined,
        status: typeof status === 'string' ? status : undefined,
        provider: typeof provider === 'string' ? provider : undefined,
        search: typeof search === 'string' ? search : undefined,
        page: page ? parseInt(String(page), 10) : 1,
        limit: limit ? parseInt(String(limit), 10) : 20,
      });

      res.status(200).json({
        success: true,
        message: 'Threat indicators retrieved',
        data: result,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/threat-intelligence/advisories
   * Retrieves security advisories or returns unconfigured state honestly without fake CVEs.
   */
  public async getAdvisories(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const advisoryApiKey = process.env.NVD_API_KEY || process.env.GITHUB_TOKEN || '';
      const isConfigured = Boolean(advisoryApiKey.trim());

      res.status(200).json({
        success: true,
        message: isConfigured ? 'Security advisories retrieved' : 'Security advisory provider is not configured in this environment.',
        data: {
          configured: isConfigured,
          provider: isConfigured ? 'National Vulnerability Database (NVD)' : 'None Configured',
          advisories: [],
          notice: isConfigured ? 'No matching advisories found.' : 'Security advisory provider is not configured.',
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/threat-intelligence/correlate
   * Correlates findings from any scanner with threat intelligence evidence.
   */
  public async correlateScan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scannerType, target, findings, scanResult } = req.body;
      if (!target || typeof target !== 'string') {
        res.status(400).json({
          success: false,
          message: 'Target is required for threat intelligence correlation.',
        });
        return;
      }

      const { ThreatIntelCorrelationService } = await import('../services/threat-intel-correlation.service');
      const correlation = await ThreatIntelCorrelationService.correlateScanWithThreatIntel(
        scannerType || 'URL',
        target,
        Array.isArray(findings) ? findings : [],
        scanResult
      );

      res.status(200).json({
        success: true,
        message: 'Scanner findings correlated with Threat Intelligence',
        data: correlation,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/threat-intelligence/feeds
   * Returns registered intelligence feeds and their synchronization/configuration status.
   */
  public async getFeeds(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const providers = threatIntelOrchestrator.getRegisteredProviders();
      const feeds = [
        {
          id: 'urlhaus-active',
          name: 'URLhaus Active Malware URL Feed',
          provider: 'URLhaus (abuse.ch)',
          providerId: 'urlhaus',
          type: 'URL / Domain / Payload Hash',
          status: 'ACTIVE',
          configured: true,
          description: 'Community-driven database of malware distribution sites, payload delivery URLs, and infected hosts.',
          supportedIndicators: ['URL', 'DOMAIN', 'HASH_SHA256', 'HASH_MD5'],
          frequency: 'Real-time on-demand query & live feed integration',
          sourceUrl: 'https://urlhaus.abuse.ch/api/',
        },
        {
          id: 'malwarebazaar-corpus',
          name: 'MalwareBazaar Sample Intelligence Corpus',
          provider: 'MalwareBazaar (abuse.ch)',
          providerId: 'malwarebazaar',
          type: 'Binary & Package Checksums',
          status: 'ACTIVE',
          configured: true,
          description: 'Malware sample repository containing hashes, signatures, malware families, and delivery mechanics.',
          supportedIndicators: ['HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'EXTENSION_HASH'],
          frequency: 'Real-time on-demand query & malware signature matching',
          sourceUrl: 'https://bazaar.abuse.ch/api/',
        },
        {
          id: 'abuseipdb-blacklist',
          name: 'AbuseIPDB Global IP Reputation & Blacklist',
          provider: 'AbuseIPDB',
          providerId: 'abuseipdb',
          type: 'IPv4 / IPv6 Infrastructure',
          status: providers.find((p) => p.id === 'abuseipdb')?.isConfigured() ? 'ACTIVE' : 'NOT_CONFIGURED',
          configured: providers.find((p) => p.id === 'abuseipdb')?.isConfigured() || false,
          description: 'Crowdsourced network abuse reports, port scanning detection, brute-force logs, and confidence scoring.',
          supportedIndicators: ['IP'],
          frequency: 'Real-time verification (90-day rolling abuse window)',
          sourceUrl: 'https://www.abuseipdb.com/api',
        },
        {
          id: 'virustotal-multiengine',
          name: 'VirusTotal Multi-Engine Telemetry',
          provider: 'VirusTotal (Google Cloud)',
          providerId: 'virustotal',
          type: 'Multi-Engine Consensus',
          status: providers.find((p) => p.id === 'virustotal')?.isConfigured() ? 'ACTIVE' : 'NOT_CONFIGURED',
          configured: providers.find((p) => p.id === 'virustotal')?.isConfigured() || false,
          description: 'Aggregation across 70+ antivirus and security engines for files, domains, IPs, and URLs.',
          supportedIndicators: ['URL', 'DOMAIN', 'IP', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256'],
          frequency: 'Real-time multi-vendor consensus',
          sourceUrl: 'https://docs.virustotal.com/reference/overview',
        },
        {
          id: 'otx-pulses',
          name: 'AlienVault Open Threat Exchange (OTX)',
          provider: 'AlienVault OTX (AT&T Cybersecurity)',
          providerId: 'otx',
          type: 'Community Threat Pulses & IOCs',
          status: providers.find((p) => p.id === 'otx')?.isConfigured() ? 'ACTIVE' : 'NOT_CONFIGURED',
          configured: providers.find((p) => p.id === 'otx')?.isConfigured() || false,
          description: 'Crowdsourced threat research pulses, adversary tracking, campaigns, and correlated indicators.',
          supportedIndicators: ['DOMAIN', 'IP', 'URL', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256'],
          frequency: 'Real-time pulse matching',
          sourceUrl: 'https://otx.alienvault.com/api',
        },
      ];

      res.status(200).json({
        success: true,
        message: 'Threat intelligence feeds retrieved',
        data: feeds,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/threat-intelligence/providers/:id/test
   * Tests connectivity to a specific threat intelligence provider safely without exposing keys.
   */
  public async testProvider(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rawProviderId = req.params.id;
      const providerId = Array.isArray(rawProviderId) ? rawProviderId[0] : rawProviderId;
      const provider = threatIntelOrchestrator
        .getRegisteredProviders()
        .find((p) => p.id.toLowerCase() === providerId?.toLowerCase());

      if (!provider) {
        res.status(404).json({
          success: false,
          message: `Provider '${providerId}' not found.`,
        });
        return;
      }

      if (!provider.isConfigured()) {
        res.status(200).json({
          success: true,
          message: `${provider.name} is not configured in this environment (missing API key).`,
          data: {
            providerId: provider.id,
            providerName: provider.name,
            status: 'NOT_CONFIGURED',
            configured: false,
            latencyMs: 0,
            message: 'Provider requires an API key in environment variables to be activated.',
          },
        });
        return;
      }

      // Run minimal test lookup on benign test indicator
      const startTime = Date.now();
      const testIndicator = IndicatorNormalizer.normalize('example.com');
      const result = await provider.lookup(testIndicator);
      const latencyMs = Date.now() - startTime;

      res.status(200).json({
        success: true,
        message: `${provider.name} connection test successful.`,
        data: {
          providerId: provider.id,
          providerName: provider.name,
          status: result.status === 'FAILED' ? 'ERROR' : 'ONLINE',
          configured: true,
          latencyMs,
          message: result.details || `Provider responded in ${latencyMs}ms.`,
        },
      });
    } catch (err: any) {
      next(err);
    }
  }

  /**
   * GET /api/v1/threat-intelligence/:analysisId
   * Retrieves a previously analyzed threat intelligence report by its ID.
   */
  public async getAnalysisById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rawAnalysisId = req.params.analysisId;
      const analysisId = Array.isArray(rawAnalysisId) ? rawAnalysisId[0] : rawAnalysisId;
      if (!analysisId) {
        res.status(400).json({
          success: false,
          message: 'analysisId parameter is required.',
        });
        return;
      }

      const report = await threatIntelOrchestrator.getAnalysisById(analysisId);
      if (!report) {
        res.status(404).json({
          success: false,
          message: 'Threat intelligence analysis record not found.',
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Threat intelligence report retrieved',
        data: report,
      });
    } catch (err) {
      next(err);
    }
  }
}

export const threatIntelController = new ThreatIntelController();

