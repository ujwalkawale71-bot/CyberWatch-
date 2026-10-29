import {
  UnifiedEvidenceItem,
  UnifiedCorrelationResult,
  ThreatIntelAnalysisReport,
  FindingSeverity,
} from '@cyberwatch/shared';
import { IndicatorExtractorService } from './indicator-extractor.service';
import { threatIntelOrchestrator } from './threat-intel-orchestrator.service';

export class ThreatIntelCorrelationService {
  /**
   * Correlates scanner findings with real Threat Intelligence reports.
   * Produces a unified, deduplicated evidence stream without double-counting.
   */
  public static async correlateScanWithThreatIntel(
    scannerType: 'URL' | 'Website' | 'API' | 'Phishing' | 'File' | 'Extension',
    target: string,
    scannerFindings: Array<{
      category?: string;
      title: string;
      description: string;
      severity: string;
      evidence?: string;
    }> = [],
    scanResult?: any
  ): Promise<UnifiedCorrelationResult> {
    const extractedIndicators = IndicatorExtractorService.extractFromScanner(scannerType, target, scanResult);
    const primaryIndicator = extractedIndicators.find((i) => i.isPrimary) || extractedIndicators[0] || {
      originalValue: target,
      normalizedValue: target.toLowerCase(),
      type: 'DOMAIN' as const,
      contextSource: `${scannerType} Scanner Target`,
      isPrimary: true,
    };

    const unifiedEvidence: UnifiedEvidenceItem[] = [];
    const seenEvidenceKeys = new Set<string>();

    // 1. Ingest Scanner Findings as SCANNER evidence
    for (const finding of scannerFindings) {
      const severity: FindingSeverity =
        finding.severity === 'CRITICAL' || finding.severity === 'critical'
          ? 'CRITICAL'
          : finding.severity === 'HIGH' || finding.severity === 'high'
          ? 'HIGH'
          : finding.severity === 'MEDIUM' || finding.severity === 'medium'
          ? 'MEDIUM'
          : finding.severity === 'LOW' || finding.severity === 'low'
          ? 'LOW'
          : 'INFO';

      const key = `SCANNER:${primaryIndicator.normalizedValue}:${finding.title}`;
      if (!seenEvidenceKeys.has(key)) {
        seenEvidenceKeys.add(key);
        unifiedEvidence.push({
          sourceType: 'SCANNER',
          source: `CyberWatch ${scannerType} Scanner`,
          indicator: primaryIndicator.normalizedValue,
          indicatorType: primaryIndicator.type,
          severity,
          description: `${finding.title}: ${finding.description || finding.evidence || ''}`.trim(),
          timestamp: new Date().toISOString(),
          relationship: primaryIndicator.contextSource,
        });
      }
    }

    // 2. Query TI Orchestrator for primary indicator (with safe fallback)
    let tiReport: ThreatIntelAnalysisReport | null = null;
    try {
      tiReport = await threatIntelOrchestrator.analyze(primaryIndicator.originalValue);
    } catch {
      tiReport = null;
    }

    const correlations: UnifiedCorrelationResult['correlations'] = [];

    // 3. Ingest TI Evidence as THREAT_INTELLIGENCE evidence
    if (tiReport && tiReport.evidence && Array.isArray(tiReport.evidence)) {
      for (const ev of tiReport.evidence) {
        const key = `TI:${ev.provider}:${ev.indicator}:${ev.value}`;
        if (!seenEvidenceKeys.has(key)) {
          seenEvidenceKeys.add(key);
          unifiedEvidence.push({
            sourceType: 'THREAT_INTELLIGENCE',
            source: ev.provider,
            indicator: ev.indicator,
            indicatorType: primaryIndicator.type,
            severity: ev.severity || 'INFO',
            confidence: String(ev.confidence || 'MEDIUM'),
            description: `${ev.value} — ${ev.description}`,
            timestamp: ev.lastSeen || ev.firstSeen || new Date().toISOString(),
            reference: ev.sourceReference,
            relationship: `Corroborated by ${ev.provider}`,
          });

          // Correlation matching
          correlations.push({
            scannerIndicator: primaryIndicator.normalizedValue,
            tiFinding: `${ev.value} (${ev.description})`,
            provider: ev.provider,
            correlationReason: `Direct canonical match on indicator ${ev.indicator}`,
          });
        }
      }
    }

    return {
      primaryIndicator: primaryIndicator.normalizedValue,
      indicatorType: primaryIndicator.type,
      reputationStatus: tiReport?.overallReputation || 'NOT_CONFIGURED',
      overallThreatStatus:
        tiReport?.status === 'MATCH_FOUND' ||
        tiReport?.status === 'NO_MATCH' ||
        tiReport?.status === 'PARTIAL' ||
        tiReport?.status === 'NOT_CONFIGURED'
          ? tiReport.status
          : 'UNAVAILABLE',
      unifiedEvidence,
      scannerFindingsCount: scannerFindings.length,
      threatIntelEvidenceCount: tiReport?.evidence?.length || 0,
      correlations,
    };
  }
}
