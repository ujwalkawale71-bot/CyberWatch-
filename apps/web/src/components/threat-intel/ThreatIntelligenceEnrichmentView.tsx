import React from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  Radio,
  ExternalLink,
  Search,
  Info,
} from 'lucide-react';
import type { ThreatIntelAnalysisReport, ThreatIntelEvidenceItem } from '../../types';
import { cn } from '../../lib/utils';

interface ThreatIntelligenceEnrichmentViewProps {
  report?: ThreatIntelAnalysisReport | null;
  target?: string;
  className?: string;
  compact?: boolean;
}

export const ThreatIntelligenceEnrichmentView: React.FC<ThreatIntelligenceEnrichmentViewProps> = ({
  report,
  target,
  className,
  compact = false,
}) => {
  if (!report) {
    return (
      <div className={cn('bg-slate-50 border border-slate-200 rounded-2xl p-6 text-center', className)}>
        <div className="w-12 h-12 rounded-2xl bg-blue-50 text-blue-600 flex items-center justify-center mx-auto mb-3">
          <Radio className="w-6 h-6" />
        </div>
        <h4 className="text-sm font-bold text-slate-900 mb-1">Threat Intelligence</h4>
        <p className="text-xs text-slate-500 max-w-md mx-auto mb-4">
          Query external threat feeds, multi-engine reputation databases, and IOC correlation for this target.
        </p>
        {target && (
          <Link
            to={`/threat-intelligence?q=${encodeURIComponent(target)}`}
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-semibold shadow-xs transition-colors"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Investigate in Threat Intelligence</span>
          </Link>
        )}
      </div>
    );
  }

  const isMalicious = report.overallReputation === 'MALICIOUS';
  const isSuspicious = report.overallReputation === 'SUSPICIOUS';
  const isNotConfigured = report.status === 'NOT_CONFIGURED';
  const isUnavailable = report.status === 'UNAVAILABLE';

  const badgeColor = isMalicious
    ? 'bg-rose-50 text-rose-700 border-rose-200'
    : isSuspicious
    ? 'bg-amber-50 text-amber-700 border-amber-200'
    : isNotConfigured
    ? 'bg-slate-100 text-slate-600 border-slate-200'
    : isUnavailable
    ? 'bg-amber-50 text-amber-700 border-amber-200'
    : 'bg-emerald-50 text-emerald-700 border-emerald-200';

  return (
    <div className={cn('bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-xs', className)}>
      {/* Header Bar */}
      <div className="p-5 border-b border-slate-100 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div
            className={cn(
              'w-10 h-10 rounded-xl flex items-center justify-center border',
              isMalicious
                ? 'bg-rose-50 text-rose-600 border-rose-100'
                : isSuspicious
                ? 'bg-amber-50 text-amber-600 border-amber-100'
                : 'bg-blue-50 text-blue-600 border-blue-100'
            )}
          >
            {isMalicious ? (
              <ShieldAlert className="w-5 h-5" />
            ) : isSuspicious ? (
              <AlertTriangle className="w-5 h-5" />
            ) : (
              <Radio className="w-5 h-5" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-bold text-slate-900">Threat Intelligence Enrichment</h4>
              <span className={cn('px-2.5 py-0.5 rounded-full text-[11px] font-bold border', badgeColor)}>
                {report.status === 'MATCH_FOUND'
                  ? `MATCH FOUND: ${report.overallReputation}`
                  : report.status === 'NO_MATCH'
                  ? 'NO KNOWN MATCH'
                  : report.status === 'NOT_CONFIGURED'
                  ? 'NOT CONFIGURED'
                  : report.status}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Target: <span className="font-mono text-slate-700 font-semibold">{report.displayValue || report.indicator}</span>
            </p>
          </div>
        </div>

        <Link
          to={`/threat-intelligence?q=${encodeURIComponent(report.indicator)}`}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 rounded-xl text-xs font-semibold transition-colors"
        >
          <span>Full Investigation</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-5 bg-slate-50/50 border-b border-slate-100 text-xs">
        <div>
          <span className="text-slate-400 block text-[11px] font-medium">Confidence Level</span>
          <span className="font-bold text-slate-800 text-sm mt-0.5 block">{report.confidence}</span>
        </div>
        <div>
          <span className="text-slate-400 block text-[11px] font-medium">Flagged Engines</span>
          <span
            className={cn(
              'font-bold text-sm mt-0.5 block',
              report.detectionSummary && report.detectionSummary.flaggedCount > 0
                ? 'text-rose-600'
                : 'text-slate-800'
            )}
          >
            {report.detectionSummary?.flaggedCount ?? 0} detections
          </span>
        </div>
        <div>
          <span className="text-slate-400 block text-[11px] font-medium">Sources Queried</span>
          <span className="font-bold text-slate-800 text-sm mt-0.5 block">
            {report.providersChecked} / {report.providersTotal || report.providersChecked} sources
          </span>
        </div>
        <div>
          <span className="text-slate-400 block text-[11px] font-medium">Categories</span>
          <span className="font-bold text-slate-800 text-sm mt-0.5 block truncate">
            {report.threatCategories.length > 0 ? report.threatCategories.join(', ') : 'None'}
          </span>
        </div>
      </div>

      {/* Provider Pills */}
      <div className="p-5 border-b border-slate-100">
        <h5 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2.5">
          Configured Intelligence Feeds
        </h5>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {report.providers.map((p, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between p-2.5 bg-slate-50 border border-slate-200/80 rounded-xl text-xs"
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className="font-bold text-slate-800 truncate">{p.providerName}</span>
              </div>
              <span
                className={cn(
                  'px-2 py-0.5 rounded text-[10px] font-bold border shrink-0',
                  p.status === 'NOT_CONFIGURED'
                    ? 'bg-slate-100 text-slate-500 border-slate-200'
                    : p.reputation === 'MALICIOUS'
                    ? 'bg-rose-50 text-rose-700 border-rose-200'
                    : p.reputation === 'SUSPICIOUS'
                    ? 'bg-amber-50 text-amber-700 border-amber-200'
                    : p.status === 'SUCCESS'
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-amber-50 text-amber-700 border-amber-200'
                )}
              >
                {p.status === 'NOT_CONFIGURED'
                  ? 'NOT CONFIGURED'
                  : p.detectionSummary && p.detectionSummary.malicious > 0
                  ? `${p.detectionSummary.malicious} Flagged`
                  : p.status === 'SUCCESS'
                  ? 'NO MATCH'
                  : p.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Evidence Items */}
      {report.evidence.length > 0 && (
        <div className="p-5 border-b border-slate-100">
          <h5 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-3">
            Corroborated Threat Evidence ({report.evidence.length})
          </h5>
          <div className="space-y-2">
            {report.evidence.slice(0, compact ? 2 : 5).map((ev: ThreatIntelEvidenceItem, i: number) => (
              <div key={i} className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl text-xs">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="font-bold text-slate-900">{ev.value}</span>
                  <span className="text-[10px] font-semibold text-slate-500 bg-white px-2 py-0.5 rounded border border-slate-200">
                    {ev.provider}
                  </span>
                </div>
                <p className="text-slate-600 text-[11px] leading-relaxed">{ev.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Honest Recommendation & Disclaimer */}
      <div className="p-4 bg-slate-50/70 flex items-start gap-2.5 text-xs text-slate-600">
        <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
        <div>
          <p className="font-semibold text-slate-800">{report.recommendation}</p>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Threat intelligence provides external reputation context. CyberWatch never manufactures clean status when feeds are unavailable.
          </p>
        </div>
      </div>
    </div>
  );
};
