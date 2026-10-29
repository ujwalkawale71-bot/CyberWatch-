import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowRight, CheckCircle2 } from 'lucide-react';
import type { ScanRecord } from '../../types';

interface AttentionRequiredProps {
  scans: ScanRecord[];
  isLoading: boolean;
}

export function AttentionRequired({ scans, isLoading }: AttentionRequiredProps) {
  if (isLoading) return null;

  // Filter for real scans requiring user attention (Suspicious, High Risk, Critical)
  const flaggedScans = scans.filter((s) => {
    const verdict = (s.result || '').toLowerCase();
    return verdict === 'suspicious' || verdict === 'high risk' || verdict === 'critical';
  });

  if (flaggedScans.length === 0) {
    return (
      <div className="bg-emerald-50/60 border border-emerald-200/80 rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs sm:text-sm">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-700 flex items-center justify-center shrink-0 border border-emerald-200">
            <CheckCircle2 className="w-4 h-4" />
          </div>
          <div>
            <span className="font-bold text-emerald-900 block">
              No immediate attention required.
            </span>
            <span className="text-emerald-700 text-xs mt-0.5 block">
              All scanned targets comply with standard security benchmarks.
            </span>
          </div>
        </div>

        <Link
          to="/reports/history"
          className="inline-flex items-center gap-1 font-bold text-emerald-800 hover:text-emerald-900 shrink-0"
        >
          <span>View Verified Scans</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    );
  }

  const primaryFinding = flaggedScans[0];
  const findingCount = flaggedScans.length;

  return (
    <div className="bg-gradient-to-r from-amber-50/90 via-orange-50/70 to-rose-50/60 border border-amber-200/90 rounded-3xl p-6 sm:p-7 shadow-sm space-y-4 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-100 text-amber-700 border border-amber-200 flex items-center justify-center shrink-0">
            <AlertTriangle className="w-5 h-5 text-amber-600" />
          </div>
          <div>
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-amber-200/70 text-amber-900 text-[10px] font-extrabold uppercase tracking-wider">
              High Priority
            </div>
            <h3 className="text-base sm:text-lg font-extrabold text-slate-900 tracking-tight mt-1">
              Attention Required
            </h3>
          </div>
        </div>

        <span className="text-xs font-bold text-amber-800 bg-amber-100/80 px-3 py-1 rounded-full border border-amber-200/80 w-fit">
          {findingCount} {findingCount === 1 ? 'result requires review' : 'results require review'}
        </span>
      </div>

      {/* Flagged Item Details */}
      <div className="bg-white/90 border border-amber-200/70 rounded-2xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xs">
        <div className="space-y-1.5 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-bold text-slate-700">Target:</span>
            <span className="font-mono text-xs sm:text-sm font-bold text-slate-900 truncate max-w-md block" title={primaryFinding.target}>
              {primaryFinding.target}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
            <span className="flex items-center gap-1">
              <span className="font-medium text-slate-400">Type:</span>
              <span className="font-semibold text-slate-700">{primaryFinding.targetType || 'URL'} Scan</span>
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <span className="font-medium text-slate-400">Status:</span>
              <span className="font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded">
                {primaryFinding.result}
              </span>
            </span>
            {primaryFinding.findings && primaryFinding.findings.length > 0 && (
              <>
                <span>•</span>
                <span className="text-slate-600 font-medium">
                  {primaryFinding.findings[0].title}
                </span>
              </>
            )}
          </div>
        </div>

        {/* Action Button */}
        <Link
          to={`/reports/scans/${primaryFinding.id}`}
          state={{ scan: primaryFinding }}
          id="attention-review-finding-btn"
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-amber-600 hover:bg-amber-700 active:bg-amber-800 text-white text-xs font-bold rounded-xl shadow-sm transition-all shrink-0"
        >
          <span>Review Finding</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  );
}
