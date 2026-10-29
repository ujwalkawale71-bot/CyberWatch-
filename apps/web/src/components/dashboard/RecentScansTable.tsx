import { Link } from 'react-router-dom';
import {
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Clock,
  ExternalLink,
  Globe,
  Search,
} from 'lucide-react';
import type { ScanRecord, ScanResultClassification } from '../../types';

interface RecentScansTableProps {
  scans: ScanRecord[];
  isLoading: boolean;
  onScanFirstUrl?: () => void;
}

export function RecentScansTable({ scans, isLoading, onScanFirstUrl }: RecentScansTableProps) {
  function getResultBadge(result: ScanResultClassification | string) {
    const norm = String(result || '').toLowerCase();

    if (norm === 'safe') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          SAFE
        </span>
      );
    }
    if (norm === 'low risk') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-cyan-50 text-cyan-700 border border-cyan-200">
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-600" />
          LOW RISK
        </span>
      );
    }
    if (norm === 'suspicious') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-50 text-amber-700 border border-amber-200">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
          SUSPICIOUS
        </span>
      );
    }
    if (norm === 'high risk') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-red-50 text-red-700 border border-red-200">
          <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
          HIGH RISK
        </span>
      );
    }
    if (norm === 'critical') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-300">
          <ShieldAlert className="w-3.5 h-3.5 text-rose-700" />
          CRITICAL
        </span>
      );
    }

    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-slate-100 text-slate-700 border border-slate-200">
        {result}
      </span>
    );
  }

  function formatRelativeTime(dateValue: string | Date | undefined): string {
    if (!dateValue) return 'Just now';
    const d = new Date(dateValue);
    if (isNaN(d.getTime())) return 'Just now';

    const diffSeconds = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diffSeconds < 60) return 'Just now';
    if (diffSeconds < 3600) {
      const mins = Math.floor(diffSeconds / 60);
      return `${mins} minute${mins === 1 ? '' : 's'} ago`;
    }
    if (diffSeconds < 86400) {
      const hours = Math.floor(diffSeconds / 3600);
      return `${hours} hour${hours === 1 ? '' : 's'} ago`;
    }
    const days = Math.floor(diffSeconds / 86400);
    if (days < 7) {
      return `${days} day${days === 1 ? '' : 's'} ago`;
    }

    return d.toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  }

  function formatTargetDisplay(target: string) {
    if (!target) return 'N/A';
    if (target.trim().startsWith('{')) {
      try {
        const parsed = JSON.parse(target);
        return `Manifest: ${parsed.name || 'Extension'} (v${parsed.version || '1.0'})`;
      } catch {
        return target.slice(0, 40) + '...';
      }
    }
    return target;
  }

  return (
    <div className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 shadow-sm transition-all duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
            Recent Scans
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Your latest security scans and their results.
          </p>
        </div>

        {scans.length > 0 && (
          <Link
            to="/reports/history"
            id="dashboard-view-all-scans-btn"
            className="inline-flex items-center gap-1.5 text-sm font-bold text-blue-600 hover:text-blue-700 transition-colors"
          >
            <span>View All</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
        )}
      </div>

      {/* Table Content */}
      <div className="mt-6">
        {isLoading ? (
          <div className="py-12 flex flex-col items-center justify-center gap-3">
            <div className="w-8 h-8 border-3 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
            <p className="text-sm text-slate-500 font-medium">Loading scans...</p>
          </div>
        ) : scans.length === 0 ? (
          /* Empty State */
          <div className="py-14 px-4 text-center max-w-md mx-auto space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center mx-auto shadow-sm">
              <Search className="w-8 h-8 text-blue-600" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-slate-900">No scans yet</h3>
              <p className="text-sm text-slate-500 mt-1 leading-relaxed">
                Analyze your first security target to start monitoring your web security.
              </p>
            </div>
            <button
              id="dashboard-scan-first-url-btn"
              type="button"
              onClick={() => {
                if (onScanFirstUrl) {
                  onScanFirstUrl();
                } else {
                  document.getElementById('dashboard-url-input')?.focus();
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }
              }}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-bold rounded-xl shadow-md shadow-blue-600/20 transition-all duration-200"
            >
              <Globe className="w-4 h-4" />
              <span>Scan Your First Target</span>
            </button>
          </div>
        ) : (
          /* Scans Table */
          <div className="overflow-x-auto -mx-6 sm:mx-0">
            <table className="w-full text-left text-sm border-collapse min-w-[640px]">
              <thead>
                <tr className="border-b border-slate-200 text-xs font-bold text-slate-500 uppercase tracking-wider bg-slate-50/60">
                  <th className="py-3.5 px-4 sm:px-6 rounded-l-xl">Target</th>
                  <th className="py-3.5 px-4">Scanner Type</th>
                  <th className="py-3.5 px-4">Result</th>
                  <th className="py-3.5 px-4">Time</th>
                  <th className="py-3.5 px-4 sm:px-6 text-right rounded-r-xl">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-50/80 transition-colors group">
                    {/* Target */}
                    <td className="py-4 px-4 sm:px-6 max-w-[280px]">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center shrink-0 border border-blue-100">
                          <Globe className="w-4 h-4" />
                        </div>
                        <span
                          className="font-semibold text-slate-900 truncate block group-hover:text-blue-600 transition-colors"
                          title={scan.target}
                        >
                          {formatTargetDisplay(scan.target)}
                        </span>
                      </div>
                    </td>

                    {/* Type */}
                    <td className="py-4 px-4 text-slate-600 font-medium">
                      <span className="px-2.5 py-0.5 rounded-md bg-slate-100 text-slate-700 text-xs font-semibold">
                        {scan.targetType || 'URL'}
                      </span>
                    </td>

                    {/* Result */}
                    <td className="py-4 px-4">{getResultBadge(scan.result)}</td>

                    {/* Scanned At */}
                    <td className="py-4 px-4 text-slate-500 text-xs font-medium whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-400" />
                        <span>{formatRelativeTime(scan.scannedAt || scan.createdAt)}</span>
                      </div>
                    </td>

                    {/* Action */}
                    <td className="py-4 px-4 sm:px-6 text-right whitespace-nowrap">
                      <Link
                        to={`/reports/scans/${scan.id}`}
                        state={{ scan }}
                        className="inline-flex items-center gap-1.5 text-xs font-bold text-blue-600 hover:text-blue-800 bg-blue-50 hover:bg-blue-100/80 px-3 py-1.5 rounded-lg transition-colors"
                      >
                        <span>View Details</span>
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
