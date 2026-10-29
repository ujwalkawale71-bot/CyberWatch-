import { Link } from 'react-router-dom';
import {
  Globe,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  FileSearch,
  Activity,
  ArrowRight,
  ExternalLink,
  Search,
  Lock,
  Plus
} from 'lucide-react';
import type { ScanRecord, ScanResultClassification } from '../../types';

interface SecurityActivityListProps {
  scans: ScanRecord[];
  isLoading: boolean;
  onScanClick?: () => void;
}

export function SecurityActivityList({ scans, isLoading, onScanClick }: SecurityActivityListProps) {
  function getActivityIcon(targetType?: string) {
    const type = (targetType || 'URL').toLowerCase();
    if (type.includes('domain')) return Activity;
    if (type.includes('file')) return FileSearch;
    if (type.includes('website')) return ShieldCheck;
    if (type.includes('ssl')) return Lock;
    return Globe;
  }

  function getActionLabel(targetType?: string) {
    const type = (targetType || 'URL').toLowerCase();
    if (type === 'domain') return 'Domain Scan completed';
    if (type === 'website') return 'Website Scan completed';
    if (type === 'file') return 'File Scan completed';
    if (type === 'ssl') return 'SSL/TLS Scan completed';
    if (type === 'redirect') return 'Redirect Scan completed';
    return 'URL Scan completed';
  }

  function getResultBadge(result: ScanResultClassification | string) {
    const norm = String(result || '').toLowerCase();
    if (norm === 'safe') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <ShieldCheck className="w-3 h-3 text-emerald-600" />
          Safe
        </span>
      );
    }
    if (norm === 'low risk') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-50 text-cyan-700 border border-cyan-200">
          <ShieldCheck className="w-3 h-3 text-cyan-600" />
          Low Risk
        </span>
      );
    }
    if (norm === 'suspicious') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-50 text-amber-700 border border-amber-200">
          <AlertTriangle className="w-3 h-3 text-amber-600" />
          Suspicious
        </span>
      );
    }
    if (norm === 'high risk') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-orange-50 text-orange-700 border border-orange-200">
          <ShieldAlert className="w-3 h-3 text-orange-600" />
          High Risk
        </span>
      );
    }
    if (norm === 'critical') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-50 text-rose-700 border border-rose-200">
          <ShieldAlert className="w-3 h-3 text-rose-700" />
          Critical
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-slate-100 text-slate-700 border border-slate-200">
        {result}
      </span>
    );
  }

  function formatTime(dateValue?: string | Date | null) {
    if (!dateValue) return 'Just now';
    const d = new Date(dateValue);
    if (isNaN(d.getTime())) return 'Just now';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  return (
    <div className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-7 shadow-sm flex flex-col justify-between gap-6 transition-all duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-100">
        <div>
          <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block">
            Timeline
          </span>
          <h3 className="text-lg font-bold text-slate-900 tracking-tight mt-0.5">
            Your Security Activity
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Your recent security actions and activity on CyberWatch.
          </p>
        </div>

        <Link
          to="/activity"
          id="dashboard-view-all-activity-btn"
          className="inline-flex items-center gap-1.5 text-xs font-bold text-blue-600 hover:text-blue-700 transition-colors group shrink-0"
        >
          <span>View All Activity</span>
          <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
        </Link>
      </div>

      {/* Activity Content */}
      <div className="min-h-[160px] flex flex-col justify-center">
        {isLoading ? (
          <div className="py-8 flex flex-col items-center justify-center gap-2">
            <div className="w-6 h-6 border-2 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
            <p className="text-xs text-slate-400 font-medium">Loading security activity...</p>
          </div>
        ) : scans.length === 0 ? (
          /* Empty State */
          <div className="py-6 px-4 text-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-slate-50 text-slate-400 border border-slate-200/80 flex items-center justify-center mx-auto">
              <Search className="w-6 h-6" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-800">No activity yet today.</h4>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto leading-relaxed">
                Start by analyzing a URL, website or supported security target.
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                if (onScanClick) {
                  onScanClick();
                } else {
                  const input = document.getElementById('dashboard-url-input');
                  if (input) {
                    input.focus();
                    input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                  }
                }
              }}
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-xl shadow-sm transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Scan Target</span>
            </button>
          </div>
        ) : (
          /* Activity List */
          <div className="space-y-3">
            {scans.slice(0, 4).map((scan) => {
              const ActionIcon = getActivityIcon(scan.targetType);
              return (
                <div
                  key={scan.id}
                  className="flex flex-col sm:flex-row sm:items-center justify-between p-3 sm:p-3.5 rounded-2xl bg-slate-50/70 border border-slate-100 hover:bg-slate-50 hover:border-slate-200 transition-all gap-3 group"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    {/* Timestamp */}
                    <span className="text-[11px] font-mono font-semibold text-slate-400 whitespace-nowrap w-16 shrink-0">
                      {formatTime(scan.scannedAt || scan.createdAt)}
                    </span>

                    {/* Icon */}
                    <div className="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center shrink-0">
                      <ActionIcon className="w-4 h-4" />
                    </div>

                    {/* Action & Target */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
                          {getActionLabel(scan.targetType)}
                        </span>
                        <span className="text-[10px] font-semibold text-slate-500 bg-slate-200/60 px-1.5 py-0.5 rounded">
                          {scan.targetType || 'URL'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 truncate font-mono mt-0.5 max-w-md" title={scan.target}>
                        {scan.target}
                      </p>
                    </div>
                  </div>

                  {/* Result badge & Link */}
                  <div className="flex items-center justify-between sm:justify-end gap-3 pl-16 sm:pl-0 shrink-0">
                    {getResultBadge(scan.result)}
                    <Link
                      to={`/reports/scans/${scan.id}`}
                      state={{ scan }}
                      className="text-slate-400 hover:text-blue-600 p-1 rounded-lg hover:bg-white transition-colors"
                      title="View scan details"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      {scans.length > 0 && (
        <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
          <span>Showing latest {Math.min(scans.length, 4)} completed activities</span>
          <Link
            to="/activity"
            className="font-bold text-blue-600 hover:text-blue-700 inline-flex items-center gap-1 group"
          >
            <span>View All Activity</span>
            <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
          </Link>
        </div>
      )}
    </div>
  );
}
