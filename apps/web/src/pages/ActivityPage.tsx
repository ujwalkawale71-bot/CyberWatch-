import { useEffect, useState, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Clock,
  Globe,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Search,
  ArrowLeft,
  ExternalLink,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Filter,
  Calendar,
  FileText,
  Activity,
  Puzzle,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { scanService, type PaginatedScans } from '../services/scan.service';
import type { ScanResultClassification } from '../types';

type TimeframeFilter = 'all' | 'today' | 'yesterday' | '7days' | '30days';
type CategoryFilter = 'all' | 'scans' | 'findings' | 'reports' | 'monitoring' | 'extension';

export function ActivityPage() {
  const [searchParams] = useSearchParams();

  const [data, setData] = useState<PaginatedScans>({
    scans: [],
    pagination: { total: 0, page: 1, limit: 20, totalPages: 0 },
  });
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const initialTimeframe = (searchParams.get('timeframe') as TimeframeFilter) || 'all';
  const initialCategory = (searchParams.get('type') as CategoryFilter) || 'all';

  const [timeframe, setTimeframe] = useState<TimeframeFilter>(initialTimeframe);
  const [category, setCategory] = useState<CategoryFilter>(initialCategory);
  const [searchTerm, setSearchTerm] = useState('');
  const [resultFilter, setResultFilter] = useState<string>('ALL');

  useEffect(() => {
    loadActivity(page);
  }, [page]);

  async function loadActivity(targetPage: number) {
    setIsLoading(true);
    try {
      // Fetch up to 50 items for rich audit filtering
      const res = await scanService.getRecentScans(50, targetPage);
      setData(res);
    } catch (err) {
      console.error('Failed to load activity logs:', err);
    } finally {
      setIsLoading(false);
    }
  }

  function getResultBadge(result: ScanResultClassification | string) {
    const norm = String(result || '').toLowerCase();
    switch (norm) {
      case 'safe':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200/80">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
            Safe
          </span>
        );
      case 'low risk':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-50 text-cyan-700 border border-cyan-200/80">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-600" />
            Low Risk
          </span>
        );
      case 'suspicious':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200/80">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
            Suspicious
          </span>
        );
      case 'high risk':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-orange-50 text-orange-700 border border-orange-200/80">
            <ShieldAlert className="w-3.5 h-3.5 text-orange-600" />
            High Risk
          </span>
        );
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-red-50 text-red-700 border border-red-200/80">
            <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
            Critical
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
            {result}
          </span>
        );
    }
  }

  const filteredScans = useMemo(() => {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const startOfYesterday = startOfToday - 86400000;
    const sevenDaysAgo = now.getTime() - 7 * 86400000;
    const thirtyDaysAgo = now.getTime() - 30 * 86400000;

    return data.scans.filter((s) => {
      const scanTime = new Date(s.scannedAt || s.createdAt).getTime();

      // 1. Timeframe Filter
      if (timeframe === 'today' && scanTime < startOfToday) return false;
      if (timeframe === 'yesterday' && (scanTime < startOfYesterday || scanTime >= startOfToday)) return false;
      if (timeframe === '7days' && scanTime < sevenDaysAgo) return false;
      if (timeframe === '30days' && scanTime < thirtyDaysAgo) return false;

      // 2. Category Filter
      if (category === 'findings') {
        const norm = (s.result || '').toLowerCase();
        if (norm === 'safe') return false;
      } else if (category === 'extension') {
        const targetType = (s.targetType || '').toLowerCase();
        if (!targetType.includes('extension') && !targetType.includes('browser')) {
          // If no extension-type scans exist yet, match target containing extension or show empty
          if (!s.target.toLowerCase().includes('extension')) return false;
        }
      } else if (category === 'reports') {
        // Scans generate reports, keep all completed
        if (s.status !== 'completed') return false;
      }

      // 3. Result Filter
      if (resultFilter !== 'ALL' && s.result !== resultFilter) return false;

      // 4. Search Filter
      if (searchTerm && !s.target.toLowerCase().includes(searchTerm.toLowerCase())) return false;

      return true;
    });
  }, [data.scans, timeframe, category, resultFilter, searchTerm]);

  return (
    <div className="pt-24 pb-20 bg-slate-50/50 min-h-screen">
      <Container>
        {/* Navigation & Header */}
        <div className="py-4 flex items-center justify-between">
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 text-sm font-semibold text-slate-600 hover:text-blue-600 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Dashboard
          </Link>

          <button
            onClick={() => loadActivity(page)}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-white border border-slate-200 hover:border-slate-300 text-slate-700 rounded-xl text-xs font-semibold shadow-xs transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5 text-blue-600" />
            Refresh Activity Log
          </button>
        </div>

        {/* Main Activity Card */}
        <div className="mt-4 bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 shadow-sm space-y-7">
          {/* Top Title & Overview */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
            <div>
              <div className="flex items-center gap-2 text-xs font-bold text-blue-600 uppercase tracking-wider mb-1">
                <Clock className="w-4 h-4" />
                <span>Security Audit Trail</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
                Your Security Activity
              </h1>
              <p className="text-sm text-slate-500 mt-1">
                Detailed history of scans, threat detections, reports, and security events across your CyberWatch account.
              </p>
            </div>

            <Link
              to="/dashboard"
              className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-blue-600 text-white text-sm font-bold rounded-xl hover:bg-blue-700 shadow-md shadow-blue-600/20 transition-all shrink-0"
            >
              <Globe className="w-4 h-4" />
              <span>New Security Scan</span>
            </Link>
          </div>

          {/* Timeframe Selector & Category Pills */}
          <div className="space-y-4">
            {/* Timeframe Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50/80 p-2.5 rounded-2xl border border-slate-200/70">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-600 px-2">
                <Calendar className="w-4 h-4 text-blue-600" />
                <span>Timeframe:</span>
              </div>

              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
                {[
                  { id: 'all', label: 'All Time' },
                  { id: 'today', label: 'Today' },
                  { id: 'yesterday', label: 'Yesterday' },
                  { id: '7days', label: 'Last 7 Days' },
                  { id: '30days', label: 'Last 30 Days' },
                ].map((tf) => (
                  <button
                    key={tf.id}
                    onClick={() => setTimeframe(tf.id as TimeframeFilter)}
                    className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all ${
                      timeframe === tf.id
                        ? 'bg-blue-600 text-white shadow-sm'
                        : 'bg-white text-slate-600 hover:bg-slate-100/80 border border-slate-200/60'
                    }`}
                  >
                    {tf.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Category Filter Bar */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1">
              <span className="text-xs font-bold text-slate-500 flex items-center gap-1 shrink-0 px-1">
                <Filter className="w-3.5 h-3.5" />
                <span>Type:</span>
              </span>

              {[
                { id: 'all', label: 'All Activities', icon: Activity },
                { id: 'scans', label: 'Scans', icon: Globe },
                { id: 'findings', label: 'Security Findings', icon: AlertTriangle },
                { id: 'reports', label: 'Reports', icon: FileText },
                { id: 'monitoring', label: 'Monitoring', icon: ShieldCheck },
                { id: 'extension', label: 'Browser Extension Activity', icon: Puzzle },
              ].map((cat) => {
                const CatIcon = cat.icon;
                return (
                  <button
                    key={cat.id}
                    onClick={() => setCategory(cat.id as CategoryFilter)}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold whitespace-nowrap transition-all border ${
                      category === cat.id
                        ? 'bg-slate-900 text-white border-slate-900 shadow-xs'
                        : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    <CatIcon className="w-3.5 h-3.5" />
                    <span>{cat.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Search & Verdict Filter Bar */}
          <div className="flex flex-col sm:flex-row gap-3 pt-1">
            <div className="relative flex-1">
              <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Filter by target URL, host or domain..."
                className="w-full pl-10 pr-4 py-2.5 text-sm bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
              {['ALL', 'Safe', 'Low Risk', 'Suspicious', 'High Risk', 'Critical'].map((res) => (
                <button
                  key={res}
                  onClick={() => setResultFilter(res)}
                  className={`px-3 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition-colors border ${
                    resultFilter === res
                      ? 'bg-blue-600 text-white border-blue-600 shadow-xs'
                      : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {res}
                </button>
              ))}
            </div>
          </div>

          {/* Activity Table */}
          <div className="pt-2">
            {isLoading ? (
              <div className="py-16 flex flex-col items-center justify-center gap-3">
                <div className="w-8 h-8 border-3 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
                <p className="text-sm text-slate-500 font-medium">Fetching complete security activity...</p>
              </div>
            ) : filteredScans.length === 0 ? (
              <div className="py-14 text-center text-sm text-slate-500 space-y-3 max-w-md mx-auto">
                <div className="w-14 h-14 rounded-2xl bg-slate-100 text-slate-400 flex items-center justify-center mx-auto border border-slate-200/80">
                  <Clock className="w-7 h-7" />
                </div>
                <h3 className="font-bold text-slate-800 text-base">No activity records match your criteria.</h3>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Try adjusting your timeframe, category filter, or query, or perform a new scan on the dashboard.
                </p>
                <Link
                  to="/dashboard"
                  className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-xs font-bold rounded-xl shadow-xs"
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Start a Scan</span>
                </Link>
              </div>
            ) : (
              <div className="overflow-x-auto -mx-6 sm:mx-0">
                <table className="w-full text-left text-sm border-collapse min-w-[680px]">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs font-bold text-slate-500 uppercase tracking-wider bg-slate-50/60">
                      <th className="py-3.5 px-4 sm:px-6 rounded-l-xl">Target</th>
                      <th className="py-3.5 px-4">Scanner Type</th>
                      <th className="py-3.5 px-4">Result</th>
                      <th className="py-3.5 px-4">Timestamp</th>
                      <th className="py-3.5 px-4 sm:px-6 text-right rounded-r-xl">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredScans.map((scan) => (
                      <tr key={scan.id} className="hover:bg-slate-50/80 transition-colors group">
                        {/* Target */}
                        <td className="py-4 px-4 sm:px-6 max-w-[320px]">
                          <div className="flex items-center gap-2.5">
                            <div className="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center shrink-0 border border-blue-100">
                              <Globe className="w-4 h-4" />
                            </div>
                            <span
                              className="font-semibold text-slate-900 truncate block group-hover:text-blue-600 transition-colors"
                              title={scan.target}
                            >
                              {scan.target}
                            </span>
                          </div>
                        </td>

                        {/* Scanner Type */}
                        <td className="py-4 px-4 text-slate-600 font-medium">
                          <span className="px-2.5 py-0.5 rounded-md bg-slate-100 text-slate-700 text-xs font-semibold">
                            {scan.targetType || 'URL'}
                          </span>
                        </td>

                        {/* Result Badge */}
                        <td className="py-4 px-4">{getResultBadge(scan.result)}</td>

                        {/* Scanned Timestamp */}
                        <td className="py-4 px-4 text-slate-500 text-xs font-medium whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-slate-400" />
                            <span>{new Date(scan.scannedAt || scan.createdAt).toLocaleString()}</span>
                          </div>
                        </td>

                        {/* Action */}
                        <td className="py-4 px-4 sm:px-6 text-right whitespace-nowrap">
                          <Link
                            to={`/reports/scans/${scan.id}`}
                            state={{ scan }}
                            className="inline-flex items-center gap-1 text-xs font-bold text-blue-600 hover:text-blue-800 bg-blue-50 hover:bg-blue-100/80 px-3 py-1.5 rounded-lg transition-colors"
                          >
                            <span>VIEW REPORT</span>
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

          {/* Pagination */}
          {data.pagination.totalPages > 1 && (
            <div className="pt-4 border-t border-slate-100 flex items-center justify-between text-xs font-semibold text-slate-600">
              <span>
                Page {data.pagination.page} of {data.pagination.totalPages} ({filteredScans.length} of {data.pagination.total} records shown)
              </span>
              <div className="flex items-center gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(p - 1, 1))}
                  className="p-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  disabled={page >= data.pagination.totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="p-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </Container>
    </div>
  );
}
