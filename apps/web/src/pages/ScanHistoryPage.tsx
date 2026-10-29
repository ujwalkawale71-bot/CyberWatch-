import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Clock,
  Globe,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Search,
  ExternalLink,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Terminal,
  FileSearch,
  Puzzle,
  GitCompare,
  CheckCircle2,
  XCircle,
  AlertCircle,
  FileSpreadsheet,
  FileCode,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { ReportsNav } from '../components/reports/ReportsNav';
import { reportService } from '../services/report.service';
import type { ScanRecord, ScanResultClassification, ScanTargetType } from '../types';

export function ScanHistoryPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [pagination, setPagination] = useState({ total: 0, page: 1, limit: 10, totalPages: 0 });
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState<string | null>(null);

  // Filters
  const [filterScanner, setFilterScanner] = useState<ScanTargetType | 'ALL'>('ALL');
  const [filterResult, setFilterResult] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'newest' | 'oldest' | 'highest_risk' | 'lowest_risk'>('newest');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadScans(page);

    function handleVisibility() {
      if (document.visibilityState === 'visible') {
        loadScans(page);
      }
    }

    window.addEventListener('focus', handleVisibility);
    document.addEventListener('visibilitychange', handleVisibility);
    return () => {
      window.removeEventListener('focus', handleVisibility);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [page, filterScanner, filterResult, filterStatus, sortBy]);

  async function loadScans(targetPage: number) {
    setIsLoading(true);
    setError(null);
    try {
      const res = await reportService.getHistory({
        scanner: filterScanner,
        riskLevel: filterResult,
        status: filterStatus,
        sortBy,
        search: searchTerm || undefined,
        page: targetPage,
        limit: 10,
      });
      setScans(res.scans);
      setPagination(res.pagination);
    } catch (err: any) {
      console.error('Failed to load scan history:', err);
      setError(err.response?.data?.message || err.message || 'Unable to load scan history.');
    } finally {
      setIsLoading(false);
    }
  }

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    loadScans(1);
  }

  async function handleExport(format: 'csv' | 'json') {
    setIsExporting(format);
    try {
      await reportService.downloadExport('history', format);
    } catch (err: any) {
      console.error('Export failed:', err);
    } finally {
      setIsExporting(null);
    }
  }

  function getScannerIcon(type: ScanTargetType | string) {
    switch (type) {
      case 'Website':
        return <ShieldAlert className="w-4 h-4 text-indigo-600" />;
      case 'API':
        return <Terminal className="w-4 h-4 text-cyan-600" />;
      case 'File':
        return <FileSearch className="w-4 h-4 text-blue-600" />;
      case 'Extension':
        return <Puzzle className="w-4 h-4 text-sky-600" />;
      case 'Phishing':
        return <AlertTriangle className="w-4 h-4 text-amber-600" />;
      case 'URL':
      default:
        return <Globe className="w-4 h-4 text-blue-600" />;
    }
  }

  function getResultBadge(result: ScanResultClassification | string) {
    const res = (result || 'Unknown').toUpperCase();
    if (res.includes('SAFE') || res.includes('LOW')) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200/80">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          {result}
        </span>
      );
    }
    if (res.includes('SUSPICIOUS') || res.includes('MEDIUM')) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200/80">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
          {result}
        </span>
      );
    }
    if (res.includes('HIGH') || res.includes('CRITICAL') || res.includes('MALICIOUS')) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200/80">
          <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
          {result}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
        {result}
      </span>
    );
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
    <div className="pt-24 pb-20 bg-slate-50/50 min-h-screen">
      <ReportsNav totalScans={pagination.total} />

      <Container className="mt-8">
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-2">
              <Clock className="w-3.5 h-3.5" />
              Scan History Archive
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Security Scan History
            </h1>
            <p className="text-sm text-slate-500 mt-1 max-w-2xl">
              Chronological log of all URL, Website, API, Phishing, File, and Browser Extension audits.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={() => loadScans(page)}
              disabled={isLoading}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-white border border-slate-200 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors shadow-sm disabled:opacity-50"
              title="Refresh scan history"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-blue-600 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
            <Link
              to="/reports/compare"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-bold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors shadow-sm"
            >
              <GitCompare className="w-3.5 h-3.5 text-blue-600" />
              <span>Compare Scans</span>
            </Link>
            <button
              onClick={() => handleExport('csv')}
              disabled={isExporting !== null}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-white border border-slate-200 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors shadow-sm disabled:opacity-50"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
              <span>{isExporting === 'csv' ? 'Exporting...' : 'Export CSV'}</span>
            </button>
            <button
              onClick={() => handleExport('json')}
              disabled={isExporting !== null}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-white border border-slate-200 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors shadow-sm disabled:opacity-50"
            >
              <FileCode className="w-3.5 h-3.5 text-cyan-600" />
              <span>{isExporting === 'json' ? 'Exporting...' : 'Export JSON'}</span>
            </button>
          </div>
        </div>

        {/* Filter Controls Bar */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm mb-6 space-y-4">
          <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
            {/* Search Input */}
            <form onSubmit={handleSearchSubmit} className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search scans by target URL, domain, filename, or SHA256 hash..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-24 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white"
              />
              <button
                type="submit"
                className="absolute right-1.5 top-1/2 -translate-y-1/2 px-3 py-1 bg-blue-600 text-white rounded text-xs font-semibold hover:bg-blue-700"
              >
                Search
              </button>
            </form>

            {/* Sort Control */}
            <div className="flex items-center gap-2 text-xs shrink-0">
              <span className="text-slate-500 font-medium">Sort by:</span>
              <select
                value={sortBy}
                onChange={(e) => {
                  setSortBy(e.target.value as any);
                  setPage(1);
                }}
                className="p-1.5 bg-slate-50 border border-slate-200 rounded text-xs font-semibold text-slate-800"
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="highest_risk">Highest Risk Score</option>
                <option value="lowest_risk">Lowest Risk Score</option>
              </select>
            </div>
          </div>

          {/* Secondary Filters Row */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-100 text-xs">
            <div className="flex flex-wrap items-center gap-3">
              {/* Scanner filter */}
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">Scanner:</span>
                <select
                  value={filterScanner}
                  onChange={(e) => {
                    setFilterScanner(e.target.value as any);
                    setPage(1);
                  }}
                  className="p-1 bg-slate-50 border border-slate-200 rounded text-xs font-medium text-slate-800"
                >
                  <option value="ALL">All Scanners</option>
                  <option value="URL">URL Security</option>
                  <option value="Website">Website Security</option>
                  <option value="API">API Security</option>
                  <option value="Phishing">Phishing Security</option>
                  <option value="File">File Security</option>
                  <option value="Extension">Extension Security</option>
                </select>
              </div>

              {/* Verdict filter */}
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">Verdict:</span>
                <select
                  value={filterResult}
                  onChange={(e) => {
                    setFilterResult(e.target.value);
                    setPage(1);
                  }}
                  className="p-1 bg-slate-50 border border-slate-200 rounded text-xs font-medium text-slate-800"
                >
                  <option value="ALL">All Verdicts</option>
                  <option value="Safe">Safe</option>
                  <option value="Low Risk">Low Risk</option>
                  <option value="Suspicious">Suspicious</option>
                  <option value="High Risk">High Risk</option>
                  <option value="Critical">Critical</option>
                </select>
              </div>

              {/* Status filter */}
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">Status:</span>
                <select
                  value={filterStatus}
                  onChange={(e) => {
                    setFilterStatus(e.target.value);
                    setPage(1);
                  }}
                  className="p-1 bg-slate-50 border border-slate-200 rounded text-xs font-medium text-slate-800"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="completed">Completed</option>
                  <option value="partial">Partial</option>
                  <option value="failed">Failed</option>
                </select>
              </div>
            </div>

            <span className="text-slate-500 font-semibold">
              Showing {scans.length} of {pagination.total} total scans
            </span>
          </div>
        </div>

        {/* Error State */}
        {error && (
          <div className="mb-6 p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs font-semibold flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => loadScans(page)}
              className="px-3 py-1 bg-white border border-red-300 text-red-700 rounded-md hover:bg-red-50 font-bold"
            >
              Retry
            </button>
          </div>
        )}

        {/* Loading State */}
        {isLoading && (
          <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm mb-6">
            <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-3" />
            <p className="text-sm font-bold text-slate-800">Loading scan history...</p>
            <p className="text-xs text-slate-500 mt-1">Querying historical database records and telemetry logs.</p>
          </div>
        )}

        {/* Empty State */}
        {!isLoading && scans.length === 0 && (
          <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm mb-6">
            <div className="w-14 h-14 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-3 text-slate-400">
              <Clock className="w-7 h-7" />
            </div>
            <h3 className="text-base font-bold text-slate-900">No scan history available</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-6">
              {searchTerm || filterScanner !== 'ALL' || filterResult !== 'ALL' || filterStatus !== 'ALL'
                ? 'No scans matched your selected filter parameters. Try clearing search or resetting filters.'
                : 'No scans have been performed yet. Run a scan on any URL, website, or file to build your scan history.'}
            </p>
            <Link
              to="/services/url-phishing"
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg shadow-sm transition-colors"
            >
              Start New Security Scan
            </Link>
          </div>
        )}

        {/* Scans Table */}
        {!isLoading && scans.length > 0 && (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden mb-6">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50/80 border-b border-slate-100 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Date</th>
                    <th className="py-3 px-4">Target</th>
                    <th className="py-3 px-4">Scanner</th>
                    <th className="py-3 px-4">Score</th>
                    <th className="py-3 px-4">Verdict</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-slate-50/70 transition-colors">
                      <td className="py-3.5 px-4 text-slate-500 whitespace-nowrap text-[11px]">
                        {scan.scannedAt ? new Date(scan.scannedAt).toLocaleString() : 'N/A'}
                      </td>
                      <td className="py-3.5 px-4 max-w-[240px]">
                        <div className="font-bold text-slate-900 truncate font-mono text-[11px]" title={scan.target}>
                          {formatTargetDisplay(scan.target)}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 text-slate-700 font-medium">
                          {getScannerIcon(scan.targetType)}
                          <span>{scan.targetType} Security</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className="font-bold text-slate-900">
                          {scan.riskScore}
                        </span>
                        <span className="text-slate-400 text-[10px]"> / 100</span>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {getResultBadge(scan.result)}
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {scan.status === 'completed' ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700">
                            <CheckCircle2 className="w-3 h-3 text-emerald-600" /> COMPLETE
                          </span>
                        ) : scan.status === 'failed' ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-700">
                            <XCircle className="w-3 h-3 text-red-600" /> FAILED
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-700">
                            <AlertTriangle className="w-3 h-3 text-amber-600" /> PARTIAL
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-2">
                          <Link
                            to={`/reports/compare?scan1=${scan.id}`}
                            className="p-1.5 rounded text-slate-500 hover:text-blue-600 hover:bg-slate-100 transition-colors"
                            title="Compare with another scan"
                          >
                            <GitCompare className="w-3.5 h-3.5" />
                          </Link>
                          <Link
                            to={`/reports/scan-report/${scan.id}`}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-bold text-blue-600 hover:text-blue-800 hover:bg-blue-50 border border-blue-200 transition-colors"
                          >
                            <span>View Report</span>
                            <ExternalLink className="w-3 h-3" />
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {pagination.totalPages > 1 && (
              <div className="p-4 border-t border-slate-100 flex items-center justify-between text-xs">
                <span className="text-slate-500 font-medium">
                  Page {pagination.page} of {pagination.totalPages}
                </span>
                <div className="flex items-center gap-2">
                  <button
                    disabled={page <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    className="p-1.5 rounded border border-slate-200 text-slate-600 hover:bg-slate-50 disabled:opacity-40"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <button
                    disabled={page >= pagination.totalPages}
                    onClick={() => setPage((p) => Math.min(pagination.totalPages, p + 1))}
                    className="p-1.5 rounded border border-slate-200 text-slate-600 hover:bg-slate-50 disabled:opacity-40"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </Container>
    </div>
  );
}
