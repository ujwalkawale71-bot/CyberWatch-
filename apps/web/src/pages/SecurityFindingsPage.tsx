import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  BarChart3,
  Search,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Terminal,
  FileSearch,
  Puzzle,
  Globe,
  X,
  AlertCircle,
  FileSpreadsheet,
  FileCode,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { ReportsNav } from '../components/reports/ReportsNav';
import { reportService } from '../services/report.service';
import type { EnrichedFinding, FindingSeverity, ScanTargetType } from '../types';

export function SecurityFindingsPage() {
  const [findings, setFindings] = useState<EnrichedFinding[]>([]);
  const [pagination, setPagination] = useState({ total: 0, page: 1, limit: 20, totalPages: 1 });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<EnrichedFinding | null>(null);
  const [isExporting, setIsExporting] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<FindingSeverity | 'ALL'>('ALL');
  const [scannerFilter, setScannerFilter] = useState<ScanTargetType | 'ALL'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(1);

  useEffect(() => {
    loadFindings(page);
  }, [page, severityFilter, scannerFilter]);

  async function loadFindings(targetPage = 1) {
    setIsLoading(true);
    setError(null);
    try {
      const res = await reportService.getFindings({
        severity: severityFilter,
        scanner: scannerFilter,
        search: searchTerm || undefined,
        page: targetPage,
        limit: 20,
      });
      setFindings(res.findings);
      setPagination(res.pagination);
    } catch (err: any) {
      console.error('Failed to load security findings:', err);
      setError(err.response?.data?.message || err.message || 'Unable to load security findings.');
    } finally {
      setIsLoading(false);
    }
  }

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    loadFindings(1);
  }

  async function handleExportFindings(format: 'csv' | 'json') {
    setIsExporting(format);
    try {
      await reportService.downloadExport('findings', format);
    } catch (err: any) {
      console.error('Export failed:', err);
    } finally {
      setIsExporting(null);
    }
  }

  function getSeverityBadge(severity: string) {
    const s = String(severity || 'INFO').toUpperCase();
    if (s === 'CRITICAL') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-bold bg-red-100 text-red-800 border border-red-200">
          CRITICAL
        </span>
      );
    }
    if (s === 'HIGH') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-bold bg-orange-100 text-orange-800 border border-orange-200">
          HIGH
        </span>
      );
    }
    if (s === 'MEDIUM') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-semibold bg-amber-100 text-amber-800 border border-amber-200">
          MEDIUM
        </span>
      );
    }
    if (s === 'LOW') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-semibold bg-blue-100 text-blue-800 border border-blue-200">
          LOW
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
        INFO
      </span>
    );
  }

  function getScannerBadge(type: ScanTargetType | string) {
    switch (type) {
      case 'Website':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-indigo-50 text-indigo-700 border border-indigo-100">
            <ShieldAlert className="w-3 h-3" /> Website
          </span>
        );
      case 'API':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-cyan-50 text-cyan-700 border border-cyan-100">
            <Terminal className="w-3 h-3" /> API
          </span>
        );
      case 'File':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-blue-50 text-blue-700 border border-blue-100">
            <FileSearch className="w-3 h-3" /> File
          </span>
        );
      case 'Extension':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-sky-50 text-sky-700 border border-sky-100">
            <Puzzle className="w-3 h-3" /> Extension
          </span>
        );
      case 'Phishing':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-amber-50 text-amber-700 border border-amber-100">
            <AlertTriangle className="w-3 h-3" /> Phishing
          </span>
        );
      case 'URL':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-blue-50 text-blue-700 border border-blue-100">
            <Globe className="w-3 h-3" /> URL
          </span>
        );
    }
  }

  return (
    <div className="pt-24 pb-20 bg-slate-50/50 min-h-screen">
      <ReportsNav totalFindings={pagination.total} />

      <Container className="mt-8">
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-2">
              <BarChart3 className="w-3.5 h-3.5" />
              Investigation Repository
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Security Findings
            </h1>
            <p className="text-sm text-slate-500 mt-1 max-w-2xl">
              Review and investigate security issues detected across CyberWatch scans.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={() => handleExportFindings('csv')}
              disabled={isExporting !== null}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-white border border-slate-200 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors shadow-sm disabled:opacity-50"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
              <span>{isExporting === 'csv' ? 'Exporting...' : 'Export CSV'}</span>
            </button>
            <button
              onClick={() => handleExportFindings('json')}
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
                placeholder="Search findings by title, target, category, evidence..."
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

            {/* Severity Filter */}
            <div className="flex items-center gap-2 overflow-x-auto no-scrollbar">
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => {
                    setSeverityFilter(sev);
                    setPage(1);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors shrink-0 ${
                    severityFilter === sev
                      ? sev === 'CRITICAL'
                        ? 'bg-red-600 text-white'
                        : sev === 'HIGH'
                        ? 'bg-orange-600 text-white'
                        : 'bg-blue-600 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Secondary Scanner Filter Row */}
          <div className="flex items-center justify-between pt-3 border-t border-slate-100 text-xs">
            <div className="flex items-center gap-2">
              <span className="text-slate-500 font-medium">Scanner:</span>
              <select
                value={scannerFilter}
                onChange={(e) => {
                  setScannerFilter(e.target.value as any);
                  setPage(1);
                }}
                className="p-1.5 bg-slate-50 border border-slate-200 rounded text-xs font-semibold text-slate-800"
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

            <span className="text-slate-500 font-semibold">
              Showing {findings.length} of {pagination.total} detected findings
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
              onClick={() => loadFindings(page)}
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
            <p className="text-sm font-bold text-slate-800">Loading security findings...</p>
            <p className="text-xs text-slate-500 mt-1">Filtering repository database across all active scan records.</p>
          </div>
        )}

        {/* Empty State */}
        {!isLoading && findings.length === 0 && (
          <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm mb-6">
            <div className="w-14 h-14 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-3 text-slate-400">
              <ShieldCheck className="w-7 h-7 text-emerald-500" />
            </div>
            <h3 className="text-base font-bold text-slate-900">No security findings detected</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
              {searchTerm || severityFilter !== 'ALL' || scannerFilter !== 'ALL'
                ? 'No findings matched your current active filter criteria. Try broadening your search or resetting filters.'
                : 'No vulnerabilities or security exposures have been recorded across your scans yet.'}
            </p>
          </div>
        )}

        {/* Findings Table */}
        {!isLoading && findings.length > 0 && (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden mb-6">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50/80 border-b border-slate-100 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Finding &amp; Category</th>
                    <th className="py-3 px-4">Target &amp; Scanner</th>
                    <th className="py-3 px-4">Evidence</th>
                    <th className="py-3 px-4">Detected Date</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {findings.map((finding) => (
                    <tr
                      key={finding.uniqueFindingId}
                      className="hover:bg-slate-50/70 transition-colors cursor-pointer"
                      onClick={() => setSelectedFinding(finding)}
                    >
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {getSeverityBadge(finding.severity)}
                      </td>
                      <td className="py-3.5 px-4 max-w-[240px]">
                        <div className="font-bold text-slate-900 line-clamp-1">
                          {finding.title}
                        </div>
                        <div className="text-[11px] text-slate-500 line-clamp-1 mt-0.5">
                          {finding.category || 'General Security'}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 max-w-[200px]">
                        <div className="font-semibold text-slate-800 truncate font-mono text-[11px]">
                          {finding.target}
                        </div>
                        <div className="mt-1">
                          {getScannerBadge(finding.targetType)}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 max-w-[220px]">
                        {finding.evidence ? (
                          <div className="text-[11px] font-mono text-slate-600 bg-slate-50 p-1.5 rounded border border-slate-200/80 truncate">
                            {finding.evidence}
                          </div>
                        ) : (
                          <span className="text-slate-400 text-[11px] italic">Telemetry logged</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-slate-500 whitespace-nowrap text-[11px]">
                        {finding.detectedAt ? new Date(finding.detectedAt).toLocaleDateString() : 'N/A'}
                      </td>
                      <td className="py-3.5 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => setSelectedFinding(finding)}
                          className="inline-flex items-center gap-1 px-3 py-1 rounded-lg text-xs font-bold text-blue-600 hover:text-blue-800 hover:bg-blue-50 border border-blue-200 transition-colors"
                        >
                          <span>Investigate</span>
                        </button>
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

        {/* Investigation Modal */}
        {selectedFinding && (
          <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="bg-white rounded-2xl max-w-xl w-full max-h-[90vh] overflow-y-auto p-6 shadow-2xl animate-in zoom-in-95 duration-150">
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                <div className="flex items-center gap-2">
                  {getSeverityBadge(selectedFinding.severity)}
                  <span className="text-xs text-slate-500 font-bold">{selectedFinding.category}</span>
                </div>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <h2 className="text-lg font-bold text-slate-900 mb-2">{selectedFinding.title}</h2>
              <div className="p-3 bg-slate-50 rounded-xl text-xs text-slate-600 mb-4 border border-slate-200/80">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Target:</span>
                  <span className="font-bold text-slate-900 font-mono text-[11px] truncate max-w-xs">{selectedFinding.target}</span>
                </div>
                <div className="flex items-center justify-between mt-1 pt-1 border-t border-slate-200/60">
                  <span className="text-slate-500">Scanner Engine:</span>
                  <span className="font-bold text-slate-900">{selectedFinding.targetType} Scanner</span>
                </div>
              </div>

              <div className="space-y-4 text-xs">
                {selectedFinding.description && (
                  <div>
                    <h3 className="font-bold text-slate-700 uppercase tracking-wider mb-1">Description</h3>
                    <p className="text-slate-600 leading-relaxed bg-slate-50 p-3 rounded-lg border border-slate-100">
                      {selectedFinding.description}
                    </p>
                  </div>
                )}

                {selectedFinding.evidence && (
                  <div>
                    <h3 className="font-bold text-slate-700 uppercase tracking-wider mb-1">Observed Evidence</h3>
                    <pre className="text-slate-800 font-mono text-[11px] bg-slate-900 text-slate-100 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
                      {selectedFinding.evidence}
                    </pre>
                  </div>
                )}

                {selectedFinding.impact && (
                  <div>
                    <h3 className="font-bold text-slate-700 uppercase tracking-wider mb-1">Why It Matters (Impact)</h3>
                    <p className="text-slate-700 leading-relaxed bg-amber-50 text-amber-950 p-3 rounded-lg border border-amber-200">
                      {selectedFinding.impact}
                    </p>
                  </div>
                )}

                {selectedFinding.recommendation && (
                  <div>
                    <h3 className="font-bold text-slate-700 uppercase tracking-wider mb-1">Remediation Guidance</h3>
                    <p className="text-slate-700 leading-relaxed bg-blue-50 text-blue-950 p-3 rounded-lg border border-blue-200">
                      {selectedFinding.recommendation}
                    </p>
                  </div>
                )}

                {selectedFinding.affectedComponent && (
                  <div>
                    <h3 className="font-bold text-slate-700 uppercase tracking-wider mb-1">Affected Component</h3>
                    <div className="text-slate-800 font-mono text-[11px] bg-slate-100 p-2 rounded">
                      {selectedFinding.affectedComponent}
                    </div>
                  </div>
                )}
              </div>

              <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between">
                <Link
                  to={`/reports/scan-report/${selectedFinding.scanId}`}
                  className="inline-flex items-center gap-1.5 text-xs font-bold text-blue-600 hover:text-blue-800"
                >
                  <span>Open Related Scan Report</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </Link>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="px-4 py-2 text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </Container>
    </div>
  );
}
