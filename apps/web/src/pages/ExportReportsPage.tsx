import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Download,
  FileText,
  FileCode,
  FileSpreadsheet,
  Lock,
  CheckCircle2,
  Search,
  RefreshCw,
  ShieldAlert,
  Layers,
  Clock,
  ExternalLink,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { ReportsNav } from '../components/reports/ReportsNav';
import { reportService } from '../services/report.service';
import type { ScanRecord } from '../types';

export function ExportReportsPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [scanSearch, setScanSearch] = useState<string>('');
  const [isLoadingScans, setIsLoadingScans] = useState(true);

  const [isExporting, setIsExporting] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
  }, []);

  async function loadScans() {
    setIsLoadingScans(true);
    try {
      const res = await reportService.getHistory({ limit: 100 });
      setScans(res.scans);
      if (res.scans.length > 0) {
        setSelectedScanId(res.scans[0].id);
      }
    } catch (err) {
      console.error('Failed to load scans for export:', err);
    } finally {
      setIsLoadingScans(false);
    }
  }

  async function handleExport(
    type: 'scan' | 'findings' | 'history',
    format: 'pdf' | 'json' | 'csv',
    scanId?: string
  ) {
    const exportKey = `${type}_${format}_${scanId || 'all'}`;
    setIsExporting(exportKey);
    setExportSuccess(null);
    setExportError(null);

    try {
      await reportService.downloadExport(type, format, scanId);
      setExportSuccess(`Successfully generated and downloaded ${type.toUpperCase()} report in ${format.toUpperCase()} format.`);
      setTimeout(() => setExportSuccess(null), 6000);
    } catch (err: any) {
      console.error('Export error:', err);
      setExportError(err.response?.data?.message || err.message || 'Export generation failed. Please try again.');
    } finally {
      setIsExporting(null);
    }
  }

  const selectedScan = scans.find((s) => s.id === selectedScanId);
  const filteredScans = scans.filter(
    (s) =>
      !scanSearch ||
      s.target.toLowerCase().includes(scanSearch.toLowerCase()) ||
      s.targetType.toLowerCase().includes(scanSearch.toLowerCase())
  );

  return (
    <div className="pt-24 pb-20 bg-slate-50/50 min-h-screen">
      <ReportsNav totalScans={scans.length} />

      <Container className="mt-8">
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-2">
              <Download className="w-3.5 h-3.5" />
              Report Export Center
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Export Security Reports
            </h1>
            <p className="text-sm text-slate-500 mt-1 max-w-2xl">
              Download formal PDF executive summaries, machine-readable JSON telemetry, or tabular CSV vulnerability records.
            </p>
          </div>
        </div>

        {/* Notifications */}
        {exportSuccess && (
          <div className="mb-6 p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-semibold flex items-center gap-2.5 animate-in fade-in duration-200">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>{exportSuccess}</span>
          </div>
        )}

        {exportError && (
          <div className="mb-6 p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs font-semibold flex items-center gap-2.5 animate-in fade-in duration-200">
            <ShieldAlert className="w-4 h-4 text-red-600 shrink-0" />
            <span>{exportError}</span>
          </div>
        )}

        {/* Security & Scrubbing Standards Notice */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 mb-8 flex items-start gap-3.5 shadow-2xs">
          <div className="p-2 rounded-lg bg-blue-50 text-blue-700 border border-blue-100 shrink-0 mt-0.5">
            <Lock className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-900">Security &amp; Data Protection Standards</h3>
            <p className="text-xs text-slate-500 mt-1 leading-relaxed">
              Exported artifacts are automatically sanitized. Sensitive API tokens, private passwords, and session credentials are redacted by the backend engine. CSV files apply strict neutralization rules to prevent spreadsheet injection attacks.
            </p>
          </div>
        </div>

        {/* Export Options Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* 1. Single Scan Export Hub (Col 1 & 2) */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
              <div className="flex items-center gap-2 mb-1">
                <FileText className="w-5 h-5 text-blue-600" />
                <h2 className="text-base font-bold text-slate-900">Single Scan Security Report</h2>
              </div>
              <p className="text-xs text-slate-500 mb-6">
                Export an official audit report for a specific completed security assessment.
              </p>

              {/* Scan Selector */}
              <div className="space-y-4 mb-6">
                <div>
                  <label className="text-xs font-bold uppercase tracking-wider text-slate-700 block mb-2">
                    Select Target Scan:
                  </label>
                  {isLoadingScans ? (
                    <div className="p-3 bg-slate-50 rounded-lg text-xs text-slate-500 flex items-center gap-2">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600" /> Loading scan history...
                    </div>
                  ) : scans.length === 0 ? (
                    <div className="p-4 bg-slate-50 rounded-lg text-xs text-slate-500 text-center">
                      No completed scans found. Please run a security scan first.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="relative">
                        <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          value={scanSearch}
                          onChange={(e) => setScanSearch(e.target.value)}
                          placeholder="Filter targets by domain or name..."
                          className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:ring-1 focus:ring-blue-500"
                        />
                      </div>
                      <select
                        value={selectedScanId}
                        onChange={(e) => setSelectedScanId(e.target.value)}
                        className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        {filteredScans.map((s) => (
                          <option key={s.id} value={s.id}>
                            [{s.targetType}] {s.target} — Verdict: {s.result} ({s.riskScore}/100) — {s.scannedAt ? new Date(s.scannedAt).toLocaleDateString() : ''}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
                </div>

                {/* Selected Scan Preview Card */}
                {selectedScan && (
                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold text-slate-800">Scan Summary:</span>
                      <Link
                        to={`/reports/scan-report/${selectedScan.id}`}
                        className="text-blue-600 hover:text-blue-800 font-bold inline-flex items-center gap-1 text-[11px]"
                      >
                        View Interactive Report <ExternalLink className="w-3 h-3" />
                      </Link>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase font-semibold">Scanner:</span>
                        <span className="font-bold text-slate-900">{selectedScan.targetType} Security</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase font-semibold">Verdict:</span>
                        <span className="font-bold text-slate-900">{selectedScan.result}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase font-semibold">Risk Score:</span>
                        <span className="font-bold text-slate-900">{selectedScan.riskScore} / 100</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase font-semibold">Findings:</span>
                        <span className="font-bold text-slate-900">{selectedScan.findings?.length || 0} issues</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Action Export Buttons */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <button
                  onClick={() => handleExport('scan', 'pdf', selectedScanId)}
                  disabled={!selectedScanId || isExporting !== null}
                  className="p-4 rounded-xl border border-blue-200 bg-blue-50/40 hover:bg-blue-50 text-left transition-all group disabled:opacity-50"
                >
                  <div className="flex items-center justify-between mb-2">
                    <FileText className="w-5 h-5 text-blue-600" />
                    <Download className="w-4 h-4 text-blue-400 group-hover:text-blue-600 transition-colors" />
                  </div>
                  <div className="font-bold text-xs text-blue-950">Export PDF Report</div>
                  <div className="text-[10px] text-blue-700 mt-0.5">
                    {isExporting === `scan_pdf_${selectedScanId}` ? 'Generating PDF...' : 'Full executive layout & branding'}
                  </div>
                </button>

                <button
                  onClick={() => handleExport('scan', 'json', selectedScanId)}
                  disabled={!selectedScanId || isExporting !== null}
                  className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 text-left transition-all group disabled:opacity-50"
                >
                  <div className="flex items-center justify-between mb-2">
                    <FileCode className="w-5 h-5 text-cyan-600" />
                    <Download className="w-4 h-4 text-slate-400 group-hover:text-cyan-600 transition-colors" />
                  </div>
                  <div className="font-bold text-xs text-slate-900">Export JSON Report</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {isExporting === `scan_json_${selectedScanId}` ? 'Exporting JSON...' : 'Raw technical telemetry & DTO'}
                  </div>
                </button>

                <button
                  onClick={() => handleExport('scan', 'csv', selectedScanId)}
                  disabled={!selectedScanId || isExporting !== null}
                  className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 text-left transition-all group disabled:opacity-50"
                >
                  <div className="flex items-center justify-between mb-2">
                    <FileSpreadsheet className="w-5 h-5 text-emerald-600" />
                    <Download className="w-4 h-4 text-slate-400 group-hover:text-emerald-600 transition-colors" />
                  </div>
                  <div className="font-bold text-xs text-slate-900">Export CSV Findings</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {isExporting === `scan_csv_${selectedScanId}` ? 'Exporting CSV...' : 'Spreadsheet table format'}
                  </div>
                </button>
              </div>
            </div>
          </div>

          {/* 2 & 3. Bulk Exports Panel (Col 3) */}
          <div className="space-y-6">
            {/* Security Findings Repository Bulk Export */}
            <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
              <div className="flex items-center gap-2 mb-1">
                <Layers className="w-4 h-4 text-amber-600" />
                <h3 className="text-sm font-bold text-slate-900">Security Findings Repository</h3>
              </div>
              <p className="text-xs text-slate-500 mb-4">
                Export all detected security findings and vulnerabilities across all six scanners.
              </p>

              <div className="space-y-2">
                <button
                  onClick={() => handleExport('findings', 'csv')}
                  disabled={isExporting !== null}
                  className="w-full py-2.5 px-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-xs font-semibold text-slate-800 flex items-center justify-between transition-colors disabled:opacity-50"
                >
                  <span className="flex items-center gap-2">
                    <FileSpreadsheet className="w-4 h-4 text-emerald-600" /> All Findings (CSV)
                  </span>
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                </button>

                <button
                  onClick={() => handleExport('findings', 'json')}
                  disabled={isExporting !== null}
                  className="w-full py-2.5 px-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-xs font-semibold text-slate-800 flex items-center justify-between transition-colors disabled:opacity-50"
                >
                  <span className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-cyan-600" /> All Findings (JSON)
                  </span>
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                </button>
              </div>
            </div>

            {/* Scan History Audit Log Bulk Export */}
            <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
              <div className="flex items-center gap-2 mb-1">
                <Clock className="w-4 h-4 text-indigo-600" />
                <h3 className="text-sm font-bold text-slate-900">Historical Scans Log</h3>
              </div>
              <p className="text-xs text-slate-500 mb-4">
                Export complete historical audit log of all targets scanned with verdicts and timestamps.
              </p>

              <div className="space-y-2">
                <button
                  onClick={() => handleExport('history', 'csv')}
                  disabled={isExporting !== null}
                  className="w-full py-2.5 px-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-xs font-semibold text-slate-800 flex items-center justify-between transition-colors disabled:opacity-50"
                >
                  <span className="flex items-center gap-2">
                    <FileSpreadsheet className="w-4 h-4 text-emerald-600" /> Scan History (CSV)
                  </span>
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                </button>

                <button
                  onClick={() => handleExport('history', 'json')}
                  disabled={isExporting !== null}
                  className="w-full py-2.5 px-3 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-xs font-semibold text-slate-800 flex items-center justify-between transition-colors disabled:opacity-50"
                >
                  <span className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-cyan-600" /> Scan History (JSON)
                  </span>
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </Container>
    </div>
  );
}
