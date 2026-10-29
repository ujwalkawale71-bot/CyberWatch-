import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  GitCompare,
  TrendingUp,
  TrendingDown,
  Minus,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Info,
  XCircle,
  ArrowUpRight,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { ReportsNav } from '../components/reports/ReportsNav';
import { reportService } from '../services/report.service';
import type { ScanRecord, ScanComparisonResult } from '../types';

export function ScanComparisonPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialScan1 = searchParams.get('scan1') || '';
  const initialScan2 = searchParams.get('scan2') || '';

  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [isLoadingScans, setIsLoadingScans] = useState(true);

  const [scan1Id, setScan1Id] = useState<string>(initialScan1);
  const [scan2Id, setScan2Id] = useState<string>(initialScan2);

  const [comparison, setComparison] = useState<ScanComparisonResult | null>(null);
  const [isComparing, setIsComparing] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);

  useEffect(() => {
    loadScanHistory();
  }, []);

  async function loadScanHistory() {
    setIsLoadingScans(true);
    try {
      const res = await reportService.getHistory({ limit: 100 });
      setScans(res.scans);

      // If params weren't set, default to first 2 scans if available
      if (res.scans.length >= 2) {
        if (!initialScan1 && !initialScan2) {
          setScan1Id(res.scans[1].id);
          setScan2Id(res.scans[0].id);
          runComparison(res.scans[1].id, res.scans[0].id);
        } else if (initialScan1 && initialScan2) {
          runComparison(initialScan1, initialScan2);
        }
      }
    } catch (err) {
      console.error('Failed to load scan history for comparison:', err);
    } finally {
      setIsLoadingScans(false);
    }
  }

  async function runComparison(id1: string, id2: string) {
    if (!id1 || !id2) return;
    if (id1 === id2) {
      setCompareError('Please select two distinct scans to generate a meaningful comparative audit.');
      setComparison(null);
      return;
    }

    setIsComparing(true);
    setCompareError(null);
    try {
      const result = await reportService.compareScans(id1, id2);
      setComparison(result);
      setSearchParams({ scan1: id1, scan2: id2 });
    } catch (err: any) {
      console.error('Scan comparison error:', err);
      setCompareError(err.response?.data?.message || err.message || 'Unable to generate scan comparison.');
      setComparison(null);
    } finally {
      setIsComparing(false);
    }
  }

  function handleCompareSubmit(e: React.FormEvent) {
    e.preventDefault();
    runComparison(scan1Id, scan2Id);
  }

  function getSeverityBadge(severity: string) {
    const s = (severity || 'INFO').toUpperCase();
    if (s === 'CRITICAL') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-800 border border-red-200">CRITICAL</span>;
    }
    if (s === 'HIGH') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-100 text-orange-800 border border-orange-200">HIGH</span>;
    }
    if (s === 'MEDIUM') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-100 text-amber-800 border border-amber-200">MEDIUM</span>;
    }
    if (s === 'LOW') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-800 border border-blue-200">LOW</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-700 border border-slate-200">INFO</span>;
  }

  function getVerdictBadge(verdict: string, score: number) {
    const v = (verdict || 'Unknown').toUpperCase();
    if (v.includes('SAFE') || v.includes('LOW')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <ShieldCheck className="w-3 h-3 text-emerald-600" /> {verdict} ({score}/100)
        </span>
      );
    }
    if (v.includes('SUSPICIOUS') || v.includes('MEDIUM')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
          <AlertTriangle className="w-3 h-3 text-amber-600" /> {verdict} ({score}/100)
        </span>
      );
    }
    if (v.includes('HIGH') || v.includes('CRITICAL') || v.includes('MALICIOUS')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
          <ShieldAlert className="w-3 h-3 text-rose-600" /> {verdict} ({score}/100)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
        {verdict} ({score}/100)
      </span>
    );
  }

  return (
    <div className="pt-24 pb-20 bg-slate-50/50 min-h-screen">
      <ReportsNav totalScans={scans.length} />

      <Container className="mt-8">
        {/* Header Title Section */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-2">
              <GitCompare className="w-3.5 h-3.5" />
              Comparative Scan Intelligence
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Scan Comparison Workspace
            </h1>
            <p className="text-sm text-slate-500 mt-1 max-w-2xl">
              Perform deep side-by-side delta analysis between two security scans. Track resolved vulnerabilities, newly introduced exposures, and overall posture shifts.
            </p>
          </div>
        </div>

        {/* Scan Selection Form */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm mb-8">
          <form onSubmit={handleCompareSubmit}>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-end">
              {/* Scan 1 (Baseline / Previous) */}
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-2">
                  Baseline / Previous Scan (Scan 1)
                </label>
                {isLoadingScans ? (
                  <div className="p-2.5 bg-slate-50 rounded-lg text-xs text-slate-500 flex items-center gap-2">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600" /> Loading available scans...
                  </div>
                ) : scans.length === 0 ? (
                  <div className="p-2.5 bg-slate-50 rounded-lg text-xs text-slate-500">
                    No scan records available in database.
                  </div>
                ) : (
                  <select
                    value={scan1Id}
                    onChange={(e) => setScan1Id(e.target.value)}
                    className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
                  >
                    <option value="">-- Select Baseline Scan --</option>
                    {scans.map((s) => (
                      <option key={`scan1-${s.id}`} value={s.id}>
                        [{s.targetType}] {s.target} · Score: {s.riskScore}/100 · {s.result} ({s.scannedAt ? new Date(s.scannedAt).toLocaleDateString() : ''})
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Scan 2 (Current / Target) */}
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-2">
                  Current / Comparative Scan (Scan 2)
                </label>
                {isLoadingScans ? (
                  <div className="p-2.5 bg-slate-50 rounded-lg text-xs text-slate-500 flex items-center gap-2">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600" /> Loading available scans...
                  </div>
                ) : scans.length === 0 ? (
                  <div className="p-2.5 bg-slate-50 rounded-lg text-xs text-slate-500">
                    No scan records available in database.
                  </div>
                ) : (
                  <select
                    value={scan2Id}
                    onChange={(e) => setScan2Id(e.target.value)}
                    className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
                  >
                    <option value="">-- Select Comparative Scan --</option>
                    {scans.map((s) => (
                      <option key={`scan2-${s.id}`} value={s.id}>
                        [{s.targetType}] {s.target} · Score: {s.riskScore}/100 · {s.result} ({s.scannedAt ? new Date(s.scannedAt).toLocaleDateString() : ''})
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-slate-100 flex items-center justify-between">
              <span className="text-xs text-slate-500 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-blue-500" />
                Select any two historical scans to calculate security posture divergence and finding deltas.
              </span>
              <button
                type="submit"
                disabled={!scan1Id || !scan2Id || isComparing || scan1Id === scan2Id}
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg shadow-sm transition-colors disabled:opacity-50"
              >
                <GitCompare className={`w-3.5 h-3.5 ${isComparing ? 'animate-spin' : ''}`} />
                {isComparing ? 'Analyzing Delta...' : 'Compare Scans'}
              </button>
            </div>
          </form>
        </div>

        {/* Error State */}
        {compareError && (
          <div className="mb-8 p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs font-semibold flex items-center gap-2.5">
            <XCircle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{compareError}</span>
          </div>
        )}

        {/* Loading State */}
        {isComparing && (
          <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm mb-8">
            <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-3" />
            <p className="text-sm font-bold text-slate-800">Calculating Scan Differences...</p>
            <p className="text-xs text-slate-500 mt-1">Cross-referencing finding titles, risk scores, and evidence signatures.</p>
          </div>
        )}

        {/* Empty State when no scans to compare */}
        {!isLoadingScans && scans.length < 2 && !comparison && (
          <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm">
            <div className="w-14 h-14 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-3 text-slate-400">
              <GitCompare className="w-7 h-7" />
            </div>
            <h3 className="text-base font-bold text-slate-900">At least 2 completed scans required</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-6">
              To compare security telemetry, execute additional security scans across URLs, websites, APIs, or files.
            </p>
            <Link
              to="/services/url-phishing"
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg shadow-sm transition-colors"
            >
              Run a New Security Scan
            </Link>
          </div>
        )}

        {/* Comparison Results */}
        {comparison && !isComparing && (
          <div className="space-y-8 animate-in fade-in duration-200">
            {/* Top Delta Summary Banner */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* Score Delta Card */}
              <div className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                  Risk Score Delta
                </span>
                <div className="flex items-center gap-2">
                  {comparison.comparison.scoreDifference > 0 ? (
                    <div className="flex items-center gap-1 text-red-600 font-bold text-2xl">
                      <TrendingUp className="w-6 h-6 text-red-600" />
                      <span>+{comparison.comparison.scoreDifference}</span>
                    </div>
                  ) : comparison.comparison.scoreDifference < 0 ? (
                    <div className="flex items-center gap-1 text-emerald-600 font-bold text-2xl">
                      <TrendingDown className="w-6 h-6 text-emerald-600" />
                      <span>{comparison.comparison.scoreDifference}</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1 text-slate-700 font-bold text-2xl">
                      <Minus className="w-6 h-6 text-slate-400" />
                      <span>0</span>
                    </div>
                  )}
                </div>
                <div className="text-xs font-semibold text-slate-500 mt-2">
                  {comparison.comparison.scoreDifference > 0
                    ? 'Increased risk observed in current scan'
                    : comparison.comparison.scoreDifference < 0
                    ? 'Reduced risk posture — improvement detected'
                    : 'Risk score remained unchanged'}
                </div>
              </div>

              {/* New Findings Card */}
              <div className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                  New Findings
                </span>
                <div className="text-2xl font-bold text-red-600">
                  {comparison.comparison.newFindingsCount}
                </div>
                <div className="text-xs text-slate-500 mt-2">
                  Newly discovered issues in current scan
                </div>
              </div>

              {/* Resolved Findings Card */}
              <div className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                  Resolved Findings
                </span>
                <div className="text-2xl font-bold text-emerald-600">
                  {comparison.comparison.resolvedFindingsCount}
                </div>
                <div className="text-xs text-slate-500 mt-2">
                  Fixed or eliminated since baseline
                </div>
              </div>

              {/* Persistent Findings Card */}
              <div className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                  Persistent Findings
                </span>
                <div className="text-2xl font-bold text-amber-600">
                  {comparison.comparison.persistentFindingsCount}
                </div>
                <div className="text-xs text-slate-500 mt-2">
                  Present in both scan assessments
                </div>
              </div>
            </div>

            {/* Side-by-Side Metadata Comparison */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Baseline Scan 1 Card */}
              <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
                <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                  <div>
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">BASELINE SCAN</span>
                    <h3 className="text-sm font-bold text-slate-900 truncate max-w-xs">{comparison.target}</h3>
                  </div>
                  <Link
                    to={`/reports/scan-report/${comparison.scan1.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800"
                  >
                    View Report <ArrowUpRight className="w-3.5 h-3.5" />
                  </Link>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-slate-50 rounded-lg">
                    <span className="text-slate-400 text-[10px] font-semibold block uppercase">Scan Date</span>
                    <span className="font-bold text-slate-800">
                      {comparison.scan1.date ? new Date(comparison.scan1.date).toLocaleString() : 'N/A'}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-50 rounded-lg">
                    <span className="text-slate-400 text-[10px] font-semibold block uppercase">Verdict & Score</span>
                    <div className="mt-1">
                      {getVerdictBadge(comparison.scan1.verdict, comparison.scan1.riskScore)}
                    </div>
                  </div>
                  <div className="p-3 bg-slate-50 rounded-lg col-span-2 flex items-center justify-between">
                    <span className="text-slate-500 font-medium">Total Detected Findings:</span>
                    <span className="font-bold text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200">
                      {comparison.scan1.findingCount} findings
                    </span>
                  </div>
                </div>
              </div>

              {/* Comparative Scan 2 Card */}
              <div className="bg-white rounded-xl border border-blue-200 bg-blue-50/20 p-5 shadow-sm">
                <div className="flex items-center justify-between pb-3 mb-4 border-b border-blue-100">
                  <div>
                    <span className="text-[10px] font-bold text-blue-600 uppercase tracking-wider">CURRENT COMPARISON</span>
                    <h3 className="text-sm font-bold text-slate-900 truncate max-w-xs">{comparison.target}</h3>
                  </div>
                  <Link
                    to={`/reports/scan-report/${comparison.scan2.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800"
                  >
                    View Report <ArrowUpRight className="w-3.5 h-3.5" />
                  </Link>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-white rounded-lg border border-blue-100">
                    <span className="text-slate-400 text-[10px] font-semibold block uppercase">Scan Date</span>
                    <span className="font-bold text-slate-800">
                      {comparison.scan2.date ? new Date(comparison.scan2.date).toLocaleString() : 'N/A'}
                    </span>
                  </div>
                  <div className="p-3 bg-white rounded-lg border border-blue-100">
                    <span className="text-slate-400 text-[10px] font-semibold block uppercase">Verdict & Score</span>
                    <div className="mt-1">
                      {getVerdictBadge(comparison.scan2.verdict, comparison.scan2.riskScore)}
                    </div>
                  </div>
                  <div className="p-3 bg-white rounded-lg border border-blue-100 col-span-2 flex items-center justify-between">
                    <span className="text-slate-500 font-medium">Total Detected Findings:</span>
                    <span className="font-bold text-slate-900 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                      {comparison.scan2.findingCount} findings
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Findings Diff Breakdown */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              <div className="p-5 border-b border-slate-100">
                <h3 className="text-base font-bold text-slate-900">Findings Divergence Log</h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Detailed breakdown of newly introduced, resolved, and persistent findings between scans.
                </p>
              </div>

              <div className="p-5 space-y-6">
                {/* 1. New Findings */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
                    <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Newly Introduced Findings ({comparison.comparison.newFindings.length})
                    </h4>
                  </div>

                  {comparison.comparison.newFindings.length === 0 ? (
                    <div className="p-3 rounded-lg bg-slate-50 text-xs text-slate-500">
                      No new security findings detected in the comparative scan.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {comparison.comparison.newFindings.map((f, idx) => (
                        <div key={idx} className="p-3 rounded-lg border border-red-200 bg-red-50/40 flex items-start justify-between gap-4">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              {getSeverityBadge(f.severity)}
                              <span className="text-xs font-bold text-slate-900">{f.title}</span>
                            </div>
                            <p className="text-xs text-slate-600 line-clamp-2">{f.description}</p>
                            {f.evidence && (
                              <div className="mt-2 text-[11px] font-mono text-red-950 bg-red-100/70 p-2 rounded">
                                {f.evidence}
                              </div>
                            )}
                          </div>
                          <span className="text-[10px] font-bold text-red-700 bg-red-100 px-2 py-0.5 rounded shrink-0">
                            NEW EXPOSURE
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* 2. Resolved Findings */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                    <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Resolved Vulnerabilities ({comparison.comparison.resolvedFindings.length})
                    </h4>
                  </div>

                  {comparison.comparison.resolvedFindings.length === 0 ? (
                    <div className="p-3 rounded-lg bg-slate-50 text-xs text-slate-500">
                      No previously detected findings were marked resolved.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {comparison.comparison.resolvedFindings.map((f, idx) => (
                        <div key={idx} className="p-3 rounded-lg border border-emerald-200 bg-emerald-50/40 flex items-start justify-between gap-4">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              {getSeverityBadge(f.severity)}
                              <span className="text-xs font-bold text-slate-900 line-through text-slate-500">{f.title}</span>
                            </div>
                            <p className="text-xs text-slate-600 line-clamp-2">{f.description}</p>
                          </div>
                          <span className="text-[10px] font-bold text-emerald-800 bg-emerald-100 px-2 py-0.5 rounded shrink-0">
                            REMEDIATED
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* 3. Persistent Findings */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                    <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Persistent Findings ({comparison.comparison.persistentFindings.length})
                    </h4>
                  </div>

                  {comparison.comparison.persistentFindings.length === 0 ? (
                    <div className="p-3 rounded-lg bg-slate-50 text-xs text-slate-500">
                      No overlapping persistent findings found.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {comparison.comparison.persistentFindings.map((f, idx) => (
                        <div key={idx} className="p-3 rounded-lg border border-slate-200 bg-slate-50/70 flex items-start justify-between gap-4">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              {getSeverityBadge(f.severity)}
                              <span className="text-xs font-bold text-slate-900">{f.title}</span>
                            </div>
                            <p className="text-xs text-slate-600 line-clamp-2">{f.description}</p>
                          </div>
                          <span className="text-[10px] font-semibold text-slate-600 bg-slate-200 px-2 py-0.5 rounded shrink-0">
                            PERSISTENT
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </Container>
    </div>
  );
}
