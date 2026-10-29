import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  FileText,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Download,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Globe,
  Terminal,
  FileSearch,
  Puzzle,
  BarChart3,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ArrowRight,
  X,
  Info,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { ReportsNav } from '../components/reports/ReportsNav';
import { reportService } from '../services/report.service';
import type { ReportOverviewStats, EnrichedFinding, ScanTargetType } from '../types';

export function ReportsLandingPage() {
  const [data, setData] = useState<ReportOverviewStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<EnrichedFinding | null>(null);

  useEffect(() => {
    loadOverview();
  }, []);

  async function loadOverview() {
    setIsLoading(true);
    setError(null);
    try {
      const overview = await reportService.getOverview();
      setData(overview);
      setLastUpdated(new Date());
    } catch (err: any) {
      console.error('Failed to load report overview:', err);
      setError(err.response?.data?.message || err.message || 'Unable to load security reports. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }

  const SCANNERS_LIST: Array<{ key: ScanTargetType; label: string; icon: any; accentColor: string }> = [
    { key: 'URL', label: 'URL Security', icon: Globe, accentColor: 'text-blue-600 bg-blue-50 border-blue-100' },
    { key: 'Website', label: 'Website Security', icon: ShieldAlert, accentColor: 'text-indigo-600 bg-indigo-50 border-indigo-100' },
    { key: 'API', label: 'API Security', icon: Terminal, accentColor: 'text-cyan-600 bg-cyan-50 border-cyan-100' },
    { key: 'Phishing', label: 'Phishing Security', icon: AlertTriangle, accentColor: 'text-amber-600 bg-amber-50 border-amber-100' },
    { key: 'File', label: 'File Security', icon: FileSearch, accentColor: 'text-blue-600 bg-blue-50 border-blue-100' },
    { key: 'Extension', label: 'Browser Extension', icon: Puzzle, accentColor: 'text-sky-600 bg-sky-50 border-sky-100' },
  ];

  function getRiskScoreLevel(score: number | null): {
    level: string;
    badgeClass: string;
    strokeColor: string;
  } {
    if (score === null || typeof score !== 'number') {
      return {
        level: 'NO SCANS',
        badgeClass: 'bg-slate-100 text-slate-500 border-slate-200',
        strokeColor: '#cbd5e1',
      };
    }
    if (score >= 75) {
      return {
        level: 'CRITICAL',
        badgeClass: 'bg-rose-50 text-rose-700 border-rose-200',
        strokeColor: '#ef4444',
      };
    }
    if (score >= 50) {
      return {
        level: 'HIGH',
        badgeClass: 'bg-orange-50 text-orange-700 border-orange-200',
        strokeColor: '#f97316',
      };
    }
    if (score >= 25) {
      return {
        level: 'MEDIUM',
        badgeClass: 'bg-amber-50 text-amber-700 border-amber-200',
        strokeColor: '#f59e0b',
      };
    }
    return {
      level: 'LOW',
      badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      strokeColor: '#10b981',
    };
  }

  function getVerdictColorClass(verdict: string | null) {
    if (!verdict) return 'text-slate-400';
    const v = verdict.toUpperCase();
    if (v.includes('SAFE') || v.includes('LOW')) return 'text-emerald-700';
    if (v.includes('SUSPICIOUS') || v.includes('MEDIUM')) return 'text-amber-700';
    if (v.includes('HIGH') || v.includes('CRITICAL') || v.includes('MALICIOUS')) return 'text-rose-700';
    return 'text-slate-700';
  }

  function formatLastUpdated(date: Date | null): string {
    if (!date) return 'Just now';
    const diffSec = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (diffSec < 15) return 'Just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin} min ago`;
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
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

  function getVerdictBadge(result: string, score: number) {
    const res = (result || 'Unknown').toUpperCase();
    if (res.includes('SAFE') || res.includes('LOW')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <CheckCircle2 className="w-3 h-3 text-emerald-600" /> {result} ({score}/100)
        </span>
      );
    }
    if (res.includes('SUSPICIOUS') || res.includes('MEDIUM')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
          <AlertTriangle className="w-3 h-3 text-amber-600" /> {result} ({score}/100)
        </span>
      );
    }
    if (res.includes('HIGH') || res.includes('CRITICAL') || res.includes('MALICIOUS')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
          <ShieldAlert className="w-3 h-3 text-rose-600" /> {result} ({score}/100)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
        {result} ({score}/100)
      </span>
    );
  }

  function getSeverityBadge(severity: string) {
    const s = String(severity || 'INFO').toUpperCase();
    if (s === 'CRITICAL') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-red-100 text-red-800 border border-red-200">
          CRITICAL
        </span>
      );
    }
    if (s === 'HIGH') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-orange-100 text-orange-800 border border-orange-200">
          HIGH
        </span>
      );
    }
    if (s === 'MEDIUM') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-100 text-amber-800 border border-amber-200">
          MEDIUM
        </span>
      );
    }
    if (s === 'LOW') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-100 text-blue-800 border border-blue-200">
          LOW
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
        INFO
      </span>
    );
  }

  return (
    <div className="pt-24 pb-20 bg-slate-50/50 min-h-screen">
      <ReportsNav
        totalFindings={data?.findingsSeverity?.total}
        totalScans={data?.totalScans}
      />

      <Container className="mt-8">
        {/* Main Dashboard Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-2">
              <FileText className="w-3.5 h-3.5" />
              Enterprise Reporting Center
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Security Reports &amp; Investigation Center
            </h1>
            <p className="text-sm text-slate-500 mt-1 max-w-2xl">
              Centralized security intelligence, scan results, findings, history and export management.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={loadOverview}
              disabled={isLoading}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors shadow-sm disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-blue-600' : ''}`} />
              Refresh
            </button>
            <Link
              to="/reports/export"
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              Export Report
            </Link>
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-8 p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs font-semibold flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={loadOverview}
              className="px-3 py-1 bg-white border border-red-300 text-red-700 rounded-md hover:bg-red-50 font-bold"
            >
              Retry
            </button>
          </div>
        )}

        {/* Loading Skeleton */}
        {isLoading && !data && (
          <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm mb-8">
            <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-3" />
            <p className="text-sm font-bold text-slate-800">Loading security reports and findings...</p>
            <p className="text-xs text-slate-500 mt-1">Aggregating telemetry from authoritative scan repositories.</p>
          </div>
        )}

        {/* Empty State */}
        {!isLoading && (!data || !data.hasData) && (
          <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm mb-8">
            <div className="w-16 h-16 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-4 text-slate-400">
              <FileText className="w-8 h-8" />
            </div>
            <h3 className="text-lg font-bold text-slate-900">No scan data available</h3>
            <p className="text-sm text-slate-500 max-w-md mx-auto mt-2">
              No security scans have been recorded for this account yet. Run an analysis with any CyberWatch scanner to populate the reporting dashboard.
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-3">
              <Link
                to="/services/url-phishing"
                className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors shadow-sm"
              >
                Scan URL / Phishing
              </Link>
              <Link
                to="/services/website-scanner"
                className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors"
              >
                Scan Website
              </Link>
              <Link
                to="/services/file"
                className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors"
              >
                Scan File
              </Link>
            </div>
          </div>
        )}

        {/* Real Summary Metrics */}
        {data && data.hasData && (
          <>
            {/* 6 Required Summary KPI Cards */}
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
              {/* 1. Total Scans */}
              <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-sm">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Total Scans</span>
                <div className="text-2xl font-bold text-slate-900 mt-1">{data.totalScans}</div>
                <div className="text-[11px] text-slate-500 mt-1">Executed audits</div>
              </div>

              {/* 2. Critical Findings */}
              <div className="p-4 bg-white rounded-xl border border-red-200/80 bg-red-50/20 shadow-sm">
                <span className="text-[10px] font-bold text-red-600 uppercase tracking-wider block">Critical Findings</span>
                <div className="text-2xl font-bold text-red-600 mt-1">{data.findingsSeverity.critical}</div>
                <div className="text-[11px] text-red-700 mt-1">Urgent remediation</div>
              </div>

              {/* 3. High Risk Findings */}
              <div className="p-4 bg-white rounded-xl border border-orange-200/80 bg-orange-50/20 shadow-sm">
                <span className="text-[10px] font-bold text-orange-600 uppercase tracking-wider block">High Risk Findings</span>
                <div className="text-2xl font-bold text-orange-600 mt-1">{data.findingsSeverity.high}</div>
                <div className="text-[11px] text-orange-700 mt-1">Elevated risk</div>
              </div>

              {/* 4. Suspicious Findings */}
              <div className="p-4 bg-white rounded-xl border border-amber-200/80 bg-amber-50/20 shadow-sm">
                <span className="text-[10px] font-bold text-amber-600 uppercase tracking-wider block">Suspicious Findings</span>
                <div className="text-2xl font-bold text-amber-600 mt-1">{data.findingsSeverity.medium}</div>
                <div className="text-[11px] text-amber-700 mt-1">Medium exposure</div>
              </div>

              {/* 5. Safe Scans */}
              <div className="p-4 bg-white rounded-xl border border-emerald-200/80 bg-emerald-50/20 shadow-sm">
                <span className="text-[10px] font-bold text-emerald-600 uppercase tracking-wider block">Safe Scans</span>
                <div className="text-2xl font-bold text-emerald-600 mt-1">{data.safeScans ?? 0}</div>
                <div className="text-[11px] text-emerald-700 mt-1">Clean posture</div>
              </div>

              {/* 6. Reports Generated */}
              <div className="p-4 bg-white rounded-xl border border-blue-200/80 bg-blue-50/20 shadow-sm">
                <span className="text-[10px] font-bold text-blue-600 uppercase tracking-wider block">Reports Generated</span>
                <div className="text-2xl font-bold text-blue-600 mt-1">{data.completedScans}</div>
                <div className="text-[11px] text-blue-700 mt-1">Completed scans</div>
              </div>
            </div>

            {/* Scanner Coverage & Risk Telemetry Section */}
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm mb-8">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-4 mb-5 border-b border-slate-100">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-bold text-slate-900 tracking-tight">
                      Scanner Coverage &amp; Risk Telemetry
                    </h2>
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-100">
                      6 Detection Engines
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Real-time security posture across CyberWatch&apos;s six detection engines.
                  </p>
                </div>

                <div className="flex items-center gap-3">
                  {lastUpdated && (
                    <span className="text-[11px] text-slate-400 font-medium">
                      Last updated: {formatLastUpdated(lastUpdated)}
                    </span>
                  )}
                  <button
                    onClick={loadOverview}
                    disabled={isLoading}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors shadow-2xs disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-blue-600' : ''}`} />
                    <span>{isLoading ? 'Refreshing scanner telemetry...' : 'Refresh'}</span>
                  </button>
                  <Link
                    to="/services"
                    className="text-xs font-semibold text-blue-600 hover:text-blue-800 flex items-center gap-1"
                  >
                    Directory <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
                {SCANNERS_LIST.map((scanner) => {
                  const key = scanner.key;
                  const Icon = scanner.icon;
                  const tel = data.scannerTelemetry?.[key];
                  const totalScans = tel?.totalScans ?? data.scannerBreakdown?.[key] ?? 0;
                  const completedScans = tel?.completedScans ?? 0;
                  const score = tel?.averageRiskScore ?? null;
                  const latestVerdict = tel?.latestVerdict ?? null;
                  const criticalFindings = tel?.criticalFindings ?? 0;
                  const highFindings = tel?.highFindings ?? 0;
                  const riskDist = tel?.riskDistribution ?? { low: 0, medium: 0, high: 0, critical: 0 };
                  const totalScored = riskDist.low + riskDist.medium + riskDist.high + riskDist.critical;
                  const riskInfo = getRiskScoreLevel(score);

                  return (
                    <Link
                      key={key}
                      to={`/reports/history?scanner=${key}`}
                      className="block p-5 rounded-xl border border-slate-200 bg-white hover:border-blue-300 hover:shadow-md transition-all group"
                    >
                      {/* Top Row: Icon + Scanner Name + Total Count */}
                      <div className="flex items-center justify-between gap-2 mb-3">
                        <div className="flex items-center gap-2.5 min-w-0">
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center border shrink-0 ${scanner.accentColor}`}>
                            <Icon className="w-4 h-4" />
                          </div>
                          <div className="min-w-0">
                            <h3 className="text-xs font-bold text-slate-900 group-hover:text-blue-600 transition-colors truncate">
                              {scanner.label}
                            </h3>
                            <span className="text-[10px] text-slate-400 font-mono block">
                              {totalScans} scan{totalScans === 1 ? '' : 's'}
                            </span>
                          </div>
                        </div>
                        <span className="text-xs font-bold text-slate-700 bg-slate-50 px-2.5 py-1 rounded-md border border-slate-200 shrink-0 font-mono shadow-2xs">
                          {totalScans}
                        </span>
                      </div>

                      {/* Middle Row: Circular Score Ring & Risk Level */}
                      <div className="flex items-center gap-3.5 py-2">
                        <div className="relative w-14 h-14 shrink-0 flex items-center justify-center">
                          <svg className="w-14 h-14 -rotate-90" viewBox="0 0 60 60">
                            <circle
                              cx="30"
                              cy="30"
                              r="23"
                              className="stroke-slate-100"
                              strokeWidth="5"
                              fill="transparent"
                            />
                            {score !== null && (
                              <circle
                                cx="30"
                                cy="30"
                                r="23"
                                stroke={riskInfo.strokeColor}
                                strokeWidth="5"
                                strokeDasharray={144.51}
                                strokeDashoffset={144.51 - (144.51 * Math.min(Math.max(score, 0), 100)) / 100}
                                strokeLinecap="round"
                                fill="transparent"
                                className="transition-all duration-700 ease-out"
                              />
                            )}
                          </svg>
                          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                            {score !== null ? (
                              <>
                                <span className="text-sm font-extrabold text-slate-900 leading-none">{score}</span>
                                <span className="text-[8px] font-semibold text-slate-400 leading-tight mt-0.5">/ 100</span>
                              </>
                            ) : (
                              <>
                                <span className="text-base font-extrabold text-slate-400 leading-none">—</span>
                              </>
                            )}
                          </div>
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1">
                            Risk Assessment
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${riskInfo.badgeClass}`}>
                              {riskInfo.level}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-500 mt-1 truncate">
                            {completedScans > 0 ? `${completedScans} completed scan${completedScans === 1 ? '' : 's'}` : 'No completed scans'}
                          </p>
                        </div>
                      </div>

                      {/* Lower Metrics Row: Average Risk, Latest Verdict, Crit / High */}
                      <div className="grid grid-cols-3 gap-2 py-2.5 my-2 border-y border-slate-100 text-xs">
                        <div>
                          <div className="flex items-center gap-1 text-[10px] text-slate-500 font-medium group/tip relative">
                            <span className="truncate">Avg Risk</span>
                            <Info className="w-3 h-3 text-slate-400 hover:text-slate-600 cursor-help shrink-0" />
                            <div className="pointer-events-none absolute bottom-full left-0 mb-1 hidden group-hover/tip:block z-30 w-48 p-2 text-[10px] font-normal text-white bg-slate-900 rounded-lg shadow-xl leading-snug">
                              Average risk score across valid completed scans for this scanner.
                            </div>
                          </div>
                          <div className="font-bold text-slate-900 mt-0.5 text-xs">
                            {score !== null ? `${score} / 100` : '—'}
                          </div>
                        </div>

                        <div>
                          <div className="text-[10px] text-slate-500 font-medium truncate">Latest Verdict</div>
                          <div className="font-bold mt-0.5 text-xs truncate" title={latestVerdict || 'None'}>
                            {latestVerdict ? (
                              <span className={getVerdictColorClass(latestVerdict)}>{latestVerdict}</span>
                            ) : (
                              <span className="text-slate-400">—</span>
                            )}
                          </div>
                        </div>

                        <div>
                          <div className="text-[10px] text-slate-500 font-medium truncate">Crit / High</div>
                          <div className="font-bold mt-0.5 text-xs">
                            {totalScans > 0 ? (
                              <span className={criticalFindings > 0 || highFindings > 0 ? 'text-red-600' : 'text-slate-700'}>
                                {criticalFindings} / {highFindings}
                              </span>
                            ) : (
                              <span className="text-slate-400">—</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Risk Distribution Mini Visualization */}
                      <div className="pt-1">
                        {totalScored > 0 ? (
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between text-[10px] text-slate-500 font-medium">
                              <span>Risk Distribution</span>
                              <span className="font-mono text-slate-400">{totalScored} scored</span>
                            </div>

                            <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden flex gap-0.5">
                              {riskDist.low > 0 && (
                                <div
                                  style={{ width: `${(riskDist.low / totalScored) * 100}%` }}
                                  className="bg-emerald-500 h-full rounded-xs transition-all"
                                  title={`LOW: ${riskDist.low}`}
                                />
                              )}
                              {riskDist.medium > 0 && (
                                <div
                                  style={{ width: `${(riskDist.medium / totalScored) * 100}%` }}
                                  className="bg-amber-500 h-full rounded-xs transition-all"
                                  title={`MEDIUM: ${riskDist.medium}`}
                                />
                              )}
                              {riskDist.high > 0 && (
                                <div
                                  style={{ width: `${(riskDist.high / totalScored) * 100}%` }}
                                  className="bg-orange-500 h-full rounded-xs transition-all"
                                  title={`HIGH: ${riskDist.high}`}
                                />
                              )}
                              {riskDist.critical > 0 && (
                                <div
                                  style={{ width: `${(riskDist.critical / totalScored) * 100}%` }}
                                  className="bg-rose-500 h-full rounded-xs transition-all"
                                  title={`CRITICAL: ${riskDist.critical}`}
                                />
                              )}
                            </div>

                            <div className="grid grid-cols-4 gap-1 text-[9px] text-slate-500 font-mono">
                              <div className="flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0"></span>
                                <span>L:{riskDist.low}</span>
                              </div>
                              <div className="flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0"></span>
                                <span>M:{riskDist.medium}</span>
                              </div>
                              <div className="flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-orange-500 shrink-0"></span>
                                <span>H:{riskDist.high}</span>
                              </div>
                              <div className="flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0"></span>
                                <span>C:{riskDist.critical}</span>
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="text-[10px] text-slate-400 italic text-center py-1">
                            No completed scan telemetry
                          </div>
                        )}
                      </div>
                    </Link>
                  );
                })}
              </div>
            </div>

            {/* Main Content Grid: Recent Scans & Findings */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
              {/* Recent Security Scans Table (2 cols) */}
              <div className="lg:col-span-2">
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                  <div className="p-5 border-b border-slate-100 flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-bold text-slate-900">Recent Security Scans</h2>
                      <p className="text-xs text-slate-500 mt-0.5">Authoritative scan results from backend engine</p>
                    </div>
                    <Link
                      to="/reports/history"
                      className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
                    >
                      View All History <ChevronRight className="w-3.5 h-3.5" />
                    </Link>
                  </div>

                  {data.recentScans.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500">
                      No recent scans recorded.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-50/80 border-b border-slate-100 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
                          <tr>
                            <th className="py-3 px-4">Target &amp; Scanner</th>
                            <th className="py-3 px-4">Risk Score</th>
                            <th className="py-3 px-4">Verdict</th>
                            <th className="py-3 px-4">Status</th>
                            <th className="py-3 px-4">Date</th>
                            <th className="py-3 px-4 text-right">Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {data.recentScans.map((scan) => (
                            <tr key={scan.id} className="hover:bg-slate-50/70 transition-colors">
                              <td className="py-3.5 px-4">
                                <div className="flex items-center gap-2.5">
                                  <div className="p-1.5 rounded-lg bg-slate-100 shrink-0">
                                    {getScannerIcon(scan.targetType)}
                                  </div>
                                  <div className="max-w-[180px] sm:max-w-xs truncate">
                                    <div className="font-semibold text-slate-900 truncate" title={scan.target}>
                                      {scan.target}
                                    </div>
                                    <div className="text-[11px] text-slate-500">
                                      {scan.targetType} Security
                                    </div>
                                  </div>
                                </div>
                              </td>
                              <td className="py-3.5 px-4">
                                <span className="font-bold text-slate-900">
                                  {scan.riskScore}
                                </span>
                                <span className="text-slate-400 text-[10px]"> / 100</span>
                              </td>
                              <td className="py-3.5 px-4">
                                {getVerdictBadge(scan.result, scan.riskScore)}
                              </td>
                              <td className="py-3.5 px-4">
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
                              <td className="py-3.5 px-4 text-slate-500 whitespace-nowrap text-[11px]">
                                {scan.scannedAt ? new Date(scan.scannedAt).toLocaleDateString() : 'N/A'}
                              </td>
                              <td className="py-3.5 px-4 text-right whitespace-nowrap">
                                <Link
                                  to={`/reports/scan-report/${scan.id}`}
                                  className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-bold text-blue-600 hover:text-blue-800 hover:bg-blue-50 border border-blue-200 transition-colors"
                                >
                                  <span>View</span>
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

              {/* Recent Security Findings (1 col) */}
              <div className="space-y-6">
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
                  <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
                    <div>
                      <h2 className="text-base font-bold text-slate-900">Recent Findings</h2>
                      <p className="text-xs text-slate-500">Active observations requiring review</p>
                    </div>
                    <Link
                      to="/reports/findings"
                      className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
                    >
                      View All <ChevronRight className="w-3.5 h-3.5" />
                    </Link>
                  </div>

                  {data.recentFindings.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 text-xs bg-slate-50 rounded-lg">
                      <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                      No security findings detected in recent scans.
                    </div>
                  ) : (
                    <div className="space-y-2.5">
                      {data.recentFindings.slice(0, 6).map((finding) => (
                        <div
                          key={finding.uniqueFindingId}
                          onClick={() => setSelectedFinding(finding)}
                          className="p-3 rounded-lg border border-slate-200/90 bg-slate-50/40 hover:bg-slate-50 hover:border-blue-300 transition-all cursor-pointer group"
                        >
                          <div className="flex items-center justify-between gap-2 mb-1">
                            {getSeverityBadge(finding.severity)}
                            <span className="text-[10px] text-slate-400 font-mono">
                              {finding.targetType}
                            </span>
                          </div>
                          <div className="font-bold text-xs text-slate-900 group-hover:text-blue-600 transition-colors line-clamp-1">
                            {finding.title}
                          </div>
                          <div className="text-[11px] text-slate-500 line-clamp-1 mt-0.5">
                            {finding.target}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Quick Compare Banner */}
                <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
                  <div className="flex items-center gap-2 text-indigo-600 font-bold text-xs uppercase tracking-wider mb-1">
                    <BarChart3 className="w-4 h-4" /> Comparison Intelligence
                  </div>
                  <h3 className="text-sm font-bold text-slate-900">Track Vulnerability Drift</h3>
                  <p className="text-xs text-slate-500 mt-1 mb-4">
                    Compare any two scans side-by-side to track security posture improvements and regression.
                  </p>
                  <Link
                    to="/reports/compare"
                    className="block w-full py-2 px-3 text-center text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-lg transition-colors border border-slate-200"
                  >
                    Open Scan Comparison
                  </Link>
                </div>
              </div>
            </div>
          </>
        )}

        {/* Finding Investigation Drawer / Modal */}
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
                  <span className="text-slate-500">Scanned Target:</span>
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
                    <h3 className="font-bold text-slate-700 uppercase tracking-wider mb-1">Technical Evidence</h3>
                    <pre className="text-slate-800 font-mono text-[11px] bg-slate-900 text-slate-100 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
                      {selectedFinding.evidence}
                    </pre>
                  </div>
                )}

                {selectedFinding.impact && (
                  <div>
                    <h3 className="font-bold text-slate-700 uppercase tracking-wider mb-1">Security Impact</h3>
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
              </div>

              <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between">
                <Link
                  to={`/reports/scan-report/${selectedFinding.scanId}`}
                  className="inline-flex items-center gap-1.5 text-xs font-bold text-blue-600 hover:text-blue-800"
                >
                  <span>Open Full Scan Report</span>
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
