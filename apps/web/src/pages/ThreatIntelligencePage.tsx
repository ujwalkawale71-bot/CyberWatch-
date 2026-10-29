import { useState, useEffect, useRef } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  Radio,
  Search,
  RefreshCw,
  ExternalLink,
  Database,
  ArrowRight,
  Info,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Terminal,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { threatIntelService, type ThreatIntelProviderMeta } from '../services/threat-intel.service';
import type {
  ThreatIntelAnalysisReport,
  ThreatIntelProviderResult,
  ThreatIntelEvidenceItem,
  ThreatIntelRelatedIndicator,
} from '../types';
import { cn } from '../lib/utils';

export function ThreatIntelligencePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const searchInputRef = useRef<HTMLInputElement>(null);

  const [indicatorInput, setIndicatorInput] = useState('');
  const [detectedType, setDetectedType] = useState<string>('Detecting...');
  const [normalizedPreview, setNormalizedPreview] = useState<string>('');
  const [isInputValid, setIsInputValid] = useState<boolean>(true);

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ThreatIntelAnalysisReport | null>(null);
  const [, setProvidersMeta] = useState<ThreatIntelProviderMeta[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'providers' | 'evidence' | 'related' | 'timeline' | 'raw'>('overview');
  const [copiedRaw, setCopiedRaw] = useState(false);

  // Load configured providers list on mount
  useEffect(() => {
    threatIntelService
      .getProviders()
      .then((res) => setProvidersMeta(res))
      .catch(() => {});
  }, []);

  // Sync with URL query parameter ?q= or ?indicator=
  useEffect(() => {
    const q = searchParams.get('q') || searchParams.get('indicator');
    if (q && q.trim()) {
      setIndicatorInput(q.trim());
      handleAnalyze(q.trim(), false);
    }
  }, [searchParams]);

  // Client-side quick indicator type detection preview
  useEffect(() => {
    const trimmed = indicatorInput.trim();
    if (!trimmed) {
      setDetectedType('None');
      setNormalizedPreview('');
      setIsInputValid(true);
      return;
    }

    // Refang check
    const refanged = trimmed
      .replace(/^hxxps:\/\//i, 'https://')
      .replace(/^hxxp:\/\//i, 'http://')
      .replace(/\[\.\]|\(\.\)|\[dot\]/gi, '.');

    if (/^[a-fA-F0-9]{32}$/.test(refanged)) {
      setDetectedType('HASH_MD5 (File Checksum)');
      setNormalizedPreview(refanged.toLowerCase());
      setIsInputValid(true);
    } else if (/^[a-fA-F0-9]{40}$/.test(refanged)) {
      setDetectedType('HASH_SHA1 (File Checksum)');
      setNormalizedPreview(refanged.toLowerCase());
      setIsInputValid(true);
    } else if (/^[a-fA-F0-9]{64}$/.test(refanged)) {
      setDetectedType('HASH_SHA256 (File Checksum)');
      setNormalizedPreview(refanged.toLowerCase());
      setIsInputValid(true);
    } else if (/^[a-pA-P]{32}$/.test(refanged)) {
      setDetectedType('EXTENSION_ID (Chrome/Edge Extension)');
      setNormalizedPreview(refanged.toLowerCase());
      setIsInputValid(true);
    } else if (/^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(refanged)) {
      setDetectedType('IP (IPv4 Address)');
      setNormalizedPreview(refanged);
      setIsInputValid(true);
    } else if (refanged.includes(':') && refanged.length > 3 && /^[a-fA-F0-9:]+$/.test(refanged)) {
      setDetectedType('IP (IPv6 Address)');
      setNormalizedPreview(refanged.toLowerCase());
      setIsInputValid(true);
    } else if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(refanged) || (refanged.includes('/') && !refanged.endsWith('/'))) {
      setDetectedType('URL (Web Resource)');
      setNormalizedPreview(refanged);
      setIsInputValid(true);
    } else if (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/i.test(refanged)) {
      setDetectedType('DOMAIN (Fully Qualified Domain)');
      setNormalizedPreview(refanged.toLowerCase());
      setIsInputValid(true);
    } else {
      setDetectedType('Unrecognized Format');
      setNormalizedPreview(refanged);
      setIsInputValid(false);
    }
  }, [indicatorInput]);

  async function handleAnalyze(targetIndicator?: string, forceRefresh = false) {
    const query = (targetIndicator || indicatorInput).trim();
    if (!query) {
      setError('Please enter an indicator to investigate.');
      return;
    }

    setIsLoading(true);
    setError(null);

    // Update URL query string
    setSearchParams({ q: query });

    try {
      const result = await threatIntelService.analyzeIndicator(query, forceRefresh);
      setReport(result);
    } catch (err: any) {
      setError(err.message || 'Threat intelligence query failed. Please check network connectivity.');
    } finally {
      setIsLoading(false);
    }
  }

  function handleQuickSample(sample: string) {
    setIndicatorInput(sample);
    handleAnalyze(sample, false);
    if (searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }

  function handleCopyRawJson() {
    if (!report) return;
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  }

  const isMalicious = report?.overallReputation === 'MALICIOUS';
  const isSuspicious = report?.overallReputation === 'SUSPICIOUS';
  const isNotConfigured = report?.status === 'NOT_CONFIGURED';
  const isUnavailable = report?.status === 'UNAVAILABLE';

  return (
    <div className="min-h-screen bg-slate-50/50 pb-24 pt-28">
      {/* ── HERO SECTION ─────────────────────────────────────────────────── */}
      <section className="relative overflow-hidden bg-white border-b border-slate-200/80 py-10 sm:py-12">
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />
        <Container>
          <div className="max-w-4xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider mb-3">
              <Radio className="w-3.5 h-3.5 text-blue-600 animate-pulse" />
              <span>Threat Intelligence</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight leading-tight">
              Investigate Threat Indicators With Real Intelligence
            </h1>
            <p className="mt-2.5 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              Enrich CyberWatch security analysis with external threat intelligence, reputation data, and indicator relationships from supported intelligence sources.
            </p>
          </div>
        </Container>
      </section>

      <Container className="mt-8">
        {/* ── SEARCH / INVESTIGATION PANEL ───────────────────────────────── */}
        <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleAnalyze();
            }}
            className="space-y-4"
          >
            <div>
              <label htmlFor="indicator-input" className="block text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
                Submit Indicator for Multi-Source Intelligence Lookup
              </label>
              <div className="relative flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-400">
                    <Search className="w-5 h-5" />
                  </div>
                  <input
                    ref={searchInputRef}
                    id="indicator-input"
                    type="text"
                    value={indicatorInput}
                    onChange={(e) => setIndicatorInput(e.target.value)}
                    placeholder="Enter a URL, domain, IP address, file hash, or extension ID"
                    className="w-full pl-11 pr-4 py-3.5 bg-slate-50 hover:bg-slate-50/80 focus:bg-white border border-slate-200 focus:border-blue-600 rounded-2xl text-sm font-medium text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-600/10 transition-all font-mono"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isLoading || !indicatorInput.trim()}
                  className="inline-flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-bold px-6 py-3.5 rounded-2xl shadow-sm shadow-blue-600/25 transition-all shrink-0"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Analyzing indicator...</span>
                    </>
                  ) : (
                    <>
                      <Radio className="w-4 h-4" />
                      <span>Analyze Indicator</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Live Indicator Type & Validation Strip */}
            {indicatorInput.trim() && (
              <div className="flex flex-wrap items-center gap-3 pt-1 text-xs">
                <div className="flex items-center gap-1.5 bg-slate-100 text-slate-700 px-3 py-1 rounded-xl font-medium border border-slate-200/80">
                  <span className="text-slate-400">Detected Type:</span>
                  <span className="font-bold text-slate-900">{detectedType}</span>
                </div>
                {normalizedPreview && (
                  <div className="flex items-center gap-1.5 bg-slate-100 text-slate-700 px-3 py-1 rounded-xl font-mono text-[11px] border border-slate-200/80 truncate max-w-md">
                    <span className="text-slate-400">Canonical:</span>
                    <span className="text-slate-800 font-semibold truncate">{normalizedPreview}</span>
                  </div>
                )}
                {!isInputValid && (
                  <span className="text-rose-600 font-semibold flex items-center gap-1 text-[11px]">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Format may not be recognized
                  </span>
                )}
              </div>
            )}

            {/* Sample Quick Chips */}
            <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-400 font-semibold mr-1">Quick Samples:</span>
              <button
                type="button"
                onClick={() => handleQuickSample('google.com')}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-600 border border-slate-200/80 transition-colors font-mono text-[11px]"
              >
                Domain: google.com
              </button>
              <button
                type="button"
                onClick={() => handleQuickSample('8.8.8.8')}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-600 border border-slate-200/80 transition-colors font-mono text-[11px]"
              >
                IPv4: 8.8.8.8
              </button>
              <button
                type="button"
                onClick={() => handleQuickSample('https://example.com/login')}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-600 border border-slate-200/80 transition-colors font-mono text-[11px]"
              >
                URL: example.com/login
              </button>
              <button
                type="button"
                onClick={() => handleQuickSample('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-600 border border-slate-200/80 transition-colors font-mono text-[11px]"
              >
                SHA-256 Checksum
              </button>
              <button
                type="button"
                onClick={() => handleQuickSample('cjpalhdlnbpafiamejdnhcphjbkeiagm')}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-600 border border-slate-200/80 transition-colors font-mono text-[11px]"
              >
                Extension ID (uBlock)
              </button>
            </div>
          </form>

          {error && (
            <div className="mt-4 p-4 rounded-2xl bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-start gap-2.5">
              <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-bold">Investigation Notice</p>
                <p className="mt-0.5">{error}</p>
              </div>
            </div>
          )}
        </div>

        {/* ── ANALYSIS RESULTS VIEW ──────────────────────────────────────── */}
        {report && (
          <div className="mt-8 space-y-8 animate-in fade-in duration-200">
            {/* 1. Header Overview Bar */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-100">
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                      Investigated Indicator
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-slate-100 text-slate-700 border border-slate-200">
                      {report.indicatorType}
                    </span>
                    {report.cached && (
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-100">
                        CACHED RESULT
                      </span>
                    )}
                  </div>
                  <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900 font-mono break-all">
                    {report.displayValue || report.indicator}
                  </h2>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <button
                    onClick={() => handleAnalyze(report.indicator, true)}
                    disabled={isLoading}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition-colors"
                  >
                    <RefreshCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin')} />
                    <span>Force Refresh</span>
                  </button>
                  <button
                    onClick={handleCopyRawJson}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition-colors"
                  >
                    {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedRaw ? 'Copied JSON' : 'Export Data'}</span>
                  </button>
                </div>
              </div>

              {/* Status Banner */}
              <div
                className={cn(
                  'mt-6 p-4 rounded-2xl border flex items-start gap-3.5 text-xs',
                  isMalicious
                    ? 'bg-rose-50 border-rose-200 text-rose-800'
                    : isSuspicious
                    ? 'bg-amber-50 border-amber-200 text-amber-800'
                    : isNotConfigured
                    ? 'bg-slate-50 border-slate-200 text-slate-700'
                    : isUnavailable
                    ? 'bg-amber-50 border-amber-200 text-amber-800'
                    : 'bg-emerald-50 border-emerald-200 text-emerald-800'
                )}
              >
                {isMalicious ? (
                  <ShieldAlert className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                ) : isSuspicious ? (
                  <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                ) : isNotConfigured ? (
                  <Info className="w-5 h-5 text-slate-500 shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                )}
                <div>
                  <p className="font-bold text-sm">
                    {report.status === 'MATCH_FOUND'
                      ? `Threat Intelligence Match: ${report.overallReputation}`
                      : report.status === 'NO_MATCH'
                      ? 'No Matching Threat Intelligence Found'
                      : report.status === 'NOT_CONFIGURED'
                      ? 'Threat Intelligence Source Not Configured'
                      : report.status === 'PARTIAL'
                      ? 'Partial Intelligence Available'
                      : report.status}
                  </p>
                  <p className="mt-0.5 text-xs leading-relaxed opacity-90">{report.recommendation}</p>
                </div>
              </div>
            </div>

            {/* 2. Threat Summary Cards (5-Card Grid) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              {/* Card 1: Threat Status */}
              <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
                <span className="text-slate-400 text-[11px] font-bold uppercase tracking-wider block">
                  Reputation Status
                </span>
                <div className="mt-2 flex items-center gap-2">
                  <span
                    className={cn(
                      'text-lg font-extrabold',
                      isMalicious
                        ? 'text-rose-600'
                        : isSuspicious
                        ? 'text-amber-600'
                        : isNotConfigured
                        ? 'text-slate-600'
                        : 'text-emerald-600'
                    )}
                  >
                    {report.overallReputation}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1 leading-snug">
                  Derived from corroborated provider evidence.
                </p>
              </div>

              {/* Card 2: Detections */}
              <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
                <span className="text-slate-400 text-[11px] font-bold uppercase tracking-wider block">
                  Vendor Detections
                </span>
                <div className="mt-2 flex items-center gap-1.5">
                  <span
                    className={cn(
                      'text-xl font-extrabold',
                      report.detectionSummary && report.detectionSummary.flaggedCount > 0
                        ? 'text-rose-600'
                        : 'text-slate-800'
                    )}
                  >
                    {report.detectionSummary?.flaggedCount ?? 0}
                  </span>
                  <span className="text-xs text-slate-500 font-medium">
                    flagged {report.detectionSummary?.totalEnginesQueried ? `/ ${report.detectionSummary.totalEnginesQueried}` : 'records'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1 leading-snug">
                  Confirmed vendor flags across queried feeds.
                </p>
              </div>

              {/* Card 3: Threat Categories */}
              <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
                <span className="text-slate-400 text-[11px] font-bold uppercase tracking-wider block">
                  Threat Categories
                </span>
                <div className="mt-2 flex flex-wrap gap-1">
                  {report.threatCategories.length > 0 ? (
                    report.threatCategories.slice(0, 2).map((cat, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded-md text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200"
                      >
                        {cat}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500 font-semibold">None Identified</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-500 mt-1 leading-snug">
                  {report.threatCategories.length > 2 ? `+${report.threatCategories.length - 2} additional tags` : 'Classified categories.'}
                </p>
              </div>

              {/* Card 4: Confidence Level */}
              <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
                <span className="text-slate-400 text-[11px] font-bold uppercase tracking-wider block">
                  Intelligence Confidence
                </span>
                <div className="mt-2">
                  <span
                    className={cn(
                      'px-2.5 py-0.5 rounded-full text-xs font-bold border inline-block',
                      report.confidence === 'HIGH'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : report.confidence === 'MEDIUM'
                        ? 'bg-blue-50 text-blue-700 border-blue-200'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
                    )}
                  >
                    {report.confidence} CONFIDENCE
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1 leading-snug truncate" title={report.confidenceExplanation}>
                  {report.confidenceExplanation || 'Evidence-weighted aggregation.'}
                </p>
              </div>

              {/* Card 5: Sources Checked */}
              <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
                <span className="text-slate-400 text-[11px] font-bold uppercase tracking-wider block">
                  Sources Checked
                </span>
                <div className="mt-2 flex items-center gap-1.5">
                  <span className="text-xl font-extrabold text-slate-800">{report.providersChecked}</span>
                  <span className="text-xs text-slate-500 font-medium">/ {report.providersTotal || report.providersChecked} compatible</span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1 leading-snug">
                  Independent threat databases queried.
                </p>
              </div>
            </div>

            {/* 3. CyberWatch Scanner Cross-Correlation Callout */}
            {report.correlationWithCyberWatch?.targetMatchesExistingScanner && (
              <div className="p-5 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200/80 rounded-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-sm shadow-blue-500/20">
                    <Shield className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900">Correlated CyberWatch Security Scan Available</h4>
                    <p className="text-xs text-slate-600 mt-0.5">
                      {report.correlationWithCyberWatch.contextNote}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => {
                    const sc = report.correlationWithCyberWatch?.suggestedScanner;
                    if (sc === 'url' || sc === 'phishing') navigate(`/services/url-phishing`);
                    else if (sc === 'website') navigate(`/services/website-scanner`);
                    else if (sc === 'file') navigate(`/services/file`);
                    else if (sc === 'extension') navigate(`/services/extension`);
                    else navigate('/services');
                  }}
                  className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-xs transition-colors shrink-0"
                >
                  <span>Launch Deep Scan</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {/* 4. Provider Results Cards */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
              <div className="flex items-center justify-between pb-4 mb-6 border-b border-slate-100">
                <div>
                  <h3 className="text-base font-bold text-slate-900">Intelligence Source Results</h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Individual feeds queried for indicator <span className="font-mono">{report.canonicalValue}</span>
                  </p>
                </div>
                <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-3 py-1 rounded-full">
                  {report.providers.length} Sources
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                {report.providers.map((p: ThreatIntelProviderResult, idx: number) => {
                  const isProvMalicious = p.reputation === 'MALICIOUS';
                  const isProvSuspicious = p.reputation === 'SUSPICIOUS';
                  const isProvNotConf = p.status === 'NOT_CONFIGURED';

                  return (
                    <div
                      key={idx}
                      className={cn(
                        'border rounded-2xl p-5 flex flex-col justify-between transition-shadow hover:shadow-xs',
                        isProvMalicious
                          ? 'bg-rose-50/40 border-rose-200'
                          : isProvSuspicious
                          ? 'bg-amber-50/40 border-amber-200'
                          : isProvNotConf
                          ? 'bg-slate-50/60 border-slate-200 opacity-80'
                          : 'bg-white border-slate-200'
                      )}
                    >
                      <div>
                        <div className="flex items-start justify-between gap-2 pb-3 border-b border-slate-100">
                          <div>
                            <h4 className="text-sm font-bold text-slate-900">{p.providerName}</h4>
                            <span className="text-[10px] font-mono text-slate-400">Query: {p.queryType}</span>
                          </div>
                          <span
                            className={cn(
                              'px-2.5 py-0.5 rounded-full text-[10px] font-bold border',
                              isProvNotConf
                                ? 'bg-slate-100 text-slate-500 border-slate-200'
                                : isProvMalicious
                                ? 'bg-rose-100 text-rose-800 border-rose-300'
                                : isProvSuspicious
                                ? 'bg-amber-100 text-amber-800 border-amber-300'
                                : p.status === 'SUCCESS'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-slate-100 text-slate-600 border-slate-200'
                            )}
                          >
                            {p.status === 'NOT_CONFIGURED'
                              ? 'NOT CONFIGURED'
                              : p.status === 'TIMEOUT'
                              ? 'TIMEOUT'
                              : p.reputation}
                          </span>
                        </div>

                        <div className="py-3 space-y-2 text-xs">
                          {p.detectionSummary && (
                            <div className="flex justify-between items-center text-[11px]">
                              <span className="text-slate-500">Detections:</span>
                              <span className="font-bold text-slate-900">
                                {p.detectionSummary.malicious > 0 ? (
                                  <span className="text-rose-600 font-bold">
                                    {p.detectionSummary.malicious} flagged
                                  </span>
                                ) : (
                                  '0 flagged (Clean)'
                                )}
                              </span>
                            </div>
                          )}

                          {p.responseTimeMs !== undefined && (
                            <div className="flex justify-between items-center text-[11px]">
                              <span className="text-slate-500">Response Time:</span>
                              <span className="font-mono text-slate-700">{p.responseTimeMs}ms</span>
                            </div>
                          )}

                          {p.lastAnalysisDate && (
                            <div className="flex justify-between items-center text-[11px]">
                              <span className="text-slate-500">Last Analysis:</span>
                              <span className="text-slate-700">
                                {new Date(p.lastAnalysisDate).toLocaleDateString()}
                              </span>
                            </div>
                          )}

                          {p.categories.length > 0 && (
                            <div className="pt-1 flex flex-wrap gap-1">
                              {p.categories.map((c, i) => (
                                <span
                                  key={i}
                                  className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-100 text-slate-600 border border-slate-200"
                                >
                                  {c}
                                </span>
                              ))}
                            </div>
                          )}

                          <p className="text-[11px] text-slate-600 pt-1 leading-relaxed">{p.details}</p>
                        </div>
                      </div>

                      {p.evidence.length > 0 && (
                        <div className="pt-2 border-t border-slate-100 text-[11px] text-blue-600 font-semibold flex items-center justify-between">
                          <span>{p.evidence.length} Evidence Record(s)</span>
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 5. Threat Intelligence Evidence Table */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100">
                <div>
                  <h3 className="text-base font-bold text-slate-900">Threat Intelligence Evidence</h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Verified findings and IOC records returned by connected providers.
                  </p>
                </div>
                <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-3 py-1 rounded-full">
                  {report.evidence.length} Items
                </span>
              </div>

              {report.evidence.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50/70 text-[11px] font-bold uppercase tracking-wider text-slate-500">
                        <th className="py-3 px-4">Provider</th>
                        <th className="py-3 px-4">Indicator</th>
                        <th className="py-3 px-4">Finding / Value</th>
                        <th className="py-3 px-4">Severity</th>
                        <th className="py-3 px-4">Confidence</th>
                        <th className="py-3 px-4">First Seen</th>
                        <th className="py-3 px-4">Last Seen</th>
                        <th className="py-3 px-4 text-right">Source</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {report.evidence.map((ev: ThreatIntelEvidenceItem, i: number) => (
                        <tr key={i} className="hover:bg-slate-50/80 transition-colors">
                          <td className="py-3.5 px-4 font-bold text-slate-900 whitespace-nowrap">{ev.provider}</td>
                          <td className="py-3.5 px-4 font-mono text-[11px] text-slate-700 max-w-[160px] truncate" title={ev.indicator}>
                            {ev.indicator}
                          </td>
                          <td className="py-3.5 px-4 max-w-[240px]">
                            <div className="font-semibold text-slate-800">{ev.value}</div>
                            <div className="text-[11px] text-slate-500 truncate" title={ev.description}>
                              {ev.description}
                            </div>
                          </td>
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            <span
                              className={cn(
                                'px-2 py-0.5 rounded text-[10px] font-bold uppercase border',
                                ev.severity === 'CRITICAL'
                                  ? 'bg-rose-100 text-rose-800 border-rose-200'
                                  : ev.severity === 'HIGH'
                                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                                  : ev.severity === 'MEDIUM'
                                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                                  : 'bg-blue-50 text-blue-700 border-blue-200'
                              )}
                            >
                              {ev.severity}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            <span className="font-bold text-slate-700">{ev.confidence}</span>
                          </td>
                          <td className="py-3.5 px-4 text-slate-600 whitespace-nowrap">
                            {ev.firstSeen ? new Date(ev.firstSeen).toLocaleDateString() : 'Not provided by source'}
                          </td>
                          <td className="py-3.5 px-4 text-slate-600 whitespace-nowrap">
                            {ev.lastSeen ? new Date(ev.lastSeen).toLocaleDateString() : 'Not provided by source'}
                          </td>
                          <td className="py-3.5 px-4 text-right whitespace-nowrap">
                            {ev.sourceReference ? (
                              <a
                                href={ev.sourceReference}
                                target="_blank"
                                rel="noreferrer noopener"
                                className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-700 font-semibold"
                              >
                                <span>Ref</span>
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            ) : (
                              <span className="text-slate-400">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-10 text-center space-y-2">
                  <div className="w-10 h-10 rounded-full bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                    <Database className="w-5 h-5" />
                  </div>
                  <p className="text-xs font-bold text-slate-700">No threat evidence records returned</p>
                  <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
                    The queried intelligence sources report no confirmed malware, phishing, or abuse entries for this indicator.
                  </p>
                </div>
              )}
            </div>

            {/* 6. Related Indicators & Infrastructure */}
            {report.relatedIndicators.length > 0 && (
              <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
                <div className="pb-4 mb-4 border-b border-slate-100 flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-slate-900">Correlated Infrastructure &amp; Indicators</h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Directly related IOCs, domains, network subnets, or payload checksums.
                    </p>
                  </div>
                  <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-3 py-1 rounded-full">
                    {report.relatedIndicators.length} Links
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {report.relatedIndicators.map((rel: ThreatIntelRelatedIndicator, i: number) => (
                    <div
                      key={i}
                      className="p-3.5 bg-slate-50 hover:bg-slate-100 border border-slate-200/80 rounded-2xl flex items-start justify-between gap-3 text-xs transition-colors"
                    >
                      <div className="min-w-0">
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                          {rel.relationship}
                        </span>
                        <span className="font-mono font-bold text-slate-900 text-xs block truncate mt-0.5">
                          {rel.indicator}
                        </span>
                        <span className="text-[10px] text-slate-500 mt-1 block">Source: {rel.source}</span>
                      </div>
                      <button
                        onClick={() => handleAnalyze(rel.indicator, false)}
                        title="Investigate this related indicator"
                        className="p-1.5 rounded-lg bg-white hover:bg-blue-50 text-slate-600 hover:text-blue-600 border border-slate-200 shadow-2xs transition-colors shrink-0"
                      >
                        <Search className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 7. Advanced Technical Details Tabbed Inspector */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-slate-600" />
                  <h3 className="text-base font-bold text-slate-900">Advanced Intelligence Details</h3>
                </div>
                <span className="text-[11px] text-slate-400 font-mono">ID: {report.analysisId}</span>
              </div>

              {/* Tabs */}
              <div className="flex items-center gap-1 border-b border-slate-200 pb-2 mb-4 overflow-x-auto text-xs">
                <button
                  onClick={() => setActiveTab('overview')}
                  className={cn(
                    'px-3 py-1.5 rounded-lg font-semibold transition-colors whitespace-nowrap',
                    activeTab === 'overview'
                      ? 'bg-blue-50 text-blue-600'
                      : 'text-slate-600 hover:bg-slate-50'
                  )}
                >
                  Overview &amp; Assessment
                </button>
                <button
                  onClick={() => setActiveTab('providers')}
                  className={cn(
                    'px-3 py-1.5 rounded-lg font-semibold transition-colors whitespace-nowrap',
                    activeTab === 'providers'
                      ? 'bg-blue-50 text-blue-600'
                      : 'text-slate-600 hover:bg-slate-50'
                  )}
                >
                  Provider Matrix ({report.providers.length})
                </button>
                <button
                  onClick={() => setActiveTab('evidence')}
                  className={cn(
                    'px-3 py-1.5 rounded-lg font-semibold transition-colors whitespace-nowrap',
                    activeTab === 'evidence'
                      ? 'bg-blue-50 text-blue-600'
                      : 'text-slate-600 hover:bg-slate-50'
                  )}
                >
                  Evidence ({report.evidence.length})
                </button>
                <button
                  onClick={() => setActiveTab('related')}
                  className={cn(
                    'px-3 py-1.5 rounded-lg font-semibold transition-colors whitespace-nowrap',
                    activeTab === 'related'
                      ? 'bg-blue-50 text-blue-600'
                      : 'text-slate-600 hover:bg-slate-50'
                  )}
                >
                  Relationships ({report.relatedIndicators.length})
                </button>
                <button
                  onClick={() => setActiveTab('timeline')}
                  className={cn(
                    'px-3 py-1.5 rounded-lg font-semibold transition-colors whitespace-nowrap',
                    activeTab === 'timeline'
                      ? 'bg-blue-50 text-blue-600'
                      : 'text-slate-600 hover:bg-slate-50'
                  )}
                >
                  Temporal Data
                </button>
                <button
                  onClick={() => setActiveTab('raw')}
                  className={cn(
                    'px-3 py-1.5 rounded-lg font-semibold transition-colors whitespace-nowrap',
                    activeTab === 'raw'
                      ? 'bg-blue-50 text-blue-600'
                      : 'text-slate-600 hover:bg-slate-50'
                  )}
                >
                  Sanitized Source Metadata
                </button>
              </div>

              {/* Tab Contents */}
              <div className="text-xs">
                {activeTab === 'overview' && (
                  <div className="space-y-4 bg-slate-50/60 p-5 rounded-2xl border border-slate-200">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <span className="text-slate-400 font-bold block mb-1">ANALYSIS ID</span>
                        <span className="font-mono text-slate-800">{report.analysisId}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-bold block mb-1">CREATED TIMESTAMP</span>
                        <span className="text-slate-800">{new Date(report.createdAt).toLocaleString()}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-bold block mb-1">CONFIDENCE EXPLANATION</span>
                        <span className="text-slate-800">{report.confidenceExplanation}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-bold block mb-1">RECOMMENDED ACTION</span>
                        <span className="text-slate-800">{report.recommendation}</span>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'providers' && (
                  <div className="space-y-3">
                    {report.providers.map((p, i) => (
                      <div key={i} className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-bold text-slate-900">{p.providerName}</span>
                          <span className="font-mono text-slate-500 text-[11px]">{p.status}</span>
                        </div>
                        <p className="text-slate-600 text-[11px] leading-relaxed">{p.details}</p>
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === 'evidence' && (
                  <div className="space-y-2">
                    {report.evidence.length > 0 ? (
                      report.evidence.map((ev, i) => (
                        <div key={i} className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
                          <div className="flex items-center justify-between font-bold text-slate-900 mb-1">
                            <span>{ev.provider} — {ev.value}</span>
                            <span className="text-slate-500 font-normal">{ev.severity}</span>
                          </div>
                          <p className="text-slate-600 text-[11px]">{ev.description}</p>
                        </div>
                      ))
                    ) : (
                      <p className="text-slate-500 py-4">No discrete evidence items to display.</p>
                    )}
                  </div>
                )}

                {activeTab === 'related' && (
                  <div className="space-y-2">
                    {report.relatedIndicators.length > 0 ? (
                      report.relatedIndicators.map((rel, i) => (
                        <div key={i} className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between">
                          <div>
                            <span className="font-bold text-slate-800 font-mono">{rel.indicator}</span>
                            <span className="text-slate-500 text-[11px] block">{rel.relationship} ({rel.type})</span>
                          </div>
                          <span className="text-[10px] text-slate-400 font-semibold">{rel.source}</span>
                        </div>
                      ))
                    ) : (
                      <p className="text-slate-500 py-4">No associated indicator relationships found.</p>
                    )}
                  </div>
                )}

                {activeTab === 'timeline' && (
                  <div className="space-y-3 bg-slate-50/60 p-5 rounded-2xl border border-slate-200">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                      <div>
                        <span className="text-slate-400 font-bold block mb-1">FIRST SEEN IN FEEDS</span>
                        <span className="text-slate-800">
                          {report.temporalData?.firstSeen ? new Date(report.temporalData.firstSeen).toLocaleString() : 'Not provided by source'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-bold block mb-1">LAST SEEN IN FEEDS</span>
                        <span className="text-slate-800">
                          {report.temporalData?.lastSeen ? new Date(report.temporalData.lastSeen).toLocaleString() : 'Not provided by source'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-bold block mb-1">LATEST ANALYSIS DATE</span>
                        <span className="text-slate-800">
                          {report.temporalData?.lastAnalysisDate ? new Date(report.temporalData.lastAnalysisDate).toLocaleString() : 'Recent'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'raw' && (
                  <div className="relative">
                    <pre className="p-4 bg-slate-900 text-slate-100 rounded-2xl font-mono text-[11px] overflow-x-auto max-h-96">
                      {JSON.stringify(report, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </Container>
    </div>
  );
}
