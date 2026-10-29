import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Server,
  Search,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  Radio,
  ExternalLink,
  Lock,
  Cpu,
  ArrowRight,
  Database,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { threatIntelService } from '../services/threat-intel.service';
import { cn } from '../lib/utils';
import type { ThreatIntelAnalysisReport } from '../types';

export function IPReputationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const [ipInput, setIpInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ThreatIntelAnalysisReport | null>(null);

  useEffect(() => {
    const q = searchParams.get('ip') || searchParams.get('q');
    if (q && q.trim()) {
      setIpInput(q.trim());
      handleLookup(q.trim());
    }
  }, [searchParams]);

  function normalizeIpInput(raw: string): string {
    let clean = raw.trim();
    clean = clean.replace(/^[a-z]+:\/\//i, '');
    clean = clean.split('/')[0].split('?')[0].split(':')[0];
    // refang
    clean = clean.replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':');
    return clean;
  }

  async function handleLookup(target?: string) {
    const raw = (target || ipInput).trim();
    if (!raw) {
      setError('Please enter an IPv4 or IPv6 address to evaluate.');
      return;
    }

    const ip = normalizeIpInput(raw);
    if (!ip) {
      setError('Please enter a valid IP address format (e.g. 8.8.8.8 or 2001:4860:4860::8888).');
      return;
    }

    setIsLoading(true);
    setError(null);
    setSearchParams({ ip });

    try {
      const result = await threatIntelService.analyzeIndicator(ip, false);
      setReport(result);
    } catch (err: any) {
      setError(err.message || 'IP reputation lookup failed. Please verify connectivity.');
    } finally {
      setIsLoading(false);
    }
  }

  const isMalicious = report?.overallReputation === 'MALICIOUS';
  const isSuspicious = report?.overallReputation === 'SUSPICIOUS';
  const isPrivate = report?.overallReputation === 'INFORMATIONAL' || report?.indicatorType === 'IP' && report?.recommendation?.includes('private');

  // Extract AbuseIPDB specific metadata if present
  const abuseProvider = report?.providers?.find((p) => p.providerId === 'abuseipdb');
  const abuseMetadata = abuseProvider?.sanitizedRawMetadata as any;

  return (
    <div className="min-h-screen bg-slate-50/50 pb-24 pt-28">
      {/* Hero Header */}
      <section className="relative overflow-hidden bg-white border-b border-slate-200/80 py-10 sm:py-12">
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />
        <Container>
          <div className="max-w-4xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider mb-3">
              <Server className="w-3.5 h-3.5 text-blue-600" />
              <span>IP Intelligence &amp; Abuse Reputation</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight leading-tight">
              IP Reputation Intelligence
            </h1>
            <p className="mt-2.5 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              Investigate IPv4 and IPv6 infrastructure, abuse report history, malicious host flags, and network attribution across verified security feeds.
            </p>
          </div>
        </Container>
      </section>

      <Container className="mt-8">
        {/* Search Panel */}
        <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm mb-8">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleLookup();
            }}
            className="flex flex-col sm:flex-row gap-4"
          >
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-400">
                <Search className="w-5 h-5" />
              </div>
              <input
                type="text"
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                placeholder="Enter IPv4 or IPv6 address (e.g., 8.8.8.8, 1.1.1.1, 2001:4860:4860::8888)..."
                className="w-full pl-12 pr-4 py-3.5 bg-slate-50 border border-slate-200 focus:border-blue-600 rounded-2xl text-sm font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-600/10 transition-all"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="inline-flex items-center justify-center gap-2 px-8 py-3.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-2xl shadow-sm hover:shadow transition-all disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Querying Feeds...</span>
                </>
              ) : (
                <>
                  <Server className="w-4 h-4" />
                  <span>Check IP</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Samples */}
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span className="font-semibold text-slate-700">Quick Targets:</span>
            {['8.8.8.8', '1.1.1.1', '192.168.1.1', '2001:4860:4860::8888'].map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => {
                  setIpInput(sample);
                  handleLookup(sample);
                }}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono transition-colors"
              >
                {sample}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="p-4 mb-6 rounded-2xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-medium flex items-center gap-3">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{error}</span>
          </div>
        )}

        {/* Results View */}
        {report && (
          <div className="space-y-6">
            {/* Private IP Notice Banner */}
            {isPrivate && (
              <div className="p-5 rounded-3xl bg-amber-50 border border-amber-200 text-amber-900 flex items-start gap-4">
                <Lock className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-sm text-amber-900">Private / Reserved IP Address</h4>
                  <p className="text-xs text-amber-800 mt-1 leading-relaxed">
                    Private/Reserved address — external reputation lookup skipped. CyberWatch automatically protects against Server-Side Request Forgery (SSRF) and does not dispatch outbound reputation requests for RFC 1918 or loopback scopes.
                  </p>
                </div>
              </div>
            )}

            {/* Assessment Card */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-slate-100">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                      Target IP
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-600">
                      {report.indicatorType}
                    </span>
                  </div>
                  <h2 className="text-2xl sm:text-3xl font-black text-slate-900 font-mono mt-1">
                    {report.displayValue || report.canonicalValue}
                  </h2>
                </div>

                <div className="flex items-center gap-3">
                  <div
                    className={cn(
                      'px-4 py-2 rounded-2xl text-xs font-extrabold tracking-wide uppercase flex items-center gap-2 border',
                      isMalicious
                        ? 'bg-rose-50 text-rose-700 border-rose-200'
                        : isSuspicious
                        ? 'bg-amber-50 text-amber-700 border-amber-200'
                        : isPrivate
                        ? 'bg-blue-50 text-blue-700 border-blue-200'
                        : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    )}
                  >
                    {isMalicious ? (
                      <ShieldAlert className="w-4 h-4 text-rose-600" />
                    ) : isSuspicious ? (
                      <AlertTriangle className="w-4 h-4 text-amber-600" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-600" />
                    )}
                    <span>{report.overallReputation}</span>
                  </div>

                  <button
                    onClick={() => navigate(`/threat-intelligence?q=${encodeURIComponent(report.canonicalValue)}`)}
                    className="px-4 py-2 rounded-2xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center gap-2 transition-colors"
                  >
                    <span>Full CTI Dossier</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Grid Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6">
                <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
                  <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                    Confidence Level
                  </div>
                  <div className="text-base font-extrabold text-slate-900 mt-1">
                    {report.confidence}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5 line-clamp-1">
                    {report.confidenceExplanation}
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
                  <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                    Sources Queried
                  </div>
                  <div className="text-base font-extrabold text-slate-900 mt-1">
                    {report.providersChecked} / {report.providersTotal}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {report.providers?.filter((p) => p.status === 'SUCCESS').length} Responded
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
                  <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                    Vendor Flags
                  </div>
                  <div className="text-base font-extrabold text-slate-900 mt-1">
                    {report.detectionSummary?.flaggedCount || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {report.detectionSummary?.providersWithDetections || 0} Flagging Sources
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
                  <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                    Evidence Count
                  </div>
                  <div className="text-base font-extrabold text-slate-900 mt-1">
                    {report.evidence?.length || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    Correlated Items
                  </div>
                </div>
              </div>

              {/* Recommendation */}
              <div className="mt-6 p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex items-start gap-3">
                <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <div className="text-xs text-slate-700 leading-relaxed">
                  <strong className="text-slate-900 font-semibold">Security Guidance: </strong>
                  {report.recommendation}
                </div>
              </div>
            </div>

            {/* Abuse Details & Provider Results */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Provider Breakdown */}
              <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
                <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Radio className="w-4 h-4 text-blue-600" />
                  <span>Intelligence Provider Matrix</span>
                </h3>
                <div className="space-y-3">
                  {report.providers?.map((p) => (
                    <div
                      key={p.providerId}
                      className="p-3.5 rounded-2xl bg-slate-50 border border-slate-100 flex items-center justify-between"
                    >
                      <div>
                        <div className="font-semibold text-xs text-slate-900">{p.providerName}</div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                          {p.status === 'NOT_CONFIGURED' ? 'Key Not Configured' : p.details || p.status}
                        </div>
                      </div>
                      <span
                        className={cn(
                          'px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider font-mono border',
                          p.reputation === 'MALICIOUS'
                            ? 'bg-rose-50 text-rose-700 border-rose-200'
                            : p.reputation === 'SUSPICIOUS'
                            ? 'bg-amber-50 text-amber-700 border-amber-200'
                            : p.status === 'NOT_CONFIGURED'
                            ? 'bg-slate-100 text-slate-500 border-slate-200'
                            : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        )}
                      >
                        {p.reputation || p.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Attribution / Network Metadata */}
              <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
                <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-indigo-600" />
                  <span>Network &amp; Abuse Telemetry</span>
                </h3>

                {abuseMetadata ? (
                  <div className="space-y-3 text-xs">
                    <div className="flex justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">Abuse Confidence Score:</span>
                      <span className="font-mono font-bold text-slate-900">
                        {abuseMetadata.abuseConfidenceScore ?? 'N/A'}%
                      </span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">Total Abuse Reports (90d):</span>
                      <span className="font-mono font-bold text-slate-900">
                        {abuseMetadata.totalReports ?? 0}
                      </span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">Distinct Reporters:</span>
                      <span className="font-mono font-bold text-slate-900">
                        {abuseMetadata.numDistinctUsers ?? 0}
                      </span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">ISP / Organization:</span>
                      <span className="font-mono font-semibold text-slate-900">
                        {abuseMetadata.isp || 'N/A'}
                      </span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">Country Code:</span>
                      <span className="font-mono font-semibold text-slate-900">
                        {abuseMetadata.countryCode || 'N/A'}
                      </span>
                    </div>
                    <div className="flex justify-between py-2">
                      <span className="text-slate-500 font-medium">Last Reported At:</span>
                      <span className="font-mono text-slate-700">
                        {abuseMetadata.lastReportedAt ? new Date(abuseMetadata.lastReportedAt).toLocaleString() : 'Never reported'}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="p-6 rounded-2xl bg-slate-50 border border-slate-100 text-center">
                    <p className="text-xs text-slate-500">
                      {isPrivate
                        ? 'Private network IP address — external WHOIS / ASN queries not executed.'
                        : 'Detailed abuse metadata not returned from configured providers.'}
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Related Indicators */}
            {report.relatedIndicators && report.relatedIndicators.length > 0 && (
              <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
                <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-600" />
                  <span>Associated Domains &amp; Infrastructure</span>
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {report.relatedIndicators.map((rel, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-2xl bg-slate-50 border border-slate-100 flex items-center justify-between"
                    >
                      <div className="truncate mr-2">
                        <div className="font-mono text-xs font-bold text-slate-900 truncate">
                          {rel.indicator}
                        </div>
                        <div className="text-[10px] text-slate-500 truncate">{rel.relationship}</div>
                      </div>
                      <button
                        onClick={() => navigate(`/threat-intelligence?q=${encodeURIComponent(rel.indicator)}`)}
                        className="p-1.5 rounded-lg bg-white hover:bg-slate-200 text-slate-600 transition-colors shrink-0"
                        title="Investigate indicator"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Container>
    </div>
  );
}
