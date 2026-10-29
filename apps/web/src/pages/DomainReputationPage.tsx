import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Activity,
  Search,
  RefreshCw,
  Globe,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  Server,
  ExternalLink,
  Radio,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { threatIntelService } from '../services/threat-intel.service';
import { cn } from '../lib/utils';
import type { ThreatIntelAnalysisReport } from '../types';

export function DomainReputationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const [domainInput, setDomainInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ThreatIntelAnalysisReport | null>(null);

  useEffect(() => {
    const q = searchParams.get('d') || searchParams.get('domain') || searchParams.get('q');
    if (q && q.trim()) {
      setDomainInput(q.trim());
      handleLookup(q.trim());
    }
  }, [searchParams]);

  function normalizeDomainInput(raw: string): string {
    let clean = raw.trim().toLowerCase();
    clean = clean.replace(/^[a-z]+:\/\//i, '');
    clean = clean.split('/')[0].split('?')[0].split(':')[0];
    return clean;
  }

  async function handleLookup(target?: string) {
    const raw = (target || domainInput).trim();
    if (!raw) {
      setError('Please enter a valid domain to evaluate.');
      return;
    }

    const domain = normalizeDomainInput(raw);
    if (!domain) {
      setError('Please enter a valid domain format (e.g. example.com).');
      return;
    }

    setIsLoading(true);
    setError(null);
    setSearchParams({ domain });

    try {
      const result = await threatIntelService.analyzeIndicator(domain, false);
      setReport(result);
    } catch (err: any) {
      setError(err.message || 'Domain reputation lookup failed. Please verify connectivity.');
    } finally {
      setIsLoading(false);
    }
  }

  const isMalicious = report?.overallReputation === 'MALICIOUS';
  const isSuspicious = report?.overallReputation === 'SUSPICIOUS';
  const isNotConfigured = report?.status === 'NOT_CONFIGURED';

  return (
    <div className="min-h-screen bg-slate-50/50 pb-24 pt-28">
      {/* Hero Header */}
      <section className="relative overflow-hidden bg-white border-b border-slate-200/80 py-10 sm:py-12">
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />
        <Container>
          <div className="max-w-4xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider mb-3">
              <Activity className="w-3.5 h-3.5 text-blue-600" />
              <span>Domain Reputation &amp; Infrastructure Intelligence</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight leading-tight">
              Domain Reputation Intelligence
            </h1>
            <p className="mt-2.5 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              Inspect multi-engine reputation scores, DNS resolution properties, malware hosting history, and infrastructure relationships for any domain.
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
            className="space-y-4"
          >
            <div>
              <label htmlFor="domain-input" className="block text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
                Evaluate Domain or FQDN
              </label>
              <div className="relative flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-400">
                    <Globe className="w-5 h-5" />
                  </div>
                  <input
                    id="domain-input"
                    type="text"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    placeholder="Enter a domain name (e.g. example.com, google.com)"
                    className="w-full pl-11 pr-4 py-3.5 bg-slate-50 hover:bg-slate-50/80 focus:bg-white border border-slate-200 focus:border-blue-600 rounded-2xl text-sm font-medium text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-600/10 transition-all font-mono"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isLoading || !domainInput.trim()}
                  className="inline-flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-bold px-6 py-3.5 rounded-2xl shadow-sm shadow-blue-600/25 transition-all shrink-0"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Evaluating domain...</span>
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4" />
                      <span>Inspect Domain</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Quick Samples */}
            <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-400 font-semibold mr-1">Quick Domain Samples:</span>
              <button
                type="button"
                onClick={() => {
                  setDomainInput('example.com');
                  handleLookup('example.com');
                }}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-600 border border-slate-200/80 transition-colors font-mono text-[11px]"
              >
                example.com
              </button>
              <button
                type="button"
                onClick={() => {
                  setDomainInput('wikipedia.org');
                  handleLookup('wikipedia.org');
                }}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-600 border border-slate-200/80 transition-colors font-mono text-[11px]"
              >
                wikipedia.org
              </button>
              <button
                type="button"
                onClick={() => {
                  setDomainInput('github.com');
                  handleLookup('github.com');
                }}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-600 border border-slate-200/80 transition-colors font-mono text-[11px]"
              >
                github.com
              </button>
            </div>
          </form>

          {error && (
            <div className="mt-4 p-4 rounded-2xl bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-bold">Evaluation Notice</p>
                <p className="mt-0.5">{error}</p>
              </div>
            </div>
          )}
        </div>

        {/* Report Section */}
        {report && (
          <div className="space-y-8 animate-in fade-in duration-200">
            {/* 1. Header Overview Card */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
                <div>
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Evaluated Domain
                  </span>
                  <h2 className="text-2xl font-extrabold text-slate-900 font-mono mt-1">
                    {report.canonicalValue || report.indicator}
                  </h2>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => navigate(`/threat-intelligence?q=${encodeURIComponent(report.canonicalValue)}`)}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-50 hover:bg-blue-100 text-blue-700 rounded-xl text-xs font-bold transition-colors"
                  >
                    <Radio className="w-3.5 h-3.5" />
                    <span>Full Investigation</span>
                  </button>
                </div>
              </div>

              {/* Status Row */}
              <div
                className={cn(
                  'mt-6 p-4 rounded-2xl border flex items-start gap-3.5 text-xs',
                  isMalicious
                    ? 'bg-rose-50 border-rose-200 text-rose-800'
                    : isSuspicious
                    ? 'bg-amber-50 border-amber-200 text-amber-800'
                    : isNotConfigured
                    ? 'bg-slate-50 border-slate-200 text-slate-700'
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
                  <ShieldCheck className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                )}
                <div>
                  <p className="font-bold text-sm">
                    {report.status === 'MATCH_FOUND'
                      ? `Threat Intelligence Match: ${report.overallReputation}`
                      : report.status === 'NO_MATCH'
                      ? 'No Matching Threat Intelligence Found'
                      : report.status === 'NOT_CONFIGURED'
                      ? 'Threat Intelligence Source Not Configured'
                      : report.status}
                  </p>
                  <p className="mt-0.5 text-xs leading-relaxed opacity-90">{report.recommendation}</p>
                </div>
              </div>
            </div>

            {/* 2. Structured Domain Intelligence Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {/* Card A: Domain Reputation */}
              <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-3">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-blue-600" />
                  <h4 className="text-sm font-bold text-slate-900">Multi-Engine Reputation</h4>
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between py-1 border-b border-slate-100">
                    <span className="text-slate-500">Reputation:</span>
                    <span className="font-bold text-slate-800">{report.overallReputation}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-100">
                    <span className="text-slate-500">Confidence:</span>
                    <span className="font-bold text-slate-800">{report.confidence}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-100">
                    <span className="text-slate-500">Detections:</span>
                    <span className="font-bold text-slate-800">
                      {report.detectionSummary?.flaggedCount ?? 0} flagged
                    </span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-500">Sources Checked:</span>
                    <span className="font-bold text-slate-800">{report.providersChecked} / {report.providersTotal}</span>
                  </div>
                </div>
              </div>

              {/* Card B: Malware & Phishing Associations */}
              <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-600" />
                  <h4 className="text-sm font-bold text-slate-900">Malware &amp; Phishing Associations</h4>
                </div>
                {report.evidence.length > 0 ? (
                  <div className="space-y-2 text-xs">
                    {report.evidence.slice(0, 3).map((ev, i) => (
                      <div key={i} className="p-2.5 bg-rose-50/50 rounded-xl border border-rose-100">
                        <span className="font-bold text-slate-800 block">{ev.value}</span>
                        <span className="text-[11px] text-slate-600">{ev.description}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 bg-slate-50 rounded-xl text-xs text-slate-500 text-center">
                    No confirmed malware or phishing associations found in configured threat feeds.
                  </div>
                )}
              </div>

              {/* Card C: Related Infrastructure */}
              <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-3">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-indigo-600" />
                  <h4 className="text-sm font-bold text-slate-900">Related Infrastructure</h4>
                </div>
                {report.relatedIndicators.length > 0 ? (
                  <div className="space-y-1.5 text-xs">
                    {report.relatedIndicators.slice(0, 4).map((rel, i) => (
                      <div key={i} className="p-2 bg-slate-50 rounded-lg flex justify-between items-center font-mono text-[11px]">
                        <span className="text-slate-800 truncate">{rel.indicator}</span>
                        <span className="text-slate-400 font-sans text-[10px] uppercase font-bold">{rel.relationship}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 bg-slate-50 rounded-xl text-xs text-slate-500 text-center">
                    Not available from configured sources.
                  </div>
                )}
              </div>
            </div>

            {/* 3. Deep Scanner Correlation Banner */}
            <div className="p-6 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-3xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <h4 className="text-sm font-bold text-slate-900">Need Comprehensive Website Security &amp; TLS Audit?</h4>
                <p className="text-xs text-slate-600 mt-1 max-w-xl">
                  Run a live CyberWatch Website Security scan to analyze HTTP headers, transport certificates, cookie hygiene, forms, and client script dependencies.
                </p>
              </div>
              <button
                onClick={() => navigate(`/services/website-scanner`)}
                className="inline-flex items-center gap-1.5 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-xs transition-colors shrink-0"
              >
                <span>Launch Website Security Scanner</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </Container>
    </div>
  );
}
