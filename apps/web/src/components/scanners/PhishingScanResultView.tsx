import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  RotateCw,
  PlusCircle,
  ChevronDown,
  ChevronUp,
  Terminal,
  Download,
  Loader2,
  ArrowRight,
  Activity,
  Layers,
  Key,
  Send,
  Eye,
  Zap,
  Radio,
  FileText,
} from 'lucide-react';
import type { ScanRecord, FindingSeverity, PhishingSecurityAnalysis } from '../../types';
import type { ParsedTargetUrl } from '../../utils/urlParser';

interface PhishingScanResultViewProps {
  scan: ScanRecord;
  parsedTarget: ParsedTargetUrl;
  onRescan?: () => void;
  isRescanning?: boolean;
  onNewScan?: () => void;
  onDownloadReport?: () => void;
  isGeneratingPdf?: boolean;
  pdfError?: string | null;
  onCopy?: (text: string) => void;
  copied?: boolean;
}

export function PhishingScanResultView({
  scan,
  parsedTarget,
  onRescan,
  isRescanning = false,
  onNewScan,
  onDownloadReport,
  isGeneratingPdf = false,
  pdfError = null,
  onCopy,
  copied = false,
}: PhishingScanResultViewProps) {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [activeIndicatorTab, setActiveIndicatorTab] = useState<
    'url' | 'brand' | 'redirects' | 'identity' | 'credentials' | 'forms' | 'social' | 'tls' | 'threatIntel'
  >('url');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedEvidence, setCopiedEvidence] = useState<string | null>(null);

  function handleCopyText(text: string, id: string) {
    if (onCopy && id === 'target-url') {
      onCopy(text);
    } else {
      navigator.clipboard.writeText(text);
      setCopiedEvidence(id);
      setTimeout(() => setCopiedEvidence(null), 2000);
    }
  }

  function toggleFinding(id: string) {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  const isTargetCopied = copied || false;

  // Extract analysis data
  const phish: PhishingSecurityAnalysis | undefined =
    (scan.checks as any)?.phishingSecurityAnalysis ||
    (scan.checks?.phishingAnalysis as any)?.phishingSecurityAnalysis;

  const legacyPhish = scan.checks?.phishingAnalysis;
  const http = scan.checks?.httpAnalysis;
  const dns = scan.checks?.domainAnalysis;
  const ssl = scan.checks?.sslAnalysis;
  const redirects = scan.checks?.redirectAnalysis;

  const riskScore = phish?.riskScore ?? scan.riskScore ?? 0;
  const allFindings = scan.findings || [];

  // Execution outcome
  const executionOutcome =
    phish?.executionOutcome ||
    (allFindings.some((f) => f.title.includes('SSRF') || f.title.includes('Private IP'))
      ? 'BLOCKED_BY_SSRF_POLICY'
      : http?.details?.includes('timed out') || dns?.dnsStatus?.includes('failed')
      ? 'TARGET_UNREACHABLE'
      : scan.status === 'failed'
      ? 'SCAN_FAILED'
      : 'COMPLETED');

  // Risk Level Config
  const riskLevelConfig = useMemo(() => {
    if (executionOutcome === 'BLOCKED_BY_SSRF_POLICY') {
      return {
        label: 'BLOCKED BY SSRF POLICY',
        badgeClass: 'bg-red-100 text-red-800 border-red-300',
        textClass: 'text-red-700',
        meterClass: 'bg-red-500',
        Icon: ShieldAlert,
        summary: 'Target destination resolves to a private, loopback, or cloud metadata address. Analysis was blocked by security policy.',
      };
    }
    if (executionOutcome === 'DNS_FAILURE' || executionOutcome === 'TARGET_UNREACHABLE' || executionOutcome === 'TIMEOUT') {
      return {
        label: 'ANALYSIS INCOMPLETE',
        badgeClass: 'bg-amber-100 text-amber-800 border-amber-300',
        textClass: 'text-amber-700',
        meterClass: 'bg-amber-500',
        Icon: AlertTriangle,
        summary: 'Target could not be reached over the network. Phishing analysis could not inspect page content.',
      };
    }

    if (riskScore >= 75 || allFindings.some((f) => String(f.severity).toUpperCase() === 'CRITICAL')) {
      return {
        label: 'CRITICAL RISK',
        badgeClass: 'bg-red-100 text-red-800 border-red-300',
        textClass: 'text-red-700',
        meterClass: 'bg-red-600',
        Icon: ShieldAlert,
        summary: 'Critical indicators associated with brand impersonation, unencrypted credential harvesting, or deceptive homographs were identified.',
      };
    }
    if (riskScore >= 50) {
      return {
        label: 'HIGH RISK',
        badgeClass: 'bg-orange-100 text-orange-800 border-orange-300',
        textClass: 'text-orange-700',
        meterClass: 'bg-orange-500',
        Icon: ShieldAlert,
        summary: 'High-risk phishing indicators detected (e.g. cross-origin credential posting or severe domain/identity mismatch).',
      };
    }
    if (riskScore >= 25) {
      return {
        label: 'MODERATE RISK',
        badgeClass: 'bg-amber-100 text-amber-800 border-amber-300',
        textClass: 'text-amber-700',
        meterClass: 'bg-amber-500',
        Icon: AlertTriangle,
        summary: 'Suspicious structural, redirect, or transport characteristics observed. Exercise caution before entering credentials.',
      };
    }
    if (riskScore >= 12) {
      return {
        label: 'LOW RISK',
        badgeClass: 'bg-blue-100 text-blue-800 border-blue-300',
        textClass: 'text-blue-700',
        meterClass: 'bg-blue-500',
        Icon: ShieldCheck,
        summary: 'Minor observations noted, with no active deceptive lures or external credential harvesting mechanisms.',
      };
    }
    return {
      label: 'SAFE / MINIMAL RISK',
      badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-300',
      textClass: 'text-emerald-700',
      meterClass: 'bg-emerald-500',
      Icon: ShieldCheck,
      summary: 'No risk contributions were identified from the checks completed during this scan.',
    };
  }, [riskScore, executionOutcome, allFindings]);

  // Score Contributors
  const scoreContributors = phish?.scoreContributors || phish?.scoreExplanation?.contributors || [];

  // Positive Signals
  const positiveSignals = useMemo(() => {
    if (phish?.positiveSignals && phish.positiveSignals.length > 0) {
      return phish.positiveSignals;
    }
    const signals: Array<{ title: string; desc: string; category?: string }> = [];
    if (parsedTarget.protocol === 'HTTPS' && ssl?.valid !== false) {
      signals.push({
        title: 'HTTPS Transport Encryption Active',
        desc: `Secure TLS communication active (${ssl?.protocol || 'TLS'}).`,
        category: 'Transport Security',
      });
    }
    if (parsedTarget.subdomainCount <= 2) {
      signals.push({
        title: 'Standard Subdomain Hierarchy',
        desc: 'Domain structure does not exhibit excessive nesting or deceptive subdomains.',
        category: 'Domain & Infrastructure',
      });
    }
    if (legacyPhish?.status === 'passed') {
      signals.push({
        title: 'Clean Credential Profile',
        desc: 'No deceptive credential harvesting forms or brand impersonation tokens identified.',
        category: 'Credential Collection',
      });
    }
    if (!redirects?.redirectCount || redirects.redirectCount === 0) {
      signals.push({
        title: 'Direct Navigation Target',
        desc: 'Direct target destination analyzed without intermediate multi-hop redirection chains.',
        category: 'Redirect Analysis',
      });
    }
    return signals;
  }, [phish, parsedTarget, ssl, legacyPhish, redirects]);

  function getSeverityBadge(severity?: FindingSeverity | string) {
    const sev = String(severity || 'INFO').toUpperCase();
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 border-amber-200';
      case 'LOW':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'INFO':
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  }



  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* ── 1. RESULT HEADER & ACTIONS ───────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-100">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-bold uppercase tracking-wider text-amber-600">
                Phishing Scanner
              </span>
              <span className="text-slate-300">•</span>
              <span
                className={`inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-0.5 rounded-full border ${
                  scan.status === 'failed' || executionOutcome.includes('BLOCKED')
                    ? 'text-red-700 bg-red-50 border-red-200'
                    : 'text-emerald-700 bg-emerald-50 border-emerald-200'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    scan.status === 'failed' || executionOutcome.includes('BLOCKED')
                      ? 'bg-red-500'
                      : 'bg-emerald-500'
                  }`}
                />
                Status: {scan.status ? scan.status.charAt(0).toUpperCase() + scan.status.slice(1) : 'Completed'}
              </span>
              {executionOutcome !== 'COMPLETED' && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200 font-semibold">
                  {executionOutcome}
                </span>
              )}
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight">
              Phishing Security Analysis
            </h1>
            {scan.scannedAt && (
              <p className="text-xs text-slate-500 font-medium">
                Scanned on: {new Date(scan.scannedAt || scan.createdAt).toLocaleString()}
              </p>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            {onRescan && (
              <button
                type="button"
                onClick={onRescan}
                disabled={isRescanning}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-xs transition-all disabled:opacity-75"
              >
                <RotateCw className={`w-3.5 h-3.5 ${isRescanning ? 'animate-spin' : ''}`} />
                <span>Scan Again</span>
              </button>
            )}

            <Link
              to={`/threat-intelligence?q=${encodeURIComponent(parsedTarget.fullUrl || scan.target)}`}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200/80 font-bold text-xs rounded-xl shadow-xs transition-all"
              title="Investigate target in Threat Intelligence"
            >
              <Radio className="w-3.5 h-3.5 text-indigo-600" />
              <span>Threat Intelligence</span>
            </Link>

            {onDownloadReport && (
              <button
                id="btn-phish-report-download"
                type="button"
                onClick={onDownloadReport}
                disabled={isGeneratingPdf}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-xl shadow-xs transition-all disabled:opacity-75"
              >
                {isGeneratingPdf ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Generating...</span>
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Report</span>
                  </>
                )}
              </button>
            )}

            {onNewScan && (
              <button
                type="button"
                onClick={onNewScan}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
              >
                <PlusCircle className="w-3.5 h-3.5 text-blue-600" />
                <span>New Scan</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => handleCopyText(parsedTarget.fullUrl, 'target-url')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
            >
              {isTargetCopied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span className="text-emerald-700">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-500" />
                  <span>Copy Target</span>
                </>
              )}
            </button>
          </div>
        </div>

        {pdfError && (
          <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded-xl px-4 py-2.5 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{pdfError}</span>
          </div>
        )}

        {/* Target Profile Bar */}
        <div className="bg-slate-50/90 border border-slate-200/80 rounded-xl p-4">
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
              Evaluated Destination
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              Length: {parsedTarget.urlLength} chars
            </span>
          </div>
          <p
            className="text-sm sm:text-base font-mono font-bold text-slate-900 break-all leading-relaxed"
            style={{ overflowWrap: 'anywhere' }}
          >
            {parsedTarget.fullUrl}
          </p>
        </div>
      </div>

      {/* ── 2. OVERALL PHISHING RISK SCORE CARD ──────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-6">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 pb-6 border-b border-slate-100">
          <div className="space-y-2 max-w-xl">
            <div className="flex items-center gap-2.5">
              <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                Overall Phishing Risk
              </span>
              <span
                className={`text-xs font-bold px-3 py-0.5 rounded-full border ${riskLevelConfig.badgeClass}`}
              >
                {riskLevelConfig.label}
              </span>
            </div>
            <p className="text-sm text-slate-600 leading-relaxed font-medium">
              {phish?.summary || riskLevelConfig.summary}
            </p>
          </div>

          {/* Dynamic Score Meter */}
          <div className="flex items-center gap-4 p-4 bg-slate-50/90 border border-slate-200/80 rounded-2xl shrink-0 w-full lg:w-auto justify-between lg:justify-start">
            <div className="space-y-1">
              <div className="flex items-baseline gap-1">
                <span className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
                  {riskScore}
                </span>
                <span className="text-sm font-bold text-slate-400">/ 100</span>
              </div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Phishing Risk Score
              </span>
            </div>

            <div className="h-12 w-px bg-slate-200 mx-2" />

            <div className="space-y-1 text-right lg:text-left">
              <div className="flex items-center gap-1.5">
                <span className="text-sm font-bold text-slate-900">
                  {phish?.confidence ?? 90}%
                </span>
                <span className="text-[11px] font-semibold text-slate-500">
                  ({phish?.confidenceLabel || 'High'})
                </span>
              </div>
              <span
                className="text-[11px] text-slate-500 block"
                title="Heuristic indicator confidence reflects the correlation density of collected technical evidence."
              >
                Heuristic Assessment
              </span>
            </div>
          </div>
        </div>

        {/* ── 2B. WHY THIS SCORE? (Score Contributors Breakdown) ──────────────── */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Why This Score?
            </h3>
          </div>

          {scoreContributors.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {scoreContributors.map((contrib, idx) => (
                <div
                  key={idx}
                  className="p-3.5 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-slate-900 truncate">
                      {contrib.title}
                    </span>
                    <span className="text-xs font-bold text-red-600 font-mono shrink-0">
                      +{contrib.contribution}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-600 line-clamp-2 leading-relaxed">
                    {contrib.reason}
                  </p>
                  {contrib.evidence && (
                    <span className="text-[10px] font-mono text-slate-500 bg-white border border-slate-200 px-2 py-0.5 rounded block truncate">
                      {contrib.evidence}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 bg-emerald-50/60 border border-emerald-200/60 rounded-xl text-xs text-emerald-800 font-medium">
              No negative risk contributions were accumulated during this scan. All evidence-based checks conformed to standard security baselines.
            </div>
          )}
        </div>
      </div>

      {/* ── 3. WHAT WE FOUND (FINDINGS LIST) ─────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                What We Found
              </h2>
              <p className="text-xs text-slate-500">
                Direct evidence-backed observations and security findings.
              </p>
            </div>
          </div>
          <span className="text-xs font-bold text-slate-600 bg-slate-100 px-2.5 py-1 rounded-full border border-slate-200">
            {allFindings.length} Finding{allFindings.length === 1 ? '' : 's'}
          </span>
        </div>

        <div className="space-y-3.5">
          {allFindings.map((finding, idx) => {
            const fid = finding.id || `phish-finding-${idx}`;
            const isExpanded = expandedFindings[fid] ?? true;

            return (
              <div
                key={fid}
                className="bg-white border border-slate-200 rounded-xl overflow-hidden transition-all shadow-2xs"
              >
                <div
                  className="p-4 flex items-start justify-between gap-3 cursor-pointer hover:bg-slate-50/50"
                  onClick={() => toggleFinding(fid)}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`text-[11px] font-bold px-2.5 py-0.5 rounded-md border ${getSeverityBadge(
                          finding.severity
                        )}`}
                      >
                        {String(finding.severity || 'INFO').toUpperCase()}
                      </span>
                      <span className="text-xs font-semibold text-slate-500">
                        {finding.category}
                      </span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-900">{finding.title}</h4>
                  </div>

                  <button
                    type="button"
                    className="text-slate-400 hover:text-slate-600 p-1 shrink-0"
                  >
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4" />
                    ) : (
                      <ChevronDown className="w-4 h-4" />
                    )}
                  </button>
                </div>

                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-100 bg-slate-50/40 space-y-3 text-xs">
                    <p className="text-slate-700 leading-relaxed font-medium">
                      {finding.description}
                    </p>

                    {finding.evidence && (
                      <div className="bg-slate-900 text-slate-100 rounded-lg p-3 font-mono text-[11px] space-y-1 relative group">
                        <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase font-bold tracking-wider">
                          <span>Collected Evidence</span>
                          <button
                            type="button"
                            onClick={() => handleCopyText(finding.evidence || '', fid)}
                            className="text-slate-400 hover:text-white inline-flex items-center gap-1"
                          >
                            {copiedEvidence === fid ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span className="text-emerald-400">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                        <p className="break-all whitespace-pre-wrap">{finding.evidence}</p>
                      </div>
                    )}

                    {finding.impact && (
                      <div className="bg-amber-50/70 border border-amber-200/70 rounded-lg p-3 space-y-1">
                        <span className="text-[10px] font-bold text-amber-800 uppercase tracking-wider block">
                          Security Impact
                        </span>
                        <p className="text-amber-900 leading-relaxed">{finding.impact}</p>
                      </div>
                    )}

                    {finding.recommendation && (
                      <div className="bg-blue-50/70 border border-blue-200/70 rounded-lg p-3 space-y-1">
                        <span className="text-[10px] font-bold text-blue-800 uppercase tracking-wider block">
                          Remediation Guidance
                        </span>
                        <p className="text-blue-900 leading-relaxed">
                          {finding.recommendation}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ── 4. PHISHING THREAT INDICATORS (9-SECTION GRID) ──────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-50 border border-amber-100 flex items-center justify-center text-amber-600">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                Phishing Threat Indicators
              </h2>
              <p className="text-xs text-slate-500">
                Multi-dimensional inspection across 9 orthogonal deception signals.
              </p>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-2 border-b border-slate-100 scrollbar-none">
          {[
            { id: 'url', label: '1. URL & Domain', icon: Globe },
            { id: 'brand', label: '2. Brand Consistency', icon: ShieldAlert },
            { id: 'redirects', label: '3. Redirection', icon: ArrowRight },
            { id: 'identity', label: '4. Page Identity', icon: Eye },
            { id: 'credentials', label: '5. Credential Forms', icon: Key },
            { id: 'forms', label: '6. Form Destinations', icon: Send },
            { id: 'social', label: '7. Social Engineering', icon: Zap },
            { id: 'tls', label: '8. HTTPS & TLS', icon: Lock },
            { id: 'threatIntel', label: '9. Threat Intel', icon: Radio },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeIndicatorTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveIndicatorTab(tab.id as any)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold shrink-0 transition-all ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-2xs'
                    : 'bg-slate-50 text-slate-600 hover:bg-slate-100 border border-slate-200/70'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Contents */}
        <div className="p-4 bg-slate-50/70 border border-slate-200/80 rounded-xl space-y-4">
          {activeIndicatorTab === 'url' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-bold text-slate-900">URL & Domain Structure</h4>
                <span className="text-xs font-semibold text-slate-500">
                  Length: {parsedTarget.urlLength} chars
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Hostname</span>
                  <span className="text-xs font-mono font-bold text-slate-800 break-all">
                    {parsedTarget.hostname}
                  </span>
                </div>
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Punycode (xn--)</span>
                  <span className={`text-xs font-bold ${parsedTarget.isPunycode ? 'text-orange-600' : 'text-emerald-600'}`}>
                    {parsedTarget.isPunycode ? 'Detected' : 'Standard ASCII'}
                  </span>
                </div>
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">IP Address Host</span>
                  <span className={`text-xs font-bold ${parsedTarget.isIpAddress ? 'text-red-600' : 'text-emerald-600'}`}>
                    {parsedTarget.isIpAddress ? 'Raw IP Target' : 'Registered Domain'}
                  </span>
                </div>
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Subdomain Levels</span>
                  <span className="text-xs font-mono font-bold text-slate-800">
                    {parsedTarget.subdomainCount} level(s)
                  </span>
                </div>
              </div>
            </div>
          )}

          {activeIndicatorTab === 'brand' && (
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900">Domain & Brand Consistency</h4>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-700">Impersonation Verdict:</span>
                  <span
                    className={`font-bold px-2 py-0.5 rounded ${
                      phish?.domainIdentityAnalysis?.impersonationDetected
                        ? 'bg-red-100 text-red-800'
                        : 'bg-emerald-100 text-emerald-800'
                    }`}
                  >
                    {phish?.domainIdentityAnalysis?.impersonationDetected
                      ? 'Deceptive Mismatch Detected'
                      : 'No Impersonation Detected'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {phish?.domainIdentityAnalysis?.assessment ||
                    'Domain identity presents consistent first-party presentation without unauthorized trademark lures.'}
                </p>
              </div>
            </div>
          )}

          {activeIndicatorTab === 'redirects' && (
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900">Redirection & Forwarding Chain</h4>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-700">Total Redirect Hops:</span>
                  <span className="font-mono font-bold text-slate-900">
                    {phish?.redirectAnalysis?.totalHops ?? redirects?.redirectCount ?? 0}
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {phish?.redirectAnalysis?.assessment ||
                    redirects?.details ||
                    'Direct target destination analyzed without intermediate redirect hops.'}
                </p>
              </div>
            </div>
          )}

          {activeIndicatorTab === 'identity' && (
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900">Page Identity & Document Title</h4>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-2">
                <div className="text-xs space-y-1">
                  <span className="font-bold text-slate-700 block">Page Title:</span>
                  <span className="font-mono text-slate-900 bg-slate-50 px-2 py-1 rounded border border-slate-200 block">
                    {phish?.pageIdentityAnalysis?.pageTitle || '(No static title tag available)'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {phish?.pageIdentityAnalysis?.assessment ||
                    'Page presents standard first-party presentation.'}
                </p>
              </div>
            </div>
          )}

          {activeIndicatorTab === 'credentials' && (
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900">Credential Collection Analysis</h4>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Password Fields</span>
                  <span className={`text-xs font-bold ${phish?.credentialAnalysis?.hasPasswordField ? 'text-amber-600' : 'text-slate-700'}`}>
                    {phish?.credentialAnalysis?.hasPasswordField ? 'Detected' : 'None Detected'}
                  </span>
                </div>
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Username / Email</span>
                  <span className="text-xs font-bold text-slate-700">
                    {phish?.credentialAnalysis?.hasUsernameOrEmailField ? 'Detected' : 'None Detected'}
                  </span>
                </div>
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Insecure HTTP Form</span>
                  <span className={`text-xs font-bold ${phish?.credentialAnalysis?.insecureFormCount && phish.credentialAnalysis.insecureFormCount > 0 ? 'text-red-600' : 'text-emerald-600'}`}>
                    {phish?.credentialAnalysis?.insecureFormCount && phish.credentialAnalysis.insecureFormCount > 0 ? 'Insecure Form' : 'Protected / None'}
                  </span>
                </div>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed bg-white p-3 border border-slate-200 rounded-lg">
                {phish?.credentialAnalysis?.assessment ||
                  'No credential collection or password inputs detected in page DOM.'}
              </p>
            </div>
          )}

          {activeIndicatorTab === 'forms' && (
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900">Form Submission Destinations</h4>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-700">Total HTML Forms:</span>
                  <span className="font-mono font-bold text-slate-900">
                    {phish?.credentialAnalysis?.formCount ?? 0}
                  </span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-700">External Action Submissions:</span>
                  <span className={`font-mono font-bold ${phish?.credentialAnalysis?.externalActionFormCount && phish.credentialAnalysis.externalActionFormCount > 0 ? 'text-red-600' : 'text-emerald-600'}`}>
                    {phish?.credentialAnalysis?.externalActionFormCount ?? 0}
                  </span>
                </div>
                {phish?.credentialAnalysis?.forms && phish.credentialAnalysis.forms.length > 0 && (
                  <div className="pt-2 border-t border-slate-100 space-y-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Form Actions Table</span>
                    {phish.credentialAnalysis.forms.map((f, i) => (
                      <div key={i} className="text-[11px] font-mono p-2 bg-slate-50 rounded border border-slate-200 flex items-center justify-between gap-2">
                        <span className="truncate">{f.method} → {f.action}</span>
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${f.isExternal ? 'bg-orange-100 text-orange-800' : 'bg-emerald-100 text-emerald-800'}`}>
                          {f.isExternal ? 'External' : 'Same-Origin'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeIndicatorTab === 'social' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-bold text-slate-900">Social Engineering & Urgency (Heuristic)</h4>
                <span className="text-[10px] font-semibold text-slate-500 bg-slate-200 px-2 py-0.5 rounded">
                  Heuristic Indicator
                </span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-2">
                <p className="text-xs text-slate-600 leading-relaxed">
                  {phish?.socialEngineeringAnalysis?.assessment ||
                    'No high-pressure account suspension or urgent coercion phrases detected.'}
                </p>
                {phish?.socialEngineeringAnalysis?.urgencyKeywordsFound &&
                  phish.socialEngineeringAnalysis.urgencyKeywordsFound.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap pt-2 border-t border-slate-100">
                      <span className="text-[10px] font-bold text-slate-400 uppercase">Matched Lures:</span>
                      {phish.socialEngineeringAnalysis.urgencyKeywordsFound.map((kw, i) => (
                        <span key={i} className="text-xs font-mono bg-red-50 text-red-700 border border-red-200 px-2 py-0.5 rounded">
                          {kw}
                        </span>
                      ))}
                    </div>
                  )}
              </div>
            </div>
          )}

          {activeIndicatorTab === 'tls' && (
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900">HTTPS Transport & TLS Encryption</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Transport Protocol</span>
                  <span className={`text-xs font-bold ${parsedTarget.protocol === 'HTTPS' ? 'text-emerald-600' : 'text-amber-600'}`}>
                    {parsedTarget.protocol === 'HTTPS' ? 'HTTPS (Encrypted)' : 'HTTP (Plaintext)'}
                  </span>
                </div>
                <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Certificate Trust</span>
                  <span className={`text-xs font-bold ${ssl?.valid !== false ? 'text-emerald-600' : 'text-red-600'}`}>
                    {ssl?.valid !== false ? 'Valid Certificate' : 'Untrusted / Invalid'}
                  </span>
                </div>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed bg-white p-3 border border-slate-200 rounded-lg">
                {phish?.transportAnalysis?.assessment || ssl?.details || 'Transport analysis completed.'}
              </p>
            </div>
          )}

          {activeIndicatorTab === 'threatIntel' && (
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900">Threat Intelligence Feeds</h4>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-700">Feed Status:</span>
                  <span className="text-slate-600 font-medium">
                    {phish?.threatIntelligence?.status || 'Not Configured'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {phish?.threatIntelligence?.details ||
                    'External threat intelligence feeds (such as commercial malware/phishing feeds) were not queried for this scan. The score is based solely on direct URL, network, transport, and DOM evidence.'}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── 5. POSITIVE SECURITY SIGNALS ─────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
        <div className="flex items-center gap-2.5 pb-3 border-b border-slate-100">
          <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600">
            <CheckCircle2 className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight">
              Positive Security Signals
            </h3>
            <p className="text-xs text-slate-500">
              Defensive controls and verified baseline characteristics.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {positiveSignals.map((sig, idx) => (
            <div
              key={idx}
              className="p-3.5 bg-emerald-50/40 border border-emerald-200/50 rounded-xl space-y-1"
            >
              <div className="flex items-center gap-2">
                <Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                <span className="text-xs font-bold text-emerald-950">{sig.title}</span>
              </div>
              <p className="text-[11px] text-emerald-900/80 leading-relaxed pl-5.5">
                {sig.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* ── 6. RECOMMENDATIONS ──────────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
        <div className="flex items-center gap-2.5 pb-3 border-b border-slate-100">
          <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
            <FileText className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight">
              Actionable Recommendations
            </h3>
            <p className="text-xs text-slate-500">
              Guidance tailored to observed findings.
            </p>
          </div>
        </div>

        <div className="space-y-2">
          {scan.recommendations.map((rec, idx) => (
            <div
              key={idx}
              className="flex items-start gap-3 p-3 bg-slate-50/80 border border-slate-200/70 rounded-xl text-xs"
            >
              <div className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 font-bold flex items-center justify-center shrink-0 text-[11px] mt-0.5">
                {idx + 1}
              </div>
              <p className="text-slate-800 font-medium leading-relaxed">{rec}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── 7. TECHNICAL DETAILS (COLLAPSED BY DEFAULT) ─────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl shadow-xs overflow-hidden">
        <button
          type="button"
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="w-full p-5 sm:p-6 flex items-center justify-between text-left hover:bg-slate-50/50 transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center text-slate-600">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">Technical Details</h3>
              <p className="text-xs text-slate-500">
                Network metrics, DNS records, headers, and scan metadata.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs font-bold text-slate-500">
            <span>{showTechnicalDetails ? 'Hide' : 'Show'} Details</span>
            {showTechnicalDetails ? (
              <ChevronUp className="w-4 h-4" />
            ) : (
              <ChevronDown className="w-4 h-4" />
            )}
          </div>
        </button>

        {showTechnicalDetails && (
          <div className="p-6 border-t border-slate-100 bg-slate-50/40 space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono">
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                <span className="text-[10px] text-slate-400 font-sans uppercase font-bold block">Scan ID</span>
                <span className="text-slate-900 text-[11px] break-all">{scan.id}</span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                <span className="text-[10px] text-slate-400 font-sans uppercase font-bold block">HTTP Status</span>
                <span className="text-slate-900 text-[11px]">
                  {http?.statusCode ? `HTTP ${http.statusCode} ${http.statusText || ''}` : 'N/A'}
                </span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                <span className="text-[10px] text-slate-400 font-sans uppercase font-bold block">Response Time</span>
                <span className="text-slate-900 text-[11px]">
                  {http?.responseTimeMs ? `${http.responseTimeMs} ms` : 'N/A'}
                </span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                <span className="text-[10px] text-slate-400 font-sans uppercase font-bold block">Resolved IPs</span>
                <span className="text-slate-900 text-[11px] truncate block">
                  {dns?.resolvedIps?.join(', ') || 'None'}
                </span>
              </div>
            </div>

            <div className="space-y-1.5">
              <span className="text-[11px] font-bold text-slate-500 uppercase font-sans">
                Normalized Target vs Final URL
              </span>
              <div className="p-3 bg-slate-900 text-slate-100 rounded-lg font-mono text-[11px] space-y-1">
                <div>Original: {parsedTarget.fullUrl}</div>
                <div>Final: {phish?.technicalDetails?.finalUrl || http?.finalUrl || parsedTarget.fullUrl}</div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── 8. METHODOLOGY & LIMITATIONS ────────────────────────────────────── */}
      <div className="p-5 bg-slate-100/70 border border-slate-200/80 rounded-2xl space-y-2 text-xs text-slate-600">
        <div className="flex items-center gap-2 text-slate-700 font-bold uppercase tracking-wider text-[11px]">
          <AlertCircle className="w-3.5 h-3.5 text-slate-500" />
          <span>Methodology & Assessment Limitations</span>
        </div>
        <ul className="list-disc list-inside space-y-1 leading-relaxed pl-1">
          <li>
            This assessment is passive and non-destructive. No login forms were submitted, and no credentials were entered.
          </li>
          <li>
            Heuristic threat indicators assess structural and deceptive patterns. They do not constitute calibrated statistical probabilities.
          </li>
          <li>
            Commercial threat intelligence feeds were evaluated if configured. Absence of threat feed flags does not guarantee immunity.
          </li>
        </ul>
      </div>
    </div>
  );
}
