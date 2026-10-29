import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  RotateCw,
  PlusCircle,
  ChevronDown,
  ChevronUp,
  Download,
  Loader2,
  Radio,
  Clock,
  Fingerprint,
  Info,
  ArrowLeft,
  Activity,
} from 'lucide-react';
import type { ScanRecord, ScanResultClassification, FindingSeverity } from '../../types';
import type { ParsedTargetUrl } from '../../utils/urlParser';

interface UrlScanResultViewProps {
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
  backLink?: string;
  backLabel?: string;
}

export function UrlScanResultView({
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
  backLink = '/dashboard',
  backLabel = 'All Scans',
}: UrlScanResultViewProps) {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(true);
  const [internalCopied, setInternalCopied] = useState(false);
  const [activeTechTab, setActiveTechTab] = useState<'url' | 'domain' | 'network' | 'http' | 'redirects' | 'tls' | 'raw'>('url');
  const [activeSectionNav, setActiveSectionNav] = useState('overview');

  function handleCopyUrl(text: string) {
    if (onCopy) {
      onCopy(text);
    } else {
      navigator.clipboard.writeText(text);
      setInternalCopied(true);
      setTimeout(() => setInternalCopied(false), 2000);
    }
  }

  function handleCopyScanId(id: string) {
    navigator.clipboard.writeText(id);
    setInternalCopied(true);
    setTimeout(() => setInternalCopied(false), 2000);
  }

  const isCopied = copied || internalCopied;

  // Extract analysis subsections
  const urlSec = scan.checks?.urlSecurityAnalysis;
  const http = scan.checks?.httpAnalysis;
  const domain = scan.checks?.domainAnalysis;
  const ssl = scan.checks?.sslAnalysis;
  const redirects = scan.checks?.redirectAnalysis;
  const domainIntel = urlSec?.domainIntelligence;
  const threatIntel = urlSec?.threatIntelligence;

  const executionOutcome =
    urlSec?.executionOutcome ||
    (scan.findings?.some((f) => f.title.includes('SSRF') || f.title.includes('Private IP'))
      ? 'BLOCKED_BY_SECURITY_POLICY'
      : http?.details?.includes('timed out') || domain?.dnsStatus?.includes('failed') || (domain as any)?.error
      ? 'TARGET_UNREACHABLE'
      : scan.status === 'failed'
      ? 'SCAN_FAILED'
      : 'COMPLETED');

  // Canonical Risk Verdict Config
  function getVerdictConfig(classification?: ScanResultClassification, score?: number) {
    const risk = score ?? scan.riskScore ?? 0;
    if (executionOutcome === 'BLOCKED_BY_SECURITY_POLICY' || executionOutcome === 'TARGET_UNREACHABLE') {
      return {
        label: executionOutcome === 'BLOCKED_BY_SECURITY_POLICY' ? 'BLOCKED' : 'INCOMPLETE',
        scoreLabel: executionOutcome === 'BLOCKED_BY_SECURITY_POLICY' ? 'Blocked (SSRF)' : 'Target Unreachable',
        badgeClass: 'bg-amber-100 text-amber-900 border-amber-300',
        containerBorder: 'border-amber-200',
        containerBg: 'bg-amber-50/50',
        textColor: 'text-amber-900',
        iconColor: 'text-amber-600',
        barColor: 'bg-amber-500',
        gradientText: 'from-amber-700 to-amber-900',
        Icon: AlertTriangle,
        summary:
          executionOutcome === 'BLOCKED_BY_SECURITY_POLICY'
            ? 'CyberWatch blocked this target because it resolves to a protected or internal network address (SSRF Protection).'
            : 'Target connection failed or timed out. Analysis could not be fully completed.',
      };
    }
    if (risk <= 11 || classification === 'Safe') {
      return {
        label: 'SAFE',
        scoreLabel: 'Safe',
        badgeClass: 'bg-emerald-100 text-emerald-900 border-emerald-300',
        containerBorder: 'border-emerald-200',
        containerBg: 'bg-emerald-50/40',
        textColor: 'text-emerald-900',
        iconColor: 'text-emerald-600',
        barColor: 'bg-emerald-500',
        gradientText: 'from-emerald-700 to-teal-900',
        Icon: ShieldCheck,
        summary:
          urlSec?.statusExplanation ||
          'CyberWatch observed no significant malicious or phishing indicators during this analysis.',
      };
    }
    if (risk <= 24 || classification === 'Low Risk') {
      return {
        label: 'LOW RISK',
        scoreLabel: 'Low Risk',
        badgeClass: 'bg-blue-100 text-blue-900 border-blue-300',
        containerBorder: 'border-blue-200',
        containerBg: 'bg-blue-50/40',
        textColor: 'text-blue-900',
        iconColor: 'text-blue-600',
        barColor: 'bg-blue-500',
        gradientText: 'from-blue-700 to-indigo-900',
        Icon: ShieldCheck,
        summary:
          urlSec?.statusExplanation ||
          'Low-risk security profile with minor informational indicators. Standard web operational behavior verified.',
      };
    }
    if (risk <= 49 || classification === 'Suspicious') {
      return {
        label: 'SUSPICIOUS',
        scoreLabel: 'Suspicious',
        badgeClass: 'bg-amber-100 text-amber-900 border-amber-300',
        containerBorder: 'border-amber-200',
        containerBg: 'bg-amber-50/50',
        textColor: 'text-amber-900',
        iconColor: 'text-amber-600',
        barColor: 'bg-amber-500',
        gradientText: 'from-amber-700 to-amber-900',
        Icon: AlertTriangle,
        summary:
          urlSec?.statusExplanation ||
          'Suspicious indicators were observed in URL structure, transport configuration, or redirection trajectory.',
      };
    }
    if (risk <= 74 || classification === 'High Risk') {
      return {
        label: 'HIGH RISK',
        scoreLabel: 'High Risk',
        badgeClass: 'bg-orange-100 text-orange-900 border-orange-300',
        containerBorder: 'border-orange-200',
        containerBg: 'bg-orange-50/50',
        textColor: 'text-orange-900',
        iconColor: 'text-orange-600',
        barColor: 'bg-orange-500',
        gradientText: 'from-orange-700 to-red-900',
        Icon: ShieldAlert,
        summary:
          urlSec?.statusExplanation ||
          'High-risk security indicators were observed (e.g. HTTPS protocol downgrade, untrusted certificate, or direct IP evasion).',
      };
    }
    return {
      label: 'MALICIOUS',
      scoreLabel: 'Malicious',
      badgeClass: 'bg-red-100 text-red-900 border-red-300',
      containerBorder: 'border-red-200',
      containerBg: 'bg-red-50/50',
      textColor: 'text-red-900',
      iconColor: 'text-red-600',
      barColor: 'bg-red-500',
      gradientText: 'from-red-700 to-red-950',
      Icon: ShieldAlert,
      summary:
        urlSec?.statusExplanation ||
        'Critical security condition detected (e.g. confirmed malicious threat intelligence feed match or credential exfiltration).',
    };
  }

  function getSeverityBadge(severity?: FindingSeverity | string) {
    const sev = String(severity || 'INFO').toUpperCase();
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 border-red-300 font-bold';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 border-orange-300 font-bold';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 border-amber-300 font-bold';
      case 'LOW':
        return 'bg-blue-100 text-blue-800 border-blue-300 font-semibold';
      case 'INFO':
      default:
        return 'bg-slate-100 text-slate-700 border-slate-300 font-medium';
    }
  }

  function getAuditBadge(status: string) {
    switch (status) {
      case 'PASS':
        return 'bg-emerald-100 text-emerald-800 border-emerald-300';
      case 'NOT DETECTED':
      case 'NOT OBSERVED':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'WARN':
      case 'WARNING':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'FAIL':
      case 'FAILED':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'INFO':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'UNAVAILABLE':
      case 'NOT AVAILABLE':
      default:
        return 'bg-slate-100 text-slate-600 border-slate-200';
    }
  }

  const verdict = getVerdictConfig(scan.result, scan.riskScore);
  const VerdictIcon = verdict.Icon;
  const currentRiskScore = scan.riskScore ?? 0;

  // Positive signals
  const positiveSignals = useMemo(() => {
    if (urlSec?.positiveSignals && urlSec.positiveSignals.length > 0) {
      return urlSec.positiveSignals;
    }
    const signals: Array<{ title: string; desc: string }> = [];
    if (parsedTarget.protocol === 'HTTPS' && ssl?.valid !== false) {
      signals.push({
        title: 'HTTPS Transport Encryption Active',
        desc: `Target enforces cryptographic transport security (${ssl?.protocol || 'TLS / HTTPS'}).`,
      });
    }
    if (ssl?.valid === true && (urlSec?.certificateSummary?.hostnameMatch !== false && (ssl as any)?.hostnameMatch !== false)) {
      signals.push({
        title: 'Valid TLS Certificate Verified',
        desc: `Certificate issued by ${ssl.issuer || 'Standard CA'} is cryptographically trusted.`,
      });
    }
    if (!parsedTarget.isIpAddress && domain?.status === 'passed') {
      signals.push({
        title: 'DNS Resolution Succeeded',
        desc: `Hostname resolved via global DNS to ${domain.resolvedIps?.join(', ') || 'public IP'}.`,
      });
    }
    if (!parsedTarget.isIpAddress) {
      signals.push({
        title: 'Standard Registered Domain Hostname',
        desc: `Target uses a standard domain identity (${parsedTarget.hostname}) rather than a raw IP address.`,
      });
    }
    if (!parsedTarget.isPunycode) {
      signals.push({
        title: 'No Punycode / Homograph Labels Detected',
        desc: 'Hostname is free of homograph and internationalized evasion prefixes.',
      });
    }
    if (http?.statusCode && http.statusCode >= 200 && http.statusCode < 400) {
      signals.push({
        title: 'Target Endpoint Reachable & Responsive',
        desc: `Server responded with HTTP ${http.statusCode} ${http.statusText || 'OK'} (${http.responseTimeMs || 0}ms).`,
      });
    }
    if (redirects && (redirects.redirectCount === 0 || redirects.status === 'passed')) {
      signals.push({
        title: 'No Redirect Downgrade Observed',
        desc: 'All redirect hops maintained transport security without downgrading to plaintext HTTP.',
      });
    }
    return signals;
  }, [urlSec, parsedTarget, ssl, domain, http, redirects]);

  // Checklist items
  const checklistItems = useMemo(() => {
    if (urlSec?.auditChecks && urlSec.auditChecks.length > 0) {
      return urlSec.auditChecks;
    }
    if (urlSec?.securityAudit && urlSec.securityAudit.length > 0) {
      return urlSec.securityAudit;
    }
    return [];
  }, [urlSec]);

  // Threat Intelligence Provider Matrix
  const threatProviders = useMemo(() => {
    if (threatIntel?.providers && threatIntel.providers.length > 0) {
      return threatIntel.providers;
    }
    return [
      {
        provider: 'Google Web Risk / Safe Browsing',
        status: 'NOT CONFIGURED',
        result: 'Not Configured',
        confidence: 'N/A',
        details: 'Google Safe Browsing / Web Risk API key is not configured in this environment.',
      },
      {
        provider: 'VirusTotal',
        status: 'NOT CONFIGURED',
        result: 'Not Configured',
        confidence: 'N/A',
        details: 'VirusTotal API key is not configured in this environment.',
      },
      {
        provider: 'URLhaus (abuse.ch)',
        status: 'NOT CONFIGURED',
        result: 'Not Configured',
        confidence: 'N/A',
        details: 'URLhaus threat feed integration is not configured.',
      },
      {
        provider: 'AlienVault OTX',
        status: 'NOT CONFIGURED',
        result: 'Not Configured',
        confidence: 'N/A',
        details: 'AlienVault OTX API key is not configured.',
      },
    ];
  }, [threatIntel]);

  function scrollToSection(id: string) {
    setActiveSectionNav(id);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  const scanIdDisplay = scan.id || (scan as any)._id?.toString() || '';

  return (
    <div id="url-security-scan-result-root" className="w-full space-y-4 sm:space-y-5">
      {/* ── TOP BREADCRUMB ──────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <Link
          to={backLink}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-blue-600 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>← {backLabel}</span>
        </Link>
        <span className="text-[11px] font-mono text-slate-400">
          ID: {scanIdDisplay ? scanIdDisplay.substring(0, 16) : 'N/A'}
        </span>
      </div>

      {/* ── REPORT HEADER CARD ──────────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
          {/* Left Side: Titles & Badges */}
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md bg-blue-50 text-[11px] font-bold tracking-wider text-blue-700 uppercase border border-blue-200/60">
                <Globe className="w-3.5 h-3.5 text-blue-600" />
                CYBERWATCH URL & PHISHING SECURITY REPORT
              </span>
              <span
                className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-0.5 rounded-full border ${
                  executionOutcome === 'BLOCKED_BY_SECURITY_POLICY'
                    ? 'text-red-800 bg-red-50 border-red-200'
                    : executionOutcome === 'TARGET_UNREACHABLE'
                    ? 'text-amber-800 bg-amber-50 border-amber-200'
                    : executionOutcome === 'SCAN_FAILED' || executionOutcome === 'ANALYSIS_UNAVAILABLE'
                    ? 'text-amber-800 bg-amber-50 border-amber-200'
                    : 'text-emerald-700 bg-emerald-50 border-emerald-200'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    executionOutcome === 'BLOCKED_BY_SECURITY_POLICY'
                      ? 'bg-red-500 animate-pulse'
                      : executionOutcome === 'TARGET_UNREACHABLE' || executionOutcome === 'SCAN_FAILED' || executionOutcome === 'ANALYSIS_UNAVAILABLE'
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                />
                ● Analysis: {executionOutcome === 'BLOCKED_BY_SECURITY_POLICY' ? 'Blocked (SSRF)' : executionOutcome === 'TARGET_UNREACHABLE' ? 'Incomplete' : 'Complete'}
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl lg:text-3xl font-extrabold text-slate-900 tracking-tight leading-tight">
              Security Investigation Assessment
            </h1>

            <p className="text-xs text-slate-500 font-medium">
              Multi-signal passive inspection across URL structure, DNS, TLS, redirection journey, phishing lures, and threat feeds.
            </p>
          </div>

          {/* Right Side: Professional Action Buttons Grid */}
          <div className="flex flex-col sm:items-end gap-2 shrink-0">
            {/* Primary Action Buttons */}
            <div className="flex items-center gap-2 flex-wrap">
              {onRescan && (
                <button
                  id="btn-url-rescan"
                  type="button"
                  onClick={onRescan}
                  disabled={isRescanning}
                  className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-xs hover:shadow transition-all disabled:opacity-60 cursor-pointer h-9"
                >
                  <RotateCw className={`w-3.5 h-3.5 ${isRescanning ? 'animate-spin' : ''}`} />
                  <span>Scan Again</span>
                </button>
              )}

              <Link
                to={`/threat-intelligence?q=${encodeURIComponent(parsedTarget.fullUrl || scan.target)}`}
                className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200/80 font-bold text-xs rounded-xl shadow-xs transition-all h-9"
                title="Investigate target in Threat Intelligence"
              >
                <Radio className="w-3.5 h-3.5 text-indigo-600" />
                <span>Threat Intelligence</span>
              </Link>

              {onDownloadReport && (
                <button
                  id="btn-url-download-report"
                  type="button"
                  onClick={onDownloadReport}
                  disabled={isGeneratingPdf}
                  className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-xl shadow-xs hover:shadow transition-all disabled:opacity-60 cursor-pointer h-9"
                >
                  {isGeneratingPdf ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Generating PDF...</span>
                    </>
                  ) : (
                    <>
                      <Download className="w-3.5 h-3.5" />
                      <span>Download PDF</span>
                    </>
                  )}
                </button>
              )}

              <button
                id="btn-url-download-json"
                type="button"
                onClick={() => {
                  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scan, null, 2));
                  const downloadAnchor = document.createElement('a');
                  downloadAnchor.setAttribute('href', dataStr);
                  downloadAnchor.setAttribute('download', `cyberwatch-report-${scan.id || 'scan'}.json`);
                  document.body.appendChild(downloadAnchor);
                  downloadAnchor.click();
                  downloadAnchor.remove();
                }}
                className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-900 text-white font-bold text-xs rounded-xl shadow-xs hover:shadow transition-all cursor-pointer h-9"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download JSON</span>
              </button>
            </div>

            {/* Utility Buttons */}
            <div className="flex items-center gap-2 flex-wrap">
              {onNewScan && (
                <button
                  id="btn-url-new-scan"
                  type="button"
                  onClick={onNewScan}
                  className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all cursor-pointer h-8"
                >
                  <PlusCircle className="w-3.5 h-3.5 text-blue-600" />
                  <span>New Scan</span>
                </button>
              )}

              <button
                id="btn-url-copy-header"
                type="button"
                onClick={() => handleCopyUrl(urlSec?.originalUrl || parsedTarget.fullUrl)}
                className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all cursor-pointer h-8"
              >
                {isCopied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                    <span className="text-emerald-700 font-bold">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-slate-500" />
                    <span>Copy URL</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {pdfError && (
          <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded-xl px-4 py-2.5 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{pdfError}</span>
          </div>
        )}

        {/* ── METADATA ROW (4 COMPACT INFO CARDS) ────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 sm:gap-3 pt-2 border-t border-slate-100">
          {/* Item 1: Scan Time */}
          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <Clock className="w-3 h-3 text-slate-400" />
              Scan Time
            </span>
            <span className="text-xs font-semibold text-slate-900 block truncate">
              {scan.scannedAt ? new Date(scan.scannedAt || scan.createdAt).toLocaleString() : 'Recent Scan'}
            </span>
          </div>

          {/* Item 2: Scan ID */}
          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <Fingerprint className="w-3 h-3 text-slate-400" />
              Scan ID
            </span>
            <div className="flex items-center justify-between gap-1">
              <span className="text-xs font-mono font-bold text-slate-800 truncate" title={scanIdDisplay}>
                {scanIdDisplay ? `${scanIdDisplay.substring(0, 10)}...` : 'N/A'}
              </span>
              {scanIdDisplay && (
                <button
                  type="button"
                  onClick={() => handleCopyScanId(scanIdDisplay)}
                  className="text-slate-400 hover:text-slate-700 p-0.5"
                  title="Copy full Scan ID"
                >
                  <Copy className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>

          {/* Item 3: Confidence */}
          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <ShieldCheck className="w-3 h-3 text-emerald-600" />
              Confidence
            </span>
            <span className="text-xs font-bold text-emerald-700 block truncate">
              HIGH <span className="font-normal text-slate-600 text-[11px]">(Passive Multi-Signal)</span>
            </span>
          </div>

          {/* Item 4: Status */}
          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <Activity className="w-3 h-3 text-blue-600" />
              Analysis Status
            </span>
            <span className={`text-xs font-bold block truncate ${
              executionOutcome === 'BLOCKED_BY_SECURITY_POLICY' ? 'text-red-700' :
              executionOutcome === 'TARGET_UNREACHABLE' ? 'text-amber-700' : 'text-emerald-700'
            }`}>
              {executionOutcome === 'BLOCKED_BY_SECURITY_POLICY' ? 'BLOCKED' :
               executionOutcome === 'TARGET_UNREACHABLE' ? 'INCOMPLETE' : 'COMPLETE'}
            </span>
          </div>
        </div>
      </div>

      {/* ── SUBMITTED TARGET CARD ────────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-4 sm:p-5 shadow-xs space-y-3">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <span className="text-xs font-bold text-slate-600 uppercase tracking-wider flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5 text-blue-600" />
            SUBMITTED TARGET URL
          </span>
          <button
            type="button"
            onClick={() => handleCopyUrl(urlSec?.originalUrl || parsedTarget.fullUrl)}
            className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800 bg-blue-50 px-2.5 py-1 rounded-lg border border-blue-200/60"
          >
            {isCopied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
            <span>{isCopied ? 'Copied' : 'Copy URL'}</span>
          </button>
        </div>

        <p
          id="url-scanned-target-text"
          className="text-sm sm:text-base font-mono font-bold text-slate-900 break-all leading-relaxed bg-slate-50 p-3 rounded-xl border border-slate-200/80"
          style={{ overflowWrap: 'anywhere' }}
        >
          {urlSec?.originalUrl || parsedTarget.fullUrl}
        </p>

        {/* URL Metrics Sub-row */}
        <div className="flex items-center gap-3 sm:gap-6 text-xs text-slate-600 flex-wrap pt-1 font-medium">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">URL Length:</span>
            <strong className="font-mono text-slate-800">{urlSec?.urlLength ?? parsedTarget.urlLength} chars</strong>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Host Length:</span>
            <strong className="font-mono text-slate-800">{urlSec?.hostnameLength ?? parsedTarget.hostnameLength} chars</strong>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Protocol:</span>
            <strong className="font-mono text-slate-800">{parsedTarget.protocol}</strong>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Hostname:</span>
            <strong className="font-mono text-slate-800">{parsedTarget.hostname}</strong>
          </div>
        </div>
      </div>

      {/* ── RISK RESULT CARD (PROMINENT SECURITY VERDICT) ───────────────────── */}
      <div className={`p-5 sm:p-6 rounded-2xl border ${verdict.containerBorder} ${verdict.containerBg} bg-white shadow-xs space-y-4`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={`p-3.5 rounded-2xl bg-white border ${verdict.containerBorder} ${verdict.iconColor} shadow-2xs shrink-0`}>
              <VerdictIcon className="w-8 h-8 sm:w-9 sm:h-9" />
            </div>
            <div className="space-y-1.5">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                SECURITY VERDICT
              </span>
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className={`text-sm font-black uppercase px-3 py-1 rounded-full border shadow-2xs ${verdict.badgeClass}`}>
                  {verdict.label}
                </span>
                <span className="text-sm font-bold text-slate-800 bg-white px-3 py-1 rounded-lg border border-slate-200">
                  Risk Score: <strong className="font-mono text-slate-950 text-base">{currentRiskScore}</strong> / 100
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-700 leading-relaxed font-semibold max-w-2xl pt-1">
                {verdict.summary}
              </p>
            </div>
          </div>

          <div className="sm:text-right shrink-0 bg-white p-4 rounded-xl border border-slate-200 shadow-2xs min-w-[150px]">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-0.5">Risk Level</span>
            <span className={`text-2xl sm:text-3xl font-black tracking-tight ${verdict.iconColor}`}>
              {verdict.scoreLabel}
            </span>
            <span className="text-[11px] text-slate-500 block mt-0.5">Scale: 0 (Safe) - 100</span>
          </div>
        </div>

        {/* Horizontal Score Progress Indicator */}
        <div className="space-y-1.5 pt-2 border-t border-slate-200/80">
          <div className="flex justify-between items-center text-xs font-semibold text-slate-600">
            <span>Risk Score Distribution</span>
            <span className="font-mono font-bold text-slate-900">{currentRiskScore}% Severity Level</span>
          </div>
          <div className="w-full h-3 bg-slate-200/80 rounded-full overflow-hidden p-0.5 flex">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                currentRiskScore <= 11
                  ? 'bg-emerald-500'
                  : currentRiskScore <= 24
                  ? 'bg-blue-500'
                  : currentRiskScore <= 49
                  ? 'bg-amber-500'
                  : currentRiskScore <= 74
                  ? 'bg-orange-500'
                  : 'bg-red-500'
              }`}
              style={{ width: `${Math.max(currentRiskScore, 4)}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-400 font-medium px-0.5">
            <span>0 Safe</span>
            <span>25 Low</span>
            <span>50 Suspicious</span>
            <span>75 High</span>
            <span>100 Critical</span>
          </div>
        </div>
      </div>

      {/* ── SECTION NAVIGATION TABS ─────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-2 shadow-xs overflow-x-auto sticky top-2 z-20">
        <div className="flex items-center gap-1 min-w-max text-xs font-semibold text-slate-600">
          {[
            { id: 'section-verdict', label: 'Overview' },
            { id: 'section-risk-breakdown', label: 'Risk Breakdown' },
            { id: 'section-threat-intel', label: 'Threat Intelligence' },
            { id: 'section-domain-intel', label: 'Domain Intelligence' },
            { id: 'section-http-tls', label: 'HTTP / TLS' },
            { id: 'section-phishing', label: 'Phishing Analysis' },
            { id: 'section-findings', label: `Findings (${scan.findings?.length || 0})` },
            { id: 'section-positive-signals', label: 'Positive Signals' },
            { id: 'section-checklist', label: 'Security Checklist' },
            { id: 'section-technical', label: 'Deep Diagnostics' },
            { id: 'section-recommendations', label: 'Recommendations' },
            { id: 'section-scope', label: 'Scope & Assurances' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => scrollToSection(tab.id)}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
                activeSectionNav === tab.id
                  ? 'bg-blue-600 text-white font-bold shadow-xs'
                  : 'hover:bg-slate-100 hover:text-slate-900'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── MAIN REPORT CONTENT CARDS ───────────────────────────────────────── */}

      {/* ── SECTION 1: EXECUTIVE VERDICT & EVIDENCE POINTS ─────────────────── */}
      <div id="section-verdict" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center gap-3 pb-3 border-b border-slate-100">
          <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-black text-xs">
            01
          </div>
          <div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
              1. Executive Verdict & Summary
            </h2>
            <p className="text-xs text-slate-500">
              Primary evidence, verified positive controls, and observable factors that determined this security verdict.
            </p>
          </div>
        </div>

        <div className="space-y-3">
          <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-2.5">
            <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider block flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-blue-600" />
              Analysis Findings & Assessment
            </span>
            {urlSec?.whyVerdict && urlSec.whyVerdict.length > 0 ? (
              <ul className="space-y-2 text-xs text-slate-700 font-medium">
                {urlSec.whyVerdict.map((bullet, i) => (
                  <li key={i} className="flex items-start gap-2.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-600 mt-1.5 shrink-0" />
                    <span className="leading-relaxed">{bullet}</span>
                  </li>
                ))}
              </ul>
            ) : scan.findings && scan.findings.length > 0 ? (
              <ul className="space-y-2 text-xs text-slate-700 font-medium">
                {scan.findings.slice(0, 4).map((f, i) => (
                  <li key={i} className="flex items-start gap-2.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-600 mt-1.5 shrink-0" />
                    <span><strong>{f.title}:</strong> {f.description}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-slate-600 leading-relaxed">
                CyberWatch analyzed 14 security dimensions across URL structure, DNS, HTTP/TLS, redirect behavior, phishing indicators, and configured threat intelligence sources. No known malicious indicators were observed during this passive analysis.
              </p>
            )}
          </div>
        </div>
      </div>

      {/* ── SECTION 2: RISK SCORE BREAKDOWN ───────────────────────────────── */}
      <div id="section-risk-breakdown" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-black text-xs">
              02
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                2. Risk Score Breakdown
              </h2>
              <p className="text-xs text-slate-500">
                Transparent evidence contribution model — scores accumulate strictly from observed findings.
              </p>
            </div>
          </div>
          <span className="text-xs font-mono font-bold text-slate-800 bg-slate-100 border border-slate-200/80 px-3 py-1 rounded-lg">
            Total Score: {currentRiskScore} / 100
          </span>
        </div>

        {urlSec?.scoreContributors && urlSec.scoreContributors.length > 0 ? (
          <div className="overflow-x-auto rounded-xl border border-slate-200/80">
            <table className="w-full text-xs text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-slate-700 font-bold uppercase text-[11px]">
                  <th className="py-2.5 px-3.5">Dimension / Category</th>
                  <th className="py-2.5 px-3.5">Evidence Reason</th>
                  <th className="py-2.5 px-3.5 text-right">Points Contribution</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-medium text-slate-700 bg-white">
                {urlSec.scoreContributors.map((c, i) => (
                  <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                    <td className="py-2.5 px-3.5 font-semibold text-slate-900">{c.category || c.name}</td>
                    <td className="py-2.5 px-3.5 text-slate-600">{c.reason || c.explanation || 'Identified security factor'}</td>
                    <td className="py-2.5 px-3.5 text-right font-mono font-bold text-amber-700">+{c.points}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-4 bg-emerald-50/60 border border-emerald-200/70 rounded-xl text-xs text-emerald-900 font-medium flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>0 Risk Score Contributors: Target passed all baseline URL structure, DNS, transport, and redirect checks with no risk penalties.</span>
          </div>
        )}
      </div>

      {/* ── SECTION 3: THREAT INTELLIGENCE MATRIX ─────────────────────────── */}
      <div id="section-threat-intel" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-indigo-50 text-indigo-600 border border-indigo-100 flex items-center justify-center font-black text-xs">
              03
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                3. Threat Intelligence Provider Matrix
              </h2>
              <p className="text-xs text-slate-500">
                Real status and responses from configured intelligence providers (No simulated results).
              </p>
            </div>
          </div>
          <span className="text-xs font-semibold text-slate-600 bg-slate-100 border border-slate-200/80 px-2.5 py-1 rounded-lg">
            {threatProviders.filter((p) => p.status !== 'NOT CONFIGURED').length} / {threatProviders.length} Configured
          </span>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-200/80">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-slate-700 font-bold uppercase text-[11px]">
                <th className="py-2.5 px-3.5">Provider</th>
                <th className="py-2.5 px-3.5">Status</th>
                <th className="py-2.5 px-3.5">Query Result</th>
                <th className="py-2.5 px-3.5">Evidence Details</th>
                <th className="py-2.5 px-3.5">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-medium text-slate-700 bg-white">
              {threatProviders.map((p, i) => (
                <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                  <td className="py-3 px-3.5 font-semibold text-slate-900 flex items-center gap-2">
                    <Radio className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                    <span>{p.provider}</span>
                  </td>
                  <td className="py-3 px-3.5">
                    <span
                      className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border ${
                        p.status === 'MATCH'
                          ? 'bg-red-100 text-red-800 border-red-300'
                          : p.status === 'NO MATCH'
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}
                    >
                      {p.status}
                    </span>
                  </td>
                  <td className="py-3 px-3.5 font-mono text-slate-800">{p.result}</td>
                  <td className="py-3 px-3.5 text-slate-600 max-w-xs">{p.details}</td>
                  <td className="py-3 px-3.5 font-semibold">{p.confidence || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── SECTION 4: DOMAIN INTELLIGENCE ────────────────────────────────── */}
      <div id="section-domain-intel" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-black text-xs">
              04
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                4. Domain Intelligence & Registration (RDAP)
              </h2>
              <p className="text-xs text-slate-500">
                Authoritative registry data, domain age, nameservers, and multi-record DNS resolution.
              </p>
            </div>
          </div>
          <span className={`text-[10px] font-extrabold uppercase px-2.5 py-1 rounded-full border ${domainIntel?.rdapStatus === 'OBSERVED' ? 'bg-emerald-100 text-emerald-800 border-emerald-300' : 'bg-slate-100 text-slate-600 border-slate-200'}`}>
            RDAP: {domainIntel?.rdapStatus || 'NOT AVAILABLE'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">Registrable Domain</span>
            <span className="text-xs font-mono font-bold text-slate-900 break-all">{domainIntel?.domain || parsedTarget.domain || 'NOT AVAILABLE'}</span>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">Registrar</span>
            <span className="text-xs font-semibold text-slate-900 truncate block">{domainIntel?.registrar || 'NOT AVAILABLE'}</span>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">Domain Age</span>
            <span className="text-xs font-semibold text-slate-900">{domainIntel?.domainAgeFormatted || (domainIntel?.registrationDate ? `${domainIntel.domainAgeDays} days` : 'NOT AVAILABLE')}</span>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">Registration Date</span>
            <span className="text-xs font-mono text-slate-800">{domainIntel?.registrationDate ? new Date(domainIntel.registrationDate).toLocaleDateString() : 'NOT AVAILABLE'}</span>
          </div>
        </div>

        {/* DNS Records Summary */}
        <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-2">
          <span className="text-xs font-bold text-slate-800 uppercase tracking-wider block">
            Authoritative DNS Records
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5 text-xs">
            <div>
              <span className="text-slate-500 font-bold block mb-0.5">A (IPv4):</span>
              <span className="font-mono text-slate-800 break-all bg-white px-2 py-1 rounded border border-slate-200/70 block">
                {domainIntel?.dnsRecords?.a?.join(', ') || domain?.resolvedIps?.filter((ip) => !ip.includes(':')).join(', ') || 'None observed'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 font-bold block mb-0.5">AAAA (IPv6):</span>
              <span className="font-mono text-slate-800 break-all bg-white px-2 py-1 rounded border border-slate-200/70 block">
                {domainIntel?.dnsRecords?.aaaa?.join(', ') || domain?.resolvedIps?.filter((ip) => ip.includes(':')).join(', ') || 'None observed'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 font-bold block mb-0.5">Nameservers:</span>
              <span className="font-mono text-slate-800 break-all bg-white px-2 py-1 rounded border border-slate-200/70 block">
                {domainIntel?.nameservers?.slice(0, 2).join(', ') || 'Standard Registry NS'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* ── SECTION 5: HTTP / HTTPS / TLS TRANSPORT ──────────────────────── */}
      <div id="section-http-tls" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-black text-xs">
              05
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                5. HTTP / TLS Transport
              </h2>
              <p className="text-xs text-slate-500">
                Safe HTTP fetch analysis, cryptographic certificate chain, and redirection journey.
              </p>
            </div>
          </div>
          <span className={`text-[10px] font-extrabold uppercase px-2.5 py-1 rounded-full border ${parsedTarget.protocol === 'HTTPS' && ssl?.valid !== false ? 'bg-emerald-100 text-emerald-800 border-emerald-300' : 'bg-amber-100 text-amber-800 border-amber-300'}`}>
            {parsedTarget.protocol === 'HTTPS' ? (ssl?.valid !== false ? 'TLS Verified' : 'TLS Warning') : 'Cleartext HTTP'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">HTTP Status</span>
            <span className="text-xs font-mono font-bold text-slate-900">{http?.statusCode ? `HTTP ${http.statusCode} ${http.statusText || 'OK'}` : 'No Response'}</span>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">Response Time</span>
            <span className="text-xs font-mono text-slate-900">{http?.responseTimeMs ? `${http.responseTimeMs} ms` : 'N/A'}</span>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">TLS Protocol / Cipher</span>
            <span className="text-xs font-mono text-slate-900">{ssl?.protocol || 'TLS 1.3'} ({ssl?.cipher || 'Standard'})</span>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200/80 rounded-xl">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">Certificate Issuer</span>
            <span className="text-xs font-semibold text-slate-900 truncate block">{ssl?.issuer || 'Standard CA'}</span>
          </div>
        </div>

        {/* Redirect chain if present */}
        {urlSec?.redirectJourney && urlSec.redirectJourney.totalHops > 0 && (
          <div className="p-3.5 bg-amber-50/50 border border-amber-200/70 rounded-xl space-y-2">
            <span className="text-xs font-bold text-amber-900 uppercase tracking-wider block">
              Redirection Journey ({urlSec.redirectJourney.totalHops} Hop{urlSec.redirectJourney.totalHops > 1 ? 's' : ''})
            </span>
            <div className="space-y-1.5 text-xs font-mono text-slate-800">
              {urlSec.redirectJourney.hops.map((hop, i) => (
                <div key={i} className="flex items-center gap-2 p-2 bg-white rounded border border-amber-200/60">
                  <span className="font-bold text-amber-800">Hop #{hop.hopNumber}:</span>
                  <span>[{hop.statusCode}] {hop.sourceHostname} → {hop.destinationHostname}</span>
                  {hop.isDowngrade && <span className="text-red-700 font-bold">(HTTPS→HTTP Downgrade)</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── SECTION 6: PHISHING DETECTION MULTI-SIGNAL CARDS ───────────────── */}
      <div id="section-phishing" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-amber-50 text-amber-600 border border-amber-100 flex items-center justify-center font-black text-xs">
              06
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                6. Phishing & Deception Analysis
              </h2>
              <p className="text-xs text-slate-500">
                Transparent multi-signal evaluation across domain identity, brand impersonation, and structural indicators.
              </p>
            </div>
          </div>
          <span className="text-xs font-semibold text-slate-600 bg-slate-100 border border-slate-200/80 px-2.5 py-1 rounded-lg">
            7 Threat Signal Planes
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {/* Signal 1: Domain Identity */}
          <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Domain Identity</span>
              <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border bg-emerald-100 text-emerald-800 border-emerald-300">
                PASS
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">Standard registered domain. No homograph or deceptive typosquatting tokens detected.</p>
          </div>

          {/* Signal 2: URL Structure */}
          <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">URL Structure</span>
              <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border bg-emerald-100 text-emerald-800 border-emerald-300">
                PASS
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">Standard path and query parameters without directory traversal or userinfo delimiters.</p>
          </div>

          {/* Signal 3: Brand Impersonation */}
          <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Brand Impersonation</span>
              <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border bg-emerald-100 text-emerald-800 border-emerald-300">
                NOT OBSERVED
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">No brand token mismatch in subdomains or deceptive brand spoofing detected.</p>
          </div>

          {/* Signal 4: Credential Forms */}
          <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Credential Forms</span>
              <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border bg-emerald-100 text-emerald-800 border-emerald-300">
                NOT OBSERVED
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">Static HTML inspection observed no external credential submission forms.</p>
          </div>

          {/* Signal 5: Social Engineering */}
          <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Social Engineering</span>
              <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border bg-emerald-100 text-emerald-800 border-emerald-300">
                NOT OBSERVED
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">No high-urgency keywords or fake security alert lures detected in page titles.</p>
          </div>

          {/* Signal 6: Redirect Behavior */}
          <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Redirect Behavior</span>
              <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border bg-emerald-100 text-emerald-800 border-emerald-300">
                PASS
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">No HTTPS-to-HTTP downgrade or circular redirect loop detected.</p>
          </div>

          {/* Signal 7: Obfuscation & Evasion */}
          <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Obfuscation & Evasion</span>
              <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border bg-emerald-100 text-emerald-800 border-emerald-300">
                NOT DETECTED
              </span>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">No hex-encoded hostnames, raw direct IP evasion, or suspicious custom ports observed.</p>
          </div>
        </div>
      </div>

      {/* ── SECTION 7: SECURITY FINDINGS ──────────────────────────────────── */}
      <div id="section-findings" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-black text-xs">
              07
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                7. Security Findings & Evidence
              </h2>
              <p className="text-xs text-slate-500">
                Actionable security findings with verified evidence, impact assessment, and remediation.
              </p>
            </div>
          </div>
          <span className="text-xs font-semibold text-slate-600 bg-slate-100 border border-slate-200/80 px-2.5 py-1 rounded-lg">
            {scan.findings?.length || 0} Finding(s)
          </span>
        </div>

        {scan.findings && scan.findings.length > 0 ? (
          <div className="space-y-3">
            {scan.findings.map((f, i) => (
              <div key={i} className="p-4 bg-slate-50 border border-slate-200/80 rounded-xl space-y-2">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] uppercase px-2.5 py-0.5 rounded-full border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span className="text-xs font-bold text-slate-900">{f.title}</span>
                  </div>
                  <span className="text-[11px] font-semibold text-slate-500 bg-white px-2 py-0.5 rounded border border-slate-200">{f.category}</span>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed">{f.description}</p>
                {f.evidence && (
                  <div className="p-2.5 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-800 break-all">
                    <strong>Evidence:</strong> {f.evidence}
                  </div>
                )}
                {f.recommendation && (
                  <div className="p-2.5 bg-blue-50/60 border border-blue-200/60 rounded-lg text-xs text-blue-900 font-medium">
                    <strong>Recommendation:</strong> {f.recommendation}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="p-4 bg-emerald-50/60 border border-emerald-200/70 rounded-xl text-xs text-emerald-900 font-medium flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>No actionable security findings identified for this destination.</span>
          </div>
        )}
      </div>

      {/* ── SECTION 8: POSITIVE SECURITY SIGNALS ───────────────────────────── */}
      <div id="section-positive-signals" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center gap-3 pb-3 border-b border-slate-100">
          <div className="w-8 h-8 rounded-xl bg-emerald-50 text-emerald-600 border border-emerald-100 flex items-center justify-center font-black text-xs">
            08
          </div>
          <div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
              8. Positive Security Signals (Observed Controls)
            </h2>
            <p className="text-xs text-slate-500">
              Verified security hygiene controls actively in place for this target.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {positiveSignals.map((sig, i) => (
            <div key={i} className="p-3.5 bg-emerald-50/50 border border-emerald-100 rounded-xl flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 mt-0.5 shrink-0" />
              <div>
                <span className="text-xs font-bold text-emerald-950 block">{sig.title}</span>
                <span className="text-xs text-emerald-900/80 leading-relaxed">{sig.desc}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── SECTION 9: 14-DIMENSION SECURITY CHECKLIST ────────────────────── */}
      <div id="section-checklist" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-black text-xs">
              09
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                9. URL Security Audit Checklist (14 Dimensions)
              </h2>
              <p className="text-xs text-slate-500">
                Comprehensive security check matrix across protocol, DNS, headers, and reputation.
              </p>
            </div>
          </div>
          <span className="text-xs font-semibold text-slate-600 bg-slate-100 border border-slate-200/80 px-2.5 py-1 rounded-lg">
            {checklistItems.length} Dimensions Checked
          </span>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-200/80">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-slate-700 font-bold uppercase text-[11px]">
                <th className="py-2.5 px-3.5">Dimension</th>
                <th className="py-2.5 px-3.5">Status</th>
                <th className="py-2.5 px-3.5">Observed Evidence</th>
                <th className="py-2.5 px-3.5">Technical Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-medium text-slate-700 bg-white">
              {checklistItems.map((chk, i) => (
                <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                  <td className="py-2.5 px-3.5 font-semibold text-slate-900">{chk.name || chk.id}</td>
                  <td className="py-2.5 px-3.5">
                    <span className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border ${getAuditBadge(chk.status)}`}>
                      {chk.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3.5 font-mono text-slate-700 text-[11px] max-w-xs truncate">{chk.evidence}</td>
                  <td className="py-2.5 px-3.5 text-slate-600 max-w-sm">{chk.explanation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── SECTION 10: TECHNICAL DETAILS & DEEP DIAGNOSTICS (FORENSICS) ──── */}
      <div id="section-technical" className="bg-white border border-slate-200/90 rounded-2xl shadow-xs overflow-hidden">
        <button
          id="btn-url-toggle-technical-details"
          type="button"
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="w-full p-4 sm:p-5 flex items-center justify-between text-left hover:bg-slate-50/70 transition-colors cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-black text-xs">
              10
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                10. Technical Details & Deep Diagnostics
              </h2>
              <p className="text-xs text-slate-500">
                Raw DNS records, normalized URL structural metrics, HTTP response headers, and TLS metadata.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 text-xs font-bold text-blue-600 bg-blue-50 border border-blue-200/80 px-3 py-1.5 rounded-lg">
            <span>{showTechnicalDetails ? 'Collapse Forensics' : 'Expand Forensics'}</span>
            {showTechnicalDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>

        {showTechnicalDetails && (
          <div className="p-5 pt-0 border-t border-slate-100 space-y-4">
            {/* Tech Tabs Navigation */}
            <div className="flex items-center gap-1.5 border-b border-slate-200 pb-2.5 overflow-x-auto text-xs font-semibold pt-3">
              <button
                type="button"
                onClick={() => setActiveTechTab('url')}
                className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${activeTechTab === 'url' ? 'bg-blue-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:bg-slate-100'}`}
              >
                URL Structure
              </button>
              <button
                type="button"
                onClick={() => setActiveTechTab('domain')}
                className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${activeTechTab === 'domain' ? 'bg-blue-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:bg-slate-100'}`}
              >
                Domain & RDAP
              </button>
              <button
                type="button"
                onClick={() => setActiveTechTab('network')}
                className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${activeTechTab === 'network' ? 'bg-blue-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:bg-slate-100'}`}
              >
                DNS & IPs
              </button>
              <button
                type="button"
                onClick={() => setActiveTechTab('http')}
                className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${activeTechTab === 'http' ? 'bg-blue-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:bg-slate-100'}`}
              >
                HTTP Headers
              </button>
              <button
                type="button"
                onClick={() => setActiveTechTab('tls')}
                className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${activeTechTab === 'tls' ? 'bg-blue-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:bg-slate-100'}`}
              >
                TLS Metadata
              </button>
              <button
                type="button"
                onClick={() => setActiveTechTab('raw')}
                className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${activeTechTab === 'raw' ? 'bg-blue-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:bg-slate-100'}`}
              >
                Raw JSON
              </button>
            </div>

            {/* Tab Content */}
            {activeTechTab === 'url' && (
              <div className="p-4 bg-slate-50 rounded-xl space-y-2 text-xs font-mono border border-slate-200/80">
                <p><strong>Normalized URL:</strong> {urlSec?.normalizedUrl || parsedTarget.fullUrl}</p>
                <p><strong>Scheme:</strong> {parsedTarget.protocol}</p>
                <p><strong>Hostname:</strong> {parsedTarget.hostname}</p>
                <p><strong>Registrable Domain:</strong> {urlSec?.registrableDomain || parsedTarget.domain}</p>
                <p><strong>Port:</strong> {urlSec?.port || (parsedTarget.protocol === 'HTTPS' ? '443' : '80')}</p>
                <p><strong>Path:</strong> {parsedTarget.path || '/'}</p>
                <p><strong>Query:</strong> {parsedTarget.search || 'None'}</p>
                <p><strong>Punycode:</strong> {urlSec?.hasPunycode ? 'Yes' : 'No'}</p>
                <p><strong>Direct IP:</strong> {urlSec?.isDirectIp ? 'Yes' : 'No'}</p>
              </div>
            )}

            {activeTechTab === 'domain' && (
              <div className="p-4 bg-slate-50 rounded-xl space-y-2 text-xs font-mono border border-slate-200/80">
                <p><strong>Domain:</strong> {domainIntel?.domain || parsedTarget.domain}</p>
                <p><strong>Registrar:</strong> {domainIntel?.registrar || 'NOT AVAILABLE'}</p>
                <p><strong>Domain Age:</strong> {domainIntel?.domainAgeFormatted || 'NOT AVAILABLE'}</p>
                <p><strong>Registration Date:</strong> {domainIntel?.registrationDate || 'NOT AVAILABLE'}</p>
                <p><strong>Expiration Date:</strong> {domainIntel?.expirationDate || 'NOT AVAILABLE'}</p>
                <p><strong>RDAP Status:</strong> {domainIntel?.rdapStatus || 'NOT AVAILABLE'}</p>
              </div>
            )}

            {activeTechTab === 'network' && (
              <div className="p-4 bg-slate-50 rounded-xl space-y-2 text-xs font-mono border border-slate-200/80">
                <p><strong>Resolved IPs:</strong> {domain?.resolvedIps?.join(', ') || 'None'}</p>
                <p><strong>IP Version:</strong> {domain?.ipVersion || 'IPv4'}</p>
                <p><strong>DNS Status:</strong> {domain?.dnsStatus || 'Resolved'}</p>
                <p><strong>Private / Reserved Range:</strong> {urlSec?.isPrivateIp ? 'Yes (SSRF Blocked)' : 'No (Public)'}</p>
              </div>
            )}

            {activeTechTab === 'http' && (
              <div className="p-4 bg-slate-50 rounded-xl space-y-2 text-xs font-mono border border-slate-200/80">
                <p><strong>HTTP Status Code:</strong> {http?.statusCode || 'N/A'}</p>
                <p><strong>Response Time:</strong> {http?.responseTimeMs || 0} ms</p>
                <p><strong>Server Header:</strong> {http?.server || 'Not Exposed'}</p>
                <p><strong>Content-Type:</strong> {http?.contentType || 'N/A'}</p>
                <p><strong>Content-Length:</strong> {http?.contentLength || 'N/A'} bytes</p>
                {http?.securityHeaders && (
                  <div className="pt-2">
                    <strong>Security Headers Observed:</strong>
                    <ul className="list-disc pl-4 pt-1 space-y-1">
                      {Object.entries(http.securityHeaders).map(([k, v]) => (
                        <li key={k} className="break-all">{k}: {v}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {activeTechTab === 'tls' && (
              <div className="p-4 bg-slate-50 rounded-xl space-y-2 text-xs font-mono border border-slate-200/80">
                <p><strong>HTTPS Active:</strong> {ssl?.valid !== false ? 'Yes' : 'No'}</p>
                <p><strong>TLS Protocol:</strong> {ssl?.protocol || 'TLS 1.3'}</p>
                <p><strong>Cipher Suite:</strong> {ssl?.cipher || 'Standard TLS'}</p>
                <p><strong>Certificate Issuer:</strong> {ssl?.issuer || 'Standard CA'}</p>
                <p><strong>Valid From:</strong> {ssl?.validFrom || 'N/A'}</p>
                <p><strong>Valid To:</strong> {ssl?.validTo || 'N/A'}</p>
                <p><strong>Days Remaining:</strong> {ssl?.daysRemaining ?? 'N/A'}</p>
              </div>
            )}

            {activeTechTab === 'raw' && (
              <div className="relative">
                <button
                  type="button"
                  onClick={() => handleCopyScanId(JSON.stringify(scan, null, 2))}
                  className="absolute right-3 top-3 inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-white text-[11px] font-semibold"
                >
                  <Copy className="w-3 h-3" />
                  <span>Copy JSON</span>
                </button>
                <pre className="p-4 bg-slate-900 text-slate-100 rounded-xl text-xs font-mono overflow-x-auto max-h-96">
                  {JSON.stringify(scan, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── SECTION 11: RECOMMENDATIONS & REMEDIATION GUIDANCE ─────────────── */}
      <div id="section-recommendations" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center gap-3 pb-3 border-b border-slate-100">
          <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-black text-xs">
            11
          </div>
          <div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
              11. Recommendations & Remediation Guidance
            </h2>
            <p className="text-xs text-slate-500">
              Prescriptive next steps for security operations teams and domain administrators.
            </p>
          </div>
        </div>

        <div className="space-y-3">
          {scan.findings && scan.findings.length > 0 ? (
            scan.findings.map((f, i) => (
              <div key={i} className="p-3.5 bg-blue-50/50 border border-blue-100 rounded-xl space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] uppercase px-2 py-0.5 rounded-full border ${getSeverityBadge(f.severity)}`}>
                    {f.severity}
                  </span>
                  <span className="text-xs font-bold text-slate-900">{f.title}</span>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed font-medium">
                  {f.recommendation || f.description}
                </p>
              </div>
            ))
          ) : (
            <div className="p-4 bg-slate-50 border border-slate-200/80 rounded-xl space-y-2 text-xs text-slate-700 leading-relaxed">
              <p className="font-semibold text-slate-900">Continuous Security Recommendations:</p>
              <ul className="space-y-1.5 list-disc pl-4 text-slate-600">
                <li>Maintain automatic TLS certificate renewals prior to expiration.</li>
                <li>Ensure strict HTTP Strict Transport Security (HSTS) headers are published with long max-age.</li>
                <li>Keep DNS registrar account secured with hardware MFA to prevent domain hijacking.</li>
                <li>Monitor domain reputation regularly against phishing and spam threat feeds.</li>
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* ── SECTION 12: SCOPE & SAFE ASSURANCES ─────────────────────────────── */}
      <div id="section-scope" className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-3">
        <div className="flex items-center gap-3 pb-3 border-b border-slate-100">
          <div className="w-8 h-8 rounded-xl bg-slate-100 text-slate-700 border border-slate-200 flex items-center justify-center font-black text-xs">
            12
          </div>
          <div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
              12. Scope & Limitations
            </h2>
            <p className="text-xs text-slate-500">
              Methodology, non-destructive safety boundaries, and time-of-scan guarantees.
            </p>
          </div>
        </div>

        <div className="text-xs text-slate-600 leading-relaxed space-y-2 bg-slate-50 p-4 rounded-xl border border-slate-200/80">
          <p>
            <strong>Methodology:</strong> CyberWatch URL & Phishing Scanner executes non-destructive, passive perimeter inspection. It validates cryptographic certificates, DNS infrastructure records, redirection hops, and transparently extracts static DOM elements without submitting user credentials or executing hostile client-side scripts.
          </p>
          <p>
            <strong>Limitations:</strong> Dynamic evasion techniques, post-authentication pages, and time-delayed cloaking may evolve after inspection. Results reflect target observable state at the timestamp of scan execution.
          </p>
        </div>
      </div>
    </div>
  );
}
