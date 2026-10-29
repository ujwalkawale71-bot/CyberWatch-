import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Globe,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Info,
  Cookie as CookieIcon,
  FileText,
  Compass,
  Terminal,
  Cpu,
  Check,
  Copy,
  Lock,
  Radio,
  ExternalLink,
  Download,
  RotateCw,
  PlusCircle,
  Layers,
  AlertCircle,
  HelpCircle,
  Sliders,
  CheckSquare,
  XSquare,
} from 'lucide-react';
import type { ScanRecord, FindingSeverity } from '../../types';
import type { ParsedTargetUrl } from '../../utils/urlParser';

interface WebsiteScanResultV2ViewProps {
  scan: ScanRecord;
  parsedTarget: ParsedTargetUrl;
  onRescan?: () => void | Promise<void>;
  isRescanning?: boolean;
  onNewScan?: () => void | Promise<void>;
  onDownloadReport?: () => void | Promise<void>;
  isGeneratingPdf?: boolean;
  pdfError?: string | null;
  onCopy?: (text: string) => void;
  copied?: boolean;
}

export function WebsiteScanResultV2View({
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
}: WebsiteScanResultV2ViewProps) {
  const [activeTab, setActiveTab] = useState<'all' | 'findings' | 'hardening' | 'info'>('all');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [expandedAccordions, setExpandedAccordions] = useState<Record<string, boolean>>({
    'tls-section': true,
    'headers-section': true,
  });
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [copiedEvidence, setCopiedEvidence] = useState<string | null>(null);

  const v2 = scan.checks?.websiteSecurityV2;
  const overview = scan.checks?.websiteOverview;
  const headersAnalysis = scan.checks?.securityHeadersAnalysis;
  const cookiesAnalysis = scan.checks?.cookiesAnalysis;
  const contentAnalysis = scan.checks?.contentAnalysis;
  const sslAnalysis = scan.checks?.sslAnalysis;
  const httpAnalysis = scan.checks?.httpAnalysis;
  const domainAnalysis = scan.checks?.domainAnalysis;
  const redirectAnalysis = scan.checks?.redirectAnalysis;

  // Derive findings lists
  const allFindings = scan.findings || [];
  const confirmedVulnerabilities = allFindings.filter((f) => {
    const sev = String(f.severity || '').toUpperCase();
    return f.findingCategory === 'CONFIRMED_VULNERABILITY' || sev === 'CRITICAL';
  });
  const securityWeaknesses = allFindings.filter((f) => {
    const sev = String(f.severity || '').toUpperCase();
    return f.findingCategory === 'SECURITY_WEAKNESS' || ((sev === 'HIGH' || sev === 'MEDIUM') && f.findingCategory !== 'CONFIRMED_VULNERABILITY');
  });
  const hardeningRecommendations = allFindings.filter((f) => {
    const sev = String(f.severity || '').toUpperCase();
    return f.findingCategory === 'HARDENING_RECOMMENDATION' || (sev === 'LOW' && f.findingCategory !== 'INFORMATIONAL');
  });
  const informationalFindings = allFindings.filter((f) => {
    const sev = String(f.severity || '').toUpperCase();
    return f.findingCategory === 'INFORMATIONAL' || sev === 'INFO';
  });

  const riskScore = v2?.riskScore ?? scan.riskScore ?? 0;
  const riskLevel = v2?.riskLevel ?? (riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MODERATE' : riskScore >= 12 ? 'LOW' : 'SAFE');
  const confidencePercent = Math.round((v2?.confidence ?? 0.95) * 100);

  const executionOutcome = v2?.executionOutcome || 'COMPLETED';

  // Score Contributors Breakdown
  const scoreExplanation = v2?.scoreExplanation;
  const scoreContributors = scoreExplanation?.contributors || [];

  // Cookie Table
  const cookieTable = v2?.cookieSecuritySummary?.table || cookiesAnalysis?.cookies.map((c) => ({
    name: c.name,
    domain: c.domain,
    path: c.path,
    secure: c.secure,
    httpOnly: c.httpOnly,
    sameSite: c.sameSite,
    expires: c.expires,
    isPotentiallySensitive: /(session|auth|token|jwt|sid|login|id|user|account)/i.test(c.name),
    assessment: c.isFlagged ? `Flagged: ${(c.issues || []).join(', ')}` : 'Secure baseline attributes configured.',
  })) || [];

  // Technology Detections
  const techList = v2?.technologyDetections || [];

  // Audit Checks Matrix
  const auditChecks = v2?.auditChecks || [];

  // Positive Controls
  const positiveControls = v2?.positiveControls && v2.positiveControls.length > 0
    ? v2.positiveControls
    : [
        ...(parsedTarget.protocol === 'HTTPS' && sslAnalysis?.valid !== false
          ? [{ title: 'Active Transport Encryption (HTTPS)', desc: `Encrypted TLS communication enforced via ${sslAnalysis?.protocol || 'TLS'}.` }]
          : []),
        ...(contentAnalysis?.mixedContentCount === 0
          ? [{ title: 'No Mixed Content Detected', desc: 'All scripts, stylesheets, and images load securely over HTTPS.' }]
          : []),
        ...(headersAnalysis?.headers.some((h) => h.status === 'present')
          ? [{ title: 'Defensive Headers Present', desc: `${headersAnalysis.presentCount} browser security header(s) configured.` }]
          : []),
        ...(cookiesAnalysis && cookiesAnalysis.flaggedCookies === 0 && cookiesAnalysis.totalCookies > 0
          ? [{ title: 'Secure Cookie Flags Maintained', desc: 'Cookies enforce Secure and HttpOnly flags.' }]
          : []),
      ];

  // Prioritized Recommendations
  const prioritizedFindings = [...allFindings].sort((a, b) => {
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return (order[String(a.severity).toUpperCase()] ?? 5) - (order[String(b.severity).toUpperCase()] ?? 5);
  });

  function toggleFinding(id: string) {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  function toggleAccordion(id: string) {
    setExpandedAccordions((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  function handleCopyText(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopiedEvidence(id);
    setTimeout(() => setCopiedEvidence(null), 2000);
  }

  function getRiskLevelConfig(level: string) {
    switch (String(level).toUpperCase()) {
      case 'SAFE':
        return {
          label: 'SAFE / MINIMAL RISK',
          badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-300',
          containerBg: 'bg-emerald-500/10',
          borderClass: 'border-emerald-200',
          textClass: 'text-emerald-700',
          meterClass: 'bg-emerald-500',
          Icon: ShieldCheck,
          summary: 'The website demonstrates a solid defensive posture with active transport encryption, standard headers, and no confirmed exploitable vulnerabilities.',
        };
      case 'LOW':
        return {
          label: 'LOW RISK',
          badgeClass: 'bg-blue-100 text-blue-800 border-blue-300',
          containerBg: 'bg-blue-500/10',
          borderClass: 'border-blue-200',
          textClass: 'text-blue-700',
          meterClass: 'bg-blue-500',
          Icon: ShieldCheck,
          summary: 'Standard website configuration observed with minor hardening opportunities. No high-severity vulnerabilities were established by this scan.',
        };
      case 'MODERATE':
      case 'MEDIUM':
        return {
          label: 'MODERATE RISK',
          badgeClass: 'bg-amber-100 text-amber-800 border-amber-300',
          containerBg: 'bg-amber-500/10',
          borderClass: 'border-amber-200',
          textClass: 'text-amber-700',
          meterClass: 'bg-amber-500',
          Icon: AlertTriangle,
          summary: 'Security weaknesses or missing defense-in-depth headers were observed. Remediation is recommended to reach optimal defensive posture.',
        };
      case 'HIGH':
        return {
          label: 'HIGH RISK',
          badgeClass: 'bg-orange-100 text-orange-800 border-orange-300',
          containerBg: 'bg-orange-500/10',
          borderClass: 'border-orange-200',
          textClass: 'text-orange-700',
          meterClass: 'bg-orange-500',
          Icon: ShieldAlert,
          summary: 'Significant security weaknesses detected (such as unencrypted HTTP transport, invalid certificate, or technical data leaks). Prompt remediation advised.',
        };
      case 'CRITICAL':
        return {
          label: 'CRITICAL RISK',
          badgeClass: 'bg-red-100 text-red-800 border-red-300',
          containerBg: 'bg-red-500/10',
          borderClass: 'border-red-200',
          textClass: 'text-red-700',
          meterClass: 'bg-red-500',
          Icon: ShieldAlert,
          summary: 'High-severity confirmed security risk detected (such as internal SSRF boundary violation or severe transport failure). Immediate remediation required.',
        };
      default:
        return {
          label: 'ASSESSMENT COMPLETE',
          badgeClass: 'bg-slate-100 text-slate-800 border-slate-300',
          containerBg: 'bg-slate-500/10',
          borderClass: 'border-slate-200',
          textClass: 'text-slate-700',
          meterClass: 'bg-slate-500',
          Icon: ShieldCheck,
          summary: 'Website security assessment complete.',
        };
    }
  }

  const riskConfig = getRiskLevelConfig(riskLevel);
  const RiskIcon = riskConfig.Icon;

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

  function getOutcomeBadge(outcome: string) {
    switch (outcome) {
      case 'COMPLETED':
        return { label: 'Scan Completed', class: 'bg-emerald-100 text-emerald-800 border-emerald-300' };
      case 'PARTIAL':
        return { label: 'Partial Scan', class: 'bg-amber-100 text-amber-800 border-amber-300' };
      case 'TIMEOUT':
        return { label: 'Scan Timed Out', class: 'bg-orange-100 text-orange-800 border-orange-300' };
      case 'DNS_FAILURE':
        return { label: 'DNS Resolution Failed', class: 'bg-red-100 text-red-800 border-red-300' };
      case 'BLOCKED_BY_SSRF_POLICY':
        return { label: 'Blocked by SSRF Policy', class: 'bg-red-100 text-red-800 border-red-300' };
      case 'TARGET_UNREACHABLE':
        return { label: 'Target Unreachable', class: 'bg-orange-100 text-orange-800 border-orange-300' };
      case 'FAILED':
      default:
        return { label: 'Scan Incomplete / Failed', class: 'bg-slate-100 text-slate-800 border-slate-300' };
    }
  }

  const outcomeBadge = getOutcomeBadge(executionOutcome);

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* ── 1. SCAN HEADER ─────────────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-extrabold uppercase tracking-wider text-indigo-600">
                Website Security Analysis
              </span>
              <span className="text-slate-300">•</span>
              <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${outcomeBadge.class}`}>
                {outcomeBadge.label}
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-xs font-semibold text-slate-500">
                Scan ID: <strong className="font-mono text-slate-700">{scan.id || 'live-scan'}</strong>
              </span>
            </div>

            <div className="flex items-center gap-2 pt-1">
              <Globe className="w-5 h-5 text-slate-500 shrink-0" />
              <span className="font-mono text-base sm:text-lg font-bold text-slate-900 truncate">
                {scan.target}
              </span>
              {onCopy && (
                <button
                  type="button"
                  onClick={() => onCopy(scan.target)}
                  aria-label="Copy target URL"
                  className="text-slate-400 hover:text-slate-700 p-1 rounded-md transition-colors"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                </button>
              )}
            </div>

            <p className="text-xs text-slate-500">
              Scanned on: {scan.scannedAt ? new Date(scan.scannedAt).toUTCString() : new Date().toUTCString()}
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2.5 flex-wrap shrink-0">
            {onDownloadReport && (
              <button
                type="button"
                id="website-download-pdf-btn"
                onClick={onDownloadReport}
                disabled={isGeneratingPdf}
                className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 active:bg-slate-950 text-white text-xs font-bold rounded-xl transition-all shadow-2xs disabled:opacity-60"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isGeneratingPdf ? 'Generating PDF...' : 'Download PDF Report'}</span>
              </button>
            )}

            {onRescan && (
              <button
                type="button"
                id="website-rescan-btn"
                onClick={onRescan}
                disabled={isRescanning}
                className="inline-flex items-center gap-2 px-4 py-2.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-xl border border-indigo-200/80 transition-all shadow-2xs disabled:opacity-60"
              >
                <RotateCw className={`w-3.5 h-3.5 ${isRescanning ? 'animate-spin' : ''}`} />
                <span>{isRescanning ? 'Rescanning...' : 'Rescan Target'}</span>
              </button>
            )}

            <Link
              to={`/threat-intelligence?q=${encodeURIComponent(v2?.websiteUnderstanding?.canonicalUrl || scan.target)}`}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-xl border border-indigo-200/80 transition-all shadow-2xs"
              title="Investigate target in Threat Intelligence"
            >
              <Radio className="w-3.5 h-3.5 text-indigo-600" />
              <span>Threat Intelligence</span>
            </Link>

            {onNewScan && (
              <button
                type="button"
                id="website-new-scan-btn"
                onClick={onNewScan}
                className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-xl transition-all shadow-2xs"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>New Scan</span>
              </button>
            )}
          </div>
        </div>

        {pdfError && (
          <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded-xl px-3.5 py-2 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
            <span>PDF Error: {pdfError}</span>
          </div>
        )}
      </div>

      {/* ── 2. OVERALL SECURITY RESULT (HERO RESULT & SCORE METER) ──────────── */}
      <div className={`bg-white border-2 ${riskConfig.borderClass} rounded-2xl p-6 sm:p-8 shadow-xs space-y-6 relative overflow-hidden`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-100">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-extrabold uppercase tracking-wider text-indigo-600">
                Evidence-Based Risk Score
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-xs font-semibold text-slate-500">
                Determined strictly by observed findings
              </span>
            </div>

            <div className="flex items-center gap-3.5">
              <div className={`w-14 h-14 rounded-2xl ${riskConfig.containerBg} flex items-center justify-center shrink-0`}>
                <RiskIcon className={`w-7 h-7 ${riskConfig.textClass}`} />
              </div>
              <div>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <h2 className="text-2xl sm:text-3xl font-black text-slate-900 tracking-tight">
                    {riskConfig.label}
                  </h2>
                  <span className={`text-xs font-extrabold px-3 py-1 rounded-full border ${riskConfig.badgeClass}`}>
                    Level: {riskLevel}
                  </span>
                </div>
                <p className="text-xs text-slate-500 font-medium mt-0.5">
                  Assessment Confidence: <strong className="text-slate-700">{confidencePercent}%</strong> (Deterministic Network & Transport Evidence)
                </p>
              </div>
            </div>
          </div>

          {/* Risk Score Display Box */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200/80 min-w-[220px] text-center space-y-1.5 shadow-2xs">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                Total Risk Score
              </span>
              <div className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
                {riskScore} <span className="text-base text-slate-400 font-semibold">/ 100</span>
              </div>
              <span className="text-[11px] font-bold text-slate-600 block">
                {riskScore <= 14 ? 'Safe / Minimal Threat' : riskScore <= 34 ? 'Low Threat' : riskScore <= 59 ? 'Moderate Threat' : riskScore <= 74 ? 'High Threat' : 'Critical Threat'}
              </span>
            </div>
          </div>
        </div>

        {/* Visual Risk Meter */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-bold text-slate-600">
            <span>Risk Level Distribution</span>
            <span>Current: {riskScore}/100 ({riskLevel})</span>
          </div>
          <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden flex relative">
            <div className={`h-full ${riskConfig.meterClass} transition-all duration-500`} style={{ width: `${Math.min(Math.max(riskScore, 2), 100)}%` }} />
          </div>
          <div className="flex items-center justify-between text-[10px] font-semibold text-slate-400 pt-0.5">
            <span>0 (Safe)</span>
            <span>15 (Low)</span>
            <span>35 (Moderate)</span>
            <span>60 (High)</span>
            <span>75 (Critical)</span>
            <span>100</span>
          </div>
        </div>

        {/* Educational Disclaimer */}
        <div className="text-xs text-slate-600 leading-relaxed bg-slate-50/70 rounded-xl p-4 border border-slate-200/70 space-y-1">
          <strong className="text-slate-800">What does this score mean?</strong>
          <p>
            CyberWatch calculates this score from security indicators observed during this scan. A lower score indicates fewer or less severe risk indicators. The score does not guarantee that a website is completely safe.
          </p>
        </div>
      </div>

      {/* ── 3. "WHY THIS SCORE?" (SCORE CONTRIBUTORS BREAKDOWN) ─────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600 shrink-0">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-slate-900 tracking-tight">
                Why This Score?
              </h3>
              <p className="text-xs text-slate-500">
                Transparent, explainable breakdown of exact security findings and their risk contributions.
              </p>
            </div>
          </div>

          {scoreExplanation && (
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-500">Raw Risk Sum: <strong className="text-slate-800">+{scoreExplanation.rawScore}</strong></span>
              <span className="text-slate-300">•</span>
              <span className="text-slate-500">Normalized Score: <strong className="text-indigo-600">{scoreExplanation.normalizedScore}/100</strong></span>
            </div>
          )}
        </div>

        {scoreContributors.length > 0 ? (
          <div className="space-y-3">
            {scoreContributors.map((contributor, idx) => (
              <div
                key={contributor.findingId || idx}
                className="p-4 bg-slate-50/90 border border-slate-200/80 rounded-xl space-y-2 hover:border-slate-300 transition-colors"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-full border ${getSeverityBadge(contributor.severity)}`}>
                        {contributor.severity}
                      </span>
                      <span className="text-xs font-bold text-slate-900">
                        {contributor.title}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed font-mono">
                      {contributor.evidence}
                    </p>
                  </div>

                  <div className="px-3 py-1 bg-white border border-slate-200 rounded-lg text-center shrink-0 shadow-2xs">
                    <span className="text-[10px] font-bold text-slate-500 uppercase block">Risk</span>
                    <span className="text-sm font-black text-indigo-600">+{contributor.contribution}</span>
                  </div>
                </div>

                {(contributor.reason || contributor.remediation) && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 border-t border-slate-200/60 text-[11px]">
                    {contributor.reason && (
                      <div className="text-slate-600">
                        <strong className="text-slate-800">Reason:</strong> {contributor.reason}
                      </div>
                    )}
                    {contributor.remediation && (
                      <div className="text-slate-600">
                        <strong className="text-indigo-700">Remediation:</strong> {contributor.remediation}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="p-6 text-center bg-emerald-50/50 border border-emerald-200 rounded-xl space-y-1.5">
            <CheckCircle2 className="w-7 h-7 text-emerald-600 mx-auto" />
            <h4 className="text-sm font-bold text-emerald-900">
              0 / 100 Risk Points
            </h4>
            <p className="text-xs text-emerald-700 max-w-lg mx-auto">
              No risk contributions were identified from the checks completed during this scan. Low risk does not guarantee that the website is completely safe.
            </p>
          </div>
        )}
      </div>

      {/* ── 4. QUICK SECURITY OVERVIEW GRID ─────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
        <div className="flex items-center gap-2.5 pb-3 border-b border-slate-100">
          <div className="w-9 h-9 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600 shrink-0">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-slate-900 tracking-tight">
              Quick Security Overview
            </h3>
            <p className="text-xs text-slate-500">
              High-level status of the primary security defense layers evaluated by the passive scanner.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 pt-1">
          {/* HTTPS / TLS */}
          <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">HTTPS / TLS</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${parsedTarget.protocol === 'HTTPS' && sslAnalysis?.valid !== false ? 'bg-emerald-100 text-emerald-800 border-emerald-200' : 'bg-red-100 text-red-800 border-red-200'}`}>
                {parsedTarget.protocol === 'HTTPS' && sslAnalysis?.valid !== false ? 'Secure' : 'Needs Attention'}
              </span>
            </div>
            <p className="text-xs font-semibold text-slate-900">
              {parsedTarget.protocol === 'HTTPS' ? `${sslAnalysis?.protocol || 'TLS 1.2+'} (Active Certificate)` : 'Plaintext HTTP in Use'}
            </p>
          </div>

          {/* Security Headers */}
          <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Security Headers</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${headersAnalysis?.presentCount && headersAnalysis.presentCount >= 4 ? 'bg-emerald-100 text-emerald-800 border-emerald-200' : 'bg-amber-100 text-amber-800 border-amber-200'}`}>
                {headersAnalysis?.presentCount && headersAnalysis.presentCount >= 4 ? 'Configured' : 'Needs Attention'}
              </span>
            </div>
            <p className="text-xs font-semibold text-slate-900">
              {headersAnalysis?.presentCount ?? 0} of {headersAnalysis?.totalChecked ?? 8} standard defensive headers
            </p>
          </div>

          {/* Cookies */}
          <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Cookies</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${cookiesAnalysis?.flaggedCookies === 0 ? 'bg-emerald-100 text-emerald-800 border-emerald-200' : cookiesAnalysis?.flaggedCookies ? 'bg-amber-100 text-amber-800 border-amber-200' : 'bg-slate-100 text-slate-700 border-slate-200'}`}>
                {cookiesAnalysis?.flaggedCookies === 0 ? 'Secure' : cookiesAnalysis?.flaggedCookies ? `${cookiesAnalysis.flaggedCookies} Flagged` : 'No Cookies'}
              </span>
            </div>
            <p className="text-xs font-semibold text-slate-900">
              {cookiesAnalysis?.totalCookies ? `${cookiesAnalysis.totalCookies} cookie(s) evaluated` : 'No response cookies set'}
            </p>
          </div>

          {/* Redirects */}
          <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Redirects</span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border bg-emerald-100 text-emerald-800 border-emerald-200">
                {(redirectAnalysis?.redirectCount ?? redirectAnalysis?.chain?.length ?? 0) === 0 ? 'Direct (0 Hops)' : 'Normal'}
              </span>
            </div>
            <p className="text-xs font-semibold text-slate-900">
              {redirectAnalysis?.redirectCount ?? redirectAnalysis?.chain?.length ?? 0} redirect hop(s) observed
            </p>
          </div>

          {/* Page Structure & Forms */}
          <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Page Structure & Forms</span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border bg-blue-100 text-blue-800 border-blue-200">
                {v2?.formsAnalysis?.totalForms ?? contentAnalysis?.formsCount ?? 0} Form(s)
              </span>
            </div>
            <p className="text-xs font-semibold text-slate-900">
              {contentAnalysis?.mixedContentCount === 0 ? '0 mixed-content resources' : `${contentAnalysis?.mixedContentCount} mixed HTTP resource(s)`}
            </p>
          </div>

          {/* Threat Intelligence */}
          <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Threat Intelligence</span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border bg-slate-100 text-slate-700 border-slate-300">
                Not Configured
              </span>
            </div>
            <p className="text-xs text-slate-600">
              External threat intelligence was not queried.
            </p>
          </div>
        </div>
      </div>

      {/* ── 5. WHAT WE FOUND / CATEGORIZED SECURITY FINDINGS (TABS) ─────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
          <div>
            <h3 className="text-lg font-bold text-slate-900 tracking-tight">
              What We Found
            </h3>
            <p className="text-xs text-slate-500">
              Security findings, weaknesses, and hardening recommendations sorted by severity.
            </p>
          </div>

          {/* Filter Tabs */}
          <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-xl flex-wrap">
            <button
              type="button"
              onClick={() => setActiveTab('all')}
              className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all ${activeTab === 'all' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'}`}
            >
              All ({allFindings.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('findings')}
              className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all ${activeTab === 'findings' ? 'bg-white text-red-700 shadow-2xs' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Vulnerabilities & Weaknesses ({confirmedVulnerabilities.length + securityWeaknesses.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('hardening')}
              className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all ${activeTab === 'hardening' ? 'bg-white text-indigo-700 shadow-2xs' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Hardening ({hardeningRecommendations.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('info')}
              className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all ${activeTab === 'info' ? 'bg-white text-slate-800 shadow-2xs' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Informational ({informationalFindings.length})
            </button>
          </div>
        </div>

        {/* Findings List */}
        {(() => {
          let displayedFindings = allFindings;
          if (activeTab === 'findings') {
            displayedFindings = [...confirmedVulnerabilities, ...securityWeaknesses];
          } else if (activeTab === 'hardening') {
            displayedFindings = hardeningRecommendations;
          } else if (activeTab === 'info') {
            displayedFindings = informationalFindings;
          }

          if (displayedFindings.length === 0) {
            return (
              <div className="p-8 text-center bg-emerald-50/50 border border-emerald-200 rounded-2xl space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-600 mx-auto" />
                <h4 className="text-sm font-bold text-emerald-900">
                  No Findings in this Category
                </h4>
                <p className="text-xs text-emerald-700 max-w-md mx-auto">
                  The passive scanner established that the target demonstrates adherence to defensive standards for these checks.
                </p>
              </div>
            );
          }

          return (
            <div className="space-y-4">
              {displayedFindings.map((finding, idx) => {
                const fId = finding.id || `finding-${idx}`;
                const isExpanded = expandedFindings[fId] ?? true;

                return (
                  <div
                    key={fId}
                    className="border border-slate-200/90 rounded-xl overflow-hidden bg-slate-50/40 transition-all hover:border-slate-300"
                  >
                    <div
                      onClick={() => toggleFinding(fId)}
                      className="p-4 sm:p-5 flex items-start justify-between gap-4 cursor-pointer hover:bg-slate-50/80 transition-colors"
                    >
                      <div className="space-y-1.5 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`text-[10px] font-black uppercase px-2.5 py-0.5 rounded-full border ${getSeverityBadge(finding.severity)}`}>
                            {finding.severity}
                          </span>

                          <span className="text-[11px] font-bold text-slate-500">
                            {finding.findingCategory || finding.category}
                          </span>

                          {finding.confidence !== undefined && (
                            <span className="text-[10px] text-slate-400 font-mono">
                              Confidence: {Math.round(finding.confidence * 100)}%
                            </span>
                          )}
                        </div>

                        <h4 className="text-sm sm:text-base font-bold text-slate-900">
                          {finding.title}
                        </h4>
                        <p className="text-xs text-slate-600 leading-relaxed">
                          {finding.description}
                        </p>
                      </div>

                      <button
                        type="button"
                        aria-label="Toggle finding details"
                        className="text-slate-400 hover:text-slate-600 p-1 mt-1 shrink-0"
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>

                    {isExpanded && (
                      <div className="p-4 sm:p-5 bg-white border-t border-slate-200/80 space-y-3.5 text-xs">
                        {/* Evidence Block */}
                        {((finding.evidences && finding.evidences.length > 0) || finding.evidence) && (
                          <div className="p-3.5 bg-slate-900 text-slate-100 rounded-xl font-mono text-[11px] space-y-1.5">
                            <div className="flex items-center justify-between text-slate-400 border-b border-slate-800 pb-1">
                              <span className="flex items-center gap-1.5 font-bold">
                                <Terminal className="w-3.5 h-3.5 text-indigo-400" />
                                Collected Technical Evidence
                              </span>
                              <button
                                type="button"
                                onClick={() => handleCopyText(finding.evidence || JSON.stringify(finding.evidences), fId)}
                                className="text-xs hover:text-white flex items-center gap-1"
                              >
                                {copiedEvidence === fId ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                <span>{copiedEvidence === fId ? 'Copied' : 'Copy'}</span>
                              </button>
                            </div>
                            {finding.evidences && finding.evidences.length > 0 ? (
                              finding.evidences.map((ev, eIdx) => (
                                <div key={eIdx} className="space-y-0.5">
                                  <div><span className="text-indigo-300">source:</span> {ev.source} | <span className="text-indigo-300">check:</span> {ev.check}</div>
                                  <div><span className="text-emerald-300">observed:</span> {ev.observed}</div>
                                  {ev.expected && <div><span className="text-amber-300">expected:</span> {ev.expected}</div>}
                                </div>
                              ))
                            ) : (
                              <div className="break-all">{finding.evidence}</div>
                            )}
                          </div>
                        )}

                        {/* Impact & Remediation */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                          {finding.impact && (
                            <div className="p-3 bg-red-50/50 border border-red-100 rounded-xl space-y-1">
                              <span className="font-bold text-red-900 block text-[11px] uppercase tracking-wider">
                                Potential Security Impact
                              </span>
                              <p className="text-slate-700 leading-relaxed text-[11px]">
                                {finding.impact}
                              </p>
                            </div>
                          )}

                          {finding.recommendation && (
                            <div className="p-3 bg-indigo-50/50 border border-indigo-100 rounded-xl space-y-1">
                              <span className="font-bold text-indigo-950 block text-[11px] uppercase tracking-wider">
                                Recommended Remediation
                              </span>
                              <p className="text-slate-700 leading-relaxed text-[11px]">
                                {finding.recommendation}
                              </p>
                            </div>
                          )}
                        </div>

                        {finding.affectedComponent && (
                          <div className="text-[11px] text-slate-500">
                            Affected Component: <span className="font-mono text-slate-700 font-semibold">{finding.affectedComponent}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          );
        })()}
      </div>

      {/* ── 6. DETAILED SECURITY ANALYSIS (9 ACCORDIONS) ────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
        <div className="pb-3 border-b border-slate-100">
          <h3 className="text-lg font-bold text-slate-900 tracking-tight">
            Detailed Security Analysis
          </h3>
          <p className="text-xs text-slate-500">
            In-depth evaluation of TLS, security headers, cookies, redirects, DOM structure, forms, external assets, and technologies.
          </p>
        </div>

        {/* 1. HTTPS & TLS */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('tls-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <Lock className="w-4 h-4 text-indigo-600" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">1. HTTPS & Transport Security</span>
            </div>
            {expandedAccordions['tls-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['tls-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-3 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                <div className="p-3 bg-slate-50 rounded-lg">
                  <span className="text-[10px] text-slate-500 font-bold uppercase block">Protocol Version</span>
                  <span className="font-mono font-bold text-slate-800">{sslAnalysis?.protocol || 'TLS 1.2+'}</span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg">
                  <span className="text-[10px] text-slate-500 font-bold uppercase block">Certificate Validity</span>
                  <span className={`font-bold ${sslAnalysis?.valid !== false ? 'text-emerald-700' : 'text-red-700'}`}>
                    {sslAnalysis?.valid !== false ? 'Valid & Trusted' : 'Invalid / Untrusted'}
                  </span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg">
                  <span className="text-[10px] text-slate-500 font-bold uppercase block">Issuer</span>
                  <span className="font-mono text-slate-800 break-words">{sslAnalysis?.issuer || 'Standard CA'}</span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg sm:col-span-2">
                  <span className="text-[10px] text-slate-500 font-bold uppercase block">Subject / Common Name</span>
                  <span className="font-mono text-slate-800 break-words">{sslAnalysis?.subject || parsedTarget.hostname}</span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg">
                  <span className="text-[10px] text-slate-500 font-bold uppercase block">Days Remaining</span>
                  <span className="font-bold text-slate-800">{sslAnalysis?.daysRemaining !== undefined ? `${sslAnalysis.daysRemaining} days` : 'Active'}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* 2. Security Headers */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('headers-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <ShieldCheck className="w-4 h-4 text-indigo-600" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">2. Security Headers Audit</span>
            </div>
            {expandedAccordions['headers-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['headers-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-3 text-xs overflow-x-auto">
              {headersAnalysis?.headers && headersAnalysis.headers.length > 0 ? (
                <table className="w-full text-left">
                  <thead className="bg-slate-50 text-slate-600 font-bold border-b border-slate-200 text-[11px]">
                    <tr>
                      <th className="p-2.5">Header Name</th>
                      <th className="p-2.5">Status</th>
                      <th className="p-2.5">Observed Value / Recommendation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {headersAnalysis.headers.map((h, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/50">
                        <td className="p-2.5 font-mono font-bold text-slate-900">{h.name}</td>
                        <td className="p-2.5">
                          <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${h.status === 'present' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}`}>
                            {h.status === 'present' ? 'PRESENT' : 'MISSING'}
                          </span>
                        </td>
                        <td className="p-2.5 text-slate-600 font-mono text-[11px] break-all">
                          {h.value || h.recommendation || 'Header not set'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-slate-500">Security headers data unavailable.</p>
              )}
            </div>
          )}
        </div>

        {/* 3. Cookies */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('cookies-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <CookieIcon className="w-4 h-4 text-amber-600" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">3. Cookie Security Audit</span>
            </div>
            {expandedAccordions['cookies-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['cookies-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-3 text-xs overflow-x-auto">
              {cookieTable.length > 0 ? (
                <table className="w-full text-left">
                  <thead className="bg-slate-50 text-slate-600 font-bold border-b border-slate-200 text-[11px]">
                    <tr>
                      <th className="p-2.5">Cookie Name</th>
                      <th className="p-2.5">Secure</th>
                      <th className="p-2.5">HttpOnly</th>
                      <th className="p-2.5">SameSite</th>
                      <th className="p-2.5">Assessment</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {cookieTable.map((c, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/50">
                        <td className="p-2.5 font-mono font-bold text-slate-900">{c.name}</td>
                        <td className="p-2.5">
                          <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${c.secure ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'}`}>
                            {c.secure ? 'YES' : 'NO'}
                          </span>
                        </td>
                        <td className="p-2.5">
                          <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${c.httpOnly ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}`}>
                            {c.httpOnly ? 'YES' : 'NO'}
                          </span>
                        </td>
                        <td className="p-2.5 font-mono text-slate-600">{c.sameSite || 'None'}</td>
                        <td className="p-2.5 text-slate-700">{c.assessment}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-slate-500">No cookies were observed in the initial HTTP response.</p>
              )}
            </div>
          )}
        </div>

        {/* 4. Redirects */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('redirects-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <Radio className="w-4 h-4 text-indigo-600" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">4. Redirects & Navigation</span>
            </div>
            {expandedAccordions['redirects-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['redirects-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-2 text-xs">
              <p className="text-slate-600 font-medium">
                Total Redirect Hops: <strong>{redirectAnalysis?.redirectCount ?? redirectAnalysis?.chain?.length ?? 0}</strong>
              </p>
              {redirectAnalysis?.chain && redirectAnalysis.chain.length > 0 ? (
                <div className="space-y-1.5 pt-1">
                  {redirectAnalysis.chain.map((hop: any, idx: number) => (
                    <div key={idx} className="p-2.5 bg-slate-50 rounded-lg font-mono text-[11px] flex items-center justify-between">
                      <span className="text-slate-800 truncate">{hop.url || hop}</span>
                      <span className="text-indigo-600 font-bold shrink-0">{hop.statusCode || '30x'}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">Direct connection. Target did not perform external redirects.</p>
              )}
            </div>
          )}
        </div>

        {/* 5. Page Structure & HTML */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('html-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <Compass className="w-4 h-4 text-indigo-600" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">5. Page Structure & Metadata</span>
            </div>
            {expandedAccordions['html-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['html-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-3 text-xs">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 bg-slate-50 rounded-lg space-y-0.5">
                  <span className="text-[10px] text-slate-500 font-bold uppercase">Page Title</span>
                  <p className="font-semibold text-slate-800">{overview?.pageTitle || 'Title not set'}</p>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg space-y-0.5">
                  <span className="text-[10px] text-slate-500 font-bold uppercase">Meta Description</span>
                  <p className="text-slate-700">{overview?.metaDescription || 'Meta description not set'}</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* 6. Forms & Credential Indicators */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('forms-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <FileText className="w-4 h-4 text-indigo-600" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">6. Forms & Credential Indicators</span>
            </div>
            {expandedAccordions['forms-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['forms-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-2 text-xs">
              <p className="text-slate-600">
                Observed Forms: <strong>{v2?.formsAnalysis?.totalForms ?? contentAnalysis?.formsCount ?? 0}</strong>
              </p>
              {(v2?.formsAnalysis?.forms || (contentAnalysis as any)?.forms) && (v2?.formsAnalysis?.forms || (contentAnalysis as any)?.forms).length > 0 ? (
                <div className="space-y-2 pt-1">
                  {(v2?.formsAnalysis?.forms || (contentAnalysis as any)?.forms).map((form: any, idx: number) => (
                    <div key={idx} className="p-3 bg-slate-50 rounded-lg space-y-1 font-mono text-[11px]">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-900">Action: {form.action || '[current-page]'}</span>
                        <span className="text-indigo-600 font-bold">Method: {form.method || 'POST'}</span>
                      </div>
                      <div className="text-slate-500">
                        Password fields: {form.hasPasswordField ? 'YES' : 'NO'} | Insecure Action: {form.isInsecureAction || form.isPlaintextHttp ? 'YES' : 'NO'}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">No interactive input forms observed in static HTML.</p>
              )}
            </div>
          )}
        </div>

        {/* 7. External Resources & Mixed Content */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('resources-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <ExternalLink className="w-4 h-4 text-indigo-600" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">7. External Resources & Mixed Content</span>
            </div>
            {expandedAccordions['resources-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['resources-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-2 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 bg-slate-50 rounded-lg">
                  <span className="text-[10px] text-slate-500 font-bold uppercase block">Mixed Content Count</span>
                  <span className={`font-bold ${contentAnalysis?.mixedContentCount === 0 ? 'text-emerald-700' : 'text-red-700'}`}>
                    {contentAnalysis?.mixedContentCount ?? 0}
                  </span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg">
                  <span className="text-[10px] text-slate-500 font-bold uppercase block">External Scripts</span>
                  <span className="font-bold text-slate-800">{contentAnalysis?.scriptsCount ?? 'Evaluated'}</span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg">
                  <span className="text-[10px] text-slate-500 font-bold uppercase block">Iframes</span>
                  <span className="font-bold text-slate-800">{contentAnalysis?.iframesCount ?? 0}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* 8. Detected Technologies */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('tech-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <Cpu className="w-4 h-4 text-indigo-600" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">8. Detected Technologies & Stack</span>
            </div>
            {expandedAccordions['tech-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['tech-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-3 text-xs">
              {techList.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {techList.map((t, idx) => (
                    <div key={idx} className="p-3 bg-slate-50 rounded-lg space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-900">{t.technology}</span>
                        <span className="text-[10px] font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-200">
                          {t.category || 'Tech'}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 font-mono break-all">{t.evidence}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">No technology signatures identified from public headers or DOM markers.</p>
              )}
            </div>
          )}
        </div>

        {/* 9. Threat Intelligence */}
        <div className="border border-slate-200/80 rounded-xl overflow-hidden">
          <div
            onClick={() => toggleAccordion('ti-section')}
            className="p-4 bg-slate-50 flex items-center justify-between cursor-pointer hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-2.5">
              <Radio className="w-4 h-4 text-slate-500" />
              <span className="text-xs sm:text-sm font-bold text-slate-900">9. Threat Intelligence & Reputation</span>
            </div>
            {expandedAccordions['ti-section'] ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
          {expandedAccordions['ti-section'] && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-2 text-xs">
              <div className="p-3 bg-slate-50 rounded-lg space-y-1">
                <span className="font-bold text-slate-900">Status: Threat Intelligence Not Configured</span>
                <p className="text-slate-600 leading-relaxed">
                  External threat intelligence feeds (such as commercial malware/phishing feeds) were not queried for this scan. The score is based solely on direct network, transport, header, cookie, and DOM evidence.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── 7. POSITIVE SECURITY SIGNALS ────────────────────────────────────── */}
      {positiveControls.length > 0 && (
        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-100">
            <div className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600 shrink-0">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-slate-900 tracking-tight">
                Positive Security Signals
              </h3>
              <p className="text-xs text-slate-500">
                Defensive controls and secure configurations verified by live evidence.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            {positiveControls.map((control, idx) => (
              <div key={idx} className="p-3.5 bg-emerald-50/40 border border-emerald-200/70 rounded-xl space-y-1">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span className="text-xs font-bold text-emerald-950">{control.title}</span>
                </div>
                <p className="text-xs text-emerald-900/80 pl-6 leading-relaxed">
                  {control.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 8. PRIORITIZED REMEDIATION RECOMMENDATIONS ──────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
        <div className="flex items-center gap-2.5 pb-3 border-b border-slate-100">
          <div className="w-9 h-9 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600 shrink-0">
            <CheckSquare className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-slate-900 tracking-tight">
              Prioritized Remediation Recommendations
            </h3>
            <p className="text-xs text-slate-500">
              Actionable hardening steps ordered by severity to systematically improve website security.
            </p>
          </div>
        </div>

        {prioritizedFindings.filter((f) => f.recommendation).length > 0 ? (
          <div className="space-y-3 pt-1">
            {prioritizedFindings
              .filter((f) => f.recommendation)
              .map((f, idx) => (
                <div key={idx} className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-slate-900">{f.title}</span>
                    <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-full border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-slate-700 leading-relaxed">
                    {f.recommendation}
                  </p>
                </div>
              ))}
          </div>
        ) : (
          <p className="text-xs text-emerald-800 bg-emerald-50 p-4 rounded-xl border border-emerald-200">
            No immediate remediation actions required based on the passive checks conducted.
          </p>
        )}
      </div>

      {/* ── 9. TECHNICAL DETAILS & AUDIT CHECKLIST (COLLAPSIBLE) ─────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl overflow-hidden shadow-xs">
        <button
          type="button"
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="w-full p-5 sm:p-6 flex items-center justify-between text-left hover:bg-slate-50 transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <Terminal className="w-5 h-5 text-slate-600" />
            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900">
                Technical Details & Security Audit Matrix
              </h3>
              <p className="text-xs text-slate-500">
                Network connection parameters, response headers, and the 12-point passive audit matrix.
              </p>
            </div>
          </div>
          {showTechnicalDetails ? <ChevronUp className="w-5 h-5 text-slate-500" /> : <ChevronDown className="w-5 h-5 text-slate-500" />}
        </button>

        {showTechnicalDetails && (
          <div className="p-6 sm:p-7 border-t border-slate-200 space-y-6 text-xs bg-slate-50/50">
            {/* Connection Parameters Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 bg-white border border-slate-200 rounded-lg">
                <span className="text-[10px] text-slate-400 font-bold uppercase block">HTTP Status</span>
                <span className="font-mono font-bold text-slate-800">{httpAnalysis?.statusCode || 200}</span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg">
                <span className="text-[10px] text-slate-400 font-bold uppercase block">Response Time</span>
                <span className="font-mono font-bold text-slate-800">{httpAnalysis?.responseTimeMs ? `${httpAnalysis.responseTimeMs}ms` : 'Recorded'}</span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg">
                <span className="text-[10px] text-slate-400 font-bold uppercase block">Content Type</span>
                <span className="font-mono font-bold text-slate-800 truncate block">{httpAnalysis?.contentType || 'text/html'}</span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg">
                <span className="text-[10px] text-slate-400 font-bold uppercase block">IP Address</span>
                <span className="font-mono font-bold text-slate-800">{domainAnalysis?.resolvedIps?.[0] || domainAnalysis?.hostname || 'Resolved'}</span>
              </div>
            </div>

            {/* 12-point Audit Matrix */}
            {auditChecks.length > 0 && (
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Deterministic Audit Checklist Matrix ({auditChecks.filter(a => a.status === 'PASS').length}/{auditChecks.length} Passed)
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {auditChecks.map((check, idx) => (
                    <div key={idx} className="p-3 bg-white border border-slate-200 rounded-lg flex items-start gap-2.5">
                      {check.status === 'PASS' ? (
                        <CheckSquare className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                      ) : check.status === 'FAIL' ? (
                        <XSquare className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                      ) : (
                        <HelpCircle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                      )}
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-slate-900">{check.name}</span>
                          <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${check.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}`}>
                            {check.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-600 font-mono">{check.evidence}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── 10. HONEST SCANNER LIMITATIONS ──────────────────────────────────── */}
      <div className="bg-slate-50 border border-slate-200/90 rounded-2xl p-5 sm:p-6 text-xs text-slate-600 space-y-1.5 leading-relaxed">
        <div className="flex items-center gap-2 text-slate-800 font-bold">
          <Info className="w-4 h-4 text-indigo-600" />
          <span>Scanner Scope & Assessment Limitations</span>
        </div>
        <p>
          This scan performs non-destructive website security analysis using observable network, transport, HTTP, and static page evidence. It does not perform intrusive penetration testing, execute arbitrary website JavaScript, or guarantee that a website is completely free of zero-day or authenticated vulnerabilities.
        </p>
      </div>
    </div>
  );
}
