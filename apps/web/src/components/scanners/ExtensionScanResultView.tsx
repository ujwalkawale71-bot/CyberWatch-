import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Puzzle,
  Shield,
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
  Activity,
  Sparkles,
  Info,
  FileSearch,
  Search,
  ExternalLink,
  Globe,
  Code2,
  Eye,
  Key,
  Share2,
  AlertTriangle,
  Link as LinkIcon,
  Radio,
} from 'lucide-react';
import type {
  ScanRecord,
  ExtensionSecurityAnalysis,
  FindingSeverity,
  ExtensionScoreContributor,
} from '../../types';
import type { ParsedTargetUrl } from '../../utils/urlParser';

interface ExtensionScanResultViewProps {
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

export function ExtensionScanResultView({
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
}: ExtensionScanResultViewProps) {
  const [showRawJson, setShowRawJson] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(true);
  const [activeTechnicalTab, setActiveTechnicalTab] = useState<
    'permissions' | 'hosts' | 'manifest' | 'code' | 'network' | 'privacy' | 'provenance'
  >('permissions');
  const [permissionFilter, setPermissionFilter] = useState('');
  const [hostFilter, setHostFilter] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [expandedPermissionName, setExpandedPermissionName] = useState<string | null>(null);
  const [expandedContributorId, setExpandedContributorId] = useState<string | null>(null);

  const ext: ExtensionSecurityAnalysis | undefined = scan.checks?.extensionAnalysis;
  const riskScore = ext?.riskScore ?? scan.riskScore ?? 0;
  const riskLevel =
    ext?.riskLevel ||
    (riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW');

  const contributors: ExtensionScoreContributor[] = ext?.scoreContributors || [];
  const positiveSignals = ext?.positiveSignals || [];
  const findings = scan.findings || [];
  const recommendations = scan.recommendations || ext?.recommendations || [];
  const breakdown = ext?.breakdown;
  const permissionDetails = ext?.permissionDetails || [];
  const codeFindings = ext?.codeFindings || [];
  const storeMetadata = ext?.storeMetadata;
  const provenance = ext?.provenance;
  const packageIdentity = ext?.packageIdentity;
  const hostPermissions = ext?.hostPermissions || [];
  const declaredPermissions = ext?.permissions || [];

  function handleCopy(text: string, key = 'target') {
    if (onCopy && key === 'target') {
      onCopy(text);
    } else {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  }

  // Dynamic counts for tabs and sections
  const totalObsCount = findings.length;
  const totalPermsCount = declaredPermissions.length;
  const totalHostsCount = hostPermissions.length;
  const totalFilesCount =
    packageIdentity?.fileCount || (codeFindings.length > 0 ? codeFindings.length : 1);
  const totalTechnicalItems =
    totalPermsCount + totalHostsCount + (codeFindings.length || 0) + (packageIdentity ? 4 : 2);

  // Security status styling
  const statusTheme = useMemo(() => {
    switch (riskLevel) {
      case 'CRITICAL':
        return {
          label: 'CRITICAL RISK',
          badgeBg: 'bg-red-500 text-white',
          border: 'border-red-300',
          bg: 'bg-red-50/40',
          dotColor: 'bg-red-500',
          textColor: 'text-red-900',
          shieldColor: 'bg-red-100 text-red-600 border-red-200',
        };
      case 'HIGH':
        return {
          label: 'HIGH RISK',
          badgeBg: 'bg-orange-500 text-white',
          border: 'border-orange-300',
          bg: 'bg-orange-50/40',
          dotColor: 'bg-orange-500',
          textColor: 'text-orange-900',
          shieldColor: 'bg-orange-100 text-orange-600 border-orange-200',
        };
      case 'MEDIUM':
        return {
          label: 'MODERATE RISK',
          badgeBg: 'bg-amber-400 text-slate-900',
          border: 'border-amber-200',
          bg: 'bg-amber-50/40',
          dotColor: 'bg-amber-400',
          textColor: 'text-amber-900',
          shieldColor: 'bg-amber-100 text-amber-700 border-amber-200',
        };
      case 'LOW':
      default:
        return {
          label: 'LOW RISK',
          badgeBg: 'bg-emerald-500 text-white',
          border: 'border-emerald-200',
          bg: 'bg-emerald-50/40',
          dotColor: 'bg-emerald-500',
          textColor: 'text-emerald-900',
          shieldColor: 'bg-emerald-100 text-emerald-700 border-emerald-200',
        };
    }
  }, [riskLevel]);

  // Severity badge component
  function renderSeverityBadge(sev: FindingSeverity | string) {
    const s = (sev || 'LOW').toUpperCase();
    if (s === 'CRITICAL') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-100 text-red-800 border border-red-200">
          Critical
        </span>
      );
    }
    if (s === 'HIGH') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-orange-100 text-orange-800 border border-orange-200">
          High
        </span>
      );
    }
    if (s === 'MEDIUM' || s === 'MODERATE' || s === 'SUSPICIOUS') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-200">
          Suspicious
        </span>
      );
    }
    if (s === 'LOW') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200">
          Low
        </span>
      );
    }
    return (
      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
        {s}
      </span>
    );
  }

  // Category risk badge component for breakdown cards
  function renderCategoryBadge(level?: string) {
    const l = (level || 'LOW').toUpperCase();
    if (l === 'CRITICAL') {
      return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-100 text-red-800 border border-red-200">CRITICAL</span>;
    }
    if (l === 'HIGH') {
      return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-200">HIGH</span>;
    }
    if (l === 'MEDIUM' || l === 'MODERATE') {
      return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-100 text-amber-800 border border-amber-200">MODERATE</span>;
    }
    return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-200">LOW</span>;
  }

  // Dynamic finding icon helper
  function getFindingIcon(finding: any) {
    const title = (finding.title || '').toLowerCase();
    const cat = (finding.category || '').toLowerCase();
    if (title.includes('code') || title.includes('eval') || cat.includes('code')) {
      return <Code2 className="w-4 h-4 text-slate-700" />;
    }
    if (title.includes('website') || title.includes('host') || title.includes('url')) {
      return <Globe className="w-4 h-4 text-slate-700" />;
    }
    if (title.includes('tab') || title.includes('scripting') || title.includes('synergy')) {
      return <Share2 className="w-4 h-4 text-slate-700" />;
    }
    if (title.includes('privacy') || title.includes('cookie') || title.includes('credential')) {
      return <Eye className="w-4 h-4 text-slate-700" />;
    }
    if (title.includes('permission') || title.includes('debugger')) {
      return <Key className="w-4 h-4 text-slate-700" />;
    }
    return <AlertTriangle className="w-4 h-4 text-slate-700" />;
  }

  // Filtered lists for technical tabs
  const filteredPermissions = useMemo(() => {
    if (!permissionFilter.trim()) return permissionDetails;
    const q = permissionFilter.toLowerCase();
    return permissionDetails.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.capability.toLowerCase().includes(q) ||
        p.securityImpact.toLowerCase().includes(q)
    );
  }, [permissionDetails, permissionFilter]);

  const filteredHosts = useMemo(() => {
    if (!hostFilter.trim()) return hostPermissions;
    const q = hostFilter.toLowerCase();
    return hostPermissions.filter((h) => h.toLowerCase().includes(q));
  }, [hostPermissions, hostFilter]);

  // Extract store URL if available
  const storeUrl =
    storeMetadata?.storeUrl ||
    (ext?.extensionId
      ? `https://chromewebstore.google.com/detail/${ext.extensionId}`
      : parsedTarget.fullUrl.includes('chromewebstore.google.com')
      ? parsedTarget.fullUrl
      : undefined);

  const networkIndicators = ext?.networkIndicators || [];
  const privacyAnalysis = ext?.privacyAnalysis;

  return (
    <div className="space-y-5 max-w-5xl mx-auto pb-16 font-sans">
      {/* ── 1. EXTENSION RESULT HEADER ───────────────────────────────────── */}
      <div className="bg-amber-50/20 border border-amber-200/60 rounded-2xl p-5 sm:p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3.5 min-w-0">
            {/* Extension Shield Icon */}
            <div
              className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border ${statusTheme.shieldColor} shadow-xs`}
            >
              <Puzzle className="w-5 h-5" />
            </div>

            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-lg sm:text-xl font-black text-slate-900 tracking-tight truncate">
                  {ext?.extensionName || 'Browser Extension'}
                </h1>

                <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-md">
                  <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                  Verified Extension Data
                </span>
              </div>

              {/* Developer, Version, ID line */}
              <div className="flex items-center gap-2 text-xs text-slate-600 flex-wrap">
                {storeMetadata?.developer || ext?.author ? (
                  <span>
                    by <strong className="text-slate-800 font-semibold">{storeMetadata?.developer || ext?.author}</strong>
                  </span>
                ) : null}

                {ext?.version && (
                  <>
                    <span className="text-slate-300">•</span>
                    <span className="font-mono text-slate-700">v{ext.version}</span>
                  </>
                )}

                {ext?.extensionId && (
                  <>
                    <span className="text-slate-300">•</span>
                    <span className="font-mono text-slate-600 truncate max-w-xs" title={ext.extensionId}>
                      ID: {ext.extensionId}
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopy(ext.extensionId!, 'extId')}
                      className="text-slate-400 hover:text-slate-700 transition-colors p-0.5"
                      title="Copy Extension ID"
                    >
                      {copiedKey === 'extId' ? (
                        <Check className="w-3 h-3 text-emerald-600" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center flex-wrap gap-2 shrink-0">
            {storeUrl && (
              <a
                href={storeUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold text-xs rounded-xl shadow-xs transition-all"
              >
                <span>Store Listing</span>
                <ExternalLink className="w-3 h-3 text-slate-400" />
              </a>
            )}

            <button
              type="button"
              onClick={() => handleCopy(parsedTarget.fullUrl, 'url')}
              className="p-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-600 rounded-xl shadow-xs transition-all"
              title="Copy Target URL"
            >
              {copied || copiedKey === 'url' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <LinkIcon className="w-3.5 h-3.5" />}
            </button>

            {onRescan && (
              <button
                type="button"
                onClick={onRescan}
                disabled={isRescanning}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold text-xs rounded-xl shadow-xs transition-all disabled:opacity-75"
                title="Rescan Extension"
              >
                <RotateCw className={`w-3.5 h-3.5 text-slate-500 ${isRescanning ? 'animate-spin' : ''}`} />
                <span>Rescan</span>
              </button>
            )}

            <Link
              to={`/threat-intelligence?q=${encodeURIComponent(ext?.extensionId || ext?.packageIdentity?.sha256 || scan.target)}`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200/80 font-semibold text-xs rounded-xl shadow-xs transition-all"
              title="Investigate extension in Threat Intelligence"
            >
              <Radio className="w-3.5 h-3.5 text-indigo-600" />
              <span>Threat Intel</span>
            </Link>

            {onDownloadReport && (
              <button
                type="button"
                onClick={onDownloadReport}
                disabled={isGeneratingPdf}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold text-xs rounded-xl shadow-xs transition-all disabled:opacity-75"
                title="Download PDF Security Report"
              >
                {isGeneratingPdf ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-teal-600" />
                ) : (
                  <Download className="w-3.5 h-3.5 text-slate-500" />
                )}
                <span>Report</span>
              </button>
            )}

            {onNewScan && (
              <button
                type="button"
                onClick={onNewScan}
                className="inline-flex items-center gap-1 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white font-bold text-xs rounded-xl shadow-xs transition-all"
              >
                <PlusCircle className="w-3 h-3" />
                <span>New Scan</span>
              </button>
            )}
          </div>
        </div>

        {pdfError && (
          <div className="mt-3 text-xs text-red-700 bg-red-50 border border-red-200 rounded-xl px-4 py-2 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
            <span>{pdfError}</span>
          </div>
        )}
      </div>

      {/* ── STATIC ANALYSIS NOTICE BANNER ────────────────────────────────── */}
      <div className="bg-slate-100/70 border border-slate-200/80 rounded-xl px-4 py-2.5 flex items-center justify-between gap-3 text-xs text-slate-600">
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-slate-500 shrink-0" />
          <span>
            <strong className="text-slate-800 font-semibold">Static Analysis: </strong>
            Extension code was not executed during this scan. Analysis is based on static inspection of manifest declarations, permissions, and JavaScript source code.
          </span>
        </div>
        <span className="text-[10px] font-mono font-bold bg-white border border-slate-200 text-slate-700 px-2 py-0.5 rounded shrink-0">
          STATIC AUDIT
        </span>
      </div>

      {/* ── 2. OVERALL SECURITY STATUS & SCORE PANEL ─────────────────────── */}
      <div className={`border ${statusTheme.border} ${statusTheme.bg} rounded-2xl p-5 sm:p-6 shadow-xs`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
          {/* Left: Overall Security Status & Explanation */}
          <div className="space-y-2 max-w-xl">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
              Overall Security Status
            </span>

            <div className="flex items-center gap-2.5">
              <span
                className={`text-xs font-black uppercase px-3 py-1 rounded-md shadow-xs ${statusTheme.badgeBg}`}
              >
                {statusTheme.label}
              </span>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed pt-0.5">
              {ext?.scoreExplanation?.summary ||
                'This score is based on permissions, website access, code behaviour, privacy exposure, network indicators and verified security findings.'}
            </p>
          </div>

          {/* Right: Risk Score Box */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-4 sm:p-5 flex flex-col items-center justify-center min-w-[170px] shadow-xs shrink-0 self-start sm:self-auto">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">
              Risk Score
            </span>
            <div className="flex items-center gap-2">
              <span className="text-2xl sm:text-3xl font-black text-slate-900 font-mono tracking-tight">
                {riskScore} <span className="text-slate-400 text-lg sm:text-xl font-bold">/ 100</span>
              </span>
              <span className={`w-3.5 h-3.5 rounded-full ${statusTheme.dotColor} shadow-xs shrink-0`} />
            </div>
          </div>
        </div>
      </div>

      {/* ── 3. WHAT WE FOUND ─────────────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between px-1">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-teal-600" />
            <h3 className="text-xs sm:text-sm font-black text-slate-900 uppercase tracking-wide">
              What We Found
            </h3>
          </div>
          <span className="text-xs font-semibold text-slate-500">
            {totalObsCount} observation{totalObsCount !== 1 ? 's' : ''}
          </span>
        </div>

        {findings.length === 0 ? (
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 text-center space-y-1.5 shadow-xs">
            <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto" />
            <h4 className="text-xs font-bold text-slate-800">No Elevated Risk Findings Detected</h4>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Static inspection detected no dangerous capabilities, wildcard host access scopes, or dynamic script injection routines.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {findings.map((finding, idx) => {
              const findingKey = finding.id || `f-${idx}`;
              const isExpanded = expandedFindingId === findingKey;
              const FindingIconComponent = getFindingIcon(finding);

              return (
                <div
                  key={findingKey}
                  onClick={() => setExpandedFindingId(isExpanded ? null : findingKey)}
                  className={`bg-white border ${
                    isExpanded ? 'border-teal-500 shadow-sm' : 'border-slate-200/90 hover:border-slate-300'
                  } rounded-2xl p-4 shadow-xs transition-all cursor-pointer space-y-2.5`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="w-7 h-7 rounded-lg bg-slate-50 border border-slate-200/60 flex items-center justify-center shrink-0">
                        {FindingIconComponent}
                      </div>
                      <h4 className="text-xs sm:text-sm font-bold text-slate-900 truncate">
                        {finding.title}
                      </h4>
                    </div>

                    <div className="shrink-0">{renderSeverityBadge(finding.severity)}</div>
                  </div>

                  <p className="text-xs text-slate-600 leading-relaxed line-clamp-2">
                    {finding.description}
                  </p>

                  <div className="flex items-center justify-between pt-1 text-[11px] text-slate-500 border-t border-slate-100">
                    <div className="font-mono text-slate-700 truncate max-w-[210px] bg-slate-50 px-2 py-0.5 rounded border border-slate-200/60">
                      {finding.evidence || (finding as any).location || finding.category || 'Manifest / Static Code'}
                    </div>

                    <div className="flex items-center gap-1 text-slate-400 hover:text-slate-700 font-semibold shrink-0">
                      <span>{isExpanded ? 'Less' : 'Details'}</span>
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </div>
                  </div>

                  {/* Expanded details */}
                  {isExpanded && (
                    <div
                      className="pt-3 border-t border-slate-100 space-y-2 text-xs text-slate-600"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {finding.impact && (
                        <div>
                          <strong className="text-slate-800 font-bold block mb-0.5">Security Impact:</strong>
                          <p className="text-slate-600 leading-relaxed">{finding.impact}</p>
                        </div>
                      )}

                      {finding.evidence && (
                        <div>
                          <strong className="text-slate-800 font-bold block mb-0.5">Observed Evidence:</strong>
                          <pre className="font-mono text-[11px] bg-slate-900 text-slate-200 p-2.5 rounded-lg overflow-x-auto whitespace-pre-wrap">
                            {finding.evidence}
                          </pre>
                        </div>
                      )}

                      {finding.recommendation && (
                        <div className="p-2.5 bg-blue-50/70 border border-blue-100 rounded-lg text-blue-900">
                          <strong className="font-bold block mb-0.5">Recommendation:</strong>
                          <span>{finding.recommendation}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── 4. SECURITY BREAKDOWN ────────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between px-1">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-teal-600" />
            <h3 className="text-xs sm:text-sm font-black text-slate-900 uppercase tracking-wide">
              Security Breakdown
            </h3>
          </div>
          <span className="text-xs font-semibold text-slate-400">Core Risk Surface</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
          {/* 1. Permissions */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-4 shadow-xs space-y-2 flex flex-col justify-between">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800">Permissions</span>
                {renderCategoryBadge(breakdown?.permissions?.riskLevel || 'LOW')}
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                {breakdown?.permissions?.explanation || 'Standard operational permissions declared.'}
              </p>
            </div>
          </div>

          {/* 2. Website Access */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-4 shadow-xs space-y-2 flex flex-col justify-between">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800">Website Access</span>
                {renderCategoryBadge(breakdown?.websiteAccess?.riskLevel || 'LOW')}
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                {breakdown?.websiteAccess?.explanation || 'No broad wildcard website access scopes requested.'}
              </p>
            </div>
          </div>

          {/* 3. Code Behaviour */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-4 shadow-xs space-y-2 flex flex-col justify-between">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800">Code Behaviour</span>
                {renderCategoryBadge(breakdown?.codeBehaviour?.riskLevel || 'LOW')}
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                {breakdown?.codeBehaviour?.explanation || 'No suspicious dynamic code execution patterns found.'}
              </p>
            </div>
          </div>

          {/* 4. Privacy Exposure */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-4 shadow-xs space-y-2 flex flex-col justify-between">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800">Privacy Exposure</span>
                {renderCategoryBadge(breakdown?.privacyExposure?.riskLevel || 'LOW')}
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                {breakdown?.privacyExposure?.explanation || 'No sensitive personal or session data accessed.'}
              </p>
            </div>
          </div>

          {/* 5. Obfuscation */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-4 shadow-xs space-y-2 flex flex-col justify-between sm:col-span-2 lg:col-span-1">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800">Obfuscation</span>
                {renderCategoryBadge(
                  ext?.jsAnalysis?.obfuscationIndicators && ext.jsAnalysis.obfuscationIndicators.length > 0
                    ? 'MODERATE'
                    : 'LOW'
                )}
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                {ext?.jsAnalysis?.obfuscationIndicators && ext.jsAnalysis.obfuscationIndicators.length > 0
                  ? 'Obfuscation or heavy packing patterns observed.'
                  : 'Standard production minification / bundler optimization.'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ── 5. POSITIVE SECURITY SIGNALS ─────────────────────────────────── */}
      <div className="bg-emerald-50/30 border border-emerald-100 rounded-2xl p-5 shadow-xs space-y-3">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
          <h3 className="text-xs sm:text-sm font-black text-slate-900 uppercase tracking-wide">
            Positive Security Signals
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          {positiveSignals.length > 0 ? (
            positiveSignals.map((signal, idx) => (
              <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-800">
                <Check className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5 font-bold" />
                <div className="space-y-0.5">
                  <span className="font-bold text-slate-900">{signal.title}</span>
                  {signal.desc && <p className="text-[11px] text-slate-600 leading-relaxed">{signal.desc}</p>}
                </div>
              </div>
            ))
          ) : (
            <>
              <div className="flex items-center gap-2 text-xs text-slate-800">
                <Check className="w-4 h-4 text-emerald-600 shrink-0 font-bold" />
                <span>Extension identity verified on official Chrome Web Store</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-800">
                <Check className="w-4 h-4 text-emerald-600 shrink-0 font-bold" />
                <span>Manifest specification successfully analyzed</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-800">
                <Check className="w-4 h-4 text-emerald-600 shrink-0 font-bold" />
                <span>Modern Manifest V3 security architecture</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-800">
                <Check className="w-4 h-4 text-emerald-600 shrink-0 font-bold" />
                <span>No confirmed malicious payloads or remote execution vectors</span>
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── 6. RECOMMENDATION & NEXT STEPS ───────────────────────────────── */}
      <div className="bg-blue-50/30 border border-blue-100 rounded-2xl p-5 shadow-xs space-y-3">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-blue-600" />
          <h3 className="text-xs sm:text-sm font-black text-slate-900 uppercase tracking-wide">
            Recommendation & Next Steps
          </h3>
        </div>

        <div className="space-y-2.5 text-xs text-slate-800">
          <div className="flex items-start gap-2">
            <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
            <p className="font-bold text-slate-900 leading-relaxed">
              {recommendations[0] ||
                'Review the requested permissions before installation to ensure they align with the extension advertised features.'}
            </p>
          </div>

          <div className="pl-6 space-y-1.5 text-slate-700">
            {recommendations.length > 1 ? (
              recommendations.slice(1).map((rec, idx) => (
                <div key={idx} className="flex items-start gap-2 text-[11px] leading-relaxed">
                  <span className="text-blue-500 font-bold">•</span>
                  <span>{rec}</span>
                </div>
              ))
            ) : (
              <>
                <div className="flex items-start gap-2 text-[11px] leading-relaxed">
                  <span className="text-blue-500 font-bold">•</span>
                  <span>Verify that requested permissions correspond directly to features you intend to use.</span>
                </div>
                <div className="flex items-start gap-2 text-[11px] leading-relaxed">
                  <span className="text-blue-500 font-bold">•</span>
                  <span>Check publisher credentials and user reviews on the Chrome Web Store.</span>
                </div>
                <div className="flex items-start gap-2 text-[11px] leading-relaxed">
                  <span className="text-blue-500 font-bold">•</span>
                  <span>Periodically review extension permissions after automatic updates.</span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* ── 7. "WHY THIS SCORE?" (Score Contributors Breakdown) ──────────── */}
      {contributors.length > 0 && (
        <div className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-teal-600" />
              <div>
                <h3 className="text-xs sm:text-sm font-black text-slate-900 uppercase tracking-wide">
                  Why This Score? (Calculated Contributors)
                </h3>
                <p className="text-[11px] text-slate-500">
                  Deterministic point additions derived strictly from observed static security evidence.
                </p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold text-slate-700 bg-slate-100 px-2.5 py-1 rounded-lg">
              Total Score: {riskScore} / 100
            </span>
          </div>

          <div className="space-y-2">
            {contributors.map((c, idx) => {
              const contribKey = c.id || `c-${idx}`;
              const isContribExpanded = expandedContributorId === contribKey;

              return (
                <div
                  key={contribKey}
                  className="p-3 bg-slate-50/80 border border-slate-200/70 rounded-xl space-y-1.5 transition-all hover:bg-slate-50"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap min-w-0">
                      <span className="text-xs font-bold text-slate-900">{c.title}</span>
                      {renderSeverityBadge(c.severity)}
                      <span className="text-[10px] font-semibold text-slate-500 bg-slate-200/60 px-2 py-0.5 rounded">
                        {c.category}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-xs font-mono font-bold text-teal-700 bg-teal-50 border border-teal-200 px-2 py-0.5 rounded-md">
                        +{c.contribution}
                      </span>
                      <button
                        type="button"
                        onClick={() => setExpandedContributorId(isContribExpanded ? null : contribKey)}
                        className="text-slate-400 hover:text-slate-700 p-0.5"
                      >
                        {isContribExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <p className="text-[11px] text-slate-600 leading-relaxed">{c.rationale || c.reason}</p>

                  {isContribExpanded && (
                    <div className="pt-2 border-t border-slate-200/60 text-[11px] text-slate-600 space-y-1">
                      {c.evidence && (
                        <div>
                          <strong className="text-slate-700 font-bold">Evidence: </strong>
                          <span className="font-mono text-slate-800">{c.evidence}</span>
                        </div>
                      )}
                      {c.source && (
                        <div>
                          <strong className="text-slate-700 font-bold">Source: </strong>
                          <span>{c.source}</span>
                        </div>
                      )}
                      {c.remediation && (
                        <div>
                          <strong className="text-teal-700 font-bold">Remediation: </strong>
                          <span>{c.remediation}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── 8. ADVANCED TECHNICAL DETAILS (Collapsible + Interactive Tabs) ── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-3 pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-teal-50 border border-teal-200 flex items-center justify-center">
              <FileSearch className="w-4 h-4 text-teal-600" />
            </div>
            <h3 className="text-xs sm:text-sm font-black text-slate-900 uppercase tracking-wide">
              Advanced Technical Details
            </h3>
            <span className="text-[11px] font-bold text-teal-800 bg-teal-50 border border-teal-200 px-2 py-0.5 rounded-full">
              {totalTechnicalItems} Items
            </span>
          </div>

          <button
            type="button"
            onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
            className="text-xs font-bold text-slate-600 hover:text-slate-900 inline-flex items-center gap-1 transition-colors"
          >
            <span>{showTechnicalDetails ? 'Hide Technical Analysis' : 'Show Technical Analysis'}</span>
            {showTechnicalDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>

        {showTechnicalDetails && (
          <div className="space-y-4">
            {/* Technical Sub-Tabs */}
            <div className="flex items-center flex-wrap gap-1.5 bg-slate-100/80 p-1 rounded-xl">
              <button
                type="button"
                onClick={() => setActiveTechnicalTab('permissions')}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition-all ${
                  activeTechnicalTab === 'permissions'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                }`}
              >
                Permissions ({totalPermsCount})
              </button>

              <button
                type="button"
                onClick={() => setActiveTechnicalTab('hosts')}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition-all ${
                  activeTechnicalTab === 'hosts'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                }`}
              >
                Host Origins ({totalHostsCount})
              </button>

              <button
                type="button"
                onClick={() => setActiveTechnicalTab('manifest')}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition-all ${
                  activeTechnicalTab === 'manifest'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                }`}
              >
                Architecture & Manifest
              </button>

              <button
                type="button"
                onClick={() => setActiveTechnicalTab('code')}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition-all ${
                  activeTechnicalTab === 'code'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                }`}
              >
                JavaScript Code ({totalFilesCount} File{totalFilesCount !== 1 ? 's' : ''})
              </button>

              <button
                type="button"
                onClick={() => setActiveTechnicalTab('network')}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition-all ${
                  activeTechnicalTab === 'network'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                }`}
              >
                Network ({networkIndicators.length})
              </button>

              <button
                type="button"
                onClick={() => setActiveTechnicalTab('privacy')}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition-all ${
                  activeTechnicalTab === 'privacy'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                }`}
              >
                Privacy
              </button>

              <button
                type="button"
                onClick={() => setActiveTechnicalTab('provenance')}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition-all ${
                  activeTechnicalTab === 'provenance'
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                }`}
              >
                Provenance
              </button>
            </div>

            {/* ── TAB 1: PERMISSIONS ── */}
            {activeTechnicalTab === 'permissions' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div className="relative flex-1 min-w-[200px]">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Filter permissions..."
                      value={permissionFilter}
                      onChange={(e) => setPermissionFilter(e.target.value)}
                      className="w-full text-xs pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-teal-500"
                    />
                  </div>
                  <span className="text-xs font-semibold text-slate-500">
                    Total: {filteredPermissions.length}
                  </span>
                </div>

                {filteredPermissions.length === 0 ? (
                  <p className="text-xs text-slate-400 italic p-4 text-center">
                    No permissions matching your filter.
                  </p>
                ) : (
                  <div className="divide-y divide-slate-100 border border-slate-200/80 rounded-xl overflow-hidden">
                    {filteredPermissions.map((p, idx) => {
                      const isPermExpanded = expandedPermissionName === p.name;
                      return (
                        <div
                          key={idx}
                          className="p-3.5 bg-white hover:bg-slate-50/60 transition-colors cursor-pointer space-y-2"
                          onClick={() => setExpandedPermissionName(isPermExpanded ? null : p.name)}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-start sm:items-center gap-3 min-w-0 flex-1">
                              <span className="font-mono font-bold text-xs text-slate-900 shrink-0">
                                {p.name}
                              </span>
                              <p className="text-xs text-slate-600 truncate hidden sm:block">
                                {p.capability || p.securityImpact}
                              </p>
                            </div>

                            <div className="flex items-center gap-2.5 shrink-0">
                              {renderSeverityBadge(p.severity)}
                              {isPermExpanded ? (
                                <ChevronUp className="w-3.5 h-3.5 text-slate-400" />
                              ) : (
                                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                              )}
                            </div>
                          </div>

                          <p className="text-xs text-slate-500 sm:hidden">{p.capability || p.securityImpact}</p>

                          {isPermExpanded && (
                            <div
                              className="pt-2 border-t border-slate-100 space-y-1.5 text-xs text-slate-600"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <div>
                                <strong className="text-slate-800 font-bold">What It Allows: </strong>
                                <span>{p.capability}</span>
                              </div>
                              <div>
                                <strong className="text-slate-800 font-bold">Security Impact: </strong>
                                <span>{p.securityImpact}</span>
                              </div>
                              <div className="flex items-center gap-4 pt-1 text-[11px]">
                                <div>
                                  <strong className="text-slate-700">Code Usage: </strong>
                                  <span
                                    className={`px-1.5 py-0.5 rounded font-semibold ${
                                      p.actualUsage === 'Detected'
                                        ? 'bg-amber-100 text-amber-800'
                                        : 'bg-slate-100 text-slate-600'
                                    }`}
                                  >
                                    {p.actualUsage}
                                  </span>
                                </div>
                                {p.contribution > 0 && (
                                  <div>
                                    <strong className="text-slate-700">Contribution: </strong>
                                    <span className="font-mono font-bold text-teal-700">
                                      +{p.contribution} pts
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 2: HOST ORIGINS ── */}
            {activeTechnicalTab === 'hosts' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div className="relative flex-1 min-w-[200px]">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Filter host origins..."
                      value={hostFilter}
                      onChange={(e) => setHostFilter(e.target.value)}
                      className="w-full text-xs pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-teal-500"
                    />
                  </div>
                  <span className="text-xs font-semibold text-slate-500">Total: {filteredHosts.length}</span>
                </div>

                {filteredHosts.length === 0 ? (
                  <div className="p-4 text-center bg-slate-50 border border-slate-200/70 rounded-xl">
                    <p className="text-xs text-slate-500">No host permissions declared in manifest.</p>
                  </div>
                ) : (
                  <div className="divide-y divide-slate-100 border border-slate-200/80 rounded-xl overflow-hidden">
                    {filteredHosts.map((host, idx) => {
                      const isWildcard =
                        host === '<all_urls>' ||
                        host === '*://*/*' ||
                        host.includes('*://*') ||
                        host === 'http://*/*' ||
                        host === 'https://*/*';
                      return (
                        <div key={idx} className="p-3.5 bg-white flex items-center justify-between gap-3">
                          <div className="space-y-0.5 min-w-0">
                            <span className="font-mono font-bold text-xs text-slate-900 block truncate">
                              {host}
                            </span>
                            <span className="text-[11px] text-slate-500 block">
                              {isWildcard
                                ? 'Universal website access across all visited origins'
                                : host.includes('*')
                                ? 'Subdomain wildcard pattern'
                                : 'Specific origin access'}
                            </span>
                          </div>
                          <div className="shrink-0">
                            {isWildcard ? renderSeverityBadge('HIGH') : renderSeverityBadge('LOW')}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 3: ARCHITECTURE & MANIFEST ── */}
            {activeTechnicalTab === 'manifest' && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Manifest Version
                    </span>
                    <span className="font-bold text-slate-800">
                      Manifest V{ext?.manifestVersion || 3}
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Extension Name
                    </span>
                    <span className="font-bold text-slate-800 truncate block">
                      {ext?.extensionName || 'Not specified'}
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Version
                    </span>
                    <span className="font-mono font-bold text-slate-800">{ext?.version || '1.0.0'}</span>
                  </div>

                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Publisher / Author
                    </span>
                    <span className="font-bold text-slate-800 truncate block">
                      {storeMetadata?.developer || ext?.author || 'Not present'}
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5 sm:col-span-2">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Background Architecture
                    </span>
                    <span className="font-mono text-slate-700 text-[11px]">
                      {ext?.backgroundScripts && ext.backgroundScripts.length > 0
                        ? ext.backgroundScripts.join(', ')
                        : 'Service Worker / None declared'}
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5 sm:col-span-2">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Content Security Policy (CSP)
                    </span>
                    <span className="font-mono text-slate-700 text-[11px] break-all">
                      {ext?.csp || 'Default Manifest V3 Sandbox Policy'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* ── TAB 4: JAVASCRIPT CODE ── */}
            {activeTechnicalTab === 'code' && (
              <div className="space-y-3">
                {codeFindings.length === 0 ? (
                  <div className="p-6 text-center bg-slate-50 border border-slate-200/70 rounded-xl space-y-1">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500 mx-auto" />
                    <h4 className="text-xs font-bold text-slate-800">
                      No Suspicious Dynamic Execution Patterns Found
                    </h4>
                    <p className="text-[11px] text-slate-500">
                      Static inspection of {totalFilesCount} JavaScript file(s) observed no arbitrary eval(), remote execution, or obfuscation.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {codeFindings.map((cf, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-2 text-xs"
                      >
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-slate-900">
                              {cf.file}:{cf.line || '1'}
                            </span>
                            {renderSeverityBadge(cf.severity)}
                          </div>
                          <span className="font-mono font-bold text-teal-700 text-[11px]">
                            +{cf.riskContribution} pts
                          </span>
                        </div>

                        <p className="text-slate-700 font-semibold">{cf.pattern}</p>

                        {cf.evidenceSnippet && (
                          <pre className="p-2.5 bg-slate-900 text-slate-200 rounded-lg font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                            {cf.evidenceSnippet}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 5: NETWORK (STATIC DISCOVERY) ── */}
            {activeTechnicalTab === 'network' && (
              <div className="space-y-3">
                <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-3.5 flex items-center gap-2 text-xs text-slate-600">
                  <Info className="w-4 h-4 text-slate-500 shrink-0" />
                  <span>
                    Endpoints and domains discovered via static code inspection. Static discovery does not imply active runtime transmission during this scan.
                  </span>
                </div>

                {networkIndicators.length === 0 ? (
                  <div className="p-6 text-center bg-slate-50 border border-slate-200/70 rounded-xl space-y-1">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500 mx-auto" />
                    <h4 className="text-xs font-bold text-slate-800">No External Network Endpoints Discovered</h4>
                    <p className="text-[11px] text-slate-500">
                      Static inspection of extension source code found no hardcoded external API URLs, remote fetch() targets, or telemetry endpoints.
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-slate-100 border border-slate-200/80 rounded-xl overflow-hidden bg-white">
                    {networkIndicators.map((net, idx) => {
                      const dest = net.url || net.domain || net.ip || (net as any).destination || 'External Target';
                      const netType = net.domain ? 'Domain' : net.ip ? 'IP' : (net as any).type || 'Endpoint';
                      const sev = (net as any).severity || (net.isSuspicious ? 'HIGH' : 'LOW');
                      return (
                        <div key={idx} className="p-3.5 hover:bg-slate-50/60 transition-colors flex items-center justify-between gap-3 text-xs">
                          <div className="space-y-0.5 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono font-bold text-slate-900 truncate">{dest}</span>
                              <span className="text-[10px] font-semibold uppercase bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded border border-slate-200/60">
                                {netType}
                              </span>
                              {net.sourceFile && (
                                <span className="text-[10px] font-mono text-slate-500">
                                  {net.sourceFile}
                                </span>
                              )}
                            </div>
                            {net.context && (
                              <p className="text-[11px] text-slate-500 truncate">{net.context}</p>
                            )}
                          </div>
                          <div className="shrink-0">
                            {renderSeverityBadge(sev)}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 6: PRIVACY ANALYSIS ── */}
            {activeTechnicalTab === 'privacy' && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Exfiltration Risk Level
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-800">
                        {privacyAnalysis?.dataExfiltrationRisk || (privacyAnalysis as any)?.exfiltrationRisk || 'None'}
                      </span>
                      {renderCategoryBadge(
                        privacyAnalysis?.dataExfiltrationRisk || (privacyAnalysis as any)?.exfiltrationRisk || 'LOW'
                      )}
                    </div>
                  </div>

                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      External Data Transmission
                    </span>
                    <span className="font-bold text-slate-800">
                      {privacyAnalysis?.externalDataTransmission ? 'Detected in static patterns' : 'None detected'}
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5 sm:col-span-2">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Declared Privacy Capabilities (Manifest)
                    </span>
                    {(privacyAnalysis?.dataCapabilities || (privacyAnalysis as any)?.declaredDataCapabilities) &&
                    (privacyAnalysis?.dataCapabilities || (privacyAnalysis as any)?.declaredDataCapabilities).length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {(privacyAnalysis?.dataCapabilities || (privacyAnalysis as any)?.declaredDataCapabilities).map(
                          (cap: string, idx: number) => (
                            <span key={idx} className="font-mono text-[11px] bg-slate-200/70 text-slate-800 px-2 py-0.5 rounded">
                              {cap}
                            </span>
                          )
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-500 text-[11px]">No high-risk privacy APIs declared</span>
                    )}
                  </div>

                  <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1.5 sm:col-span-2">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                      Observed Data Access & Details
                    </span>
                    {privacyAnalysis?.observedDataAccess && privacyAnalysis.observedDataAccess.length > 0 ? (
                      <div className="space-y-1 text-[11px] text-slate-700">
                        {privacyAnalysis.observedDataAccess.map((obs: string, idx: number) => (
                          <div key={idx} className="flex items-start gap-2">
                            <span className="text-teal-600 font-bold">•</span>
                            <span>{obs}</span>
                          </div>
                        ))}
                      </div>
                    ) : privacyAnalysis?.details ? (
                      <p className="text-[11px] text-slate-600">{privacyAnalysis.details}</p>
                    ) : (
                      <span className="text-slate-500 text-[11px]">No privacy violations or tracking patterns observed.</span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* ── TAB 7: PROVENANCE ── */}
            {activeTechnicalTab === 'provenance' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    Store Origin
                  </span>
                  <span className="font-bold text-slate-800">
                    {provenance?.store || storeMetadata?.store || 'Chrome Web Store'}
                  </span>
                </div>

                <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    Extension ID
                  </span>
                  <span className="font-mono font-bold text-slate-800 truncate block">
                    {provenance?.extensionId || ext?.extensionId || 'Direct Manifest'}
                  </span>
                </div>

                <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    Developer
                  </span>
                  <span className="font-bold text-slate-800 truncate block">
                    {provenance?.developer || storeMetadata?.developer || ext?.author || 'Not verified'}
                  </span>
                </div>

                <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    Package Type
                  </span>
                  <span className="font-bold text-slate-800">
                    {provenance?.packageType || packageIdentity?.format || 'MANIFEST_JSON'}
                  </span>
                </div>

                <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1 sm:col-span-2">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    SHA-256 Checksum
                  </span>
                  <span className="font-mono text-slate-700 text-[11px] break-all block">
                    {provenance?.sha256 || packageIdentity?.sha256 || 'N/A (Parsed from webstore/manifest URL)'}
                  </span>
                </div>

                <div className="p-3.5 bg-slate-50 border border-slate-200/70 rounded-xl space-y-1 sm:col-span-2">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    Scan Timestamp
                  </span>
                  <span className="text-slate-700 font-mono text-[11px]">
                    {provenance?.scanTimestamp
                      ? String(provenance.scanTimestamp)
                      : scan.createdAt
                      ? new Date(scan.createdAt).toISOString()
                      : new Date().toISOString()}
                  </span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── 9. RAW JSON INSPECTOR ─────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-5 shadow-xs space-y-3">
        <button
          type="button"
          onClick={() => setShowRawJson(!showRawJson)}
          className="w-full flex items-center justify-between text-left font-bold text-xs sm:text-sm text-slate-800 hover:text-slate-900"
        >
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-slate-500" />
            <span>Raw Technical Security Analysis (JSON Payload)</span>
          </div>
          {showRawJson ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </button>

        {showRawJson && (
          <div className="bg-slate-950 text-slate-200 rounded-xl p-4 font-mono text-xs overflow-x-auto max-h-96">
            <pre>{JSON.stringify(scan, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
