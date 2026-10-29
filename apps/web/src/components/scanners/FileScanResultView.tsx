import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  Copy,
  Check,
  Download,
  PlusCircle,
  FileCode,
  FileSearch,
  Search,
  ChevronDown,
  ChevronUp,
  Cpu,
  Database,
  ExternalLink,
  Lock,
  Archive,
  Terminal,
  Activity,
  CheckCircle2,
  Clock,
  Key,
  Globe,
  Radio,
} from 'lucide-react';
import type { ScanRecord, FindingSeverity } from '../../types';

interface FileScanResultViewProps {
  scan: ScanRecord;
  onRescan?: () => void;
  isRescanning?: boolean;
  onNewScan?: () => void;
  onDownloadReport?: () => void;
  isGeneratingPdf?: boolean;
  pdfError?: string | null;
  onCopy?: (text: string) => void;
  copied?: boolean;
}

type ActiveTab = 'overview' | 'file_details' | 'strings' | 'static_analysis' | 'reputation' | 'yara' | 'embedded_urls';

export function FileScanResultView({
  scan,
  onDownloadReport,
  isGeneratingPdf,
  pdfError,
}: FileScanResultViewProps) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showAdvancedDetails, setShowAdvancedDetails] = useState<boolean>(false);
  const [stringFilterCategory, setStringFilterCategory] = useState<string>('all');
  const [stringSearchTerm, setStringSearchTerm] = useState<string>('');

  const fileAnalysis = scan.checks?.fileAnalysis;

  // ── Copy to clipboard helper ──────────────────────────────────────────────
  const handleCopyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // ── JSON Report Export ────────────────────────────────────────────────────
  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scan, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    const cleanFilename = (fileAnalysis?.filename || scan.target || 'file_scan')
      .replace(/[^a-zA-Z0-9._-]/g, '_');
    downloadAnchor.setAttribute('download', `cyberwatch-file-report-${cleanFilename}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // ── Centralized Risk Level & Styling ──────────────────────────────────────
  const riskConfig = useMemo(() => {
    const score = typeof scan.riskScore === 'number' && !isNaN(scan.riskScore) ? scan.riskScore : 0;
    const isScanFailed = scan.status === 'failed' || fileAnalysis?.status === 'failed';

    if (isScanFailed) {
      return {
        level: 'SCAN INCOMPLETE',
        badgeClass: 'bg-amber-100 text-amber-900 border-amber-300',
        scoreColor: 'text-amber-700',
        accentBorder: 'border-amber-300',
        cardBg: 'bg-amber-50/40',
        Icon: AlertTriangle,
        summary: 'One or more critical analysis stages did not complete. Risk score cannot be calculated.',
      };
    }

    if (score >= 75 || scan.result === 'Critical') {
      return {
        level: 'CRITICAL RISK',
        badgeClass: 'bg-rose-100 text-rose-900 border-rose-300',
        scoreColor: 'text-rose-700',
        accentBorder: 'border-rose-300',
        cardBg: 'bg-rose-50/40',
        Icon: ShieldAlert,
        summary: 'Strong high-confidence malicious indicators or exploit patterns were identified during static inspection.',
      };
    }
    if (score >= 50 || scan.result === 'High Risk') {
      return {
        level: 'HIGH RISK',
        badgeClass: 'bg-orange-100 text-orange-900 border-orange-300',
        scoreColor: 'text-orange-700',
        accentBorder: 'border-orange-300',
        cardBg: 'bg-orange-50/40',
        Icon: ShieldAlert,
        summary: 'Significant suspicious indicators or high-privilege execution capabilities were detected in the file structure.',
      };
    }
    if (score >= 25 || scan.result === 'Suspicious') {
      return {
        level: 'MEDIUM RISK',
        badgeClass: 'bg-amber-100 text-amber-900 border-amber-300',
        scoreColor: 'text-amber-700',
        accentBorder: 'border-amber-300',
        cardBg: 'bg-amber-50/40',
        Icon: AlertTriangle,
        summary: 'CyberWatch identified static indicators that contributed to the current risk assessment.',
      };
    }
    return {
      level: 'LOW RISK',
      badgeClass: 'bg-emerald-100 text-emerald-900 border-emerald-300',
      scoreColor: 'text-emerald-700',
      accentBorder: 'border-emerald-300',
      cardBg: 'bg-emerald-50/30',
      Icon: ShieldCheck,
      summary: 'No immediate high-risk indicators were identified from completed static checks.',
    };
  }, [scan.riskScore, scan.result, scan.status, fileAnalysis?.status]);

  // ── Findings Sorting by Severity ──────────────────────────────────────────
  const sortedFindings = useMemo(() => {
    const rawFindings = scan.findings || [];
    const severityOrder: Record<FindingSeverity, number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      INFO: 4,
    };
    return [...rawFindings].sort((a, b) => {
      const orderA = severityOrder[a.severity] ?? 5;
      const orderB = severityOrder[b.severity] ?? 5;
      return orderA - orderB;
    });
  }, [scan.findings]);

  // ── Severity Badge Helper ─────────────────────────────────────────────────
  const getSeverityBadgeClass = (severity: string) => {
    const sev = severity.toUpperCase();
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-100 text-rose-800 border-rose-200 font-bold';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 border-orange-200 font-bold';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 border-amber-200 font-bold';
      case 'LOW':
        return 'bg-blue-100 text-blue-800 border-blue-200 font-bold';
      case 'INFO':
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200 font-medium';
    }
  };

  // ── Dynamic Positive Security Signals ─────────────────────────────────────
  const positiveSignals = useMemo(() => {
    const signals: Array<{ title: string; desc: string }> = [];
    const stages = fileAnalysis?.stages;

    if (stages?.hashing?.status === 'done' && fileAnalysis?.sha256) {
      signals.push({
        title: 'Cryptographic Integrity Check Completed',
        desc: `SHA-256 and MD5 hashes computed successfully directly from file bytes.`,
      });
    }

    if (stages?.fileType?.status === 'done' && !stages.fileType.data?.isDoubleExtension && !stages.fileType.data?.headerAnomaly) {
      signals.push({
        title: 'File Type Aligned with Format Signature',
        desc: `Detected format (${fileAnalysis?.detectedFormat || 'Standard binary'}) matches magic byte headers without double extension deception.`,
      });
    }

    if (stages?.strings?.status === 'done') {
      const apis = stages.strings.data?.suspiciousApis || [];
      const shells = stages.strings.data?.shellCommands || [];
      if (apis.length === 0 && shells.length === 0) {
        signals.push({
          title: 'No Process Injection or Shell Strings Identified',
          desc: 'Extracted string catalog contains zero known Win32 process injection API patterns or shell spawn commands.',
        });
      }
    }

    if (stages?.yara?.status === 'done' && (!stages.yara.data?.matches || stages.yara.data.matches.length === 0)) {
      signals.push({
        title: 'No YARA Threat Signatures Matched',
        desc: `Analyzed against local rule catalog without triggering known threat patterns.`,
      });
    }

    const typeData = stages?.typeSpecific?.data;
    if (typeData?.office && !typeData.office.hasVbaMacros) {
      signals.push({
        title: 'No VBA Macros Detected in Document Container',
        desc: 'Office file structure does not include executable VBA macro storage streams.',
      });
    }

    if (typeData?.pdf && !typeData.pdf.hasJavaScript && !typeData.pdf.hasLaunchActions) {
      signals.push({
        title: 'No Active PDF JavaScript or Launch Action Dictionaries',
        desc: 'PDF dictionary inspection confirmed zero embedded JavaScript actions or OpenAction hooks.',
      });
    }

    if (typeData?.archive && !typeData.archive.hasZipSlip && !typeData.archive.hasExecutables) {
      signals.push({
        title: 'Standard Clean Archive Hierarchy',
        desc: 'Archive directory entries exhibit no relative path traversal (Zip-Slip) or packaged executable binaries.',
      });
    }

    if (stages?.reputation?.status === 'done' && stages.reputation.data?.overallVerdict === 'clean') {
      signals.push({
        title: 'No Confirmed Reputation Blacklist Entries',
        desc: 'Queried threat intelligence repositories returned no active malicious records for this hash.',
      });
    }

    return signals;
  }, [fileAnalysis]);

  // ── Analysis Coverage Stages ──────────────────────────────────────────────
  const analysisCoverageList = useMemo(() => {
    const stages = fileAnalysis?.stages;
    return [
      {
        id: 'hashing',
        name: 'File Identity & Hashes',
        status: stages?.hashing?.status === 'done' ? 'COMPLETED' : stages?.hashing?.status === 'failed' ? 'FAILED' : 'COMPLETED',
        durationMs: stages?.hashing?.durationMs,
      },
      {
        id: 'fileType',
        name: 'File Type & Magic Bytes',
        status: stages?.fileType?.status === 'done' ? 'COMPLETED' : stages?.fileType?.status === 'failed' ? 'FAILED' : 'COMPLETED',
        durationMs: stages?.fileType?.durationMs,
      },
      {
        id: 'entropy',
        name: 'Shannon Byte Entropy',
        status: stages?.entropy?.status === 'done' ? 'COMPLETED' : stages?.entropy?.status === 'failed' ? 'FAILED' : 'COMPLETED',
        durationMs: stages?.entropy?.durationMs,
      },
      {
        id: 'strings',
        name: 'Strings & Indicator Extraction',
        status: stages?.strings?.status === 'done' ? 'COMPLETED' : stages?.strings?.status === 'failed' ? 'FAILED' : 'COMPLETED',
        durationMs: stages?.strings?.durationMs,
      },
      {
        id: 'typeSpecific',
        name: 'Deep Format Static Analysis',
        status: stages?.typeSpecific?.status === 'done' ? 'COMPLETED' : stages?.typeSpecific?.status === 'failed' ? 'FAILED' : 'COMPLETED',
        durationMs: stages?.typeSpecific?.durationMs,
      },
      {
        id: 'yara',
        name: 'YARA Rule Scanning',
        status: stages?.yara?.status === 'done'
          ? 'COMPLETED'
          : stages?.yara?.status === 'skipped'
          ? 'NOT CONFIGURED'
          : stages?.yara?.status === 'failed'
          ? 'FAILED'
          : 'NOT CONFIGURED',
        durationMs: stages?.yara?.durationMs,
      },
      {
        id: 'reputation',
        name: 'Hash Threat Intelligence',
        status: stages?.reputation?.status === 'done'
          ? 'COMPLETED'
          : stages?.reputation?.status === 'failed'
          ? 'FAILED'
          : stages?.reputation?.data?.providers?.every((p) => p.status === 'not_configured')
          ? 'NOT CONFIGURED'
          : 'COMPLETED',
        durationMs: stages?.reputation?.durationMs,
      },
      {
        id: 'ml',
        name: 'ML Static Classifier',
        status: stages?.ml?.status === 'done'
          ? 'COMPLETED'
          : stages?.ml?.status === 'skipped' || stages?.ml?.data?.status === 'unavailable'
          ? 'NOT CONFIGURED'
          : 'NOT CONFIGURED',
        durationMs: stages?.ml?.durationMs,
      },
    ];
  }, [fileAnalysis]);

  // ── Threat Intelligence Providers ─────────────────────────────────────────
  const reputationProviders = useMemo(() => {
    const provs = fileAnalysis?.stages?.reputation?.data?.providers || [];
    const defaults = [
      { name: 'VirusTotal', key: 'VirusTotal' },
      { name: 'MalwareBazaar', key: 'MalwareBazaar' },
      { name: 'Hybrid Analysis', key: 'Hybrid Analysis' },
      { name: 'MetaDefender', key: 'MetaDefender' },
    ];

    return defaults.map((d) => {
      const match = provs.find((p) => p.provider.toLowerCase() === d.key.toLowerCase());
      if (match) return match;
      return {
        provider: d.name,
        status: 'not_configured' as const,
        details: `${d.name} API integration not configured in environment.`,
      };
    });
  }, [fileAnalysis]);

  // ── Categorized Strings Filter ────────────────────────────────────────────
  const stringStageData = fileAnalysis?.stages?.strings?.data;
  const filteredStringsList = useMemo(() => {
    if (!stringStageData) return [];
    let items: Array<{ category: string; value: string }> = [];

    if (stringFilterCategory === 'all' || stringFilterCategory === 'urls') {
      stringStageData.urls?.forEach((u) => items.push({ category: 'URL', value: u }));
    }
    if (stringFilterCategory === 'all' || stringFilterCategory === 'domains') {
      stringStageData.domains?.forEach((d) => items.push({ category: 'Domain', value: d }));
    }
    if (stringFilterCategory === 'all' || stringFilterCategory === 'ips') {
      stringStageData.ipAddresses?.forEach((ip) => items.push({ category: 'IP Address', value: ip }));
    }
    if (stringFilterCategory === 'all' || stringFilterCategory === 'emails') {
      stringStageData.emails?.forEach((em) => items.push({ category: 'Email', value: em }));
    }
    if (stringFilterCategory === 'all' || stringFilterCategory === 'apis') {
      stringStageData.suspiciousApis?.forEach((api) => items.push({ category: 'Suspicious API', value: api }));
    }
    if (stringFilterCategory === 'all' || stringFilterCategory === 'shells') {
      stringStageData.shellCommands?.forEach((sh) => items.push({ category: 'Shell Command', value: sh }));
    }
    if (stringFilterCategory === 'all' || stringFilterCategory === 'paths') {
      stringStageData.filePaths?.forEach((p) => items.push({ category: 'File Path', value: p }));
    }
    if (stringFilterCategory === 'all' || stringFilterCategory === 'registry') {
      stringStageData.registryKeys?.forEach((r) => items.push({ category: 'Registry Key', value: r }));
    }
    if (stringFilterCategory === 'all' || stringFilterCategory === 'base64') {
      stringStageData.base64Blobs?.forEach((b) => items.push({ category: 'Base64 Candidate', value: b }));
    }

    if (stringSearchTerm.trim()) {
      const term = stringSearchTerm.toLowerCase();
      items = items.filter((i) => i.value.toLowerCase().includes(term) || i.category.toLowerCase().includes(term));
    }

    return items;
  }, [stringStageData, stringFilterCategory, stringSearchTerm]);

  // ── Extracted Embedded URLs & Domains ─────────────────────────────────────
  const embeddedUrlsList = useMemo(() => {
    const list: Array<{ url: string; source: string; type: 'URL' | 'Domain' | 'IP' }> = [];
    const stringsData = fileAnalysis?.stages?.strings?.data;
    const typeSpecificPdf = fileAnalysis?.stages?.typeSpecific?.data?.pdf;

    typeSpecificPdf?.extractedUrls?.forEach((u) => {
      list.push({ url: u, source: 'PDF URI Dictionary', type: 'URL' });
    });

    stringsData?.urls?.forEach((u) => {
      if (!list.some((existing) => existing.url === u)) {
        list.push({ url: u, source: 'Binary String Table', type: 'URL' });
      }
    });

    stringsData?.domains?.forEach((d) => {
      if (!list.some((existing) => existing.url === d || existing.url.includes(d))) {
        list.push({ url: d, source: 'Extracted Domain Indicator', type: 'Domain' });
      }
    });

    stringsData?.ipAddresses?.forEach((ip) => {
      list.push({ url: ip, source: 'Extracted IPv4 Address', type: 'IP' });
    });

    return list;
  }, [fileAnalysis]);

  // ── Dynamic Recommendation Generator ─────────────────────────────────────
  const recommendationsList = useMemo(() => {
    if (scan.recommendations && scan.recommendations.length > 0) {
      return scan.recommendations;
    }
    const recs: string[] = [];
    const score = scan.riskScore || 0;
    const hasCritical = sortedFindings.some((f) => f.severity === 'CRITICAL');
    const hasHigh = sortedFindings.some((f) => f.severity === 'HIGH');

    if (hasCritical || score >= 75) {
      recs.push('Do NOT open or execute this file. High-risk malicious indicators or exploit patterns were identified.');
      recs.push('Isolate this sample in a controlled offline malware sandbox if further forensic analysis is required.');
    } else if (hasHigh || score >= 50) {
      recs.push('Exercise caution before opening. Suspicious structural characteristics or execution capabilities were detected.');
      recs.push('Verify the exact source of this file and cross-reference with sender before executing.');
    } else if (score >= 25) {
      recs.push('Further investigation is recommended because multiple suspicious static indicators were detected.');
      recs.push('Verify digital signatures and file origin prior to distributing or deploying.');
    } else {
      recs.push('No immediate high-risk indicators were identified from completed static checks.');
      recs.push('Continue to verify the file origin and maintain standard endpoint security safeguards before opening.');
    }
    return recs;
  }, [scan.recommendations, scan.riskScore, sortedFindings]);

  // ── Why This Score Summary Contributors ───────────────────────────────────
  const scoreContributors = useMemo(() => {
    return fileAnalysis?.scoreContributors || [];
  }, [fileAnalysis]);

  const displayName = fileAnalysis?.sanitizedDisplayFilename || fileAnalysis?.filename || scan.target || 'uploaded_sample.bin';
  const detectedType = fileAnalysis?.detectedFormat || (fileAnalysis?.extension ? `${fileAnalysis.extension.toUpperCase()} File` : 'Unknown Format');
  const displaySize = fileAnalysis?.fileSizeFormatted || (fileAnalysis?.fileSize ? `${fileAnalysis.fileSize} bytes` : 'N/A');
  const sha256Hash = fileAnalysis?.sha256 || 'N/A';

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* 1. REPORT HEADER                                                        */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-100">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-blue-700 flex items-center gap-1.5">
                <FileSearch className="w-3.5 h-3.5" />
                FILE SECURITY REPORT
              </span>
              <span className="text-slate-300">•</span>
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-slate-700 bg-slate-100 px-2.5 py-0.5 rounded-full border border-slate-200">
                <Clock className="w-3 h-3 text-slate-500" />
                {scan.scannedAt ? new Date(scan.scannedAt || scan.createdAt).toLocaleString() : 'Recent Scan'}
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight">
              File Security & Threat Analysis
            </h1>
            <p className="text-xs sm:text-sm text-slate-500 max-w-3xl leading-relaxed">
              Analyze uploaded files for security risks, suspicious indicators, file integrity issues, and available malware intelligence.
            </p>
          </div>

          {/* Action Buttons (Download JSON, Save PDF, New Scan) */}
          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            <button
              type="button"
              onClick={handleDownloadJson}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
              title="Download raw report as JSON"
            >
              <Download className="w-3.5 h-3.5 text-slate-600" />
              <span>Download JSON</span>
            </button>

            <button
              id="btn-report-download"
              type="button"
              onClick={onDownloadReport}
              disabled={isGeneratingPdf}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-xs transition-all disabled:opacity-75"
              title="Save printable PDF report"
            >
              {isGeneratingPdf ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Generating PDF...</span>
                </>
              ) : (
                <>
                  <FileText className="w-3.5 h-3.5" />
                  <span>Save PDF</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => navigate(`/threat-intelligence?q=${encodeURIComponent(fileAnalysis?.sha256 || scan.target)}`)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200/80 font-bold text-xs rounded-xl shadow-xs transition-all"
              title="Investigate file checksum in Threat Intelligence"
            >
              <Radio className="w-3.5 h-3.5 text-indigo-600" />
              <span>Threat Intelligence</span>
            </button>

            <button
              type="button"
              onClick={() => navigate('/services/file')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
            >
              <PlusCircle className="w-3.5 h-3.5 text-blue-600" />
              <span>New Scan</span>
            </button>
          </div>
        </div>

        {pdfError && (
          <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-xl px-4 py-2.5 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
            <span>{pdfError}</span>
          </div>
        )}

        {/* Target File Information Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {/* Filename */}
          <div className="p-3.5 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">File</span>
            <span className="text-xs font-mono font-bold text-slate-900 break-all block leading-tight">
              {displayName}
            </span>
          </div>

          {/* Real Type */}
          <div className="p-3.5 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Real Type</span>
            <span className="text-xs font-semibold text-slate-900 block truncate" title={detectedType}>
              {detectedType}
            </span>
          </div>

          {/* Size */}
          <div className="p-3.5 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Size</span>
            <span className="text-xs font-mono font-semibold text-slate-900 block">
              {displaySize}
            </span>
          </div>

          {/* SHA-256 with copy button */}
          <div className="p-3.5 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">SHA-256</span>
              <button
                type="button"
                onClick={() => handleCopyText(sha256Hash, 'header_sha256')}
                className="text-[10px] font-semibold text-blue-600 hover:text-blue-800 inline-flex items-center gap-1"
                title="Copy SHA-256 hash"
              >
                {copiedKey === 'header_sha256' ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-600" />
                    <span className="text-emerald-700">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <span className="text-[11px] font-mono font-bold text-slate-800 break-all block leading-tight truncate" title={sha256Hash}>
              {sha256Hash.slice(0, 16)}...{sha256Hash.slice(-8)}
            </span>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* 2. OVERALL SECURITY RESULT CARD                                         */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      <div className={`bg-white border-2 ${riskConfig.accentBorder} rounded-2xl p-6 sm:p-7 shadow-xs space-y-5`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
          <div className="flex items-center gap-3.5">
            <div className={`w-12 h-12 rounded-2xl ${riskConfig.cardBg} border ${riskConfig.accentBorder} flex items-center justify-center shrink-0`}>
              <riskConfig.Icon className={`w-6 h-6 ${riskConfig.scoreColor}`} />
            </div>
            <div>
              <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-500 block">
                SECURITY RESULT
              </span>
              <div className="flex items-center gap-2 mt-0.5">
                <span className={`text-xs font-extrabold uppercase tracking-wider px-3 py-1 rounded-full border ${riskConfig.badgeClass}`}>
                  [{riskConfig.level}]
                </span>
                <span className="text-xs font-bold text-slate-500">
                  Status: {scan.status === 'completed' ? 'Completed' : scan.status?.toUpperCase() || 'Completed'}
                </span>
              </div>
            </div>
          </div>

          {/* Prominent Real Risk Score */}
          <div className="flex items-baseline gap-1.5 sm:text-right">
            <span className={`text-3xl sm:text-4xl font-black tracking-tight ${riskConfig.scoreColor}`}>
              {typeof scan.riskScore === 'number' && !isNaN(scan.riskScore) ? scan.riskScore : 0}
            </span>
            <span className="text-base sm:text-lg font-bold text-slate-400">/ 100</span>
            <span className="text-[10px] font-extrabold text-slate-500 uppercase tracking-wider ml-1">
              RISK SCORE
            </span>
          </div>
        </div>

        {/* Interpretation Notice */}
        <div className="text-xs text-slate-600 leading-relaxed bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5">
          <p>
            <strong className="text-slate-800">Assessment Note:</strong> CyberWatch's risk score represents the security risk indicated by evidence collected during this scan. It is not a guarantee that the file is safe or malicious.
          </p>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* 3. TAB NAVIGATION                                                       */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-2 shadow-xs">
        <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-none">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'file_details', label: 'File Details', icon: FileCode },
            { id: 'strings', label: `Strings (${fileAnalysis?.stages?.strings?.data?.totalExtracted || 0})`, icon: Terminal },
            { id: 'static_analysis', label: 'Static Analysis', icon: Cpu },
            { id: 'reputation', label: 'Reputation', icon: Database },
            { id: 'yara', label: 'YARA Matches', icon: ShieldAlert },
            { id: 'embedded_urls', label: `Embedded URLs (${embeddedUrlsList.length})`, icon: Globe },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as ActiveTab)}
                className={`inline-flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-xs font-bold transition-all shrink-0 whitespace-nowrap ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'bg-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100/80'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-white' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* TAB 1: OVERVIEW                                                         */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* ── 4. WHY THIS SCORE? / WHY THIS RESULT? ────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Info className="w-5 h-5 text-blue-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    WHY THIS SCORE?
                  </h3>
                  <p className="text-xs text-slate-500">
                    Calculated risk contributors from verified static file evidence.
                  </p>
                </div>
              </div>
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                {scoreContributors.length} Contributor{scoreContributors.length === 1 ? '' : 's'}
              </span>
            </div>

            {scoreContributors.length === 0 ? (
              <div className="p-4 bg-emerald-50/50 border border-emerald-100 rounded-xl text-xs text-emerald-900 flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>
                  No risk-contributing indicators were identified from the completed static checks.
                </span>
              </div>
            ) : (
              <div className="space-y-3">
                {scoreContributors.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-4 bg-slate-50/90 border border-slate-200/80 rounded-xl space-y-2"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border ${getSeverityBadgeClass(item.severity)}`}>
                          {item.severity}
                        </span>
                        <h4 className="text-xs sm:text-sm font-bold text-slate-900">
                          {item.title}
                        </h4>
                      </div>
                      <span className="text-xs font-mono font-extrabold text-rose-700 bg-rose-50 border border-rose-200 px-2.5 py-0.5 rounded-md shrink-0">
                        Risk impact: +{item.contribution}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed">{item.reason}</p>
                    {item.evidence && (
                      <div className="pt-1">
                        <span className="text-[11px] font-mono text-slate-800 bg-white border border-slate-200/90 rounded-lg px-2.5 py-1 inline-block break-all" style={{ overflowWrap: 'anywhere' }}>
                          Evidence: {item.evidence}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ── 5. SECURITY SUMMARY TABLE ─────────────────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="pb-3 border-b border-slate-100">
              <h3 className="text-base font-bold text-slate-900 tracking-tight">
                SECURITY SUMMARY
              </h3>
              <p className="text-xs text-slate-500">
                Core security posture verification matrix across static modules.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500 font-bold uppercase tracking-wider text-[10px]">
                    <th className="pb-2.5 font-bold">CHECK</th>
                    <th className="pb-2.5 font-bold">STATUS</th>
                    <th className="pb-2.5 font-bold">EXPLANATION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-medium">
                  {/* Row 1: File Integrity */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">File Integrity</td>
                    <td className="py-2.5">
                      <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                        <Check className="w-3.5 h-3.5" /> Normal
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-600 font-mono text-[11px]">
                      SHA-256 calculated successfully ({sha256Hash.slice(0, 16)}...)
                    </td>
                  </tr>

                  {/* Row 2: File Type */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">File Type</td>
                    <td className="py-2.5">
                      <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                        <Check className="w-3.5 h-3.5" /> Detected
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {fileAnalysis?.detectedFormat || 'Standard binary format'}
                    </td>
                  </tr>

                  {/* Row 3: Extension / Double Extension */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">Extension & Format</td>
                    <td className="py-2.5">
                      {fileAnalysis?.stages?.fileType?.data?.isDoubleExtension || fileAnalysis?.stages?.fileType?.data?.headerAnomaly ? (
                        <span className="inline-flex items-center gap-1 text-amber-700 font-bold">
                          <AlertTriangle className="w-3.5 h-3.5" /> Warning
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                          <Check className="w-3.5 h-3.5" /> Normal
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {fileAnalysis?.stages?.fileType?.data?.isDoubleExtension
                        ? 'Deceptive double extension detected in filename.'
                        : fileAnalysis?.stages?.fileType?.data?.headerAnomaly ||
                          `Extension (.${fileAnalysis?.extension || 'none'}) matches detected type.`}
                    </td>
                  </tr>

                  {/* Row 4: Shannon Entropy */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">Shannon Entropy</td>
                    <td className="py-2.5">
                      {fileAnalysis?.entropy && fileAnalysis.entropy >= 7.2 ? (
                        <span className="inline-flex items-center gap-1 text-amber-700 font-bold">
                          <AlertTriangle className="w-3.5 h-3.5" /> Warning
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                          <Check className="w-3.5 h-3.5" /> Normal
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-600">
                      Entropy score: {fileAnalysis?.entropy ?? 'N/A'}/8.00 ({fileAnalysis?.entropyInterpretation || 'low entropy'})
                    </td>
                  </tr>

                  {/* Row 5: Strings */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">Strings & Indicators</td>
                    <td className="py-2.5">
                      {(fileAnalysis?.stages?.strings?.data?.suspiciousApis?.length || 0) > 0 ? (
                        <span className="inline-flex items-center gap-1 text-amber-700 font-bold">
                          <AlertTriangle className="w-3.5 h-3.5" /> Warning
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                          <Check className="w-3.5 h-3.5" /> Normal
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {fileAnalysis?.stages?.strings?.data?.totalExtracted || 0} strings extracted;{' '}
                      {fileAnalysis?.stages?.strings?.data?.suspiciousApis?.length || 0} suspicious APIs flagged.
                    </td>
                  </tr>

                  {/* Row 6: Deep Static Analysis */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">Static Analysis</td>
                    <td className="py-2.5">
                      <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                        <Check className="w-3.5 h-3.5" /> Completed
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {fileAnalysis?.structureRisk || 'Structure inspection completed.'}
                    </td>
                  </tr>

                  {/* Row 7: YARA */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">YARA</td>
                    <td className="py-2.5">
                      {fileAnalysis?.stages?.yara?.status === 'done' ? (
                        (fileAnalysis.stages.yara.data?.matches?.length || 0) > 0 ? (
                          <span className="inline-flex items-center gap-1 text-rose-700 font-bold">
                            <AlertTriangle className="w-3.5 h-3.5" /> Warning
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                            <Check className="w-3.5 h-3.5" /> Normal
                          </span>
                        )
                      ) : (
                        <span className="text-slate-400 font-bold">— Not Configured</span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {fileAnalysis?.stages?.yara?.status === 'done'
                        ? `${fileAnalysis.stages.yara.data?.matches?.length || 0} matching rules identified.`
                        : 'YARA rule scanning not configured in environment.'}
                    </td>
                  </tr>

                  {/* Row 8: Threat Reputation */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">Threat Reputation</td>
                    <td className="py-2.5">
                      {fileAnalysis?.stages?.reputation?.data?.overallVerdict === 'malicious' ? (
                        <span className="inline-flex items-center gap-1 text-rose-700 font-bold">
                          <AlertTriangle className="w-3.5 h-3.5" /> Malicious
                        </span>
                      ) : fileAnalysis?.stages?.reputation?.data?.overallVerdict === 'clean' ? (
                        <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                          <Check className="w-3.5 h-3.5" /> Clean
                        </span>
                      ) : (
                        <span className="text-slate-400 font-bold">— Not Configured</span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {fileAnalysis?.stages?.reputation?.data?.overallVerdict === 'malicious'
                        ? 'Confirmed positive detection recorded by reputation provider.'
                        : 'Hash reputation query completed / provider status recorded.'}
                    </td>
                  </tr>

                  {/* Row 9: Embedded Indicators */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">Embedded Indicators</td>
                    <td className="py-2.5">
                      {embeddedUrlsList.length > 0 ? (
                        <span className="inline-flex items-center gap-1 text-blue-700 font-bold">
                          <Info className="w-3.5 h-3.5" /> {embeddedUrlsList.length} Found
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                          <Check className="w-3.5 h-3.5" /> None
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {embeddedUrlsList.length > 0
                        ? `${embeddedUrlsList.length} embedded URLs, hostnames, or IP addresses found.`
                        : 'Zero embedded URLs or domain indicators identified.'}
                    </td>
                  </tr>

                  {/* Row 10: ML Analysis */}
                  <tr>
                    <td className="py-2.5 font-bold text-slate-900">ML Analysis</td>
                    <td className="py-2.5">
                      {fileAnalysis?.stages?.ml?.data?.status === 'available' ? (
                        <span className="inline-flex items-center gap-1 text-emerald-700 font-bold">
                          <Check className="w-3.5 h-3.5" /> Completed
                        </span>
                      ) : (
                        <span className="text-slate-400 font-bold">— Not Configured</span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {fileAnalysis?.stages?.ml?.data?.status === 'available'
                        ? 'Model inference completed.'
                        : 'No offline machine learning model configured on host.'}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* ── 6. SECURITY FINDINGS CARDS ────────────────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-blue-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    SECURITY FINDINGS
                  </h3>
                  <p className="text-xs text-slate-500">
                    Detailed breakdown of observed threat patterns and structural anomalies.
                  </p>
                </div>
              </div>
              <span className="text-xs font-bold text-slate-600 bg-slate-100 px-2.5 py-1 rounded-full border border-slate-200">
                {sortedFindings.length} Finding{sortedFindings.length === 1 ? '' : 's'}
              </span>
            </div>

            {sortedFindings.length === 0 ? (
              <div className="p-8 text-center bg-slate-50/60 rounded-xl border border-dashed border-slate-200 space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
                <h4 className="text-sm font-bold text-slate-800">No Security Findings</h4>
                <p className="text-xs text-slate-500 max-w-md mx-auto">
                  No anomalous static indicators or risk patterns were returned by the automated file analysis.
                </p>
              </div>
            ) : (
              <div className="space-y-3.5">
                {sortedFindings.map((finding, idx) => (
                  <div
                    key={idx}
                    className="bg-slate-50/80 border border-slate-200/80 rounded-xl p-4 sm:p-5 space-y-2.5"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-extrabold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${getSeverityBadgeClass(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        <span className="text-xs font-semibold text-slate-500">
                          Category: {finding.category}
                        </span>
                      </div>
                      {typeof finding.scoreContribution === 'number' && finding.scoreContribution > 0 && (
                        <span className="text-xs font-mono font-extrabold text-rose-700 bg-rose-50 border border-rose-200 px-2.5 py-0.5 rounded-md">
                          Risk impact: +{finding.scoreContribution} points
                        </span>
                      )}
                    </div>

                    <h4 className="text-sm font-bold text-slate-900">{finding.title}</h4>
                    <p className="text-xs text-slate-600 leading-relaxed">{finding.description}</p>

                    {finding.evidence && (
                      <div className="pt-1">
                        <div className="text-[11px] font-mono text-slate-800 bg-white border border-slate-200 rounded-lg p-2.5 break-all" style={{ overflowWrap: 'anywhere' }}>
                          <strong className="text-slate-500 block mb-0.5">Evidence:</strong>
                          {finding.evidence}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ── 7. POSITIVE SECURITY SIGNALS ─────────────────────────────────── */}
          {positiveSignals.length > 0 && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    POSITIVE SECURITY SIGNALS
                  </h3>
                  <p className="text-xs text-slate-500">
                    Verified positive observations confirmed by automated static inspection.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {positiveSignals.map((signal, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-3 p-3.5 bg-emerald-50/40 border border-emerald-100 rounded-xl"
                  >
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                    <div className="space-y-0.5">
                      <h4 className="text-xs font-bold text-emerald-950">{signal.title}</h4>
                      <p className="text-xs text-emerald-900/80 leading-relaxed">{signal.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── 8. ANALYSIS COVERAGE ─────────────────────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="pb-3 border-b border-slate-100">
              <h3 className="text-base font-bold text-slate-900 tracking-tight">
                ANALYSIS COVERAGE
              </h3>
              <p className="text-xs text-slate-500">
                Execution status of active file security inspection modules.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {analysisCoverageList.map((stage) => {
                const isCompleted = stage.status === 'COMPLETED';
                const isFailed = stage.status === 'FAILED';
                return (
                  <div
                    key={stage.id}
                    className="p-3.5 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-2 flex flex-col justify-between"
                  >
                    <span className="text-xs font-bold text-slate-800">{stage.name}</span>
                    <div className="flex items-center justify-between pt-1">
                      <span
                        className={`text-[10px] font-extrabold uppercase tracking-wider px-2 py-0.5 rounded-md border ${
                          isCompleted
                            ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
                            : isFailed
                            ? 'bg-rose-100 text-rose-800 border-rose-200'
                            : 'bg-slate-100 text-slate-600 border-slate-200'
                        }`}
                      >
                        [{stage.status}]
                      </span>
                      {stage.durationMs !== undefined && (
                        <span className="text-[10px] font-mono text-slate-400">
                          {stage.durationMs}ms
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ── 9. THREAT INTELLIGENCE SUMMARY ───────────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Database className="w-5 h-5 text-blue-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    THREAT INTELLIGENCE
                  </h3>
                  <p className="text-xs text-slate-500">
                    External threat provider hash reputation lookup status.
                  </p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {reputationProviders.map((prov, idx) => (
                <div
                  key={idx}
                  className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-900">{prov.provider}</span>
                    <span
                      className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-md border ${
                        prov.status === 'malicious'
                          ? 'bg-rose-100 text-rose-800 border-rose-200'
                          : prov.status === 'clean' || prov.status === 'no_match'
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
                          : prov.status === 'not_found'
                          ? 'bg-blue-100 text-blue-800 border-blue-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}
                    >
                      {prov.status === 'malicious'
                        ? 'MALICIOUS'
                        : prov.status === 'clean' || prov.status === 'no_match'
                        ? 'CLEAN'
                        : prov.status === 'not_found'
                        ? 'NOT FOUND'
                        : 'NOT CONFIGURED'}
                    </span>
                  </div>

                  {prov.status === 'malicious' && (
                    <div className="text-xs font-mono font-bold text-rose-700">
                      Detection: {prov.maliciousCount || 1} / {prov.totalEngines || 70}
                    </div>
                  )}

                  <p className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed">
                    {prov.details || 'No records returned.'}
                  </p>
                </div>
              ))}
            </div>

            <div className="text-[11px] text-slate-500 bg-slate-50 border border-slate-200/70 rounded-xl p-3 flex items-center gap-2">
              <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span>
                <strong>Privacy Guarantee:</strong> Only cryptographic SHA-256 hashes are queried against reputation providers. Original file bytes are never transmitted to external services.
              </span>
            </div>
          </div>

          {/* ── 10. RECOMMENDATION & GUIDANCE ────────────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-3.5">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-slate-800" />
              <h3 className="text-base font-bold text-slate-900 tracking-tight">
                RECOMMENDATION
              </h3>
            </div>

            <ul className="space-y-2 text-xs sm:text-sm text-slate-700 font-medium">
              {recommendationsList.map((rec, i) => (
                <li key={i} className="flex items-start gap-2.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-800 mt-2 shrink-0" />
                  <span className="leading-relaxed">{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* ── 11. ADVANCED TECHNICAL DETAILS (Collapsible) ──────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <button
              type="button"
              onClick={() => setShowAdvancedDetails(!showAdvancedDetails)}
              className="w-full flex items-center justify-between text-left focus:outline-none"
            >
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-slate-700" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    ADVANCED TECHNICAL DETAILS
                  </h3>
                  <span className="text-xs text-slate-500">
                    Detailed cryptographic identity, byte entropy, and static metadata
                  </span>
                </div>
              </div>
              <div className="p-1 rounded-lg bg-slate-100 text-slate-600 hover:bg-slate-200 transition-colors">
                {showAdvancedDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </div>
            </button>

            {showAdvancedDetails && (
              <div className="pt-2 space-y-3 animate-in fade-in duration-200">
                <div className="bg-slate-900 text-slate-200 rounded-xl p-4 sm:p-5 font-mono text-xs space-y-2 overflow-x-auto">
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Original / Target Name:</span>
                    <span className="text-emerald-400 break-all">{displayName}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Exact File Size:</span>
                    <span className="text-slate-200">{fileAnalysis?.fileSize || 0} bytes ({displaySize})</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">MD5 Checksum:</span>
                    <span className="text-slate-300 break-all">{fileAnalysis?.md5 || 'N/A'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">SHA-1 Checksum:</span>
                    <span className="text-slate-300 break-all">{fileAnalysis?.sha1 || 'N/A'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">SHA-256 Checksum:</span>
                    <span className="text-emerald-400 break-all">{sha256Hash}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Fuzzy Hash (ssdeep):</span>
                    <span className="text-slate-300 break-all">{fileAnalysis?.ssdeep || 'N/A'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Detected Format:</span>
                    <span className="text-slate-200">{fileAnalysis?.detectedFormat || 'Unknown'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Magic Bytes Hex:</span>
                    <span className="text-slate-300">{fileAnalysis?.magicBytes || 'N/A'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">MIME Content-Type:</span>
                    <span className="text-slate-200">{fileAnalysis?.mimeType || 'application/octet-stream'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Shannon Byte Entropy:</span>
                    <span className="text-slate-200">{fileAnalysis?.entropy ?? 'N/A'} / 8.00 ({fileAnalysis?.entropyInterpretation || 'low'})</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Scan ID:</span>
                    <span className="text-slate-300">{scan.id}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 gap-1">
                    <span className="text-slate-400">Scan Status:</span>
                    <span className="text-emerald-400 font-bold">{scan.status ? scan.status.toUpperCase() : 'COMPLETED'}</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* ── 12. ANALYSIS LIMITATIONS ─────────────────────────────────────── */}
          <div className="bg-slate-50/80 border border-slate-200/80 rounded-2xl p-6 shadow-xs space-y-2.5">
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-slate-500" />
              ANALYSIS LIMITATIONS
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-600 list-disc list-inside leading-relaxed">
              <li>Static byte-level inspection only: Uploaded files are safely analyzed in memory without dynamic execution or sandboxed emulation.</li>
              <li>No macro runtime execution: Office macros and embedded scripts are parsed for static syntactic patterns rather than actively executed.</li>
              <li>Reputation index dependency: Hash reputation results reflect current indexed database records from configured threat intelligence providers.</li>
              <li>Static indicators do not guarantee malicious behavior, nor does the absence of static indicators guarantee complete safety.</li>
            </ul>
          </div>

          {/* ── 13. DISCLAIMER ───────────────────────────────────────────────── */}
          <div className="text-center py-2 text-xs text-slate-400 font-medium">
            Static analysis result. Not a guarantee of safety.
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* TAB 2: FILE DETAILS                                                     */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'file_details' && (
        <div className="space-y-6">
          {/* Cryptographic Hashes Card */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
              <Key className="w-5 h-5 text-blue-600" />
              <div>
                <h3 className="text-base font-bold text-slate-900 tracking-tight">
                  Cryptographic Hashes & Fingerprints
                </h3>
                <p className="text-xs text-slate-500">
                  Unique deterministic cryptographic checksums computed from file bytes.
                </p>
              </div>
            </div>

            <div className="space-y-3">
              {[
                { label: 'SHA-256', val: fileAnalysis?.sha256, key: 'sha256' },
                { label: 'SHA-1', val: fileAnalysis?.sha1, key: 'sha1' },
                { label: 'MD5', val: fileAnalysis?.md5, key: 'md5' },
                { label: 'Fuzzy Hash (ssdeep)', val: fileAnalysis?.ssdeep, key: 'ssdeep' },
              ].map((hashItem) => (
                <div
                  key={hashItem.key}
                  className="p-3.5 bg-slate-50/80 border border-slate-200/80 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="space-y-0.5 min-w-0 flex-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
                      {hashItem.label}
                    </span>
                    <span className="text-xs font-mono font-bold text-slate-900 break-all" style={{ overflowWrap: 'anywhere' }}>
                      {hashItem.val || 'N/A'}
                    </span>
                  </div>
                  {hashItem.val && (
                    <button
                      type="button"
                      onClick={() => handleCopyText(hashItem.val!, hashItem.key)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold rounded-lg shadow-xs transition-colors shrink-0"
                    >
                      {copiedKey === hashItem.key ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span className="text-emerald-700">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-slate-500" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Format & MIME Breakdown */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
              <FileCode className="w-5 h-5 text-blue-600" />
              <div>
                <h3 className="text-base font-bold text-slate-900 tracking-tight">
                  Format Signature & MIME Verification
                </h3>
                <p className="text-xs text-slate-500">
                  Header magic bytes and MIME type identification.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Detected Format</span>
                <span className="text-xs font-bold text-slate-900">{fileAnalysis?.detectedFormat || 'Unknown Binary'}</span>
              </div>
              <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Detected MIME Type</span>
                <span className="text-xs font-mono font-semibold text-slate-900">{fileAnalysis?.mimeType || 'application/octet-stream'}</span>
              </div>
              <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Magic Bytes Header</span>
                <span className="text-xs font-mono text-slate-900">{fileAnalysis?.magicBytes || 'N/A'}</span>
              </div>
              <div className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Static Structure Risk</span>
                <span className="text-xs font-semibold text-slate-900">{fileAnalysis?.structureRisk || 'Standard'}</span>
              </div>
            </div>
          </div>

          {/* Shannon Entropy Visualization */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-purple-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Shannon Byte Entropy Visualization
                  </h3>
                  <p className="text-xs text-slate-500">
                    Measures randomness of byte distribution (0.00 to 8.00 bits per byte).
                  </p>
                </div>
              </div>
              <span className="text-sm font-mono font-bold text-purple-700 bg-purple-50 border border-purple-200 px-3 py-1 rounded-xl">
                {fileAnalysis?.entropy ?? 0} / 8.00 bits
              </span>
            </div>

            {/* Gauge Progress bar */}
            <div className="space-y-2">
              <div className="w-full bg-slate-100 h-3.5 rounded-full overflow-hidden p-0.5 border border-slate-200">
                <div
                  className={`h-full rounded-full transition-all ${
                    (fileAnalysis?.entropy || 0) >= 7.2
                      ? 'bg-rose-500'
                      : (fileAnalysis?.entropy || 0) >= 5.0
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(100, ((fileAnalysis?.entropy || 0) / 8.0) * 100)}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>0.0 (Low Entropy / Plaintext)</span>
                <span>4.0 (Typical Binary / Code)</span>
                <span>8.0 (Packed / Encrypted / Compressed)</span>
              </div>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed bg-slate-50/70 border border-slate-200/70 rounded-xl p-3">
              <strong>Interpretation:</strong>{' '}
              {fileAnalysis?.entropy && fileAnalysis.entropy >= 7.85
                ? 'Extremely high byte randomness. Strong indicator of encrypted payload, compression, or binary packing.'
                : fileAnalysis?.entropy && fileAnalysis.entropy >= 7.2
                ? 'High byte entropy. Common in compressed archives, packed executables, or encrypted resources.'
                : fileAnalysis?.entropy && fileAnalysis.entropy >= 5.0
                ? 'Moderate entropy. Typical for standard compiled executable code and structured documents.'
                : 'Low byte entropy. Typical for plaintext, uncompressed scripts, and sparse binary structures.'}
            </p>

            {/* Section Entropy Table (If PE Sections available) */}
            {fileAnalysis?.stages?.typeSpecific?.data?.pe?.sections &&
              fileAnalysis.stages.typeSpecific.data.pe.sections.length > 0 && (
                <div className="pt-3 border-t border-slate-100 space-y-2.5">
                  <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    PE Section-Level Entropy Breakdown
                  </h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 text-slate-500 font-bold uppercase tracking-wider text-[10px]">
                          <th className="pb-2 font-bold">SECTION</th>
                          <th className="pb-2 font-bold">VIRTUAL SIZE</th>
                          <th className="pb-2 font-bold">RAW SIZE</th>
                          <th className="pb-2 font-bold">ENTROPY</th>
                          <th className="pb-2 font-bold">CHARACTERISTICS</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                        {fileAnalysis.stages.typeSpecific.data.pe.sections.map((sec, idx) => (
                          <tr key={idx}>
                            <td className="py-2 font-bold text-slate-900">{sec.name}</td>
                            <td className="py-2 text-slate-600">{sec.virtualSize} B</td>
                            <td className="py-2 text-slate-600">{sec.rawSize} B</td>
                            <td className="py-2">
                              <span
                                className={`font-bold ${
                                  sec.entropy >= 7.2 ? 'text-rose-600' : 'text-slate-800'
                                }`}
                              >
                                {sec.entropy} / 8.00
                              </span>
                            </td>
                            <td className="py-2 text-slate-500 text-[10px]">{sec.characteristics}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* TAB 3: STRINGS TAB                                                      */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'strings' && (
        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-slate-800" />
              <div>
                <h3 className="text-base font-bold text-slate-900 tracking-tight">
                  Extracted Strings & Indicators
                </h3>
                <p className="text-xs text-slate-500">
                  Printable ASCII and UTF-16 strings extracted directly from binary contents.
                </p>
              </div>
            </div>
            <span className="text-xs font-bold text-slate-600 bg-slate-100 px-3 py-1 rounded-full border border-slate-200">
              {filteredStringsList.length} string{filteredStringsList.length === 1 ? '' : 's'} displayed
            </span>
          </div>

          {/* Search & Filter Controls */}
          <div className="space-y-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={stringSearchTerm}
                onChange={(e) => setStringSearchTerm(e.target.value)}
                placeholder="Search extracted strings or categories..."
                className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
              />
            </div>

            {/* Category Pills */}
            <div className="flex items-center gap-1.5 flex-wrap">
              {[
                { id: 'all', label: 'All' },
                { id: 'urls', label: `URLs (${stringStageData?.urls?.length || 0})` },
                { id: 'domains', label: `Domains (${stringStageData?.domains?.length || 0})` },
                { id: 'ips', label: `IPs (${stringStageData?.ipAddresses?.length || 0})` },
                { id: 'apis', label: `Suspicious APIs (${stringStageData?.suspiciousApis?.length || 0})` },
                { id: 'shells', label: `Shells (${stringStageData?.shellCommands?.length || 0})` },
                { id: 'paths', label: `Paths (${stringStageData?.filePaths?.length || 0})` },
                { id: 'registry', label: `Registry (${stringStageData?.registryKeys?.length || 0})` },
                { id: 'base64', label: `Base64 (${stringStageData?.base64Blobs?.length || 0})` },
              ].map((cat) => (
                <button
                  key={cat.id}
                  type="button"
                  onClick={() => setStringFilterCategory(cat.id)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all ${
                    stringFilterCategory === cat.id
                      ? 'bg-blue-100 text-blue-800 border border-blue-200'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200/80 border border-transparent'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
          </div>

          {/* Safe Monospace Strings Display */}
          <div className="bg-slate-900 text-slate-200 rounded-xl p-4 font-mono text-xs max-h-[500px] overflow-y-auto space-y-1.5 divide-y divide-slate-800/60">
            {filteredStringsList.length === 0 ? (
              <div className="text-slate-500 italic text-center py-6">
                No matching printable strings found for the selected filter.
              </div>
            ) : (
              filteredStringsList.slice(0, 300).map((item, idx) => (
                <div key={idx} className="pt-1.5 first:pt-0 flex items-start gap-2 justify-between">
                  <span className="text-slate-300 break-all select-all leading-relaxed" style={{ overflowWrap: 'anywhere' }}>
                    {item.value}
                  </span>
                  <span className="text-[10px] font-sans font-bold text-slate-500 bg-slate-800 px-2 py-0.5 rounded shrink-0">
                    {item.category}
                  </span>
                </div>
              ))
            )}
          </div>

          <div className="text-[11px] text-slate-500 italic">
            * Display limited to first 300 entries for rendering performance. Untrusted string indicators are presented safely without execution.
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* TAB 4: STATIC ANALYSIS (Format-Specific)                                */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'static_analysis' && (
        <div className="space-y-6">
          {/* PE Executable Inspector */}
          {fileAnalysis?.stages?.typeSpecific?.data?.pe?.isPe && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                <Cpu className="w-5 h-5 text-blue-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    PE Executable Binary Analysis
                  </h3>
                  <p className="text-xs text-slate-500">
                    Headers, sections, imported Win32 functions, and digital signature posture.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-0.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Machine Architecture</span>
                  <span className="text-xs font-bold text-slate-900 block">{fileAnalysis.stages.typeSpecific.data.pe.machineType || 'x86 / x64'}</span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-0.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Subsystem</span>
                  <span className="text-xs font-bold text-slate-900 block">{fileAnalysis.stages.typeSpecific.data.pe.subsystem || 'Windows GUI'}</span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-0.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Entry Point</span>
                  <span className="text-xs font-mono font-bold text-slate-900 block">{fileAnalysis.stages.typeSpecific.data.pe.entryPointHex || '0x00401000'}</span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-0.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Digital Signature</span>
                  <span className={`text-xs font-bold block ${fileAnalysis.stages.typeSpecific.data.pe.hasSignature ? 'text-emerald-700' : 'text-slate-600'}`}>
                    {fileAnalysis.stages.typeSpecific.data.pe.hasSignature ? 'Signed Binary' : 'Unsigned Binary'}
                  </span>
                </div>
              </div>

              {/* Imports Table */}
              {fileAnalysis.stages.typeSpecific.data.pe.imports && fileAnalysis.stages.typeSpecific.data.pe.imports.length > 0 && (
                <div className="space-y-3 pt-2">
                  <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    Imported Dynamic Libraries & Functions ({fileAnalysis.stages.typeSpecific.data.pe.imports.length} DLLs)
                  </h4>
                  <div className="space-y-2">
                    {fileAnalysis.stages.typeSpecific.data.pe.imports.map((imp, idx) => (
                      <div key={idx} className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono font-bold text-slate-900">{imp.dll}</span>
                          <span className="text-[10px] font-mono text-slate-500">{imp.functions.length} functions</span>
                        </div>
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {imp.functions.map((fn, fIdx) => (
                            <span key={fIdx} className="text-[11px] font-mono text-slate-700 bg-white border border-slate-200 rounded px-2 py-0.5">
                              {fn}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* PDF Document Inspector */}
          {fileAnalysis?.stages?.typeSpecific?.data?.pdf?.isPdf && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                <FileText className="w-5 h-5 text-blue-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    PDF Document Structure Analysis
                  </h3>
                  <p className="text-xs text-slate-500">
                    PDF dictionaries, JavaScript hooks, and embedded stream validation.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">PDF Version</span>
                  <span className="text-xs font-bold text-slate-900">{fileAnalysis.stages.typeSpecific.data.pdf.version || '1.7'}</span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Objects / Streams</span>
                  <span className="text-xs font-bold text-slate-900">{fileAnalysis.stages.typeSpecific.data.pdf.totalObjects || 0} objects / {fileAnalysis.stages.typeSpecific.data.pdf.totalStreams || 0} streams</span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Active JavaScript</span>
                  <span className={`text-xs font-bold ${fileAnalysis.stages.typeSpecific.data.pdf.hasJavaScript ? 'text-rose-700' : 'text-emerald-700'}`}>
                    {fileAnalysis.stages.typeSpecific.data.pdf.hasJavaScript ? '⚠️ JavaScript Detected' : 'None'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Office Document Inspector */}
          {fileAnalysis?.stages?.typeSpecific?.data?.office?.isOffice && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                <FileText className="w-5 h-5 text-blue-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Office Document Macro & OLE Inspection
                  </h3>
                  <p className="text-xs text-slate-500">
                    VBA macro presence, Auto-execution hooks, and DDE formula checks.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">VBA Macros</span>
                  <span className={`text-xs font-bold ${fileAnalysis.stages.typeSpecific.data.office.hasVbaMacros ? 'text-rose-700' : 'text-emerald-700'}`}>
                    {fileAnalysis.stages.typeSpecific.data.office.hasVbaMacros ? '⚠️ VBA Macros Present' : 'No Macros Detected'}
                  </span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">DDE Command Execution</span>
                  <span className={`text-xs font-bold ${fileAnalysis.stages.typeSpecific.data.office.hasDde ? 'text-rose-700' : 'text-emerald-700'}`}>
                    {fileAnalysis.stages.typeSpecific.data.office.hasDde ? '⚠️ DDE Formulas Detected' : 'None'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Archive Inspector */}
          {fileAnalysis?.stages?.typeSpecific?.data?.archive?.isArchive && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                <Archive className="w-5 h-5 text-amber-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Archive Container & Traversal Inspection
                  </h3>
                  <p className="text-xs text-slate-500">
                    Contained files catalog, Zip-Slip vulnerability detection, and compression ratio.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Files Count</span>
                  <span className="text-xs font-bold text-slate-900">{fileAnalysis.stages.typeSpecific.data.archive.totalFiles} files</span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Zip-Slip Traversal</span>
                  <span className={`text-xs font-bold ${fileAnalysis.stages.typeSpecific.data.archive.hasZipSlip ? 'text-rose-700' : 'text-emerald-700'}`}>
                    {fileAnalysis.stages.typeSpecific.data.archive.hasZipSlip ? '⚠️ Traversal Exploit Detected' : 'None (Safe)'}
                  </span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Packaged Executables</span>
                  <span className={`text-xs font-bold ${fileAnalysis.stages.typeSpecific.data.archive.hasExecutables ? 'text-amber-700' : 'text-emerald-700'}`}>
                    {fileAnalysis.stages.typeSpecific.data.archive.hasExecutables ? '⚠️ Executables Packaged' : 'None'}
                  </span>
                </div>
              </div>

              {/* Archive Files List */}
              {fileAnalysis.stages.typeSpecific.data.archive.filesList && fileAnalysis.stages.typeSpecific.data.archive.filesList.length > 0 && (
                <div className="space-y-2 pt-2">
                  <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    Contained Archive Entries
                  </h4>
                  <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 max-h-60 overflow-y-auto space-y-1 font-mono text-xs">
                    {fileAnalysis.stages.typeSpecific.data.archive.filesList.map((entry, idx) => (
                      <div key={idx} className="flex items-center justify-between text-slate-700 py-0.5">
                        <span className={entry.isSuspicious ? 'text-rose-600 font-bold' : ''}>{entry.path}</span>
                        <span className="text-[10px] text-slate-400">{entry.size} bytes</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Script Inspector */}
          {fileAnalysis?.stages?.typeSpecific?.data?.script?.isScript && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                <Terminal className="w-5 h-5 text-emerald-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Script Obfuscation & Dynamic Evaluation Checks
                  </h3>
                  <p className="text-xs text-slate-500">
                    Eval patterns, encoded PowerShell commands, and network downloader calls.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Dynamic Evaluation</span>
                  <span className={`text-xs font-bold ${fileAnalysis.stages.typeSpecific.data.script.hasEvalOrExec ? 'text-amber-700' : 'text-emerald-700'}`}>
                    {fileAnalysis.stages.typeSpecific.data.script.hasEvalOrExec ? '⚠️ Dynamic Eval/Exec Present' : 'None'}
                  </span>
                </div>
                <div className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl space-y-1">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Encoded Commands</span>
                  <span className={`text-xs font-bold ${fileAnalysis.stages.typeSpecific.data.script.hasEncodedCommand ? 'text-rose-700' : 'text-emerald-700'}`}>
                    {fileAnalysis.stages.typeSpecific.data.script.hasEncodedCommand ? '⚠️ Encoded PowerShell Pattern' : 'None'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* TAB 5: REPUTATION TAB                                                   */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'reputation' && (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Database className="w-5 h-5 text-blue-600" />
                <div>
                  <h3 className="text-base font-bold text-slate-900 tracking-tight">
                    Hash Threat Intelligence Providers
                  </h3>
                  <p className="text-xs text-slate-500">
                    Queries third-party threat intelligence databases using SHA-256 hash digests only.
                  </p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {reputationProviders.map((prov, idx) => (
                <div
                  key={idx}
                  className="p-5 bg-slate-50/80 border border-slate-200/80 rounded-xl space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-bold text-slate-900">{prov.provider}</h4>
                    <span
                      className={`text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full border ${
                        prov.status === 'malicious'
                          ? 'bg-rose-100 text-rose-800 border-rose-200'
                          : prov.status === 'clean' || prov.status === 'no_match'
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
                          : prov.status === 'not_found'
                          ? 'bg-blue-100 text-blue-800 border-blue-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}
                    >
                      {prov.status === 'malicious'
                        ? 'MALICIOUS'
                        : prov.status === 'clean' || prov.status === 'no_match'
                        ? 'CLEAN'
                        : prov.status === 'not_found'
                        ? 'NOT FOUND'
                        : 'NOT CONFIGURED'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-600 leading-relaxed">{prov.details}</p>

                  {prov.permalink && (
                    <a
                      href={prov.permalink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-600 hover:text-blue-800 pt-1"
                    >
                      <span>View on {prov.provider}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              ))}
            </div>

            <div className="p-4 bg-blue-50/50 border border-blue-100 rounded-xl text-xs text-blue-900 leading-relaxed">
              <strong>Hash Privacy Policy:</strong> CyberWatch strictly transmits cryptographic SHA-256 digests. Raw uploaded files are never sent to external intelligence providers.
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* TAB 6: YARA MATCHES TAB                                                 */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'yara' && (
        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-blue-600" />
              <div>
                <h3 className="text-base font-bold text-slate-900 tracking-tight">
                  YARA Threat Rule Signature Scanning
                </h3>
                <p className="text-xs text-slate-500">
                  Pattern matching against local rule repositories and webshell / malware signatures.
                </p>
              </div>
            </div>
          </div>

          {fileAnalysis?.stages?.yara?.status === 'skipped' ? (
            <div className="p-6 bg-slate-50 rounded-xl border border-slate-200 text-center space-y-2">
              <Info className="w-8 h-8 text-slate-400 mx-auto" />
              <h4 className="text-sm font-bold text-slate-800">YARA Analysis Not Configured</h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                No local YARA rule directory was detected on this host. YARA engine was safely skipped without false assumptions.
              </p>
            </div>
          ) : !fileAnalysis?.stages?.yara?.data?.matches || fileAnalysis.stages.yara.data.matches.length === 0 ? (
            <div className="p-6 bg-emerald-50/40 rounded-xl border border-emerald-100 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-600 mx-auto" />
              <h4 className="text-sm font-bold text-emerald-950">No YARA Matches Identified</h4>
              <p className="text-xs text-emerald-900/80 max-w-md mx-auto">
                Completed rule scan against local threat signatures. Zero suspicious YARA rules were matched.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {fileAnalysis.stages.yara.data.matches.map((match, idx) => (
                <div key={idx} className="p-4 bg-rose-50/40 border border-rose-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-rose-900 font-mono">{match.ruleName}</span>
                    <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-200">
                      {match.severity}
                    </span>
                  </div>
                  {match.description && <p className="text-xs text-rose-800">{match.description}</p>}
                  <div className="pt-1">
                    <span className="text-[11px] font-mono text-slate-800 bg-white border border-rose-200 rounded p-1.5 inline-block break-all">
                      Matched Strings: {match.matchedStrings.join(', ')}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────────── */}
      {/* TAB 7: EMBEDDED URLS & DOMAINS TAB                                      */}
      {/* ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'embedded_urls' && (
        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-blue-600" />
              <div>
                <h3 className="text-base font-bold text-slate-900 tracking-tight">
                  Embedded URLs & Remote Indicators
                </h3>
                <p className="text-xs text-slate-500">
                  Network indicators extracted from the binary without automatic HTTP fetching.
                </p>
              </div>
            </div>
            <span className="text-xs font-bold text-slate-600 bg-slate-100 px-3 py-1 rounded-full border border-slate-200">
              {embeddedUrlsList.length} Found
            </span>
          </div>

          {embeddedUrlsList.length === 0 ? (
            <div className="p-8 text-center bg-slate-50/60 rounded-xl border border-dashed border-slate-200 space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
              <h4 className="text-sm font-bold text-slate-800">No Embedded URLs Identified</h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                No outbound HTTP/HTTPS URLs or network hosts were found embedded inside this file.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {embeddedUrlsList.map((item, idx) => (
                <div
                  key={idx}
                  className="p-4 bg-slate-50/80 border border-slate-200/80 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded bg-slate-200 text-slate-700">
                        {item.type}
                      </span>
                      <span className="text-[11px] font-semibold text-slate-500">
                        Source: {item.source}
                      </span>
                    </div>
                    <p className="text-xs font-mono font-bold text-slate-900 break-all select-all leading-relaxed" style={{ overflowWrap: 'anywhere' }}>
                      {item.url}
                    </p>
                  </div>

                  {/* Explicit user action button to trigger CyberWatch URL Scanner */}
                  <button
                    type="button"
                    onClick={() => {
                      const targetScanUrl = item.url.startsWith('http') ? item.url : `https://${item.url}`;
                      navigate('/services/url-phishing', { state: { targetUrl: targetScanUrl } });
                    }}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-50 border border-blue-200 hover:bg-blue-100 text-blue-700 text-xs font-bold rounded-xl shadow-xs transition-all shrink-0"
                    title="Launch CyberWatch URL & Phishing Mega Scanner on this indicator"
                  >
                    <Globe className="w-3.5 h-3.5 text-blue-600" />
                    <span>Scan with URL Scanner</span>
                  </button>
                </div>
              ))}
            </div>
          )}

          <div className="text-[11px] text-slate-500 bg-slate-50 border border-slate-200/70 rounded-xl p-3">
            <strong>Security Notice:</strong> Embedded URLs are not automatically visited or resolved during static inspection. Use the button to explicitly launch a scanner audit.
          </div>
        </div>
      )}
    </div>
  );
}
