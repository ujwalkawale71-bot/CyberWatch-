import { useEffect, useState, useMemo } from 'react';
import { useParams, useLocation, Link, useNavigate } from 'react-router-dom';
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
  ArrowLeft,
  Info,
  Download,
  Loader2,
  FileText,
  Activity,
  Server,
  Zap,
  Radio,
  GitCompare,
  FileSpreadsheet,
  FileCode,
} from 'lucide-react';

import { Container } from '../components/ui/Container';
import { scanService } from '../services/scan.service';
import { reportService } from '../services/report.service';
import { ReportsNav } from '../components/reports/ReportsNav';
import { parseTargetUrl, type ParsedTargetUrl } from '../utils/urlParser';
import { generateScanPdfReport } from '../utils/pdfGenerator';
import { UrlScanResultView } from '../components/scanners/UrlScanResultView';
import { WebsiteScanResultV2View } from '../components/scanners/WebsiteScanResultV2View';
import { PhishingScanResultView } from '../components/scanners/PhishingScanResultView';
import { FileScanResultView } from '../components/scanners/FileScanResultView';
import { ExtensionScanResultView } from '../components/scanners/ExtensionScanResultView';
import type { ScanRecord, ScanResultClassification, FindingSeverity } from '../types';

export function ScanResultPage() {
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const isReportsContext = location.pathname.startsWith('/reports');

  const [scan, setScan] = useState<ScanRecord | null>((location.state as any)?.scan || null);
  const [isLoading, setIsLoading] = useState(!scan && Boolean(id));
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(true);
  const [isRescanning, setIsRescanning] = useState(false);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);

  useEffect(() => {
    if ((location.state as any)?.scan) {
      setScan((location.state as any).scan);
      setIsLoading(false);
      return;
    }
    if (id) {
      setIsLoading(true);
      setError(null);
      scanService
        .getScanById(id)
        .then((data) => {
          setScan(data);
          setIsLoading(false);
        })
        .catch((err) => {
          setError(err.response?.data?.message || err.message || 'Unable to load scan report.');
          setIsLoading(false);
        });
    }
  }, [id, location.state]);

  const parsedTarget: ParsedTargetUrl | null = useMemo(() => {
    if (scan?.target) {
      return parseTargetUrl(scan.target);
    }
    return null;
  }, [scan]);

  const tiIndicator = useMemo(() => {
    if (!scan) return '';
    if (scan.targetType === 'File' && scan.checks?.fileAnalysis?.sha256) {
      return scan.checks.fileAnalysis.sha256;
    }
    if (scan.targetType === 'Extension') {
      return scan.checks?.extensionAnalysis?.extensionId || scan.target;
    }
    if (scan.targetType === 'Website') {
      return scan.checks?.domainAnalysis?.hostname || parsedTarget?.hostname || scan.target;
    }
    return scan.target || parsedTarget?.fullUrl || '';
  }, [scan, parsedTarget]);

  function handleCopy(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function handleRescan() {
    if (!scan?.target) return;
    setIsRescanning(true);
    setPdfError(null);
    try {
      const result = await scanService.analyzeUrl(scan.target, scan.targetType || 'URL', true);
      setScan(result);
      setIsRescanning(false);
    } catch (err: any) {
      setIsRescanning(false);
      let userFriendlyMessage = 'Rescan failed.';
      if (err.response?.data?.message) {
        userFriendlyMessage = err.response.data.message;
      } else if (err.response?.data?.error?.message) {
        userFriendlyMessage = err.response.data.error.message;
      } else if (err.code === 'ECONNABORTED' || err.message?.toLowerCase().includes('timeout')) {
        userFriendlyMessage = 'Rescan timed out: The target server took too long to respond.';
      } else if (err.message === 'Network Error' || err.code === 'ERR_NETWORK') {
        userFriendlyMessage = 'Connection error: Unable to reach the CyberWatch API server.';
      } else if (err.message) {
        userFriendlyMessage = err.message;
      }
      setError(userFriendlyMessage);
    }
  }

  async function handleDownloadReport() {
    if (!scan) return;
    setPdfError(null);
    setIsGeneratingPdf(true);
    try {
      // Try backend PDF export endpoint first
      await reportService.downloadExport('scan', 'pdf', scan.id);
      setIsGeneratingPdf(false);
    } catch {
      // Fallback to client-side PDF generation if needed
      try {
        if (parsedTarget) {
          generateScanPdfReport(scan, parsedTarget);
        }
        setIsGeneratingPdf(false);
      } catch (err: any) {
        setIsGeneratingPdf(false);
        setPdfError(err.message || 'Unable to generate report PDF.');
      }
    }
  }

  async function handleExportFormat(format: 'json' | 'csv') {
    if (!scan) return;
    try {
      await reportService.downloadExport('scan', format, scan.id);
    } catch (err: any) {
      console.error('Export error:', err);
      setPdfError(err.message || `Unable to export ${format.toUpperCase()}`);
    }
  }

  const isApiScan = scan?.targetType === 'API';

  function getVerdictConfig(classification?: ScanResultClassification) {
    switch (classification) {
      case 'Safe':
        return {
          label: 'LOW RISK / SAFE',
          pillText: 'SAFE',
          badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-200',
          containerBorder: 'border-emerald-200',
          containerBg: 'bg-emerald-50/40',
          textColor: 'text-emerald-900',
          iconColor: 'text-emerald-600',
          Icon: ShieldCheck,
          summary: isApiScan
            ? 'The live API endpoint responded normally with valid transport security and no critical CORS misconfigurations or technical data leaks.'
            : 'The available analysis did not identify deceptive patterns or active security anomalies.',
          attentionRequired: false,
        };
      case 'Low Risk':
        return {
          label: 'LOW RISK',
          pillText: 'LOW RISK',
          badgeClass: 'bg-blue-100 text-blue-800 border-blue-200',
          containerBorder: 'border-blue-200',
          containerBg: 'bg-blue-50/40',
          textColor: 'text-blue-900',
          iconColor: 'text-blue-600',
          Icon: ShieldCheck,
          summary: isApiScan
            ? 'Standard API configuration observed. Minor informational indicators or optional response security headers may be optimized.'
            : 'Standard baseline security configuration observed with minor informational indicators.',
          attentionRequired: false,
        };
      case 'Suspicious':
        return {
          label: 'SUSPICIOUS / MEDIUM RISK',
          pillText: 'SUSPICIOUS',
          badgeClass: 'bg-amber-100 text-amber-800 border-amber-200',
          containerBorder: 'border-amber-200',
          containerBg: 'bg-amber-50/40',
          textColor: 'text-amber-900',
          iconColor: 'text-amber-600',
          Icon: AlertTriangle,
          summary: isApiScan
            ? 'Potential API configuration issues detected (e.g. unencrypted transport, permissive CORS policy, or missing defensive headers). Review findings below.'
            : 'Potential deceptive patterns, sensitive authentication keywords, or anomalies detected. Review recommended.',
          attentionRequired: true,
        };
      case 'High Risk':
        return {
          label: 'HIGH RISK',
          pillText: 'HIGH RISK',
          badgeClass: 'bg-orange-100 text-orange-800 border-orange-200',
          containerBorder: 'border-orange-200',
          containerBg: 'bg-orange-50/40',
          textColor: 'text-orange-900',
          iconColor: 'text-orange-600',
          Icon: ShieldAlert,
          summary: isApiScan
            ? 'Significant API vulnerabilities or technical data disclosures identified (e.g. wildcard CORS with credentials, stack traces, or cleartext transmission).'
            : 'Significant threat indicators identified. Caution strongly advised before submitting credentials or data.',
          attentionRequired: true,
        };
      case 'Critical':
        return {
          label: 'CRITICAL THREAT',
          pillText: 'CRITICAL',
          badgeClass: 'bg-red-100 text-red-800 border-red-200',
          containerBorder: 'border-red-200',
          containerBg: 'bg-red-50/40',
          textColor: 'text-red-900',
          iconColor: 'text-red-600',
          Icon: ShieldAlert,
          summary: isApiScan
            ? 'Critical security risk detected: Endpoint points to private network IP (SSRF blocked) or exposes severe technical vulnerability.'
            : 'High-confidence threat indicators detected (e.g. direct IP address routing, unencrypted communications, or internal network SSRF exposure).',
          attentionRequired: true,
        };
      default:
        return {
          label: 'ASSESSMENT COMPLETE',
          pillText: 'COMPLETED',
          badgeClass: 'bg-slate-100 text-slate-800 border-slate-200',
          containerBorder: 'border-slate-200',
          containerBg: 'bg-slate-50',
          textColor: 'text-slate-900',
          iconColor: 'text-slate-600',
          Icon: ShieldCheck,
          summary: 'Security assessment completed.',
          attentionRequired: false,
        };
    }
  }

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

  const scannerMeta = useMemo(() => {
    switch (scan?.targetType) {
      case 'Website':
        return { title: 'Website Security Scanner', slug: 'website-scanner' };
      case 'API':
        return { title: 'API Security Scanner', slug: 'api-scanner' };
      case 'File':
        return { title: 'File Security Scanner', slug: 'file' };
      case 'Extension':
        return { title: 'Browser Extension Scanner', slug: 'extension' };
      case 'Phishing':
      case 'URL':
      default:
        return { title: 'URL & Phishing Mega Scanner', slug: 'url-phishing' };
    }
  }, [scan?.targetType]);

  const positiveSignals = useMemo(() => {
    if (!scan || !parsedTarget) return [];
    const signals: Array<{ title: string; desc: string }> = [];

    // ── Dedicated API Positive Signals ──────────────────────────────────────
    if (scan.targetType === 'API') {
      const api = scan.checks?.apiAnalysis;
      const http = scan.checks?.httpAnalysis;

      if (parsedTarget.protocol === 'HTTPS' && scan.checks?.sslAnalysis?.valid !== false) {
        signals.push({
          title: 'HTTPS Transport Encryption Active',
          desc: 'API communications and tokens are encrypted over TLS/HTTPS.',
        });
      }

      if (http?.statusCode && http.statusCode >= 200 && http.statusCode < 400) {
        signals.push({
          title: 'Endpoint Reachable & Responsive',
          desc: `API endpoint responded with HTTP ${http.statusCode} ${http.statusText || 'OK'} (${http.responseTimeMs || 0}ms response time).`,
        });
      }

      if (api?.responseStructure?.isStructured) {
        signals.push({
          title: `Structured ${api.responseStructure.format} Response Payload`,
          desc: `Target returned valid structured ${api.responseStructure.format} API data.`,
        });
      }

      if (api?.informationDisclosure && (!api.informationDisclosure.disclosedSecrets || api.informationDisclosure.disclosedSecrets.length === 0)) {
        signals.push({
          title: 'No Error Stack Trace Disclosed',
          desc: 'Response body does not expose internal stack traces, exception dumps, or raw database messages.',
        });
        signals.push({
          title: 'No Sensitive Secrets Disclosed',
          desc: 'Observed response payload is free from obvious private credentials or database connection strings.',
        });
      }

      if (api?.corsConfig && !api.corsConfig.isPermissive && api.corsConfig.allowOrigin) {
        signals.push({
          title: 'CORS Origin Restricted',
          desc: `API restricts cross-origin access to specific origin: ${api.corsConfig.allowOrigin}.`,
        });
      }

      if (api?.authIndicators?.scheme || http?.statusCode === 401 || http?.statusCode === 403) {
        signals.push({
          title: 'Authentication Boundary Enforced',
          desc: `Endpoint enforces access control challenge (${api?.authIndicators?.scheme || 'HTTP ' + http?.statusCode}).`,
        });
      }

      if (api?.rateLimitIndicators?.limit) {
        signals.push({
          title: 'Active Rate Limiting Headers Detected',
          desc: `Server publishes throttling headers (Limit: ${api.rateLimitIndicators.limit}, Remaining: ${api.rateLimitIndicators.remaining || 'N/A'}).`,
        });
      }

      return signals;
    }

    // ── Standard Web/URL Signals for other Scanners ─────────────────────────
    if (parsedTarget.protocol === 'HTTPS' && scan.checks?.sslAnalysis?.valid !== false) {
      signals.push({
        title: 'HTTPS Transport Encryption Active',
        desc: `Target enforces cryptographic transport layer (${scan.checks?.sslAnalysis?.protocol || 'TLS / HTTPS'}).`,
      });
    }

    if (!parsedTarget.isIpAddress && scan.checks?.domainAnalysis?.status === 'passed') {
      signals.push({
        title: 'Standard Registered Domain Name',
        desc: `Hostname (${parsedTarget.hostname}) resolved via global DNS (${scan.checks?.domainAnalysis?.ipVersion || 'IPv4'}).`,
      });
    }

    if (scan.checks?.httpAnalysis?.statusCode === 200) {
      signals.push({
        title: 'Target Endpoint Reachable & Responsive',
        desc: `Web server responded with HTTP 200 OK (${scan.checks.httpAnalysis.responseTimeMs || 0}ms response time).`,
      });
    }

    if (parsedTarget.subdomainCount <= 2) {
      signals.push({
        title: 'Normal Subdomain Depth',
        desc: 'Subdomain structure does not exhibit excessive nesting or obfuscation layers.',
      });
    }

    if (scan.checks?.phishingAnalysis?.status === 'passed') {
      signals.push({
        title: 'Clean Credential Keyword Profile',
        desc: 'No known deceptive authentication or credential harvesting keywords found in URL path.',
      });
    }

    if (scan.checks?.redirectAnalysis?.status === 'passed') {
      signals.push({
        title: 'Direct Navigation Target',
        desc: scan.checks.redirectAnalysis.redirectCount && scan.checks.redirectAnalysis.redirectCount > 0
          ? `Safely followed ${scan.checks.redirectAnalysis.redirectCount} redirect hop(s) to destination.`
          : 'Direct target destination analyzed without intermediate multi-hop redirection chains.',
      });
    }

    // File specific signals
    if (scan.checks?.fileAnalysis) {
      const file = scan.checks.fileAnalysis;
      if (file.sha256) {
        signals.push({
          title: 'Cryptographic Checksum Verified',
          desc: `SHA-256 fingerprint generated successfully (${file.sha256.substring(0, 16)}...).`,
        });
      }
      if (file.structureRisk === 'safe' || file.structureRisk === 'standard') {
        signals.push({
          title: 'Standard Non-Executable File Extension',
          desc: `File format (.${file.extension}) is not classified as high-risk executable binary.`,
        });
      }
    }

    // Extension specific signals
    if (scan.checks?.extensionAnalysis) {
      const ext = scan.checks.extensionAnalysis;
      if (ext.manifestVersion === 3) {
        signals.push({
          title: 'Manifest V3 Standard Architecture',
          desc: 'Extension adheres to modern Chrome Manifest V3 security model with service workers.',
        });
      }
      if (!ext.dangerousPermissions || ext.dangerousPermissions.length === 0) {
        signals.push({
          title: 'Safe Permissions Scope',
          desc: 'Extension requests standard functional permissions without high-risk browser debugging or intercept APIs.',
        });
      }
    }

    return signals;
  }, [scan, parsedTarget]);

  if (isLoading) {
    return (
      <div className="pt-28 pb-16 min-h-[70vh] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-3 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
          <p className="text-sm font-semibold text-slate-600">Loading security report...</p>
        </div>
      </div>
    );
  }

  if (error || !scan || !parsedTarget) {
    return (
      <div className="pt-28 pb-16 min-h-[70vh] flex items-center justify-center">
        <Container>
          <div className="max-w-md mx-auto text-center space-y-4 bg-white border border-slate-200 p-8 rounded-2xl shadow-xs">
            <div className="w-12 h-12 rounded-xl bg-red-50 text-red-600 flex items-center justify-center mx-auto">
              <AlertCircle className="w-6 h-6" />
            </div>
            <h2 className="text-xl font-bold text-slate-900">Report Not Found</h2>
            <p className="text-sm text-slate-500">{error || 'The requested scan record does not exist or has expired.'}</p>
            <Link
              to="/services/url-scanner"
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 text-white text-sm font-semibold rounded-xl hover:bg-blue-700 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Go to Scanners
            </Link>
          </div>
        </Container>
      </div>
    );
  }

  const verdict = getVerdictConfig(scan.result);
  const VerdictIcon = verdict.Icon;
  const hasRiskScore = typeof scan.riskScore === 'number' && !isNaN(scan.riskScore);

  const isScanTimeout = scan.checks?.httpAnalysis?.details?.includes('timed out') ||
    scan.findings?.some((f) => f.title === 'Request Timed Out' || f.evidence === 'ETIMEDOUT');
  const isScanFailed = scan.status === 'failed' || scan.checks?.httpAnalysis?.status === 'failed';

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER: API SECURITY SCANNER DEDICATED RESULT PAGE
  // ─────────────────────────────────────────────────────────────────────────────
  if (isApiScan) {
    const api = scan.checks?.apiAnalysis;
    const http = scan.checks?.httpAnalysis;

    return (
      <div className="pt-24 pb-20 bg-slate-50/60 min-h-screen">
        {isReportsContext && <ReportsNav />}
        <Container className={isReportsContext ? 'mt-8' : ''}>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to={isReportsContext ? "/reports/history" : "/dashboard"}
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-blue-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-xs transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>{isReportsContext ? 'Back to Scan History' : 'Dashboard'}</span>
              </Link>

              <div className="flex items-center gap-2">
                <Link
                  to={`/reports/compare?scan1=${scan.id}`}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-bold rounded-xl shadow-xs transition-all"
                >
                  <GitCompare className="w-3.5 h-3.5 text-blue-600" />
                  <span>Compare Scan</span>
                </Link>

                <Link
                  to="/services/api-scanner"
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-emerald-50 border border-emerald-200 hover:bg-emerald-100 text-emerald-800 text-xs font-bold rounded-xl transition-all"
                >
                  <PlusCircle className="w-3.5 h-3.5 text-emerald-700" />
                  <span>New API Scan</span>
                </Link>
              </div>
            </div>

            {/* ── 1. SCAN HEADER / STATUS ──────────────────────────────────────── */}
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-100">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-emerald-700 flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5" />
                      API Security Scanner
                    </span>
                    <span className="text-slate-300">•</span>
                    <span className={`inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-0.5 rounded-full border ${
                      isScanTimeout || isScanFailed
                        ? 'text-amber-800 bg-amber-50 border-amber-200'
                        : 'text-emerald-700 bg-emerald-50 border-emerald-200'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${isScanTimeout || isScanFailed ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                      Status: {isScanTimeout ? 'Request Timed Out' : isScanFailed ? 'Connection Failed' : 'Completed'}
                    </span>
                  </div>
                  <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight">
                    API Endpoint Security Audit
                  </h1>
                  {scan.scannedAt && (
                    <p className="text-xs text-slate-500 font-medium">
                      Audited on: {new Date(scan.scannedAt || scan.createdAt).toLocaleString()}
                    </p>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0 flex-wrap">
                  <button
                    type="button"
                    onClick={handleRescan}
                    disabled={isRescanning}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-xl shadow-xs transition-all disabled:opacity-75"
                  >
                    <RotateCw className="w-3.5 h-3.5" />
                    <span>Scan Again</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => navigate(`/threat-intelligence?q=${encodeURIComponent(tiIndicator)}`)}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200/80 font-bold text-xs rounded-xl shadow-xs transition-all"
                    title="Investigate target in Threat Intelligence"
                  >
                    <Radio className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Threat Intelligence</span>
                  </button>

                  <button
                    id="btn-report-download"
                    type="button"
                    onClick={handleDownloadReport}
                    disabled={isGeneratingPdf}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-xs transition-all disabled:opacity-75"
                  >
                    {isGeneratingPdf ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Generating...</span>
                      </>
                    ) : (
                      <>
                        <Download className="w-3.5 h-3.5" />
                        <span>PDF</span>
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => handleExportFormat('json')}
                    className="inline-flex items-center gap-1.5 px-3 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
                    title="Export JSON"
                  >
                    <FileCode className="w-3.5 h-3.5 text-cyan-600" />
                    <span>JSON</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleExportFormat('csv')}
                    className="inline-flex items-center gap-1.5 px-3 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
                    title="Export CSV"
                  >
                    <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
                    <span>CSV</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => navigate('/services/api-scanner')}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
                  >
                    <PlusCircle className="w-3.5 h-3.5 text-emerald-600" />
                    <span>New Scan</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleCopy(parsedTarget.fullUrl)}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span className="text-emerald-700">Copied</span>
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

              {pdfError && (
                <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded-xl px-4 py-2.5 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
                  <span>{pdfError}</span>
                </div>
              )}

              {/* Timeout or Connection Error Warning Banner */}
              {isScanTimeout && (
                <div className="p-4 bg-amber-50 border border-amber-200/80 rounded-xl flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                  <div className="space-y-0.5">
                    <h4 className="text-xs font-bold text-amber-900">Scan Notice: Request Timed Out</h4>
                    <p className="text-xs text-amber-800 leading-relaxed">
                      Scan could not be completed: request timed out. The target server did not respond within the connection period. Passive header inspection and response payload analysis were skipped.
                    </p>
                  </div>
                </div>
              )}

              {/* Endpoint Display */}
              <div className="bg-slate-50/90 border border-slate-200/80 rounded-xl p-4">
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                    Scanned API Endpoint
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

            {/* ── 2. API TARGET INFORMATION ────────────────────────────────────── */}
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
              <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                <div className="flex items-center gap-2">
                  <Activity className="w-5 h-5 text-emerald-600" />
                  <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                    API Target Information
                  </h3>
                </div>
                <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-2.5 py-1 rounded-lg">
                  Observed Network & Endpoint Metrics
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Full Endpoint URL
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900 break-all block" style={{ overflowWrap: 'anywhere' }}>
                    {parsedTarget.fullUrl}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Hostname
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900 break-all block" style={{ overflowWrap: 'anywhere' }}>
                    {parsedTarget.hostname}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Endpoint Path
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900 break-all block" style={{ overflowWrap: 'anywhere' }}>
                    {parsedTarget.path || '/'}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Protocol / Scheme
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900 flex items-center gap-1.5">
                    <Lock className={`w-3.5 h-3.5 ${parsedTarget.protocol === 'HTTPS' ? 'text-emerald-600' : 'text-amber-600'}`} />
                    {parsedTarget.protocol} ({parsedTarget.scheme})
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Port
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900">
                    {parsedTarget.port} {parsedTarget.port === '443' ? '(Default HTTPS)' : parsedTarget.port === '80' ? '(Default HTTP)' : '(Custom Port)'}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    HTTP Method Used
                  </span>
                  <span className="text-xs font-mono font-bold text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200/60 inline-block">
                    {api?.httpMethod || 'GET'}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    HTTP Status
                  </span>
                  <span className={`text-xs font-bold ${
                    http?.statusCode && http.statusCode >= 200 && http.statusCode < 400
                      ? 'text-emerald-700'
                      : http?.statusCode === 404
                      ? 'text-slate-700'
                      : http?.statusCode
                      ? 'text-amber-700'
                      : 'text-slate-500'
                  }`}>
                    {http?.statusCode
                      ? `HTTP ${http.statusCode} ${http.statusText || ''}`
                      : isScanTimeout
                      ? 'Not available (Timed Out)'
                      : 'Not available'}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Response Time
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900">
                    {http?.responseTimeMs !== undefined ? `${http.responseTimeMs} ms` : 'Not available'}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Content-Type
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900 break-all block" style={{ overflowWrap: 'anywhere' }}>
                    {http?.contentType || 'Not available'}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Response Size
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900">
                    {http?.contentLength !== undefined ? `${http.contentLength} bytes` : 'Not available'}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Query Parameters
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900">
                    {parsedTarget.queryCount > 0 ? `${parsedTarget.queryCount} parameter(s)` : 'None'}
                  </span>
                </div>

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Final Destination / Routing
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900 break-all block" style={{ overflowWrap: 'anywhere' }}>
                    {scan.checks?.redirectAnalysis?.redirectCount && scan.checks.redirectAnalysis.redirectCount > 0
                      ? `Followed ${scan.checks.redirectAnalysis.redirectCount} redirect hop(s)`
                      : 'Direct endpoint (0 redirects)'}
                  </span>
                </div>

                {http?.server && (
                  <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                    <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                      Response Server Header
                    </span>
                    <span className="text-xs font-mono font-semibold text-slate-900">
                      {http.server}
                    </span>
                  </div>
                )}

                <div className="bg-slate-50/70 border border-slate-200/70 rounded-xl p-3.5 space-y-1 min-w-0">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    API Response Format
                  </span>
                  <span className="text-xs font-mono font-semibold text-slate-900">
                    {api?.responseStructure?.format || 'Unknown'} (Structured: {api?.responseStructure?.isStructured ? 'Yes' : 'No'})
                  </span>
                </div>
              </div>
            </div>

            {/* ── 3. OVERALL API SECURITY RESULT ───────────────────────────────── */}
            <div className={`bg-white border-2 ${verdict.containerBorder} rounded-2xl p-6 sm:p-7 shadow-xs space-y-5 relative overflow-hidden`}>
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-5 border-b border-slate-100">
                <div className="space-y-2">
                  <span className="text-xs font-extrabold uppercase tracking-wider text-slate-500">
                    Overall API Security Result
                  </span>
                  <div className="flex items-center gap-3">
                    <div className={`w-12 h-12 rounded-xl ${verdict.containerBg} flex items-center justify-center shrink-0`}>
                      <VerdictIcon className={`w-6 h-6 ${verdict.iconColor}`} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-2xl font-black text-slate-900 tracking-tight">
                          {verdict.label}
                        </h3>
                        <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${verdict.badgeClass}`}>
                          {verdict.pillText}
                        </span>
                      </div>
                      <span className="text-xs font-semibold text-slate-500">
                        Classification Assessment: Verified via CyberWatch API Security Rule Engine
                      </span>
                    </div>
                  </div>
                </div>

                {/* Risk Score */}
                <div className="shrink-0">
                  <div className="p-4 sm:p-5 rounded-xl bg-slate-50 border border-slate-200/80 min-w-[200px] text-center space-y-1">
                    <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                      API Risk Score
                    </span>
                    <div className="text-3xl font-black text-slate-900 tracking-tight">
                      {hasRiskScore ? (
                        <>
                          {scan.riskScore} <span className="text-base text-slate-400 font-semibold">/ 100</span>
                        </>
                      ) : (
                        <span className="text-sm font-semibold text-slate-500">Unavailable</span>
                      )}
                    </div>
                    <span className="text-[11px] font-bold text-slate-600 block">
                      {hasRiskScore
                        ? scan.riskScore === 0
                          ? 'Zero Security Risks Identified'
                          : scan.riskScore <= 25
                          ? 'Low API Threat Level'
                          : scan.riskScore <= 50
                          ? 'Moderate API Threat Level'
                          : 'High API Threat Level'
                        : 'Calculated from indicators'}
                    </span>
                  </div>
                </div>
              </div>

              {/* ── 4. API ANALYSIS SUMMARY ───────────────────────────────────── */}
              <div className="space-y-2 bg-slate-50/70 border border-slate-200/70 rounded-xl p-4">
                <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-emerald-600" />
                  API Analysis Summary
                </span>
                <p className="text-xs sm:text-sm text-slate-700 leading-relaxed">
                  {verdict.summary}
                </p>
                <div className="pt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-600">
                  <span>• <strong>Analyzed:</strong> CORS boundaries, authentication indicators, rate limiting posture, response structure, and technical error disclosures.</span>
                  <span>• <strong>Attention Required:</strong> {verdict.attentionRequired ? 'Yes (Review findings below)' : 'No immediate action required'}</span>
                </div>
              </div>
            </div>

            {/* ── 5. API SECURITY & CONFIGURATION AUDIT (PRIMARY ANALYSIS) ─────── */}
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
                <div className="flex items-center gap-2.5">
                  <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600 shrink-0">
                    <Terminal className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                      API Security & Configuration Audit
                    </h3>
                    <p className="text-xs text-slate-500">
                      Passive assessment of CORS boundaries, authentication challenge schemes, rate limits, and information exposure.
                    </p>
                  </div>
                </div>
                <span className="text-xs font-bold px-3 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                  Primary Audit
                </span>
              </div>

              {api ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* A. CORS Policy Card */}
                  <div className="p-4 bg-slate-50/70 border border-slate-200/80 rounded-xl space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-blue-600" />
                        CORS Policy
                      </span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        api.corsConfig?.isPermissive && api.corsConfig?.allowCredentials === 'true'
                          ? 'bg-red-100 text-red-800'
                          : api.corsConfig?.isPermissive
                          ? 'bg-amber-100 text-amber-800'
                          : api.corsConfig?.allowOrigin
                          ? 'bg-emerald-100 text-emerald-800'
                          : 'bg-slate-100 text-slate-700'
                      }`}>
                        {api.corsConfig?.isPermissive && api.corsConfig?.allowCredentials === 'true'
                          ? 'Insecure (Wildcard + Credentials)'
                          : api.corsConfig?.isPermissive
                          ? 'Wildcard (*)'
                          : api.corsConfig?.allowOrigin
                          ? 'Restricted Origin'
                          : 'Default / Same-Origin'}
                      </span>
                    </div>
                    <div className="space-y-1 text-xs text-slate-600">
                      <p>
                        Allowed Origin:{' '}
                        <span className="font-mono font-semibold text-slate-800">
                          {api.corsConfig?.allowOrigin || 'Not set / Same-origin default'}
                        </span>
                      </p>
                      <p>
                        Wildcard Origin (*):{' '}
                        <span className="font-semibold text-slate-800">
                          {api.corsConfig?.isPermissive ? 'Yes (Open public access)' : 'No'}
                        </span>
                      </p>
                      <p>
                        Allowed Credentials:{' '}
                        <span className="font-semibold text-slate-800">
                          {api.corsConfig?.allowCredentials || 'Not configured'}
                        </span>
                      </p>
                      <p>
                        Allowed Methods:{' '}
                        <span className="font-mono text-slate-800">
                          {api.corsConfig?.allowMethods || 'Standard GET/POST'}
                        </span>
                      </p>
                    </div>
                    <div className="pt-1.5 border-t border-slate-200/60 text-[11px] text-slate-500">
                      {api.corsConfig?.isPermissive && api.corsConfig?.allowCredentials === 'true'
                        ? 'Wildcard origin combined with credentials represents an insecure CORS configuration.'
                        : api.corsConfig?.isPermissive
                        ? 'The endpoint permits cross-origin requests from any client origin (*).'
                        : api.corsConfig?.allowOrigin
                        ? `Cross-origin access is explicitly restricted to: ${api.corsConfig.allowOrigin}`
                        : 'No cross-origin sharing headers detected; browsers enforce standard same-origin restriction.'}
                    </div>
                  </div>

                  {/* B. Authentication Card */}
                  <div className="p-4 bg-slate-50/70 border border-slate-200/80 rounded-xl space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                        <Lock className="w-3.5 h-3.5 text-purple-600" />
                        Authentication Posture
                      </span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        api.authIndicators?.scheme || http?.statusCode === 401
                          ? 'bg-blue-100 text-blue-800'
                          : http?.statusCode === 403
                          ? 'bg-purple-100 text-purple-800'
                          : 'bg-slate-100 text-slate-700'
                      }`}>
                        {api.authIndicators?.scheme || http?.statusCode === 401
                          ? 'Required (HTTP 401)'
                          : http?.statusCode === 403
                          ? 'Forbidden (HTTP 403)'
                          : http?.statusCode && http.statusCode >= 200 && http.statusCode < 300
                          ? 'Public / None Required'
                          : 'Unavailable'}
                      </span>
                    </div>
                    <div className="space-y-1 text-xs text-slate-600">
                      <p>
                        Challenge Scheme:{' '}
                        <span className="font-semibold text-slate-800">
                          {api.authIndicators?.scheme || 'None detected'}
                        </span>
                      </p>
                      <p>
                        Access Status:{' '}
                        <span className="font-semibold text-slate-800">
                          {api.authIndicators?.status || 'Public / Unauthenticated'}
                        </span>
                      </p>
                    </div>
                    <div className="pt-1.5 border-t border-slate-200/60 text-[11px] text-slate-500 leading-relaxed">
                      {api.authIndicators?.details || 'Authentication analysis unavailable — credentials were not provided.'}
                    </div>
                  </div>

                  {/* C. Rate Limiting Card */}
                  <div className="p-4 bg-slate-50/70 border border-slate-200/80 rounded-xl space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                        <Zap className="w-3.5 h-3.5 text-amber-600" />
                        Rate Limiting Posture
                      </span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        api.rateLimitIndicators?.limit
                          ? 'bg-emerald-100 text-emerald-800'
                          : http?.statusCode === 429
                          ? 'bg-purple-100 text-purple-800'
                          : 'bg-slate-100 text-slate-600'
                      }`}>
                        {api.rateLimitIndicators?.limit
                          ? 'Headers Active'
                          : http?.statusCode === 429
                          ? 'Rate Limited (HTTP 429)'
                          : 'Not Verified'}
                      </span>
                    </div>
                    <div className="space-y-1 text-xs text-slate-600">
                      <p>
                        Observed Limit:{' '}
                        <span className="font-mono font-semibold text-slate-800">
                          {api.rateLimitIndicators?.limit || 'Not present in headers'}
                        </span>
                      </p>
                      <p>
                        Remaining Quota:{' '}
                        <span className="font-mono font-semibold text-slate-800">
                          {api.rateLimitIndicators?.remaining || 'Not present in headers'}
                        </span>
                      </p>
                      {api.rateLimitIndicators?.reset && (
                        <p>
                          Reset Window:{' '}
                          <span className="font-mono font-semibold text-slate-800">
                            {api.rateLimitIndicators.reset} seconds
                          </span>
                        </p>
                      )}
                    </div>
                    <div className="pt-1.5 border-t border-slate-200/60 text-[11px] text-slate-500">
                      {api.rateLimitIndicators?.limit
                        ? `Passive headers confirm rate-limiting is active (Limit: ${api.rateLimitIndicators.limit}, Remaining: ${api.rateLimitIndicators.remaining || 'N/A'}).`
                        : 'Rate limiting could not be verified from passive response headers.'}
                    </div>
                  </div>

                  {/* D. Response Security & Information Disclosure Card */}
                  <div className="p-4 bg-slate-50/70 border border-slate-200/80 rounded-xl space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-indigo-600" />
                        Response Security & Disclosure
                      </span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        api.informationDisclosure?.disclosedSecrets?.length
                          ? 'bg-red-100 text-red-800'
                          : api.informationDisclosure?.disclosedHeaders?.length
                          ? 'bg-amber-100 text-amber-800'
                          : 'bg-emerald-100 text-emerald-800'
                      }`}>
                        {api.informationDisclosure?.disclosedSecrets?.length
                          ? 'Exposure Alert'
                          : api.informationDisclosure?.disclosedHeaders?.length
                          ? 'Potential Disclosure'
                          : 'Protected'}
                      </span>
                    </div>
                    <div className="space-y-1 text-xs text-slate-600">
                      <p>
                        Response Format:{' '}
                        <span className="font-mono font-semibold text-slate-800">
                          {api.responseStructure?.format?.toUpperCase() || 'HTTP Response'}
                        </span>{' '}
                        (Structured: {api.responseStructure?.isStructured ? 'Yes' : 'No'})
                      </p>
                      <p>
                        Disclosure Status:{' '}
                        <span className="font-semibold text-slate-800">
                          {api.informationDisclosure?.details || 'No technical information disclosure indicators detected.'}
                        </span>
                      </p>
                    </div>
                    {api.informationDisclosure?.disclosedHeaders && api.informationDisclosure.disclosedHeaders.length > 0 && (
                      <div className="pt-1 flex flex-wrap gap-1">
                        {api.informationDisclosure.disclosedHeaders.map((dh, i) => (
                          <span key={i} className="text-[10px] font-mono bg-amber-50 text-amber-800 border border-amber-200 rounded px-1.5 py-0.5">
                            {dh}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* E. HTTP Method & OPTIONS Information */}
                  <div className="p-4 bg-slate-50/70 border border-slate-200/80 rounded-xl space-y-2.5 md:col-span-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-slate-700" />
                        HTTP Method & Methods Allowed
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700">
                        Method Audit
                      </span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs text-slate-600">
                      <div>
                        <span className="text-[11px] font-bold text-slate-500 block uppercase">Method Tested</span>
                        <span className="font-mono font-bold text-slate-900">{api.httpMethod || 'GET'}</span>
                      </div>
                      <div>
                        <span className="text-[11px] font-bold text-slate-500 block uppercase">Supported Methods Observed</span>
                        <span className="font-mono text-slate-900">
                          {api.supportedMethods && api.supportedMethods.length > 0
                            ? api.supportedMethods.join(', ')
                            : 'Not advertised in response headers'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-6 text-center text-xs text-slate-500 bg-slate-50 rounded-xl border border-slate-200">
                  API Security Analysis data unavailable for this scan.
                </div>
              )}
            </div>

            {/* ── 6. SECURITY FINDINGS ────────────────────────────────────────── */}
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-amber-600" />
                  <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                    API Security Findings ({scan.findings?.length || 0})
                  </h3>
                </div>
              </div>

              {(!scan.findings || scan.findings.length === 0) ? (
                <div className="p-8 text-center bg-slate-50 border border-slate-200/70 rounded-xl space-y-2">
                  <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
                  <h4 className="text-sm font-bold text-slate-800">No Security Findings</h4>
                  <p className="text-xs text-slate-500 max-w-md mx-auto">
                    No security findings were returned by the available API analysis.
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {scan.findings.map((finding, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-50/80 border border-slate-200/80 rounded-xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-start justify-between gap-4"
                    >
                      <div className="space-y-2 flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`text-[10px] font-extrabold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${getSeverityBadge(finding.severity)}`}>
                            {finding.severity}
                          </span>
                          <span className="text-xs font-semibold text-slate-500">
                            Category: {finding.category}
                          </span>
                        </div>
                        <h4 className="text-sm font-bold text-slate-900">{finding.title}</h4>
                        <p className="text-xs text-slate-600 leading-relaxed">{finding.description}</p>
                        {finding.evidence && (
                          <div className="pt-1">
                            <span className="text-[11px] font-mono text-slate-700 bg-white border border-slate-200 rounded-lg px-2.5 py-1 inline-block break-all" style={{ overflowWrap: 'anywhere' }}>
                              Evidence: {finding.evidence}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* ── 7. POSITIVE SECURITY SIGNALS ─────────────────────────────────── */}
            {positiveSignals.length > 0 && (
              <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
                <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                  <div>
                    <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                      Positive Security Signals
                    </h3>
                    <p className="text-xs text-slate-500">
                      Verified positive observations confirmed by automated API inspection.
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
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

            {/* ── 8. RECOMMENDATION & GUIDANCE ─────────────────────────────────── */}
            {scan.recommendations && scan.recommendations.length > 0 && (
              <div className="bg-emerald-50/40 border border-emerald-100 rounded-2xl p-6 sm:p-7 shadow-xs space-y-3.5">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-700" />
                  <h3 className="text-base sm:text-lg font-bold text-emerald-950 tracking-tight">
                    API Hardening Recommendations & Guidance
                  </h3>
                </div>

                <ul className="space-y-2 text-xs sm:text-sm text-emerald-950 font-medium">
                  {scan.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-2.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 mt-2 shrink-0" />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* ── 9. TECHNICAL DETAILS ────────────────────────────────────────── */}
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
              <button
                type="button"
                onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                className="w-full flex items-center justify-between text-left focus:outline-none"
              >
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-slate-700" />
                  <div>
                    <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                      Technical Details
                    </h3>
                    <span className="text-xs text-slate-500">
                      Verified technical specifications and scanner metadata
                    </span>
                  </div>
                </div>
                <div className="p-1 rounded-lg bg-slate-100 text-slate-600 hover:bg-slate-200 transition-colors">
                  {showTechnicalDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </div>
              </button>

              {showTechnicalDetails && (
                <div className="pt-2 space-y-3 animate-in fade-in duration-200">
                  <div className="bg-slate-900 text-slate-200 rounded-xl p-4 sm:p-5 font-mono text-xs space-y-2 overflow-x-auto">
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Endpoint URL:</span>
                      <span className="text-emerald-400 break-all" style={{ overflowWrap: 'anywhere' }}>{parsedTarget.fullUrl}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Hostname:</span>
                      <span className="text-slate-200">{parsedTarget.hostname}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Protocol / Scheme:</span>
                      <span className="text-slate-200">{parsedTarget.protocol} ({parsedTarget.scheme})</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Port:</span>
                      <span className="text-slate-200">{parsedTarget.port}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Path:</span>
                      <span className="text-slate-200">{parsedTarget.path}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Resolved IP(s):</span>
                      <span className="text-slate-200">
                        {scan.checks?.domainAnalysis?.resolvedIps?.join(', ') || 'Not resolved'}
                      </span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">HTTP Status:</span>
                      <span className="text-slate-200">
                        {http?.statusCode ? `HTTP ${http.statusCode} ${http.statusText || ''}` : 'N/A'}
                      </span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Content-Type:</span>
                      <span className="text-slate-200">{http?.contentType || 'Unknown'}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Response Time:</span>
                      <span className="text-slate-200">{http?.responseTimeMs !== undefined ? `${http.responseTimeMs}ms` : 'N/A'}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Server Header:</span>
                      <span className="text-slate-200">{http?.server || 'Not disclosed'}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Scan ID:</span>
                      <span className="text-slate-300">{scan.id}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                      <span className="text-slate-400">Scan Status:</span>
                      <span className="text-emerald-400 font-bold">{scan.status ? scan.status.toUpperCase() : 'COMPLETED'}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:justify-between py-1 gap-1">
                      <span className="text-slate-400">Scan Timestamp:</span>
                      <span className="text-slate-300">{new Date(scan.scannedAt || scan.createdAt).toUTCString()}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* ── 10. SCAN ACTIONS / FOOTER ────────────────────────────────────── */}
            <div className="pt-2 flex items-center justify-between flex-wrap gap-3">
              <Link
                to="/services/api-scanner"
                className="inline-flex items-center gap-1.5 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-xl shadow-xs transition-all"
              >
                <PlusCircle className="w-4 h-4" />
                <span>Audit Another API</span>
              </Link>
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-1.5 px-4 py-2.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back to Dashboard</span>
              </Link>
            </div>
          </div>
        </Container>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER: DEDICATED BROWSER EXTENSION SCANNER VIEW
  // ─────────────────────────────────────────────────────────────────────────────
  if (scan.targetType === 'Extension' || scan.checks?.extensionAnalysis) {
    return (
      <div className="pt-24 pb-20 bg-slate-50/60 min-h-screen">
        <Container>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-teal-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-xs transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Dashboard</span>
              </Link>

              <Link
                to="/services/extension"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-teal-50 border border-teal-200 hover:bg-teal-100 text-teal-800 text-xs font-bold rounded-xl transition-all"
              >
                <PlusCircle className="w-3.5 h-3.5 text-teal-700" />
                <span>New Extension Scan</span>
              </Link>
            </div>

            <ExtensionScanResultView
              scan={scan}
              parsedTarget={parsedTarget}
              onRescan={handleRescan}
              isRescanning={isRescanning}
              onNewScan={() => navigate('/services/extension')}
              onDownloadReport={handleDownloadReport}
              isGeneratingPdf={isGeneratingPdf}
              pdfError={pdfError}
              onCopy={handleCopy}
              copied={copied}
            />
          </div>
        </Container>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER: DEDICATED FILE SECURITY SCANNER VIEW
  // ─────────────────────────────────────────────────────────────────────────────
  if (scan.targetType === 'File' || scan.checks?.fileAnalysis) {
    return (
      <div className="pt-24 pb-20 bg-slate-50/60 min-h-screen">
        <Container>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-blue-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-xs transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Dashboard</span>
              </Link>

              <Link
                to="/services/file"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-50 border border-blue-200 hover:bg-blue-100 text-blue-800 text-xs font-bold rounded-xl transition-all"
              >
                <PlusCircle className="w-3.5 h-3.5 text-blue-700" />
                <span>New File Scan</span>
              </Link>
            </div>

            <FileScanResultView
              scan={scan}
              onRescan={handleRescan}
              isRescanning={isRescanning}
              onNewScan={() => navigate('/services/file')}
              onDownloadReport={handleDownloadReport}
              isGeneratingPdf={isGeneratingPdf}
              pdfError={pdfError}
              onCopy={handleCopy}
              copied={copied}
            />
          </div>
        </Container>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER: DEDICATED PHISHING SCANNER VIEW
  // ─────────────────────────────────────────────────────────────────────────────
  if (scan.targetType === 'Phishing' || scan.checks?.phishingSecurityAnalysis) {
    return (
      <div className="pt-24 pb-20 bg-slate-50/60 min-h-screen">
        <Container>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-amber-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-xs transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Dashboard</span>
              </Link>

              <Link
                to="/services/phishing"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-amber-50 border border-amber-200 hover:bg-amber-100 text-amber-800 text-xs font-bold rounded-xl transition-all"
              >
                <PlusCircle className="w-3.5 h-3.5 text-amber-600" />
                <span>New Phishing Scan</span>
              </Link>
            </div>

            <PhishingScanResultView
              scan={scan}
              parsedTarget={parsedTarget}
              onRescan={handleRescan}
              isRescanning={isRescanning}
              onNewScan={() => navigate('/services/phishing')}
              onDownloadReport={handleDownloadReport}
              isGeneratingPdf={isGeneratingPdf}
              pdfError={pdfError}
              onCopy={handleCopy}
              copied={copied}
            />
          </div>
        </Container>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER: WEBSITE SECURITY SCANNER V2 DEDICATED RESULT PAGE
  // ─────────────────────────────────────────────────────────────────────────────
  const isWebsiteScan = scan.targetType === 'Website' || scan.checks?.websiteSecurityV2;
  if (isWebsiteScan) {
    return (
      <div className="pt-24 pb-20 bg-slate-50/60 min-h-screen">
        <Container>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-indigo-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-xs transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Dashboard</span>
              </Link>

              <Link
                to="/services/website-scanner"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-indigo-50 border border-indigo-200 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-xl transition-all"
              >
                <PlusCircle className="w-3.5 h-3.5 text-indigo-600" />
                <span>New Website Scan</span>
              </Link>
            </div>

            <WebsiteScanResultV2View
              scan={scan}
              parsedTarget={parsedTarget}
              onRescan={handleRescan}
              isRescanning={isRescanning}
              onNewScan={() => navigate('/services/website-scanner')}
              onDownloadReport={handleDownloadReport}
              isGeneratingPdf={isGeneratingPdf}
              pdfError={pdfError}
              onCopy={handleCopy}
              copied={copied}
            />
          </div>
        </Container>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER: URL SECURITY SCANNER DEDICATED RESULT PAGE (16 SECTIONS)
  // ─────────────────────────────────────────────────────────────────────────────
  const isUrlScan = scan.targetType === 'URL' || !scan.targetType;
  if (isUrlScan) {
    return (
      <div className="pt-20 sm:pt-24 pb-20 bg-slate-50/60 min-h-screen">
        <Container>
          <div className="space-y-6 w-full">
            <UrlScanResultView
              scan={scan}
              parsedTarget={parsedTarget}
              onRescan={handleRescan}
              isRescanning={isRescanning}
              onNewScan={() => navigate('/services/url-phishing')}
              onDownloadReport={handleDownloadReport}
              isGeneratingPdf={isGeneratingPdf}
              pdfError={pdfError}
              onCopy={handleCopy}
              copied={copied}
              backLink={isReportsContext ? '/reports/history' : '/dashboard'}
              backLabel={isReportsContext ? 'All Scans' : 'All Scans'}
            />
          </div>
        </Container>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER: STANDARD URL / OTHER SCANNERS
  // ─────────────────────────────────────────────────────────────────────────────
  return (
    <div className="pt-24 pb-20 bg-slate-50/60 min-h-screen">
      <Container>
        <div className="space-y-6 w-full">
          {/* Breadcrumb Navigation */}
          <div className="flex items-center justify-between">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-blue-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-xs transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Dashboard</span>
            </Link>

            <Link
              to={`/services/${scannerMeta.slug}`}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-50 border border-blue-200 hover:bg-blue-100 text-blue-700 text-xs font-bold rounded-xl transition-all"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Launch {scannerMeta.title}</span>
            </Link>
          </div>

          {/* ── 1. RESULT HEADER ─────────────────────────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-100">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-blue-600">
                    {scannerMeta.title}
                  </span>
                  <span className="text-slate-300">•</span>
                  <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded-full border border-emerald-200">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                    Status: {scan.status ? scan.status.charAt(0).toUpperCase() + scan.status.slice(1) : 'Completed'}
                  </span>
                </div>
                <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight">
                  Security Analysis Report
                </h1>
                {scan.scannedAt && (
                  <p className="text-xs text-slate-500 font-medium">
                    Scanned on: {new Date(scan.scannedAt || scan.createdAt).toLocaleString()}
                  </p>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 shrink-0 flex-wrap">
                <button
                  type="button"
                  onClick={handleRescan}
                  disabled={isRescanning}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-xs transition-all disabled:opacity-75"
                >
                  <RotateCw className="w-3.5 h-3.5" />
                  <span>Scan Again</span>
                </button>

                <button
                  id="btn-report-download"
                  type="button"
                  onClick={handleDownloadReport}
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

                <button
                  type="button"
                  onClick={() => navigate(`/services/${scannerMeta.slug}`)}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
                >
                  <PlusCircle className="w-3.5 h-3.5 text-blue-600" />
                  <span>New Scan</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleCopy(parsedTarget.fullUrl)}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-bold text-xs rounded-xl shadow-xs transition-all"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                      <span className="text-emerald-700">Copied</span>
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

            {pdfError && (
              <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded-xl px-4 py-2.5 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
                <span>{pdfError}</span>
              </div>
            )}

            {/* Target Display */}
            <div className="bg-slate-50/90 border border-slate-200/80 rounded-xl p-4">
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                  Scanned Target
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



          {/* ── FILE SECURITY ANALYSIS SECTION (When Available) ─────────────── */}
          {scan.checks?.fileAnalysis && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
                <div className="flex items-center gap-2.5">
                  <div className="w-10 h-10 rounded-xl bg-rose-50 border border-rose-100 flex items-center justify-center text-rose-600 shrink-0">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                      File Security & Cryptographic Hashes
                    </h3>
                    <p className="text-xs text-slate-500">
                      Static inspection of file extension risks, magic byte signatures, and cryptographic fingerprints.
                    </p>
                  </div>
                </div>
                <span className={`text-xs font-bold px-3 py-1 rounded-full border ${scan.checks.fileAnalysis.structureRisk === 'high' || scan.checks.fileAnalysis.structureRisk === 'executable' ? 'bg-amber-100 text-amber-800 border-amber-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200'}`}>
                  Risk: {(scan.checks.fileAnalysis.structureRisk || 'standard').toUpperCase()}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
                <div className="p-3.5 bg-slate-50/70 border border-slate-200/70 rounded-xl space-y-1">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">Filename</span>
                  <span className="text-xs font-mono font-bold text-slate-900 break-all">{scan.checks.fileAnalysis.filename || 'asset.bin'}</span>
                </div>
                <div className="p-3.5 bg-slate-50/70 border border-slate-200/70 rounded-xl space-y-1">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">Extension</span>
                  <span className="text-xs font-mono font-bold text-slate-900">.{scan.checks.fileAnalysis.extension || 'unknown'}</span>
                </div>
                <div className="p-3.5 bg-slate-50/70 border border-slate-200/70 rounded-xl space-y-1">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">MIME Type</span>
                  <span className="text-xs font-mono font-semibold text-slate-700">{scan.checks.fileAnalysis.mimeType || 'application/octet-stream'}</span>
                </div>
                <div className="p-3.5 bg-slate-50/70 border border-slate-200/70 rounded-xl space-y-1">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">File Size</span>
                  <span className="text-xs font-mono font-semibold text-slate-700">{scan.checks.fileAnalysis.fileSizeFormatted || (scan.checks.fileAnalysis.fileSize ? `${scan.checks.fileAnalysis.fileSize} bytes` : 'Remote asset')}</span>
                </div>
              </div>

              <div className="bg-slate-900 text-slate-200 rounded-xl p-4 font-mono text-xs space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 pb-1.5 border-b border-slate-800">
                  <span className="text-slate-400">SHA-256 Checksum:</span>
                  <span className="text-emerald-400 break-all">{scan.checks.fileAnalysis.sha256 || 'N/A'}</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <span className="text-slate-400">MD5 Checksum:</span>
                  <span className="text-slate-300 break-all">{scan.checks.fileAnalysis.md5 || 'N/A'}</span>
                </div>
              </div>
            </div>
          )}

          {/* ── BROWSER EXTENSION SECURITY SECTION (When Available) ─────────── */}
          {scan.checks?.extensionAnalysis && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
                <div className="flex items-center gap-2.5">
                  <div className="w-10 h-10 rounded-xl bg-purple-50 border border-purple-100 flex items-center justify-center text-purple-600 shrink-0">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                      Browser Extension Manifest & Permissions Audit
                    </h3>
                    <p className="text-xs text-slate-500">
                      Evaluation of declared Chrome extension capabilities, background workers, and dangerous API permissions.
                    </p>
                  </div>
                </div>
                <span className="text-xs font-bold px-3 py-1 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
                  Manifest V{scan.checks.extensionAnalysis.manifestVersion || 3}
                </span>
              </div>

              {/* Declared Permissions */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-900 uppercase tracking-wider block">
                  Declared Permissions ({scan.checks.extensionAnalysis.permissions?.length || 0})
                </span>
                <div className="flex flex-wrap gap-2">
                  {scan.checks.extensionAnalysis.permissions && scan.checks.extensionAnalysis.permissions.length > 0 ? (
                    scan.checks.extensionAnalysis.permissions.map((perm, idx) => {
                      const dangerousObj = scan.checks?.extensionAnalysis?.dangerousPermissions?.find(d => d.permission === perm);
                      return (
                        <span
                          key={idx}
                          className={`text-xs font-mono font-semibold px-2.5 py-1 rounded-lg border ${
                            dangerousObj ? 'bg-red-50 text-red-700 border-red-200' : 'bg-slate-100 text-slate-700 border-slate-200'
                          }`}
                        >
                          {perm} {dangerousObj && '⚠️'}
                        </span>
                      );
                    })
                  ) : (
                    <span className="text-xs text-slate-500 italic">No special browser permissions requested.</span>
                  )}
                </div>
              </div>

              {/* Host Permissions */}
              {scan.checks.extensionAnalysis.hostPermissions && scan.checks.extensionAnalysis.hostPermissions.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-100">
                  <span className="text-xs font-bold text-slate-900 uppercase tracking-wider block">
                    Host Access Scopes ({scan.checks.extensionAnalysis.hostPermissions.length})
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {scan.checks.extensionAnalysis.hostPermissions.map((host, idx) => (
                      <span key={idx} className="text-xs font-mono font-semibold px-2.5 py-1 rounded-lg bg-blue-50 text-blue-700 border border-blue-200">
                        {host}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── 7. POSITIVE SECURITY SIGNALS ─────────────────────────────────── */}
          {positiveSignals.length > 0 && (
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
              <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
                <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                <div>
                  <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                    Positive Security Signals
                  </h3>
                  <p className="text-xs text-slate-500">
                    Verified positive observations confirmed by automated analysis.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
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

          {/* ── 8. SECURITY FINDINGS ──────────────────────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-amber-600" />
                <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                  Security Findings ({scan.findings?.length || 0})
                </h3>
              </div>
            </div>

            {(!scan.findings || scan.findings.length === 0) ? (
              <div className="p-8 text-center bg-slate-50 border border-slate-200/70 rounded-xl space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
                <h4 className="text-sm font-bold text-slate-800">No Security Findings</h4>
                <p className="text-xs text-slate-500 max-w-md mx-auto">
                  No security findings were returned by the available analysis.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {scan.findings.map((finding, idx) => (
                  <div
                    key={idx}
                    className="bg-slate-50/80 border border-slate-200/80 rounded-xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-start justify-between gap-4"
                  >
                    <div className="space-y-2 flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-extrabold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${getSeverityBadge(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        <span className="text-xs font-semibold text-slate-500">
                          Category: {finding.category}
                        </span>
                      </div>
                      <h4 className="text-sm font-bold text-slate-900">{finding.title}</h4>
                      <p className="text-xs text-slate-600 leading-relaxed">{finding.description}</p>
                      {finding.evidence && (
                        <div className="pt-1">
                          <span className="text-[11px] font-mono text-slate-700 bg-white border border-slate-200 rounded-lg px-2.5 py-1 inline-block break-all" style={{ overflowWrap: 'anywhere' }}>
                            Evidence: {finding.evidence}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ── 9. RECOMMENDATION & GUIDANCE ─────────────────────────────────── */}
          {scan.recommendations && scan.recommendations.length > 0 && (
            <div className="bg-blue-50/50 border border-blue-100 rounded-2xl p-6 sm:p-7 shadow-xs space-y-3.5">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-blue-600" />
                <h3 className="text-base sm:text-lg font-bold text-blue-950 tracking-tight">
                  Recommendation & Guidance
                </h3>
              </div>

              <ul className="space-y-2 text-xs sm:text-sm text-blue-950 font-medium">
                {scan.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-600 mt-2 shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* ── 10. TECHNICAL DETAILS ────────────────────────────────────────── */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 shadow-xs space-y-4">
            <button
              type="button"
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="w-full flex items-center justify-between text-left focus:outline-none"
            >
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-slate-700" />
                <div>
                  <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                    Technical Details
                  </h3>
                  <span className="text-xs text-slate-500">
                    Verified technical specifications and scanner metadata
                  </span>
                </div>
              </div>
              <div className="p-1 rounded-lg bg-slate-100 text-slate-600 hover:bg-slate-200 transition-colors">
                {showTechnicalDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </div>
            </button>

            {showTechnicalDetails && (
              <div className="pt-2 space-y-3 animate-in fade-in duration-200">
                <div className="bg-slate-900 text-slate-200 rounded-xl p-4 sm:p-5 font-mono text-xs space-y-2 overflow-x-auto">
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Target URL:</span>
                    <span className="text-emerald-400 break-all" style={{ overflowWrap: 'anywhere' }}>{parsedTarget.fullUrl}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Hostname:</span>
                    <span className="text-slate-200">{parsedTarget.hostname}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Protocol / Scheme:</span>
                    <span className="text-slate-200">{parsedTarget.protocol} ({parsedTarget.scheme})</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Port:</span>
                    <span className="text-slate-200">{parsedTarget.port}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Path:</span>
                    <span className="text-slate-200">{parsedTarget.path}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Query String:</span>
                    <span className="text-slate-200">{parsedTarget.search || 'None'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">URL Length:</span>
                    <span className="text-slate-200">{parsedTarget.urlLength} characters</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Resolved IP(s):</span>
                    <span className="text-slate-200">
                      {scan.checks?.domainAnalysis?.resolvedIps?.join(', ') || 'None'}
                    </span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">HTTP Status:</span>
                    <span className="text-slate-200">
                      {scan.checks?.httpAnalysis?.statusCode ? `HTTP ${scan.checks.httpAnalysis.statusCode} ${scan.checks.httpAnalysis.statusText || ''}` : 'N/A'}
                    </span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Server Header:</span>
                    <span className="text-slate-200">{scan.checks?.httpAnalysis?.server || 'Not disclosed'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Scan ID:</span>
                    <span className="text-slate-300">{scan.id}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-slate-800 gap-1">
                    <span className="text-slate-400">Scan Status:</span>
                    <span className="text-emerald-400 font-bold">{scan.status ? scan.status.toUpperCase() : 'COMPLETED'}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:justify-between py-1 gap-1">
                    <span className="text-slate-400">Scan Timestamp:</span>
                    <span className="text-slate-300">{new Date(scan.scannedAt || scan.createdAt).toUTCString()}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </Container>
    </div>
  );
}

