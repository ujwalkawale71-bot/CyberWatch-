import { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ArrowRight,
  Loader2,
  AlertCircle,
  X,
  Layers,
  FileCode,
  CheckCircle2,
} from 'lucide-react';
import { scanService } from '../../services/scan.service';
import { parseTargetUrl, type ParsedTargetUrl } from '../../utils/urlParser';
import { generateScanPdfReport } from '../../utils/pdfGenerator';
import { WebsiteScanResultV2View } from './WebsiteScanResultV2View';
import type { ScanRecord } from '../../types';

export function WebsiteSecurityScanner() {
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [copied, setCopied] = useState(false);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);

  // Parse target URL components if a result is present
  const parsedTarget: ParsedTargetUrl | null = useMemo(() => {
    if (scanResult?.target) {
      return parseTargetUrl(scanResult.target);
    }
    return null;
  }, [scanResult]);

  function validateInput(raw: string): { valid: boolean; normalized?: string; error?: string } {
    const trimmed = raw.trim();
    if (!trimmed) {
      return { valid: false, error: 'Please enter a website URL or domain to scan.' };
    }

    let testUrl = trimmed;
    if (!testUrl.startsWith('http://') && !testUrl.startsWith('https://')) {
      testUrl = `https://${testUrl}`;
    }

    try {
      const parsed = new URL(testUrl);
      if (!parsed.hostname || !parsed.hostname.includes('.')) {
        return {
          valid: false,
          error: 'Please enter a valid target website (e.g. https://example.com).',
        };
      }
      return { valid: true, normalized: trimmed };
    } catch {
      return { valid: false, error: 'Please enter a valid website URL format.' };
    }
  }

  async function executeScan(urlToScan: string) {
    setErrorMessage(null);
    setPdfError(null);
    const validation = validateInput(urlToScan);
    if (!validation.valid) {
      setErrorMessage(validation.error || 'Please enter a valid website.');
      return;
    }

    setIsScanning(true);

    try {
      const result = await scanService.analyzeUrl(validation.normalized!, 'Website');
      setScanResult(result);
      setIsScanning(false);
    } catch (err: any) {
      setIsScanning(false);
      let userFriendlyMessage = 'The website could not be analyzed with the available scanner service.';
      if (err.response?.data?.message) {
        userFriendlyMessage = err.response.data.message;
      } else if (err.response?.data?.error?.message) {
        userFriendlyMessage = err.response.data.error.message;
      } else if (err.code === 'ECONNABORTED' || err.message?.toLowerCase().includes('timeout')) {
        userFriendlyMessage = 'Website scan timed out: The target server took too long to respond. Please verify the URL is online and try again.';
      } else if (err.message === 'Network Error' || err.code === 'ERR_NETWORK') {
        userFriendlyMessage = 'Connection error: Unable to reach the CyberWatch API server at http://localhost:5000. Please ensure the backend service is running.';
      } else if (err.message) {
        userFriendlyMessage = err.message;
      }
      setErrorMessage(userFriendlyMessage);
    }
  }

  function handleFormSubmit(e: React.FormEvent) {
    e.preventDefault();
    executeScan(targetUrl);
  }

  function handleNewScan() {
    setScanResult(null);
    setTargetUrl('');
    setErrorMessage(null);
    setPdfError(null);
  }

  function handleRescan() {
    if (scanResult?.target) {
      executeScan(scanResult.target);
    } else if (targetUrl) {
      executeScan(targetUrl);
    }
  }

  function handleCopy(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleDownloadReport() {
    if (!scanResult || !parsedTarget) return;
    setPdfError(null);
    setIsGeneratingPdf(true);
    try {
      generateScanPdfReport(scanResult, parsedTarget);
      setIsGeneratingPdf(false);
    } catch (err: any) {
      setIsGeneratingPdf(false);
      setPdfError(err.message || 'Unable to generate the report. Please try again.');
    }
  }

  return (
    <div className="space-y-8 w-full">
      {/* ── SCAN INPUT SECTION ─────────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 shadow-xs relative">
        <div className="max-w-3xl">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
                Website Security Scanner
              </h1>
              <span className="text-xs font-semibold text-slate-500">
                CyberWatch Evidence-Based Web Security, Headers, Cookies, TLS & DOM Audit Engine
              </span>
            </div>
          </div>

          <p className="text-sm text-slate-600 leading-relaxed mt-2">
            Inspect any public website with passive evidence collection. Evaluates HTTP response parameters, TLS connection integrity, security headers (CSP, HSTS, XFO), cookie security attributes, mixed-content, DOM forms, and technology stacks without destructive tests.
          </p>

          <form onSubmit={handleFormSubmit} className="mt-5 space-y-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <input
                  id="website-scanner-target-input"
                  type="text"
                  value={targetUrl}
                  onChange={(e) => {
                    setTargetUrl(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  disabled={isScanning}
                  placeholder="Enter website URL (e.g. https://example.com, https://portal.company.com)"
                  className="w-full px-4 py-3 sm:py-3.5 text-sm bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:border-transparent text-slate-900 placeholder:text-slate-400 font-medium transition-all disabled:opacity-60"
                />
                {targetUrl && !isScanning && (
                  <button
                    type="button"
                    onClick={() => setTargetUrl('')}
                    aria-label="Clear target input"
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1 rounded-md"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>

              <button
                id="website-scanner-submit-btn"
                type="submit"
                disabled={isScanning}
                className="inline-flex items-center justify-center gap-2 px-6 py-3 sm:py-3.5 bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 text-white font-bold text-sm rounded-xl shadow-xs transition-all duration-200 shrink-0 disabled:opacity-75 disabled:cursor-not-allowed"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Analyzing Website...</span>
                  </>
                ) : (
                  <>
                    <span>Scan Website</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>

            {/* Error State Banner */}
            {errorMessage && (
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs sm:text-sm text-red-700 bg-red-50 border border-red-200 rounded-xl px-4 py-3 animate-in fade-in duration-200">
                <div className="flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0 text-red-600" />
                  <span>{errorMessage}</span>
                </div>
                <button
                  type="button"
                  onClick={() => executeScan(targetUrl)}
                  className="text-xs font-bold text-red-800 underline hover:text-red-950 shrink-0"
                >
                  Try Again
                </button>
              </div>
            )}

            {/* Scanning State */}
            {isScanning && (
              <div
                id="website-scanner-loading-state"
                className="bg-slate-50 border border-slate-200 rounded-xl p-4 sm:p-5 space-y-2.5 animate-in fade-in duration-200"
              >
                <div className="flex items-center justify-between text-xs font-bold text-indigo-700">
                  <div className="flex items-center gap-2">
                    <Loader2 className="w-4 h-4 animate-spin text-indigo-600" />
                    <span>Collecting Evidence & Auditing Website Security...</span>
                  </div>
                  <span className="text-slate-500 font-semibold">Live website audit</span>
                </div>
                <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                  <div className="h-full bg-indigo-600 rounded-full animate-pulse w-4/5" />
                </div>
                <p className="text-[11px] text-slate-500">
                  Auditing security headers (CSP, HSTS, XFO), cookie attributes, TLS certificates, form targets, mixed-content, technology stack, and website classification.
                </p>
              </div>
            )}
          </form>
        </div>
      </div>

      {/* ── COMPLETED SCAN REPORT VIEW (V2) ─────────────────────────────────── */}
      {scanResult && parsedTarget && (
        <WebsiteScanResultV2View
          scan={scanResult}
          parsedTarget={parsedTarget}
          onRescan={handleRescan}
          isRescanning={isScanning}
          onNewScan={handleNewScan}
          onDownloadReport={handleDownloadReport}
          isGeneratingPdf={isGeneratingPdf}
          pdfError={pdfError}
          onCopy={handleCopy}
          copied={copied}
        />
      )}

      {/* ── EDUCATIONAL & SPECIFICATIONS (When no scan has been executed yet) ── */}
      {!scanResult && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 space-y-4 shadow-xs">
              <div className="flex items-center gap-2">
                <Layers className="w-5 h-5 text-indigo-600" />
                <h3 className="text-base font-bold text-slate-900">What Does The Website Scanner V2 Analyze?</h3>
              </div>
              <ul className="space-y-2.5">
                {[
                  'Live HTTP response headers (CSP directives, HSTS preload/subdomains, frame protection)',
                  'Set-Cookie security attributes with context-aware sensitivity & deduplication',
                  'SSL/TLS certificate chain, SANs, cipher suites, protocol version, and expiration',
                  'HTML forms, password fields, cross-origin/HTTP submission targets, and mixed-content resources',
                  'Technical error & stack trace leakage detection in response bodies',
                  'Evidence-based technology detection and deterministic website classification',
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-xs sm:text-sm text-slate-600">
                    <CheckCircle2 className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 space-y-4 shadow-xs">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-indigo-600" />
                <h3 className="text-base font-bold text-slate-900">Why Evidence-Based Web Scanning?</h3>
              </div>
              <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
                Prevents false-alarm critical ratings by strictly classifying findings into confirmed vulnerabilities, security weaknesses, hardening recommendations, and informational observations based on actual observed data.
              </p>
              <div className="pt-2 flex items-center gap-2">
                <span className="text-xs font-bold text-slate-900">Scanner Engine:</span>
                <span className="px-2.5 py-0.5 rounded-md bg-indigo-50 text-indigo-700 font-mono text-xs font-bold border border-indigo-100">
                  Website Security Scanner V2
                </span>
              </div>
            </div>
          </div>

          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 space-y-5 shadow-xs">
            <div className="flex items-center gap-2">
              <FileCode className="w-5 h-5 text-slate-700" />
              <h3 className="text-base sm:text-lg font-bold text-slate-900">How Does The Evidence-Based Scan Work?</h3>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {[
                { step: 1, title: 'DNS & SSRF Gate', desc: 'Resolves IP records and verifies SSRF network boundaries.' },
                { step: 2, title: 'Connection & TLS', desc: 'Inspects certificate validity, cipher suites, and redirect hops.' },
                { step: 3, title: 'Headers & Cookies', desc: 'Evaluates CSP, HSTS, frame protection, and cookie flags.' },
                { step: 4, title: 'Evidence & Score', desc: 'Synthesizes weighted risk score, findings, and explainability.' },
              ].map((step) => (
                <div key={step.step} className="bg-slate-50 border border-slate-200/70 rounded-xl p-4 space-y-1.5">
                  <div className="w-7 h-7 rounded-lg bg-indigo-600 text-white font-bold text-xs flex items-center justify-center">
                    {step.step}
                  </div>
                  <h4 className="text-xs sm:text-sm font-bold text-slate-900">{step.title}</h4>
                  <p className="text-xs text-slate-500 leading-relaxed">{step.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
