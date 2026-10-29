import { useState, useMemo } from 'react';
import {
  Globe,
  ArrowRight,
  Loader2,
  AlertCircle,
  X,
  HelpCircle,
  FileCode,
  ShieldCheck,
} from 'lucide-react';
import { scanService } from '../../services/scan.service';
import { parseTargetUrl, type ParsedTargetUrl } from '../../utils/urlParser';
import { generateScanPdfReport } from '../../utils/pdfGenerator';
import type { ScanRecord } from '../../types';
import { UrlScanResultView } from './UrlScanResultView';

export function UrlSecurityScanner() {
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
      return { valid: false, error: 'Please enter a URL to scan.' };
    }

    let testUrl = trimmed;
    if (!testUrl.startsWith('http://') && !testUrl.startsWith('https://')) {
      testUrl = `https://${testUrl}`;
    }

    try {
      const parsed = new URL(testUrl);
      if (!parsed.hostname) {
        return {
          valid: false,
          error: 'Please enter a valid target URL (e.g. https://example.com/login).',
        };
      }
      return { valid: true, normalized: trimmed };
    } catch {
      return { valid: false, error: 'Please enter a valid target URL format.' };
    }
  }

  async function executeScan(urlToScan: string) {
    setErrorMessage(null);
    setPdfError(null);
    const validation = validateInput(urlToScan);
    if (!validation.valid) {
      setErrorMessage(validation.error || 'Please enter a valid URL.');
      return;
    }

    setIsScanning(true);

    try {
      const result = await scanService.analyzeUrl(validation.normalized!, 'URL');
      setScanResult(result);
      setIsScanning(false);
    } catch (err: any) {
      setIsScanning(false);
      setErrorMessage(
        err.response?.data?.message ||
          err.message ||
          'The URL could not be analyzed with the available scanner service.'
      );
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
            <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
                URL & PHISHING THREAT SCANNER
              </h1>
              <span className="text-xs font-semibold text-slate-500">
                CyberWatch Unified Web & Threat Detection Platform
              </span>
            </div>
          </div>

          <p className="text-sm text-slate-600 leading-relaxed mt-2">
            Analyze URLs, domains, redirects, page structure and phishing indicators before you trust the web.
          </p>

          <form onSubmit={handleFormSubmit} className="mt-5 space-y-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <input
                  id="url-scanner-target-input"
                  type="text"
                  value={targetUrl}
                  onChange={(e) => {
                    setTargetUrl(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  disabled={isScanning}
                  placeholder="Enter URL (e.g. https://example.com, https://github.com/login)"
                  className="w-full px-4 py-3 sm:py-3.5 text-sm bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent text-slate-900 placeholder:text-slate-400 font-medium transition-all disabled:opacity-60"
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
                id="url-scanner-submit-btn"
                type="submit"
                disabled={isScanning}
                className="inline-flex items-center justify-center gap-2 px-6 py-3 sm:py-3.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-bold text-sm rounded-xl shadow-xs transition-all duration-200 shrink-0 disabled:opacity-75 disabled:cursor-not-allowed cursor-pointer"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Scanning...</span>
                  </>
                ) : (
                  <>
                    <span>Scan Target</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>

            {/* Quick Example Links */}
            <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-500">
              <span className="font-semibold text-slate-600">Examples:</span>
              <button
                type="button"
                onClick={() => {
                  setTargetUrl('https://example.com');
                  executeScan('https://example.com');
                }}
                className="px-2.5 py-1 bg-slate-100 hover:bg-blue-50 hover:text-blue-700 rounded-lg font-mono text-[11px] text-slate-700 transition-colors cursor-pointer"
              >
                https://example.com
              </button>
              <button
                type="button"
                onClick={() => {
                  setTargetUrl('https://github.com/login');
                  executeScan('https://github.com/login');
                }}
                className="px-2.5 py-1 bg-slate-100 hover:bg-blue-50 hover:text-blue-700 rounded-lg font-mono text-[11px] text-slate-700 transition-colors cursor-pointer"
              >
                https://github.com/login
              </button>
            </div>

            {/* Privacy & Safety Note */}
            <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-3 text-[11px] text-slate-500 leading-relaxed">
              <strong className="text-slate-700 font-semibold">Privacy & Safety Notice: </strong>
              CyberWatch performs a non-destructive security analysis. It does not submit credentials or execute the scanned website's JavaScript.
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
                  className="text-xs font-bold text-red-800 underline hover:text-red-950 shrink-0 cursor-pointer"
                >
                  Try Again
                </button>
              </div>
            )}

            {/* Scanning State with 9-Stage Progress Checklist */}
            {isScanning && (
              <div
                id="url-scanner-loading-state"
                className="bg-slate-50 border border-blue-200 rounded-xl p-5 space-y-4 animate-in fade-in duration-200"
              >
                <div className="flex items-center justify-between text-xs font-bold text-blue-700 border-b border-blue-100 pb-2.5">
                  <div className="flex items-center gap-2">
                    <Loader2 className="w-4 h-4 animate-spin text-blue-600" />
                    <span>Executing Unified Mega Security Pipeline</span>
                  </div>
                  <span className="text-slate-500 font-semibold">Live Stage Checklist</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
                  {[
                    'URL Validation',
                    'URL Analysis',
                    'DNS Analysis',
                    'TLS Analysis',
                    'Redirect Analysis',
                    'Safe Page Fetch',
                    'HTML Analysis',
                    'Phishing Analysis',
                    'Risk Evaluation',
                  ].map((stageName) => (
                    <div
                      key={stageName}
                      className="flex items-center gap-2 p-2 bg-white rounded-lg border border-slate-200 text-slate-700 shadow-2xs"
                    >
                      <Loader2 className="w-3.5 h-3.5 text-blue-600 animate-spin shrink-0" />
                      <span className="font-medium truncate">{stageName}</span>
                    </div>
                  ))}
                </div>

                <p className="text-[11px] text-slate-500 text-center pt-1">
                  Correlating transport certificates, DOM forms, and phishing indicators across shared evidence.
                </p>
              </div>
            )}
          </form>
        </div>
      </div>

      {/* ── COMPLETED SCAN REPORT VIEW ─────────────────────────────────────── */}
      {scanResult && parsedTarget && (
        <UrlScanResultView
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
          backLink="/services"
          backLabel="All Scans"
        />
      )}

      {/* ── EDUCATIONAL / HOW IT WORKS (Shown when no active result) ────────── */}
      {!scanResult && !isScanning && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 space-y-3 shadow-xs">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="w-5 h-5 text-blue-600" />
                <h3 className="text-base font-bold text-slate-900">What Does This Scanner Check?</h3>
              </div>
              <ul className="space-y-2 text-xs sm:text-sm text-slate-600">
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-600 mt-2 shrink-0" />
                  <span><strong>Transport Security:</strong> Validates HTTPS encryption and TLS certificates.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-600 mt-2 shrink-0" />
                  <span><strong>Network Infrastructure:</strong> Resolves DNS IP addresses and detects edge proxies.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-600 mt-2 shrink-0" />
                  <span><strong>Redirect Chains:</strong> Inspects multi-hop routing paths and protects against SSRF.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-600 mt-2 shrink-0" />
                  <span><strong>Structural Deception:</strong> Detects IP hosts, homographs, and obfuscation.</span>
                </li>
              </ul>
            </div>

            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 space-y-3 shadow-xs">
              <div className="flex items-center gap-2.5">
                <HelpCircle className="w-5 h-5 text-slate-700" />
                <h3 className="text-base font-bold text-slate-900">Why Is This Scanner Useful?</h3>
              </div>
              <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
                Protects users and security analysts from deceptive phishing landing pages, drive-by malware links, and malicious redirections before visiting or sharing them.
              </p>
              <div className="pt-2 flex items-center gap-2">
                <span className="text-xs font-bold text-slate-900">Supported Target Types:</span>
                <span className="px-2.5 py-0.5 rounded-md bg-slate-100 text-slate-700 font-mono text-xs font-bold">
                  HTTP / HTTPS URLs
                </span>
              </div>
            </div>
          </div>

          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 space-y-5 shadow-xs">
            <div className="flex items-center gap-2">
              <FileCode className="w-5 h-5 text-slate-700" />
              <h3 className="text-base font-bold text-slate-900">How Does The Real Scan Work?</h3>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {[
                { step: 1, title: 'URL Normalization', desc: 'Validates target syntax and extracts component tokens.' },
                { step: 2, title: 'DNS & IP Lookup', desc: 'Resolves live IP records and enforces SSRF boundaries.' },
                { step: 3, title: 'TLS & HTTP Inspection', desc: 'Inspects certificate issuer, response codes, and latency.' },
                { step: 4, title: 'Verdict & Report Synthesis', desc: 'Synthesizes real indicators into a verifiable security report.' },
              ].map((step) => (
                <div key={step.step} className="bg-slate-50 border border-slate-200/70 rounded-xl p-4 space-y-1.5">
                  <div className="w-7 h-7 rounded-lg bg-blue-600 text-white font-bold text-xs flex items-center justify-center">
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
