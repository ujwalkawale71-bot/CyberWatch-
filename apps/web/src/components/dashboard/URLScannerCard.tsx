import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ArrowRight, Loader2, CheckCircle2, AlertCircle, X, Shield, Lock } from 'lucide-react';
import { scanService } from '../../services/scan.service';

const SCAN_STAGES = [
  'URL Structure Analysis',
  'Domain & DNS Inspection',
  'SSL/TLS Certificate Verification',
  'Phishing & Deception Modeling',
  'Redirect & Forwarding Audit',
  'Synthesizing Security Verdict',
];

const ANALYSIS_CAPABILITIES = [
  'URL Security',
  'Phishing Detection',
  'SSL/TLS Analysis',
  'Redirect Analysis',
  'Domain Analysis',
];

interface URLScannerCardProps {
  onScanComplete?: () => void;
}

export function URLScannerCard({ onScanComplete }: URLScannerCardProps) {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const navigate = useNavigate();

  function validateInput(rawUrl: string): { valid: boolean; normalized?: string; error?: string } {
    const trimmed = rawUrl.trim();
    if (!trimmed) {
      return { valid: false, error: 'Please enter a valid URL.' };
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
          error: 'Please enter a valid domain or website URL (e.g. https://example.com).',
        };
      }
      return { valid: true, normalized: trimmed };
    } catch {
      return { valid: false, error: 'Please enter a valid URL.' };
    }
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setErrorMessage(null);

    const validation = validateInput(url);
    if (!validation.valid) {
      setErrorMessage(validation.error || 'Please enter a valid URL.');
      return;
    }

    setIsScanning(true);
    setStageIndex(0);

    // Progressive stage animation
    const stageInterval = setInterval(() => {
      setStageIndex((prev) => (prev < SCAN_STAGES.length - 1 ? prev + 1 : prev));
    }, 450);

    try {
      const scanRecord = await scanService.analyzeUrl(validation.normalized!);
      clearInterval(stageInterval);
      setStageIndex(SCAN_STAGES.length - 1);

      if (onScanComplete) {
        onScanComplete();
      }

      setTimeout(() => {
        setIsScanning(false);
        navigate(`/reports/scans/${scanRecord.id}`, { state: { scan: scanRecord } });
      }, 400);
    } catch (err: any) {
      clearInterval(stageInterval);
      setIsScanning(false);
      const msg =
        err.response?.data?.message || err.message || 'Security analysis failed. Please try again.';
      setErrorMessage(msg);
    }
  }

  return (
    <div
      id="url-scanner-section"
      className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-sm relative overflow-hidden transition-all duration-300 hover:shadow-md hover:border-slate-300"
    >
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8">
        {/* Left / Center Area: Form & Indicators */}
        <div className="flex-1 w-full">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
            Analyze a URL
          </h2>

          <p className="text-sm sm:text-base text-slate-600 mt-2 leading-relaxed">
            Check a website or URL for potential security risks using CyberWatch's unified security analysis.
          </p>

          {/* Scanner Input Form */}
          <form onSubmit={handleScan} className="mt-6 space-y-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400">
                  <Search className="w-5 h-5" />
                </div>
                <input
                  id="dashboard-url-input"
                  type="text"
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  disabled={isScanning}
                  placeholder="Enter URL (e.g. https://example.com)"
                  className="w-full pl-12 pr-10 py-3.5 sm:py-4 text-sm sm:text-base bg-slate-50/90 border border-slate-200 rounded-2xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent text-slate-900 placeholder:text-slate-400 transition-all font-medium disabled:opacity-60"
                />
                {url && !isScanning && (
                  <button
                    type="button"
                    onClick={() => setUrl('')}
                    aria-label="Clear input"
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1 rounded-md"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>

              <button
                id="dashboard-scan-btn"
                type="submit"
                disabled={isScanning}
                className="inline-flex items-center justify-center gap-2 px-7 py-3.5 sm:py-4 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-bold text-sm sm:text-base rounded-2xl shadow-md shadow-blue-600/25 hover:shadow-lg hover:shadow-blue-600/35 transition-all duration-200 shrink-0 disabled:opacity-75 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <span>Scan URL</span>
                    <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </button>
            </div>

            {/* Validation Error Banner */}
            {errorMessage && (
              <div className="flex items-center gap-2 text-xs sm:text-sm text-red-600 bg-red-50 border border-red-200/80 rounded-xl px-4 py-3 animate-in fade-in duration-200">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            {/* Live Scanning Progress Indicator */}
            {isScanning && (
              <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 sm:p-5 space-y-3 animate-in fade-in duration-300">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-600">
                  <span className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-blue-600 animate-ping" />
                    Analyzing target...
                  </span>
                  <span className="text-blue-700 font-bold">
                    {Math.round(((stageIndex + 1) / SCAN_STAGES.length) * 100)}%
                  </span>
                </div>

                <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-600 transition-all duration-300 rounded-full"
                    style={{ width: `${((stageIndex + 1) / SCAN_STAGES.length) * 100}%` }}
                  />
                </div>

                <div className="flex items-center gap-2 text-xs font-medium text-slate-700 pt-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-600 animate-pulse" />
                  <span>
                    Current Stage: <strong className="text-slate-900">{SCAN_STAGES[stageIndex]}</strong>
                  </span>
                </div>
              </div>
            )}

            {/* Supported Analysis Checkmark Indicators */}
            <div className="pt-2 flex flex-wrap items-center gap-y-2 gap-x-4 sm:gap-x-6 text-xs text-slate-600 font-medium">
              {ANALYSIS_CAPABILITIES.map((cap) => (
                <div key={cap} className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-600 shrink-0" />
                  <span>{cap}</span>
                </div>
              ))}
            </div>
          </form>
        </div>

        {/* Right Side: Subtle CyberWatch Shield Visual & "Scan. Analyze. Stay Safe." */}
        <div className="shrink-0 hidden lg:flex flex-col items-center justify-center p-6 bg-gradient-to-br from-blue-50/60 to-sky-50/40 rounded-2xl border border-blue-100/80 min-w-[230px] text-center space-y-3">
          <div className="relative">
            <div className="w-16 h-16 rounded-2xl bg-blue-600 text-white flex items-center justify-center shadow-md shadow-blue-500/25">
              <Shield className="w-8 h-8" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-emerald-500 border-2 border-white flex items-center justify-center">
              <Lock className="w-2.5 h-2.5 text-white" />
            </div>
          </div>
          <div>
            <p className="text-xs font-bold text-slate-900 tracking-tight">CyberWatch Engine</p>
            <p className="text-[11px] font-semibold text-blue-700 mt-0.5">
              Scan. Analyze. Stay Safe.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
