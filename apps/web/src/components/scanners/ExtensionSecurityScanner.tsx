import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Puzzle,
  ArrowRight,
  Loader2,
  AlertCircle,
  RotateCcw,
  History,
  X,
  Layers,
  ShieldAlert,
  FileCode,
  CheckCircle2,
} from 'lucide-react';
import { scanService } from '../../services/scan.service';

const QUICK_TRY_EXTENSIONS = [
  {
    name: 'Dark Reader',
    url: 'https://chromewebstore.google.com/detail/dark-reader/eimadpbcbfnmbkopoojfekhnkhdbieeh',
  },
  {
    name: 'React DevTools',
    url: 'https://chromewebstore.google.com/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi',
  },
  {
    name: 'uBlock Origin',
    url: 'https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh',
  },
  {
    name: 'Grammarly',
    url: 'https://chromewebstore.google.com/detail/grammarly-ai-writing-and/kbfnbcaeplbcioakkpcpgfkobkghlhen',
  },
];

export function ExtensionSecurityScanner() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  function validateTarget(raw: string): { valid: boolean; normalized?: string; error?: string } {
    const trimmed = raw.trim();
    if (!trimmed) {
      return { valid: false, error: 'Please enter an extension store URL, extension ID, or manifest JSON.' };
    }
    return { valid: true, normalized: trimmed };
  }

  async function handleScan(e?: React.FormEvent) {
    if (e) e.preventDefault();
    setErrorMessage(null);

    const validation = validateTarget(target);
    if (!validation.valid) {
      setErrorMessage(validation.error || 'Please enter a valid extension target.');
      return;
    }

    setIsScanning(true);
    setScanStage('Ingesting extension package & manifest...');

    const stages = [
      'Ingesting extension package & manifest...',
      'Evaluating declared APIs & dangerous permissions...',
      'Auditing host permission scopes & content scripts...',
      'Executing static JavaScript pattern evaluation...',
      'Calculating deterministic evidence-based risk score...',
      'Finalizing transparent security report...',
    ];

    let current = 0;
    const interval = setInterval(() => {
      current++;
      if (current < stages.length) {
        setScanStage(stages[current]);
      }
    }, 450);

    try {
      const result = await scanService.analyzeUrl(validation.normalized!, 'Extension');
      clearInterval(interval);
      setScanStage('Scan complete! Rendering security report...');

      setTimeout(() => {
        setIsScanning(false);
        navigate(`/reports/scans/${result.id}`, { state: { scan: result } });
      }, 350);
    } catch (err: any) {
      clearInterval(interval);
      setIsScanning(false);
      let userFriendlyMessage = 'Extension security scan failed. Please try again.';
      if (err.response?.data?.message) {
        userFriendlyMessage = err.response.data.message;
      } else if (err.response?.data?.error?.message) {
        userFriendlyMessage = err.response.data.error.message;
      } else if (err.message) {
        userFriendlyMessage = err.message;
      }
      setErrorMessage(userFriendlyMessage);
    }
  }

  function handleQuickTry(url: string) {
    setTarget(url);
    if (errorMessage) setErrorMessage(null);
  }

  function handleReset() {
    setTarget('');
    setErrorMessage(null);
  }

  return (
    <div className="space-y-8 w-full">
      {/* ── MAIN INPUT CARD ────────────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 shadow-xs relative">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b border-slate-100">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shrink-0">
              <Puzzle className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
                Browser Extension Scanner
              </h1>
              <span className="text-xs font-semibold text-slate-500">
                CyberWatch Evidence-Based Extension Security, Manifest & Permission Audit Engine
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Link
              to="/reports/history"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold text-xs rounded-xl shadow-2xs transition-all"
            >
              <History className="w-3.5 h-3.5 text-slate-500" />
              <span>Scan History</span>
            </Link>

            <button
              type="button"
              onClick={handleReset}
              disabled={isScanning}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200/80 text-slate-700 font-semibold text-xs rounded-xl transition-all disabled:opacity-50 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5 text-slate-500" />
              <span>Reset</span>
            </button>
          </div>
        </div>

        <p className="text-sm text-slate-600 leading-relaxed mt-4">
          Analyze Chrome Web Store and Firefox extensions for high-risk permissions, broad host access, content scripts, and dynamic code execution with deterministic scoring.
        </p>

        <form onSubmit={handleScan} className="mt-5 space-y-4">
          <div>
            <label htmlFor="ext-target-input" className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
              Extension Store URL, Extension ID, or Manifest JSON
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <input
                  id="ext-target-input"
                  type="text"
                  placeholder="https://chromewebstore.google.com/detail/dark-reader/eimadpbcbfnmbkopoojfekhnkhdbieeh"
                  value={target}
                  onChange={(e) => {
                    setTarget(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  disabled={isScanning}
                  className="w-full px-4 py-3 sm:py-3.5 text-sm bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent text-slate-900 placeholder:text-slate-400 font-medium transition-all disabled:opacity-60 font-mono"
                />
                {target && !isScanning && (
                  <button
                    type="button"
                    onClick={() => setTarget('')}
                    aria-label="Clear extension input"
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1 rounded-md"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>

              <button
                id="extension-scanner-submit-btn"
                type="submit"
                disabled={isScanning || !target.trim()}
                className="inline-flex items-center justify-center gap-2 px-6 py-3 sm:py-3.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-bold text-sm rounded-xl shadow-xs transition-all duration-200 shrink-0 disabled:opacity-75 disabled:cursor-not-allowed"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Analyzing Extension...</span>
                  </>
                ) : (
                  <>
                    <span>Analyze Security Risks</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Quick Try Shortcuts */}
          <div className="flex items-center gap-2 flex-wrap pt-1">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              Quick Test Examples:
            </span>
            {QUICK_TRY_EXTENSIONS.map((item) => (
              <button
                key={item.name}
                type="button"
                onClick={() => handleQuickTry(item.url)}
                disabled={isScanning}
                className="text-xs font-semibold px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200/80 text-slate-700 border border-slate-200/70 transition-colors cursor-pointer"
              >
                {item.name}
              </button>
            ))}
          </div>

          {/* Error Banner */}
          {errorMessage && (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs sm:text-sm text-red-700 bg-red-50 border border-red-200 rounded-xl px-4 py-3 animate-in fade-in duration-200">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-red-600" />
                <span>{errorMessage}</span>
              </div>
              <button
                type="button"
                onClick={() => handleScan()}
                className="text-xs font-bold text-red-800 underline hover:text-red-950 shrink-0"
              >
                Try Again
              </button>
            </div>
          )}

          {/* Scanning Progress State */}
          {isScanning && (
            <div
              id="extension-scanner-loading-state"
              className="bg-slate-50 border border-slate-200 rounded-xl p-4 sm:p-5 space-y-2.5 animate-in fade-in duration-200"
            >
              <div className="flex items-center justify-between text-xs font-bold text-blue-700">
                <div className="flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-blue-600" />
                  <span>{scanStage}</span>
                </div>
                <span className="text-slate-500 font-semibold">Live manifest audit</span>
              </div>
              <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                <div className="h-full bg-blue-600 rounded-full animate-pulse w-4/5" />
              </div>
              <p className="text-[11px] text-slate-500">
                Evaluating declared APIs, high-risk host permissions, content script injection, dynamic code execution, and telemetry exfiltration.
              </p>
            </div>
          )}
        </form>
      </div>

      {/* ── INFORMATION CARDS (Matching Website Scanner layout) ────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 space-y-4 shadow-xs">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-blue-600" />
            <h3 className="text-base font-bold text-slate-900">What Does This Extension Scanner Check?</h3>
          </div>
          <ul className="space-y-2.5">
            {[
              'High-risk manifest permissions (<all_urls>, webRequest, cookies, management)',
              'Broad host permission scopes and cross-origin communication rules',
              'Content script injection rules, active web page access, and DOM mutations',
              'Dynamic code evaluation (eval, new Function) and obfuscated script detection',
              'Native messaging hosts and background service worker privileges',
              'Deterministic evidence-based risk scoring and explainable findings',
            ].map((item, i) => (
              <li key={i} className="flex items-start gap-2.5 text-xs sm:text-sm text-slate-600">
                <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 space-y-4 shadow-xs">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-blue-600" />
            <h3 className="text-base font-bold text-slate-900">Why Is This Scanner Useful?</h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
            Browser extensions run with elevated permissions inside authenticated sessions. This passive analyzer audits manifest definitions and code patterns to detect over-privileged or suspicious extensions without altering browser configurations.
          </p>
          <div className="pt-2 flex items-center gap-2">
            <span className="text-xs font-bold text-slate-900">Scanner Engine:</span>
            <span className="px-2.5 py-0.5 rounded-md bg-blue-50 text-blue-700 font-mono text-xs font-bold border border-blue-100">
              Browser Extension Audit Engine
            </span>
          </div>
        </div>
      </div>

      {/* ── SCAN WORKFLOW SECTION ──────────────────────────────────────────── */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-7 space-y-5 shadow-xs">
        <div className="flex items-center gap-2">
          <FileCode className="w-5 h-5 text-slate-700" />
          <h3 className="text-base sm:text-lg font-bold text-slate-900">How Does The Evidence-Based Scan Work?</h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {[
            { step: 1, title: 'Manifest Ingestion', desc: 'Parses extension manifest structure and validates schemas.' },
            { step: 2, title: 'Permissions Audit', desc: 'Evaluates declared APIs, dangerous flags, and host scopes.' },
            { step: 3, title: 'Static Pattern Checks', desc: 'Audits content scripts, dynamic code, and exfiltration risks.' },
            { step: 4, title: 'Evidence & Score', desc: 'Calculates deterministic evidence-based score and report.' },
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
    </div>
  );
}
