import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  Shield,
  ShieldAlert,
  Puzzle,
  FileSearch,
  Server,
  Terminal,
  Activity,
  ArrowRight,
  Loader2,
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  RefreshCw,
  Lock,
  Database,
} from 'lucide-react';
import { scanService } from '../../services/scan.service';
import { threatIntelService } from '../../services/threat-intel.service';
import type { ScanRecord, ScanTargetType, ThreatIntelAnalysisReport } from '../../types';

export type CheckupTargetCategory =
  | 'URL'
  | 'Phishing'
  | 'Website'
  | 'Extension'
  | 'File'
  | 'API'
  | 'Domain'
  | 'IP';

interface TargetOption {
  id: CheckupTargetCategory;
  name: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  iconColor: string;
  iconBg: string;
  scannerType: 'scanner' | 'threatIntel';
  targetType?: ScanTargetType;
  placeholder: string;
  example: string;
  inputType: 'text' | 'file';
}

const TARGET_OPTIONS: TargetOption[] = [
  {
    id: 'URL',
    name: 'Website / URL',
    description: 'Verify URL destination, TLS certificate, redirects, and web server infrastructure.',
    icon: Globe,
    iconColor: 'text-blue-600',
    iconBg: 'bg-blue-50 border-blue-100',
    scannerType: 'scanner',
    targetType: 'URL',
    placeholder: 'https://example.com/login',
    example: 'https://example.com/login',
    inputType: 'text',
  },
  {
    id: 'Phishing',
    name: 'Suspicious Phishing Link',
    description: 'Assess deceptive login pages, brand spoofing keywords, and credential harvesting signals.',
    icon: Shield,
    iconColor: 'text-amber-600',
    iconBg: 'bg-amber-50 border-amber-100',
    scannerType: 'scanner',
    targetType: 'Phishing',
    placeholder: 'https://secure-account-verification-alert.com',
    example: 'https://secure-account-verification-alert.com',
    inputType: 'text',
  },
  {
    id: 'Website',
    name: 'Full Website Security',
    description: 'Audit HTTP security headers, cookie flags, mixed content, and TLS encryption cipher suites.',
    icon: ShieldAlert,
    iconColor: 'text-indigo-600',
    iconBg: 'bg-indigo-50 border-indigo-100',
    scannerType: 'scanner',
    targetType: 'Website',
    placeholder: 'https://portal.company.com',
    example: 'https://portal.company.com',
    inputType: 'text',
  },
  {
    id: 'Extension',
    name: 'Browser Extension',
    description: 'Audit extension permissions, background scripts, Manifest V3 compliance, and dangerous host access.',
    icon: Puzzle,
    iconColor: 'text-sky-600',
    iconBg: 'bg-sky-50 border-sky-100',
    scannerType: 'scanner',
    targetType: 'Extension',
    placeholder: 'https://chromewebstore.google.com/detail/example-extension-id',
    example: 'https://chromewebstore.google.com/detail/sample-id',
    inputType: 'text',
  },
  {
    id: 'File',
    name: 'File / Download Asset',
    description: 'Evaluate downloadable files, double extensions, MIME consistency, and cryptographic hashes.',
    icon: FileSearch,
    iconColor: 'text-blue-600',
    iconBg: 'bg-blue-50 border-blue-100',
    scannerType: 'scanner',
    targetType: 'File',
    placeholder: 'https://example.com/downloads/package.zip',
    example: 'https://example.com/downloads/package.zip',
    inputType: 'text',
  },
  {
    id: 'API',
    name: 'API Endpoint',
    description: 'Safely audit CORS configurations, header leakages, auth requirements, and rate-limit indicators.',
    icon: Terminal,
    iconColor: 'text-cyan-600',
    iconBg: 'bg-cyan-50 border-cyan-100',
    scannerType: 'scanner',
    targetType: 'API',
    placeholder: 'https://api.example.com/v1/auth',
    example: 'https://api.example.com/v1/auth',
    inputType: 'text',
  },
  {
    id: 'Domain',
    name: 'Domain Reputation',
    description: 'Query threat intelligence feeds for malicious infrastructure, passive DNS, and blacklists.',
    icon: Activity,
    iconColor: 'text-purple-600',
    iconBg: 'bg-purple-50 border-purple-100',
    scannerType: 'threatIntel',
    placeholder: 'suspicious-domain.com',
    example: 'suspicious-domain.com',
    inputType: 'text',
  },
  {
    id: 'IP',
    name: 'IP Address Telemetry',
    description: 'Query abuse databases, ASN hosting reputation, known botnets, and geolocation telemetry.',
    icon: Server,
    iconColor: 'text-emerald-600',
    iconBg: 'bg-emerald-50 border-emerald-100',
    scannerType: 'threatIntel',
    placeholder: '198.51.100.24',
    example: '198.51.100.24',
    inputType: 'text',
  },
];

export function CheckupScannerRunner({ initialTargetType }: { initialTargetType?: CheckupTargetCategory }) {
  const [selectedTarget, setSelectedTarget] = useState<CheckupTargetCategory>(initialTargetType || 'URL');
  const [targetInput, setTargetInput] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [threatIntelResult, setThreatIntelResult] = useState<ThreatIntelAnalysisReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [currentStep, setCurrentStep] = useState<1 | 2 | 3>(1);

  const currentOption = TARGET_OPTIONS.find((opt) => opt.id === selectedTarget) || TARGET_OPTIONS[0];

  async function handleRunAssessment(e?: React.FormEvent) {
    if (e) e.preventDefault();
    if (!targetInput.trim()) {
      setScanError('Please enter a valid target to assess.');
      return;
    }

    setScanning(true);
    setScanError(null);
    setScanResult(null);
    setThreatIntelResult(null);
    setCurrentStep(2);

    try {
      if (currentOption.scannerType === 'threatIntel') {
        const intelReport = await threatIntelService.analyzeIndicator(targetInput.trim());
        setThreatIntelResult(intelReport);
        setCurrentStep(3);
      } else {
        const record = await scanService.analyzeUrl(targetInput.trim(), currentOption.targetType || 'URL');
        setScanResult(record);
        setCurrentStep(3);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Analysis failed. Please check target and retry.';
      setScanError(msg);
      setCurrentStep(2);
    } finally {
      setScanning(false);
    }
  }

  function handleReset() {
    setScanResult(null);
    setThreatIntelResult(null);
    setScanError(null);
    setCurrentStep(1);
  }

  const riskBadgeStyles = {
    Safe: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    'Low Risk': 'bg-blue-50 text-blue-700 border-blue-200',
    Suspicious: 'bg-amber-50 text-amber-700 border-amber-200',
    'High Risk': 'bg-orange-50 text-orange-700 border-orange-200',
    Critical: 'bg-red-50 text-red-700 border-red-200',
  };

  return (
    <div className="space-y-8">
      {/* 3-Step Flow Indicator */}
      <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-6 shadow-xs">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div
            className={`flex items-center gap-3 p-3 rounded-xl border transition-all ${
              currentStep === 1
                ? 'bg-blue-50/70 border-blue-200 text-blue-900'
                : currentStep > 1
                ? 'bg-emerald-50/50 border-emerald-200 text-slate-800'
                : 'bg-slate-50 border-slate-200 text-slate-400'
            }`}
          >
            <div
              className={`w-7 h-7 rounded-full flex items-center justify-center font-bold text-xs shrink-0 ${
                currentStep === 1
                  ? 'bg-blue-600 text-white'
                  : currentStep > 1
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-200 text-slate-600'
              }`}
            >
              {currentStep > 1 ? <CheckCircle2 className="w-4 h-4" /> : '1'}
            </div>
            <div className="min-w-0">
              <div className="text-xs font-bold uppercase tracking-wider">Step 1</div>
              <div className="text-xs font-semibold truncate">Select Assessment Target</div>
            </div>
          </div>

          <div
            className={`flex items-center gap-3 p-3 rounded-xl border transition-all ${
              currentStep === 2
                ? 'bg-blue-50/70 border-blue-200 text-blue-900'
                : currentStep > 2
                ? 'bg-emerald-50/50 border-emerald-200 text-slate-800'
                : 'bg-slate-50 border-slate-200 text-slate-400'
            }`}
          >
            <div
              className={`w-7 h-7 rounded-full flex items-center justify-center font-bold text-xs shrink-0 ${
                currentStep === 2
                  ? 'bg-blue-600 text-white animate-pulse'
                  : currentStep > 2
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-200 text-slate-600'
              }`}
            >
              {currentStep > 2 ? <CheckCircle2 className="w-4 h-4" /> : '2'}
            </div>
            <div className="min-w-0">
              <div className="text-xs font-bold uppercase tracking-wider">Step 2</div>
              <div className="text-xs font-semibold truncate">Run CyberWatch Engine</div>
            </div>
          </div>

          <div
            className={`flex items-center gap-3 p-3 rounded-xl border transition-all ${
              currentStep === 3
                ? 'bg-blue-50/70 border-blue-200 text-blue-900'
                : 'bg-slate-50 border-slate-200 text-slate-400'
            }`}
          >
            <div
              className={`w-7 h-7 rounded-full flex items-center justify-center font-bold text-xs shrink-0 ${
                currentStep === 3
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-200 text-slate-600'
              }`}
            >
              3
            </div>
            <div className="min-w-0">
              <div className="text-xs font-bold uppercase tracking-wider">Step 3</div>
              <div className="text-xs font-semibold truncate">Evidence &amp; Guidance</div>
            </div>
          </div>
        </div>
      </div>

      {/* STEP 1: Select Target Type */}
      {currentStep <= 2 && (
        <div className="bg-white rounded-2xl border border-slate-200 p-6 md:p-8 shadow-xs space-y-6">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
              Step 1: Choose What You Want to Review
            </h3>
            <p className="text-xs text-slate-500 mt-1">
              Select an asset category to trigger the appropriate CyberWatch security engine.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {TARGET_OPTIONS.map((opt) => {
              const isSelected = selectedTarget === opt.id;
              const Icon = opt.icon;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => {
                    setSelectedTarget(opt.id);
                    setTargetInput('');
                    setScanError(null);
                  }}
                  className={`flex flex-col text-left p-4 rounded-xl border transition-all ${
                    isSelected
                      ? 'bg-blue-50/60 border-blue-600 shadow-xs ring-1 ring-blue-600/30'
                      : 'bg-slate-50/60 border-slate-200/80 hover:bg-white hover:border-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between w-full mb-3">
                    <div className={`w-9 h-9 rounded-lg border flex items-center justify-center ${opt.iconBg}`}>
                      <Icon className={`w-4 h-4 ${opt.iconColor}`} />
                    </div>
                    {isSelected && (
                      <span className="w-2 h-2 rounded-full bg-blue-600" />
                    )}
                  </div>
                  <div className="text-xs font-bold text-slate-900">{opt.name}</div>
                  <div className="text-[11px] text-slate-500 mt-1 leading-relaxed line-clamp-2">
                    {opt.description}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Target Input & Run Form */}
          <form onSubmit={handleRunAssessment} className="pt-4 border-t border-slate-100 space-y-4">
            <div>
              <label htmlFor="checkup-target-input" className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1.5">
                Enter {currentOption.name} Target
              </label>
              <div className="relative">
                <input
                  id="checkup-target-input"
                  type="text"
                  value={targetInput}
                  onChange={(e) => {
                    setTargetInput(e.target.value);
                    if (scanError) setScanError(null);
                  }}
                  placeholder={currentOption.placeholder}
                  className="w-full pl-4 pr-32 py-3 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white transition-all font-mono"
                  disabled={scanning}
                />
                <div className="absolute inset-y-0 right-1.5 flex items-center">
                  <button
                    type="submit"
                    disabled={scanning || !targetInput.trim()}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50 text-white text-xs font-bold rounded-lg transition-all shadow-xs"
                  >
                    {scanning ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Analyzing...</span>
                      </>
                    ) : (
                      <>
                        <span>Execute Checkup</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500">
              <div>
                <span className="font-semibold text-slate-700">Example:</span>{' '}
                <button
                  type="button"
                  onClick={() => setTargetInput(currentOption.example)}
                  className="text-blue-600 hover:underline font-mono"
                >
                  {currentOption.example}
                </button>
              </div>
              <div className="flex items-center gap-1 text-slate-400">
                <Lock className="w-3 h-3" />
                <span>Connected directly to CyberWatch unified scanning telemetry</span>
              </div>
            </div>

            {scanError && (
              <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-900 flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                <span>{scanError}</span>
              </div>
            )}
          </form>
        </div>
      )}

      {/* STEP 3: Assessment Results & Findings */}
      {currentStep === 3 && (scanResult || threatIntelResult) && (
        <div className="space-y-6">
          {/* Result Banner Header */}
          <div className="bg-white rounded-2xl border border-slate-200 p-6 md:p-8 shadow-xs space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
              <div>
                <div className="flex items-center gap-2 text-xs font-bold text-blue-600 uppercase tracking-wider mb-1">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  <span>Assessment Complete</span>
                </div>
                <h3 className="text-xl font-bold text-slate-900">
                  Security Assessment Findings
                </h3>
                <div className="text-xs text-slate-500 font-mono mt-1 break-all">
                  Target: {targetInput}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleReset}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold rounded-xl transition-colors"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>New Checkup</span>
                </button>

                {scanResult && (
                  <Link
                    to={`/reports/scans/${scanResult.id}`}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-xl transition-colors shadow-xs"
                  >
                    <span>Full Security Report</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                )}
              </div>
            </div>

            {/* If Scanner Result */}
            {scanResult && (
              <div className="space-y-6">
                {/* Score and Status Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                      Calculated Risk Score
                    </div>
                    <div className="my-2 flex items-baseline gap-2">
                      <span className="text-3xl font-extrabold text-slate-900">
                        {scanResult.riskScore}
                      </span>
                      <span className="text-xs font-medium text-slate-500">/ 100</span>
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Empirical evidence risk index
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                      Risk Classification
                    </div>
                    <div className="my-2">
                      <span
                        className={`inline-block text-xs font-bold px-2.5 py-1 rounded-md border ${
                          riskBadgeStyles[scanResult.result] || 'bg-slate-100 text-slate-700'
                        }`}
                      >
                        {scanResult.result}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Target type: {scanResult.targetType}
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                      Findings Flagged
                    </div>
                    <div className="my-2 flex items-baseline gap-2">
                      <span className="text-3xl font-extrabold text-blue-600">
                        {scanResult.findings?.length || 0}
                      </span>
                      <span className="text-xs font-medium text-slate-500">issues</span>
                    </div>
                    <div className="text-[11px] text-slate-500">
                      {scanResult.findings?.filter((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL').length || 0} High/Critical
                    </div>
                  </div>
                </div>

                {/* Findings List */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                    Technical Evidence &amp; Findings
                  </h4>

                  {(!scanResult.findings || scanResult.findings.length === 0) ? (
                    <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-900">
                      <span className="font-bold">No High-Risk Vulnerabilities Detected: </span>
                      The scanned target passed baseline protocol and heuristic checks without triggering critical alarms.
                    </div>
                  ) : (
                    <div className="space-y-2.5">
                      {scanResult.findings.map((f, idx) => (
                        <div key={idx} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-bold text-slate-900">{f.title}</span>
                            <span
                              className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                                f.severity === 'CRITICAL' || f.severity === 'HIGH'
                                  ? 'bg-red-50 text-red-700 border-red-200'
                                  : f.severity === 'MEDIUM'
                                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                                  : 'bg-blue-50 text-blue-700 border-blue-200'
                              }`}
                            >
                              {f.severity}
                            </span>
                          </div>
                          <p className="text-xs text-slate-600 leading-relaxed">{f.description}</p>
                          {f.recommendation && (
                            <div className="text-[11px] text-blue-700 bg-blue-50/60 p-2 rounded-lg mt-2 font-medium">
                              <span className="font-bold">Recommended Remediation:</span> {f.recommendation}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Threat Intelligence Context if present */}
                {scanResult.checks?.urlSecurityAnalysis?.threatIntelligence && (
                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-800 uppercase tracking-wider">
                      <Database className="w-4 h-4 text-blue-600" />
                      <span>Threat Intelligence Context</span>
                    </div>
                    <p className="text-xs text-slate-600">
                      {scanResult.checks.urlSecurityAnalysis.threatIntelligence.details || 'Threat intelligence feeds queried for target indicators.'}
                    </p>
                    <div className="text-[11px] text-slate-500">
                      Status: <span className="font-semibold">{scanResult.checks.urlSecurityAnalysis.threatIntelligence.status || 'Queried'}</span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* If Threat Intel Lookup Result */}
            {threatIntelResult && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                      Threat Intelligence Verdict
                    </div>
                    <div className="my-2">
                      <span className="inline-block text-xs font-bold px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 border border-blue-200">
                        {threatIntelResult.overallReputation}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Normalized Type: {threatIntelResult.indicatorType}
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                      Confidence Level
                    </div>
                    <div className="my-2">
                      <span className="inline-block text-xs font-bold px-2.5 py-1 rounded-md bg-slate-100 text-slate-800 border border-slate-200">
                        {threatIntelResult.confidence} CONFIDENCE
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500">
                      {threatIntelResult.confidenceExplanation || 'Multi-source confidence index'}
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                      Providers Queried
                    </div>
                    <div className="my-2 flex items-baseline gap-2">
                      <span className="text-3xl font-extrabold text-blue-600">
                        {threatIntelResult.providersChecked}
                      </span>
                      <span className="text-xs font-medium text-slate-500">/ {threatIntelResult.providersTotal} feeds</span>
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Multi-source verification
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                    Provider Telemetry Breakdown
                  </h4>
                  <div className="space-y-2">
                    {threatIntelResult.providers?.map((p, idx: number) => (
                      <div key={idx} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between text-xs">
                        <div>
                          <div className="font-bold text-slate-900">{p.providerName}</div>
                          <div className="text-slate-500 text-[11px]">{p.details || 'Queried'}</div>
                        </div>
                        <span className="font-semibold text-slate-700 bg-white px-2.5 py-1 rounded border border-slate-200">
                          {p.reputation}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
