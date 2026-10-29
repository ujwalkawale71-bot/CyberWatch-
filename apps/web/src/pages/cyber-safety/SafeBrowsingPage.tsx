import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  Shield,
  ShieldAlert,
  AlertTriangle,
  Lock,
  ArrowRight,
  Loader2,
  ExternalLink,
  AlertCircle,
  Layers,
  FileSearch,
} from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { CyberSafetyHeader } from '../../components/cyber-safety/CyberSafetyHeader';
import { scanService } from '../../services/scan.service';
import type { ScanRecord } from '../../types';

export function SafeBrowsingPage() {
  const [urlInput, setUrlInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const checklist = [
    {
      title: 'Verify the Complete Domain Name',
      desc: 'Inspect the address bar carefully. Focus on the root domain (e.g. "company.com") rather than prepended subdomains or misleading path segments.',
    },
    {
      title: 'Check Transport Encryption (HTTPS & TLS)',
      desc: 'Confirm the site uses HTTPS. Remember that HTTPS only guarantees encrypted transport — malicious phishing websites also obtain free SSL certificates.',
    },
    {
      title: 'Watch for Look-alike & Typo-squatted Domains',
      desc: 'Attackers replace letters with similar characters (e.g., "o" with "0", "l" with "1") or use foreign punycode characters to simulate legitimate brands.',
    },
    {
      title: 'Avoid Suspicious Shortened URLs',
      desc: 'Shortened links (e.g. bit.ly, tinyurl) mask the final destination. Use CyberWatch to resolve the full redirect journey before entering credentials.',
    },
    {
      title: 'Be Cautious with Unexpected Binary Downloads',
      desc: 'Legitimate web pages rarely prompt for spontaneous executable or script downloads (.exe, .scr, .iso, .bat, .vbs) without explicit user intent.',
    },
    {
      title: "Don't Trust Browser Security Warnings Blindly",
      desc: 'If your browser displays an SSL/TLS warning or deceptive site flag, heed the warning and never bypass security interstitials without verification.',
    },
  ];

  const warningSigns = [
    {
      title: 'Suspicious Domain Structure',
      icon: Globe,
      desc: 'Excessive subdomains, random alphanumeric strings, or unfamiliar top-level domains (.xyz, .top, .work) used for impersonation.',
      riskLevel: 'HIGH RISK',
      color: 'text-orange-600 bg-orange-50 border-orange-100',
    },
    {
      title: 'Look-alike Domain (Typo-squatting)',
      icon: ShieldAlert,
      desc: 'Deliberate misspellings of popular brands (e.g., paypa1-auth.com or netflx-billing.com) designed to deceive glance inspections.',
      riskLevel: 'CRITICAL',
      color: 'text-red-600 bg-red-50 border-red-100',
    },
    {
      title: 'Unexpected Multi-Hop Redirect',
      icon: Layers,
      desc: 'Page transitions rapidly across multiple intermediate hosts or tracking domains before reaching an unverified landing destination.',
      riskLevel: 'SUSPICIOUS',
      color: 'text-amber-600 bg-amber-50 border-amber-100',
    },
    {
      title: 'Fake Login / Authentication Page',
      icon: Lock,
      desc: 'Generic login prompts rendered on non-official domains requesting corporate SSO, email credentials, or credit card details.',
      riskLevel: 'CRITICAL',
      color: 'text-red-600 bg-red-50 border-red-100',
    },
    {
      title: 'Urgent Security / Infection Warning',
      icon: AlertTriangle,
      desc: 'Aggressive popups claiming "Your device is infected! Call support now" — a standard psychological scareware scam.',
      riskLevel: 'HIGH RISK',
      color: 'text-orange-600 bg-orange-50 border-orange-100',
    },
    {
      title: 'Untrusted Automatic Download',
      icon: FileSearch,
      desc: 'Drive-by download prompts initiating payload downloads immediately upon page load without prior user interaction.',
      riskLevel: 'CRITICAL',
      color: 'text-red-600 bg-red-50 border-red-100',
    },
  ];

  async function handleScanUrl(e: React.FormEvent) {
    e.preventDefault();
    if (!urlInput.trim()) {
      setScanError('Please provide a URL or domain to scan.');
      return;
    }

    setIsScanning(true);
    setScanError(null);
    setScanResult(null);

    try {
      const record = await scanService.analyzeUrl(urlInput.trim(), 'URL');
      setScanResult(record);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan execution failed. Please verify the URL.';
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  }

  const riskBadgeStyles = {
    Safe: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    'Low Risk': 'bg-blue-50 text-blue-700 border-blue-200',
    Suspicious: 'bg-amber-50 text-amber-700 border-amber-200',
    'High Risk': 'bg-orange-50 text-orange-700 border-orange-200',
    Critical: 'bg-red-50 text-red-700 border-red-200',
  };

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      <CyberSafetyHeader
        title="Safe Browsing"
        subtitle="Identify risky websites, suspicious links, deceptive redirects, and unsafe browsing behavior."
        breadcrumbs={[{ label: 'Cyber Safety Center', href: '/cyber-safety' }]}
        primaryCta={{
          label: 'Run Security Checkup',
          href: '/cyber-safety/security-checkup',
          icon: Shield,
        }}
      />

      <Container className="py-8 md:py-10 space-y-10">
        {/* ── Section C: Real CyberWatch Live Scanner Check ───────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100">
            <div>
              <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
                <Globe className="w-3.5 h-3.5" />
                <span>Live Verification</span>
              </div>
              <h2 className="text-xl font-bold text-slate-900">
                Verify a Suspicious URL with CyberWatch Scanner
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Analyze domain infrastructure, DNS resolution, TLS certificates, redirects, and threat indicators in real time.
              </p>
            </div>
          </div>

          <form onSubmit={handleScanUrl} className="space-y-4">
            <div>
              <label htmlFor="url-scan-input" className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1.5">
                Enter Web Address or Domain
              </label>
              <div className="relative">
                <input
                  id="url-scan-input"
                  type="text"
                  value={urlInput}
                  onChange={(e) => {
                    setUrlInput(e.target.value);
                    if (scanError) setScanError(null);
                  }}
                  placeholder="https://example.com/login"
                  className="w-full pl-4 pr-32 py-3 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white transition-all font-mono"
                  disabled={isScanning}
                />
                <div className="absolute inset-y-0 right-1.5 flex items-center">
                  <button
                    type="submit"
                    disabled={isScanning || !urlInput.trim()}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50 text-white text-xs font-bold rounded-lg transition-all shadow-xs"
                  >
                    {isScanning ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Scanning...</span>
                      </>
                    ) : (
                      <>
                        <span>Scan URL</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            {scanError && (
              <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-900 flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                <span>{scanError}</span>
              </div>
            )}
          </form>

          {/* Actual Result Display */}
          {scanResult && (
            <div className="pt-4 border-t border-slate-200 space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div>
                  <div className="text-xs text-slate-500 font-mono break-all">
                    Scanned Target: <span className="font-bold text-slate-800">{scanResult.target}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Scan ID: <span className="font-mono">{scanResult.id}</span> • Executed at {new Date(scanResult.createdAt).toLocaleTimeString()}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <Link
                    to={`/reports/scans/${scanResult.id}`}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg transition-colors shadow-xs"
                  >
                    <span>Open Full Report</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                    Risk Score
                  </div>
                  <div className="my-2 flex items-baseline gap-2">
                    <span className="text-3xl font-extrabold text-slate-900">
                      {scanResult.riskScore}
                    </span>
                    <span className="text-xs text-slate-400">/ 100</span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Computed evidence score
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                    Verdict Classification
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
                    Target Type: {scanResult.targetType}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                    Security Findings
                  </div>
                  <div className="my-2 flex items-baseline gap-2">
                    <span className="text-3xl font-extrabold text-blue-600">
                      {scanResult.findings?.length || 0}
                    </span>
                    <span className="text-xs text-slate-400">detected</span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Evidence-backed flags
                  </div>
                </div>
              </div>

              {/* Findings Summary */}
              {scanResult.findings && scanResult.findings.length > 0 && (
                <div className="space-y-2.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                    Observed Risk Indicators:
                  </h4>
                  {scanResult.findings.map((finding, idx) => (
                    <div key={idx} className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-slate-900">{finding.title}</span>
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                            finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                              ? 'bg-red-50 text-red-700 border-red-200'
                              : 'bg-amber-50 text-amber-700 border-amber-200'
                          }`}
                        >
                          {finding.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600">{finding.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>

        {/* ── Section A: Before You Visit Checklist ───────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
              Section A: Pre-Navigation Verification
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Before You Visit: The Safe Browsing Protocol
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Follow this standard operating checklist before entering sensitive credentials or executing downloads on unfamiliar domains.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {checklist.map((item, idx) => (
              <div key={idx} className="p-4 rounded-xl bg-slate-50/80 border border-slate-200/80 flex items-start gap-3.5">
                <div className="w-6 h-6 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
                  {idx + 1}
                </div>
                <div className="space-y-1">
                  <h3 className="text-sm font-bold text-slate-900">{item.title}</h3>
                  <p className="text-xs text-slate-600 leading-relaxed">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Section B: Common Website Warning Signs ─────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
              Section B: Risk Indicators
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Common Website Warning Signs
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Key anatomical indicators that signal deceptive or compromised web destinations.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {warningSigns.map((sign, idx) => {
              const Icon = sign.icon;
              return (
                <div key={idx} className="p-5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between space-y-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className={`w-9 h-9 rounded-lg border flex items-center justify-center ${sign.color}`}>
                        <Icon className="w-4 h-4" />
                      </div>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700">
                        {sign.riskLevel}
                      </span>
                    </div>

                    <div>
                      <h3 className="text-sm font-bold text-slate-900">{sign.title}</h3>
                      <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                        {sign.desc}
                      </p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </Container>
    </div>
  );
}
