import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  Mail,
  Lock,
  ArrowRight,
  ExternalLink,
  AlertCircle,
  Loader2,
  Clock,
  Eye,
} from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { CyberSafetyHeader } from '../../components/cyber-safety/CyberSafetyHeader';
import { PhishingQuiz } from '../../components/cyber-safety/PhishingQuiz';
import { scanService } from '../../services/scan.service';
import type { ScanRecord } from '../../types';

export function PhishingAwarenessPage() {
  const [phishingInput, setPhishingInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const phishingPhases = [
    {
      step: '01',
      title: 'Initial Lure',
      subtitle: 'The Baited Message',
      desc: 'Attackers distribute deceptive emails, SMS messages (smishing), or chat communications mimicking trusted institutions, colleagues, or vendors.',
    },
    {
      step: '02',
      title: 'Trust Manipulation',
      subtitle: 'Psychological Coercion',
      desc: 'The lure leverages artificial urgency, fear of financial loss, account suspension notices, or executive impersonation to bypass critical evaluation.',
    },
    {
      step: '03',
      title: 'Malicious Destination',
      subtitle: 'Deceptive Infrastructure',
      desc: 'Victim is routed to a cloned landing page with look-alike branding, spoofed SSL certificates, or a real-time proxy capturing session tokens.',
    },
    {
      step: '04',
      title: 'Data & Session Capture',
      subtitle: 'Credential Exfiltration',
      desc: 'Submitted credentials, two-factor authentication codes, or session cookies are recorded by attackers, leading to unauthorized account takeover.',
    },
  ];

  const redFlags = [
    {
      title: 'Artificial Urgency',
      desc: 'Deadlines demanding action "within 24 hours" to prevent account suspension, tax penalties, or missed payments.',
      icon: Clock,
      category: 'Psychological',
    },
    {
      title: 'Unexpected Attachments',
      desc: 'Unsolicited invoice attachments (.html, .iso, .zip, .svg, or macro-enabled docs) carrying embedded redirect scripts.',
      icon: Mail,
      category: 'Payload Delivery',
    },
    {
      title: 'Spoofed Sender Display Names',
      desc: 'Display name showing "CEO or IT Admin" while the underlying email header originates from an unrelated external address.',
      icon: Eye,
      category: 'Header Forgery',
    },
    {
      title: 'Look-alike & Punycode Domains',
      desc: 'Domains substituting visual character twins (e.g., paypa1.com, micros0ft.org, or cyrillic characters).',
      icon: Globe,
      category: 'Domain Deception',
    },
    {
      title: 'Suspicious Login / Credential Demands',
      desc: 'Requests to re-enter passwords to view standard PDF documents, voicemails, or shared spreadsheets.',
      icon: Lock,
      category: 'Credential Harvesting',
    },
    {
      title: 'Payment & Gift Card Pressure',
      desc: 'Requests for urgent wire transfers, micro-payments, or gift card purchases outside standard procurement channels.',
      icon: AlertTriangle,
      category: 'Financial Fraud',
    },
    {
      title: 'Threats of Account Deactivation',
      desc: 'Intimidating claims that your email, cloud storage, or SSO access will be terminated unless verified immediately.',
      icon: ShieldAlert,
      category: 'Coercion Vector',
    },
  ];

  async function handleScanPhishingLink(e: React.FormEvent) {
    e.preventDefault();
    if (!phishingInput.trim()) {
      setScanError('Please enter a suspicious URL or link to analyze.');
      return;
    }

    setIsScanning(true);
    setScanError(null);
    setScanResult(null);

    try {
      const record = await scanService.analyzeUrl(phishingInput.trim(), 'Phishing');
      setScanResult(record);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Phishing scan execution failed.';
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  }



  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      <CyberSafetyHeader
        title="Phishing Awareness"
        subtitle="Phishing attempts use deception to make you reveal credentials, open malicious links, transfer money, or install unsafe software."
        breadcrumbs={[{ label: 'Cyber Safety', href: '/cyber-safety' }]}
        primaryCta={{
          label: 'Run Phishing Scanner',
          href: '/services/url-phishing',
          icon: ShieldAlert,
        }}
      />

      <Container className="py-8 md:py-10 space-y-10">
        {/* ── Live Scanner Integration Section ────────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div className="pb-4 border-b border-slate-100">
            <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-amber-600 mb-1">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Real Phishing Scanner</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Audit a Suspicious Link with CyberWatch Phishing Engine
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Inspect suspicious links for credential harvesting forms, deceptive subdomains, and impersonation heuristics.
            </p>
          </div>

          <form onSubmit={handleScanPhishingLink} className="space-y-4">
            <div>
              <label htmlFor="phishing-scan-input" className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1.5">
                Paste Suspicious URL
              </label>
              <div className="relative">
                <input
                  id="phishing-scan-input"
                  type="text"
                  value={phishingInput}
                  onChange={(e) => {
                    setPhishingInput(e.target.value);
                    if (scanError) setScanError(null);
                  }}
                  placeholder="https://account-verification-alert.com/login"
                  className="w-full pl-4 pr-36 py-3 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white transition-all font-mono"
                  disabled={isScanning}
                />
                <div className="absolute inset-y-0 right-1.5 flex items-center">
                  <button
                    type="submit"
                    disabled={isScanning || !phishingInput.trim()}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-amber-600 hover:bg-amber-700 active:bg-amber-800 disabled:opacity-50 text-white text-xs font-bold rounded-lg transition-all shadow-xs"
                  >
                    {isScanning ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Analyzing...</span>
                      </>
                    ) : (
                      <>
                        <span>Scan Phishing Link</span>
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
                    Analyzed Target: <span className="font-bold text-slate-800">{scanResult.target}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Risk Classification: <span className="font-bold">{scanResult.result}</span> • Risk Index: {scanResult.riskScore}/100
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <Link
                    to={`/reports/scans/${scanResult.id}`}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg transition-colors shadow-xs"
                  >
                    <span>View Phishing Report</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              {scanResult.findings && scanResult.findings.length > 0 && (
                <div className="space-y-2.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                    Phishing &amp; Deception Indicators Flagged:
                  </h4>
                  {scanResult.findings.map((finding, idx) => (
                    <div key={idx} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
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

        {/* ── Interactive Training Module: "Would You Trust This?" ── */}
        <section className="space-y-4">
          <div>
            <h2 className="text-xl font-bold text-slate-900">
              Interactive Training: "Would You Trust This?"
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Practice identifying deceptive tactics across realistic, safe simulated scenarios.
            </p>
          </div>

          <PhishingQuiz />
        </section>

        {/* ── How Phishing Works: 4-Stage Anatomy ─────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
              Threat Anatomy
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              How Phishing Attacks Operate
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Modern social engineering follows a structured multi-stage execution model.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {phishingPhases.map((phase, idx) => (
              <div key={idx} className="p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5 relative">
                <div className="text-2xl font-black text-slate-300 font-mono">
                  {phase.step}
                </div>
                <h3 className="text-sm font-bold text-slate-900">{phase.title}</h3>
                <div className="text-[11px] font-bold text-blue-600 uppercase tracking-wider">
                  {phase.subtitle}
                </div>
                <p className="text-xs text-slate-600 leading-relaxed pt-1">
                  {phase.desc}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Key Phishing Red Flags ──────────────────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-red-600 mb-1">
              Detection Matrix
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Critical Phishing Red Flags
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Always pause and conduct independent verification when any of these indicators are present.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {redFlags.map((flag, idx) => {
              const Icon = flag.icon;
              return (
                <div key={idx} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="w-8 h-8 rounded-lg bg-white border border-slate-200 flex items-center justify-center text-red-600">
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200">
                      {flag.category}
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-900">{flag.title}</h3>
                  <p className="text-xs text-slate-600 leading-relaxed">{flag.desc}</p>
                </div>
              );
            })}
          </div>
        </section>
      </Container>
    </div>
  );
}

function Globe(props: { className?: string }) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
      <path d="M2 12h20" />
    </svg>
  );
}
