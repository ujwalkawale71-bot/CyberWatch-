import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Puzzle,
  ShieldAlert,
  Lock,
  ArrowRight,
  ExternalLink,
  AlertCircle,
  Loader2,
  Layers,
  FileCode,
  Eye,
} from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { CyberSafetyHeader } from '../../components/cyber-safety/CyberSafetyHeader';
import { scanService } from '../../services/scan.service';
import type { ScanRecord } from '../../types';

export function BrowserSecurityPage() {
  const [extensionInput, setExtensionInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const hardeningControls = [
    {
      title: 'Keep Your Web Browser Updated',
      desc: 'Browser vendors regularly patch zero-day Remote Code Execution (RCE) and sandbox escape vulnerabilities. Ensure auto-updates are enabled.',
    },
    {
      title: 'Regularly Audit Installed Extensions',
      desc: 'Extensions execute with high privileges within your web pages. Routinely inspect your active add-on list and discard obsolete utilities.',
    },
    {
      title: 'Remove Abandoned or Unused Extensions',
      desc: 'Dormant extensions are often purchased by third-party advertising brokers or threat actors to inject malicious telemetry without notice.',
    },
    {
      title: 'Review Broad Host Permissions',
      desc: 'Be skeptical of extensions requesting access to "all websites" (<all_urls>) or wide wildcard domain matching when they only operate on specific domains.',
    },
    {
      title: 'Block Unsolicited Popups and Redirects',
      desc: 'Configure browser popup blocking to default-deny and disable automatic tab spawning to prevent drive-by redirect chains.',
    },
    {
      title: 'Be Cautious with Spontaneous Downloads',
      desc: 'Always require browser confirmation for download destinations. Never execute binaries originating from unrequested download prompts.',
    },
    {
      title: 'Manage Website Notification Permissions',
      desc: 'Attackers abuse browser push notifications to send fake infection popups directly to your desktop OS even when the browser tab is closed.',
    },
  ];

  const whatCyberWatchChecks = [
    {
      title: 'Manifest Version & Permissions',
      desc: 'Audits declared permissions against Manifest V3 guidelines, flagging dangerous capabilities like webRequestBlocking, debugger, and storage access.',
      icon: FileCode,
    },
    {
      title: 'Broad Host Access Patterns',
      desc: 'Identifies excessive host match patterns (such as http://*/* or https://*/*) that enable extensions to inspect sensitive session DOM across all web traffic.',
      icon: Layers,
    },
    {
      title: 'Content Script Injection',
      desc: 'Analyzes embedded content scripts and matches execution timing against DOM elements, password inputs, and clipboard APIs.',
      icon: Eye,
    },
    {
      title: 'JavaScript Execution Capabilities',
      desc: 'Inspects background workers and service scripts for dynamic remote script execution, eval() usage, and external endpoint communication.',
      icon: Puzzle,
    },
    {
      title: 'Suspicious Storage & Cookie Access',
      desc: 'Evaluates whether the extension requests access to sensitive browser storage APIs, authentication cookies, or credential keystrokes.',
      icon: Lock,
    },
    {
      title: 'Calculated Risk Contributors',
      desc: 'Synthesizes all declared capabilities into an empirical 0–100 risk score with actionable permission mitigation recommendations.',
      icon: ShieldAlert,
    },
  ];

  async function handleScanExtension(e: React.FormEvent) {
    e.preventDefault();
    if (!extensionInput.trim()) {
      setScanError('Please enter an extension Chrome Web Store link or manifest target.');
      return;
    }

    setIsScanning(true);
    setScanError(null);
    setScanResult(null);

    try {
      const record = await scanService.analyzeUrl(extensionInput.trim(), 'Extension');
      setScanResult(record);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Extension scan execution failed.';
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  }



  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      <CyberSafetyHeader
        title="Browser Security"
        subtitle="Harden your browser configuration, audit dangerous extension permissions, and prevent drive-by execution."
        breadcrumbs={[{ label: 'Cyber Safety', href: '/cyber-safety' }]}
        primaryCta={{
          label: 'Scan Browser Extension',
          href: '/services/extension',
          icon: Puzzle,
        }}
      />

      <Container className="py-8 md:py-10 space-y-10">
        {/* ── Live Scanner Check ──────────────────────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div className="pb-4 border-b border-slate-100">
            <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-sky-600 mb-1">
              <Puzzle className="w-3.5 h-3.5" />
              <span>Real Extension Scanner</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Audit a Browser Extension Manifest
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Verify declared capabilities, broad host matching, content scripts, and high-risk API permissions using CyberWatch.
            </p>
          </div>

          <form onSubmit={handleScanExtension} className="space-y-4">
            <div>
              <label htmlFor="extension-scan-input" className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1.5">
                Enter Chrome Web Store URL or Extension ID
              </label>
              <div className="relative">
                <input
                  id="extension-scan-input"
                  type="text"
                  value={extensionInput}
                  onChange={(e) => {
                    setExtensionInput(e.target.value);
                    if (scanError) setScanError(null);
                  }}
                  placeholder="https://chromewebstore.google.com/detail/example-extension/..."
                  className="w-full pl-4 pr-36 py-3 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white transition-all font-mono"
                  disabled={isScanning}
                />
                <div className="absolute inset-y-0 right-1.5 flex items-center">
                  <button
                    type="submit"
                    disabled={isScanning || !extensionInput.trim()}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-sky-600 hover:bg-sky-700 active:bg-sky-800 disabled:opacity-50 text-white text-xs font-bold rounded-lg transition-all shadow-xs"
                  >
                    {isScanning ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Scanning...</span>
                      </>
                    ) : (
                      <>
                        <span>Scan Extension</span>
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
                    Scanned Extension: <span className="font-bold text-slate-800">{scanResult.target}</span>
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
                    <span>Full Extension Audit</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              {scanResult.findings && scanResult.findings.length > 0 && (
                <div className="space-y-2.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                    Extension Findings &amp; Permission Risks:
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

        {/* ── Browser Hardening Checklist ─────────────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
              Configuration Hardening
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Browser Hardening Best Practices
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Follow these standard operating controls to minimize attack surface in everyday web browsing.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {hardeningControls.map((item, idx) => (
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

        {/* ── What CyberWatch Checks Explanation ──────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
              Technical Audit Capabilities
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              What CyberWatch Evaluates in Extension Manifests
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Our static analysis engine inspects extension declarations against real-world threat indicators.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {whatCyberWatchChecks.map((item, idx) => {
              const Icon = item.icon;
              return (
                <div key={idx} className="p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                  <div className="w-9 h-9 rounded-lg bg-white border border-slate-200 flex items-center justify-center text-blue-600 shadow-2xs">
                    <Icon className="w-4 h-4" />
                  </div>
                  <h3 className="text-sm font-bold text-slate-900">{item.title}</h3>
                  <p className="text-xs text-slate-600 leading-relaxed">{item.desc}</p>
                </div>
              );
            })}
          </div>
        </section>
      </Container>
    </div>
  );
}
