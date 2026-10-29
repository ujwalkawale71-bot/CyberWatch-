import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Eye,
  ArrowRight,
  ExternalLink,
  AlertCircle,
  Loader2,
  Cookie,
} from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { CyberSafetyHeader } from '../../components/cyber-safety/CyberSafetyHeader';
import { scanService } from '../../services/scan.service';
import type { ScanRecord } from '../../types';

export function OnlinePrivacyPage() {
  const [targetDomain, setTargetDomain] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Self-reported checklist states for user interactive privacy check
  const [answers, setAnswers] = useState<Record<string, boolean>>({});

  const privacyFundamentals = [
    {
      title: 'Minimize Unnecessary Personal Data Sharing',
      desc: 'Never provide real phone numbers, birthdates, or physical addresses unless legally required. Use disposable email aliases for non-critical signups.',
    },
    {
      title: 'Routinely Review Account Privacy Settings',
      desc: 'Lock down social media and search engine telemetry settings. Default data sharing and search index visibility to private/off.',
    },
    {
      title: 'Enforce Phishing-Resistant MFA Everywhere',
      desc: 'Protect primary communication and financial hubs with hardware security keys (FIDO2) or authenticator apps to prevent unauthorized data exfiltration.',
    },
    {
      title: 'Limit Unnecessary App & Device Permissions',
      desc: 'Audit mobile and desktop app permissions. Restrict background location, contacts, microphone, and clipboard access to explicit foreground use.',
    },
    {
      title: 'Review Browser Storage & Cookie Policies',
      desc: 'Block third-party tracking cookies by default and clear local site data upon browser termination to prevent cross-site advertising graph correlation.',
    },
    {
      title: 'Be Cautious with Publicly Visible Information',
      desc: 'Information posted publicly across forums, resumes, and code repositories is permanently indexed by automated OSINT scrapers and threat groups.',
    },
    {
      title: 'Delete Abandoned Accounts and Stored Data',
      desc: 'Old unused services continue to hold your hashed passwords, credit cards, and addresses. Submit formal GDPR/CCPA account deletion requests.',
    },
  ];

  const exposureDomains = [
    {
      id: 'identity',
      title: 'Identity Exposure',
      desc: 'Public visibility of full legal name, phone numbers, home address, and government identifiers.',
      checklist: [
        'Phone number is shielded or alias number used for online purchases',
        'Physical home address is not listed in public WHOIS or social bios',
        'Date of birth is hidden or minimized across public profiles',
      ],
    },
    {
      id: 'account',
      title: 'Account Exposure',
      desc: 'Credential reuse, weak password recovery questions, and lack of secondary authentication.',
      checklist: [
        'Unique passwords used across all services (no reuse)',
        'MFA enabled on primary email, cloud storage, and financial accounts',
        'Security questions use randomized passphrases rather than real answers',
      ],
    },
    {
      id: 'browser',
      title: 'Browser Exposure',
      desc: 'Invasive third-party cookies, persistent canvas/audio fingerprinting, and search history leakage.',
      checklist: [
        'Third-party cross-site cookies blocked by default',
        'WebRTC local IP leakage disabled or shielded via VPN',
        'Browser cache and temporary storage automatically purged periodically',
      ],
    },
    {
      id: 'tracking',
      title: 'Tracking Exposure',
      desc: 'Cross-site advertising pixels, telemetry SDKs, and behavioral surveillance profiles.',
      checklist: [
        'Content blockers or privacy-preserving DNS filtering active',
        'Do Not Track / Global Privacy Control (GPC) headers broadcasted',
        'Ad personalization opted-out in major platform consoles',
      ],
    },
    {
      id: 'dataSharing',
      title: 'Data Sharing Exposure',
      desc: 'Third-party OAuth integrations, connected social logins, and automated cloud sync permissions.',
      checklist: [
        'Revoked obsolete OAuth authorizations in Google/Microsoft/Apple settings',
        'Automated telemetry and diagnostic data collection disabled on OS',
        'Cloud photo/document sync restricted from public sharing links',
      ],
    },
  ];

  function toggleCheck(key: string) {
    setAnswers((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  // Calculate self-assessed exposure score if user has interacted
  const totalItems = exposureDomains.reduce((acc, d) => acc + d.checklist.length, 0);
  const checkedItems = Object.values(answers).filter(Boolean).length;
  const hasUserAssessed = checkedItems > 0;
  const selfExposureScore = hasUserAssessed ? Math.round((checkedItems / totalItems) * 100) : null;

  async function handleScanDomainPrivacy(e: React.FormEvent) {
    e.preventDefault();
    if (!targetDomain.trim()) {
      setScanError('Please enter a website URL or domain to audit for privacy/trackers.');
      return;
    }

    setIsScanning(true);
    setScanError(null);
    setScanResult(null);

    try {
      const record = await scanService.analyzeUrl(targetDomain.trim(), 'Website');
      setScanResult(record);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Website privacy audit failed.';
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      <CyberSafetyHeader
        title="Online Privacy"
        subtitle="Minimize digital telemetry footprints, audit third-party trackers, and harden personal data boundaries."
        breadcrumbs={[{ label: 'Cyber Safety', href: '/cyber-safety' }]}
        primaryCta={{
          label: 'Run Security Checkup',
          href: '/cyber-safety/security-checkup',
          icon: Eye,
        }}
      />

      <Container className="py-8 md:py-10 space-y-10">
        {/* ── Privacy Exposure Assessment Matrix ──────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-purple-600 mb-1">
                Self-Assessment Matrix
              </div>
              <h2 className="text-xl font-bold text-slate-900">
                Privacy Exposure Checklist
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Evaluate your personal exposure across five critical digital privacy domains.
              </p>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 shrink-0 text-center min-w-[160px]">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                Exposure Assessment
              </div>
              <div className="text-xl font-bold text-slate-900 mt-0.5">
                {hasUserAssessed ? (
                  <span className="text-blue-600">{selfExposureScore} / 100</span>
                ) : (
                  <span className="text-slate-400 text-sm font-semibold">Not assessed</span>
                )}
              </div>
              <div className="text-[10px] text-slate-500">
                {hasUserAssessed
                  ? `${checkedItems} of ${totalItems} controls verified`
                  : 'Complete checklist to score'}
              </div>
            </div>
          </div>

          <div className="space-y-6">
            {exposureDomains.map((domain) => (
              <div key={domain.id} className="p-5 rounded-xl bg-slate-50/70 border border-slate-200/80 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <h3 className="text-sm font-bold text-slate-900">{domain.title}</h3>
                  <span className="text-xs text-slate-500">{domain.desc}</span>
                </div>

                <div className="space-y-2 pt-2 border-t border-slate-200/60">
                  {domain.checklist.map((item, idx) => {
                    const itemKey = `${domain.id}-${idx}`;
                    const isChecked = !!answers[itemKey];
                    return (
                      <label
                        key={idx}
                        className="flex items-start gap-3 p-2.5 rounded-lg bg-white border border-slate-200/70 hover:border-slate-300 cursor-pointer text-xs text-slate-700 select-none transition-colors"
                      >
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => toggleCheck(itemKey)}
                          className="mt-0.5 rounded text-blue-600 focus:ring-blue-500 border-slate-300"
                        />
                        <span className={isChecked ? 'line-through text-slate-400 font-medium' : 'font-medium'}>
                          {item}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Real Website Tracker & Privacy Checker ──────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div className="pb-4 border-b border-slate-100">
            <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-indigo-600 mb-1">
              <Cookie className="w-3.5 h-3.5" />
              <span>Real Website Privacy Audit</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Audit a Web Property for Third-Party Trackers &amp; Cookie Flags
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Connect to CyberWatch Website Security Scanner to evaluate cookie security flags, external script trackers, and headers.
            </p>
          </div>

          <form onSubmit={handleScanDomainPrivacy} className="space-y-4">
            <div>
              <label htmlFor="privacy-domain-input" className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1.5">
                Enter Website Domain
              </label>
              <div className="relative">
                <input
                  id="privacy-domain-input"
                  type="text"
                  value={targetDomain}
                  onChange={(e) => {
                    setTargetDomain(e.target.value);
                    if (scanError) setScanError(null);
                  }}
                  placeholder="https://example.com"
                  className="w-full pl-4 pr-36 py-3 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white transition-all font-mono"
                  disabled={isScanning}
                />
                <div className="absolute inset-y-0 right-1.5 flex items-center">
                  <button
                    type="submit"
                    disabled={isScanning || !targetDomain.trim()}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 disabled:opacity-50 text-white text-xs font-bold rounded-lg transition-all shadow-xs"
                  >
                    {isScanning ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Auditing...</span>
                      </>
                    ) : (
                      <>
                        <span>Audit Privacy</span>
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
                    Target Property: <span className="font-bold text-slate-800">{scanResult.target}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Risk Classification: <span className="font-bold">{scanResult.result}</span> • Security Score: {scanResult.riskScore}/100
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <Link
                    to={`/reports/scans/${scanResult.id}`}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg transition-colors shadow-xs"
                  >
                    <span>Full Website Report</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              {scanResult.findings && scanResult.findings.length > 0 && (
                <div className="space-y-2.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                    Observed Cookie &amp; Tracker Findings:
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

        {/* ── Privacy Fundamentals ──────────────────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
              Core Tenets
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Privacy Fundamentals
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Systematic operational principles to protect personal data from commercial scrapers and surveillance.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {privacyFundamentals.map((item, idx) => (
              <div key={idx} className="p-5 rounded-xl bg-slate-50 border border-slate-200/80 space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-md bg-purple-100 text-purple-700 font-bold text-xs flex items-center justify-center shrink-0">
                    {idx + 1}
                  </div>
                  <h3 className="text-sm font-bold text-slate-900">{item.title}</h3>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed pt-1">
                  {item.desc}
                </p>
              </div>
            ))}
          </div>
        </section>
      </Container>
    </div>
  );
}
