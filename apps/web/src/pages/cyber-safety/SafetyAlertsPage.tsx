import { useState, useEffect } from 'react';
import {
  Bell,
  Shield,
  ShieldCheck,
  RefreshCw,
  ExternalLink,
  BookOpen,
} from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { CyberSafetyHeader } from '../../components/cyber-safety/CyberSafetyHeader';
import { threatIntelService } from '../../services/threat-intel.service';

interface AdvisoryItem {
  id?: string;
  cveId?: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  publishedDate?: string;
  affectedComponent?: string;
  summary: string;
  mitigation: string;
}

export function SafetyAlertsPage() {
  const [loading, setLoading] = useState(true);
  const [activeAlerts, setActiveAlerts] = useState<any[]>([]);
  const [providerConfigured, setProviderConfigured] = useState(false);

  // Curated educational security advisories (strictly labeled as educational advisories)
  const educationalAdvisories: AdvisoryItem[] = [
    {
      cveId: 'SEC-ADV-2024-01',
      title: 'Credential Stuffing Attacks via Compromised Web API Proxies',
      severity: 'HIGH',
      publishedDate: 'Educational Advisory',
      affectedComponent: 'Web Applications & REST APIs',
      summary: 'Automated botnets leverage residential proxy networks to distribute credential stuffing attacks against public authentication endpoints.',
      mitigation: 'Implement rate-limiting, CAPTCHA challenges, and WebAuthn multi-factor authentication on all login endpoints.',
    },
    {
      cveId: 'SEC-ADV-2024-02',
      title: 'Malicious Browser Extension Takeovers via Abandoned Publisher Accounts',
      severity: 'HIGH',
      publishedDate: 'Educational Advisory',
      affectedComponent: 'Chrome & Edge Browser Extensions',
      summary: 'Threat groups acquire abandoned developer credentials to push malicious background update scripts to existing browser extension installs.',
      mitigation: 'Routinely audit installed browser add-ons and restrict permissions to on-click execution.',
    },
    {
      cveId: 'SEC-ADV-2024-03',
      title: 'Punycode & Homoglyph URL Spoofing in Brand Impersonation',
      severity: 'MEDIUM',
      publishedDate: 'Educational Advisory',
      affectedComponent: 'Web Browsers & Email Clients',
      summary: 'Adversaries register internationalized domain names (IDN) with Cyrillic characters visually identical to Latin characters to evade user inspection.',
      mitigation: 'Verify domains with CyberWatch URL Scanner and configure browsers to display raw punycode (xn--) for non-Latin character sets.',
    },
  ];

  useEffect(() => {
    let mounted = true;
    async function loadAlerts() {
      try {
        setLoading(true);
        const res = await threatIntelService.getAdvisories();
        if (mounted) {
          setProviderConfigured(res.configured || false);
          setActiveAlerts(res.advisories || []);
        }
      } catch (err) {
        console.error('Failed to load active advisories', err);
      } finally {
        if (mounted) setLoading(false);
      }
    }
    loadAlerts();
    return () => {
      mounted = false;
    };
  }, []);

  const severityBadge = {
    CRITICAL: 'bg-red-50 text-red-700 border-red-200',
    HIGH: 'bg-orange-50 text-orange-700 border-orange-200',
    MEDIUM: 'bg-amber-50 text-amber-700 border-amber-200',
    LOW: 'bg-blue-50 text-blue-700 border-blue-200',
  };

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      <CyberSafetyHeader
        title="Safety Alerts & Advisories"
        subtitle="Verified live threat alerts, telemetry bulletins, and educational security advisories."
        breadcrumbs={[{ label: 'Cyber Safety', href: '/cyber-safety' }]}
        primaryCta={{
          label: 'Run Security Checkup',
          href: '/cyber-safety/security-checkup',
          icon: Shield,
        }}
        secondaryCta={{
          label: 'Threat Intelligence Suite',
          href: '/threat-intelligence',
          icon: ExternalLink,
        }}
      />

      <Container className="py-8 md:py-10 space-y-10">
        {/* ── 1. Live Verified Security Alerts ─────────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
            <div>
              <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
                <Bell className="w-3.5 h-3.5" />
                <span>Verified Threat Stream</span>
              </div>
              <h2 className="text-xl font-bold text-slate-900">
                Active CyberWatch Safety Alerts
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Real-time threat alerts verified by configured Threat Intelligence adapters.
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="font-semibold text-slate-500">Provider Status:</span>
              <span
                className={`px-2 py-0.5 rounded-full font-bold border ${
                  providerConfigured
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-slate-100 text-slate-600 border-slate-200'
                }`}
              >
                {providerConfigured ? 'CONNECTED' : 'NOT CONFIGURED'}
              </span>
            </div>
          </div>

          {loading ? (
            <div className="py-12 flex flex-col items-center justify-center text-center space-y-3">
              <RefreshCw className="w-6 h-6 text-blue-600 animate-spin" />
              <p className="text-xs text-slate-500 font-medium">Checking live threat streams...</p>
            </div>
          ) : activeAlerts.length === 0 ? (
            /* State: Strictly honest zero fake data */
            <div className="p-8 rounded-xl bg-slate-50 border border-slate-200/80 text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-blue-50 text-blue-600 flex items-center justify-center mx-auto border border-blue-100">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900">
                No active CyberWatch safety alerts.
              </h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
                There are currently no active high-severity live alerts flagged by connected intelligence feeds.
                CyberWatch never generates simulated threat alarms to maintain strict telemetry integrity.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {activeAlerts.map((alert, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-red-50 border border-red-200 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-red-900">{alert.title}</span>
                    <span className="bg-red-100 text-red-700 px-2 py-0.5 rounded font-bold">
                      {alert.severity || 'CRITICAL'}
                    </span>
                  </div>
                  <p className="text-xs text-red-800">{alert.summary}</p>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ── 2. Educational Security Advisories (Clearly Labeled) ─── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-amber-700 mb-1">
              <BookOpen className="w-3.5 h-3.5" />
              <span>Educational Guidance</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Security Advisories &amp; Threat Briefings
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Curated architectural threat advisories explaining emerging attack patterns and engineering mitigations.
            </p>
          </div>

          <div className="space-y-4">
            {educationalAdvisories.map((advisory, idx) => (
              <div key={idx} className="p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                      SECURITY ADVISORY
                    </span>
                    <span className="text-xs font-mono font-semibold text-slate-500">
                      {advisory.cveId}
                    </span>
                  </div>

                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border self-start sm:self-auto ${severityBadge[advisory.severity]}`}>
                    {advisory.severity} SEVERITY
                  </span>
                </div>

                <div>
                  <h3 className="text-sm sm:text-base font-bold text-slate-900">
                    {advisory.title}
                  </h3>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    Target Surface: <span className="font-semibold text-slate-700">{advisory.affectedComponent}</span>
                  </div>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed">
                  {advisory.summary}
                </p>

                <div className="p-3 rounded-lg bg-blue-50/60 border border-blue-100 text-xs text-blue-950 space-y-0.5">
                  <div className="font-bold flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5 text-blue-700" />
                    <span>Recommended Mitigation:</span>
                  </div>
                  <div className="text-slate-700 pl-4">{advisory.mitigation}</div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </Container>
    </div>
  );
}
