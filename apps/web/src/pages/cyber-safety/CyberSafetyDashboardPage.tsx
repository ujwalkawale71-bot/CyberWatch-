import { Link } from 'react-router-dom';
import {
  Shield,
  Globe,
  Eye,
  Key,
  Puzzle,
  ArrowRight,
  CheckCircle2,
  FileSearch,
  BookOpen,
  Bell,
  Sparkles,
  ExternalLink,
  Clock,
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { SecurityPostureCard } from '../../components/cyber-safety/SecurityPostureCard';

export function CyberSafetyDashboardPage() {
  const quickChecks = [
    {
      title: 'Safe Browsing',
      icon: Globe,
      iconBg: 'bg-blue-50 border-blue-100',
      iconColor: 'text-blue-600',
      desc: 'Identify risky websites, deceptive redirects, and unsafe browsing behavior before visiting.',
      statusIndicator: 'Live Scanner Ready',
      statusColor: 'bg-blue-50 text-blue-700 border-blue-200',
      actionLabel: 'Verify a URL',
      actionHref: '/cyber-safety/safe-browsing',
    },
    {
      title: 'Phishing Protection',
      icon: ShieldAlert,
      iconBg: 'bg-amber-50 border-amber-100',
      iconColor: 'text-amber-600',
      desc: 'Recognize credential harvesting lures, brand impersonation, and deceptive payment requests.',
      statusIndicator: 'Interactive Training',
      statusColor: 'bg-amber-50 text-amber-700 border-amber-200',
      actionLabel: 'Spot Phishing Tactics',
      actionHref: '/cyber-safety/phishing-awareness',
    },
    {
      title: 'Password Security',
      icon: Key,
      iconBg: 'bg-indigo-50 border-indigo-100',
      iconColor: 'text-indigo-600',
      desc: 'Evaluate password entropy locally in browser memory and generate resilient passphrases.',
      statusIndicator: 'Client-Side Analyzer',
      statusColor: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      actionLabel: 'Test Password Entropy',
      actionHref: '/cyber-safety/password-safety',
    },
    {
      title: 'Browser Hardening',
      icon: Puzzle,
      iconBg: 'bg-sky-50 border-sky-100',
      iconColor: 'text-sky-600',
      desc: 'Audit installed browser extensions for excessive host permissions and dangerous APIs.',
      statusIndicator: 'Extension Audit',
      statusColor: 'bg-sky-50 text-sky-700 border-sky-200',
      actionLabel: 'Scan Extension Manifest',
      actionHref: '/cyber-safety/browser-security',
    },
    {
      title: 'Privacy Protection',
      icon: Eye,
      iconBg: 'bg-purple-50 border-purple-100',
      iconColor: 'text-purple-600',
      desc: 'Audit digital tracking telemetry, third-party cookies, and unnecessary data disclosure.',
      statusIndicator: 'Privacy Audit',
      statusColor: 'bg-purple-50 text-purple-700 border-purple-200',
      actionLabel: 'Assess Privacy Risk',
      actionHref: '/cyber-safety/online-privacy',
    },
  ];

  const protectionCategories = [
    {
      title: 'Web Browsing Defense',
      desc: 'Proactive verification of URLs, TLS handshakes, redirects, and suspicious domain registrations.',
      icon: Globe,
      features: ['Domain typo-squatting detection', 'HTTPS & TLS certificate audits', 'Open redirect verification'],
      link: '/cyber-safety/safe-browsing',
    },
    {
      title: 'Phishing & Deception',
      desc: 'Techniques to identify social engineering, urgent credential harvesting, and adversary-in-the-middle attacks.',
      icon: ShieldAlert,
      features: ['Urgency lure identification', 'Brand impersonation heuristics', 'Simulated decision training'],
      link: '/cyber-safety/phishing-awareness',
    },
    {
      title: 'Credentials & Identity',
      desc: 'High-entropy passphrase generation, multi-factor authentication (MFA) practices, and credential rotation.',
      icon: Key,
      features: ['Mathematical bit entropy', 'Offline GPU crack resistance', 'Secure multi-word passphrases'],
      link: '/cyber-safety/password-safety',
    },
    {
      title: 'Browser & Endpoint Hardening',
      desc: 'Evaluating browser security permissions, extension manifest capabilities, and download scrutiny.',
      icon: Puzzle,
      features: ['Manifest V3 compliance checks', 'Broad host access audits', 'Dangerous API privilege flags'],
      link: '/cyber-safety/browser-security',
    },
    {
      title: 'Data & Privacy Exposure',
      desc: 'Techniques to minimize digital footprint, third-party tracker exposure, and metadata disclosures.',
      icon: Eye,
      features: ['Third-party cookie auditing', 'Header leakage checks', 'Self-guided exposure checklist'],
      link: '/cyber-safety/online-privacy',
    },
    {
      title: 'File & Download Integrity',
      desc: 'Assessing downloadable binary assets, double extension evasion, and static cryptographic checksums.',
      icon: FileSearch,
      features: ['MIME & magic byte verification', 'SHA-256 hash lookups', 'Executable payload flags'],
      link: '/services/file',
    },
  ];

  const featuredGuides = [
    {
      title: 'How to Check Whether a Link Is Safe Before Clicking',
      difficulty: 'Beginner',
      readTime: '4 min read',
      category: 'Web Security',
      summary: 'Learn the exact verification protocol security engineers use to inspect URLs, domains, and certificates.',
      href: '/cyber-safety/guides',
      scannerLabel: 'Scan a Link',
      scannerHref: '/cyber-safety/safe-browsing',
    },
    {
      title: 'Recognizing Advanced Adversary-in-the-Middle (AiTM) Phishing',
      difficulty: 'Intermediate',
      readTime: '6 min read',
      category: 'Phishing',
      summary: 'Understand modern reverse-proxy phishing kits that bypass SMS and push multi-factor authentication.',
      href: '/cyber-safety/guides',
      scannerLabel: 'Test Suspicious Link',
      scannerHref: '/cyber-safety/phishing-awareness',
    },
    {
      title: 'Auditing High-Risk Browser Extensions and Permissions',
      difficulty: 'Advanced',
      readTime: '7 min read',
      category: 'Browser Security',
      summary: 'How malicious extensions leverage webRequest and all_urls permissions to capture sensitive form data.',
      href: '/cyber-safety/guides',
      scannerLabel: 'Scan Extension',
      scannerHref: '/cyber-safety/browser-security',
    },
  ];

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      {/* ── 1. Hero Section ────────────────────────────────────────── */}
      <section className="bg-white border-b border-slate-200/80 py-8 md:py-10">
        <Container>
          <div className="max-w-4xl mx-auto text-center space-y-4">
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-md bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider">
              <Shield className="w-3.5 h-3.5" />
              <span>Cyber Safety &amp; Security Guidance Center</span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900">
              Cyber Safety &amp; Personal Security Center
            </h1>

            <p className="text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl mx-auto">
              Understand common cyber threats, strengthen your accounts, protect your browser,
              and reduce your exposure online with actionable guidance backed by CyberWatch security engines.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <Link
                to="/cyber-safety/security-checkup"
                className="inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-bold text-sm transition-all shadow-sm shadow-blue-500/20"
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>Start Security Checkup</span>
              </Link>

              <Link
                to="/cyber-safety/guides"
                className="inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-semibold text-sm transition-colors shadow-xs"
              >
                <BookOpen className="w-4 h-4 text-slate-500" />
                <span>Explore Safety Guides</span>
              </Link>

              <Link
                to="/cyber-safety/alerts"
                className="inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-semibold text-sm transition-colors shadow-xs"
              >
                <Bell className="w-4 h-4 text-slate-500" />
                <span>View Security Alerts</span>
              </Link>
            </div>
          </div>
        </Container>
      </section>

      {/* ── 2. Security Posture Card Section ──────────────────────── */}
      <section className="py-8 md:py-10">
        <Container>
          <SecurityPostureCard />
        </Container>
      </section>

      {/* ── 3. Quick Security Checks ──────────────────────────────── */}
      <section className="py-6">
        <Container>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-bold text-slate-900">Quick Security Checks</h2>
              <p className="text-xs sm:text-sm text-slate-500 mt-0.5">
                Launch targeted evaluations connected directly to CyberWatch detection tools.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {quickChecks.map((item, idx) => {
              const Icon = item.icon;
              return (
                <div
                  key={idx}
                  className="bg-white rounded-2xl border border-slate-200 p-6 flex flex-col justify-between hover:border-slate-300 hover:shadow-sm transition-all"
                >
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className={`w-10 h-10 rounded-xl border flex items-center justify-center ${item.iconBg}`}>
                        <Icon className={`w-5 h-5 ${item.iconColor}`} />
                      </div>
                      <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${item.statusColor}`}>
                        {item.statusIndicator}
                      </span>
                    </div>

                    <div>
                      <h3 className="text-base font-bold text-slate-900">{item.title}</h3>
                      <p className="text-xs sm:text-sm text-slate-500 mt-1.5 leading-relaxed">
                        {item.desc}
                      </p>
                    </div>
                  </div>

                  <div className="pt-6 mt-4 border-t border-slate-100">
                    <Link
                      to={item.actionHref}
                      className="inline-flex items-center justify-between w-full text-xs font-bold text-blue-600 hover:text-blue-700 transition-colors group"
                    >
                      <span>{item.actionLabel}</span>
                      <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        </Container>
      </section>

      {/* ── 4. Core Protection Pillars Grid ──────────────────────── */}
      <section className="py-8">
        <Container>
          <div className="bg-white rounded-2xl border border-slate-200 p-6 sm:p-8 shadow-xs space-y-6">
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
                Protection Categories
              </div>
              <h2 className="text-xl sm:text-2xl font-bold text-slate-900">
                End-to-End Cyber Defense Domains
              </h2>
              <p className="text-xs sm:text-sm text-slate-500 mt-1 max-w-2xl">
                CyberWatch combines proactive educational guidance with real scanner telemetry across six critical security disciplines.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 pt-2">
              {protectionCategories.map((cat, idx) => {
                const Icon = cat.icon;
                return (
                  <div key={idx} className="p-5 rounded-xl bg-slate-50/70 border border-slate-200/80 space-y-4">
                    <div className="w-9 h-9 rounded-lg bg-white border border-slate-200 flex items-center justify-center text-blue-600 shadow-2xs">
                      <Icon className="w-4 h-4" />
                    </div>

                    <div>
                      <h3 className="text-sm font-bold text-slate-900">{cat.title}</h3>
                      <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                        {cat.desc}
                      </p>
                    </div>

                    <ul className="space-y-1.5 text-xs text-slate-600 pt-1 border-t border-slate-200/60">
                      {cat.features.map((f, fIdx) => (
                        <li key={fIdx} className="flex items-center gap-2">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                          <span>{f}</span>
                        </li>
                      ))}
                    </ul>

                    <div className="pt-2">
                      <Link
                        to={cat.link}
                        className="text-xs font-bold text-blue-600 hover:text-blue-700 flex items-center gap-1 group"
                      >
                        <span>Explore Domain</span>
                        <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </Container>
      </section>

      {/* ── 5. Security Checkup CTA Banner ───────────────────────── */}
      <section className="py-6">
        <Container>
          <div className="bg-gradient-to-r from-slate-900 to-blue-950 rounded-2xl p-8 md:p-10 text-white flex flex-col md:flex-row items-center justify-between gap-8 shadow-sm">
            <div className="space-y-2 max-w-2xl text-center md:text-left">
              <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-blue-500/20 text-blue-300 text-xs font-semibold border border-blue-400/30">
                <Sparkles className="w-3 h-3 text-blue-300" />
                <span>Guided Security Assessment</span>
              </div>
              <h3 className="text-2xl sm:text-3xl font-bold tracking-tight">
                Not Sure Where to Start? Run a Checkup.
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                Step through our guided workflow to review suspicious links, analyze downloadable files, audit browser extensions, or query domain threat intelligence.
              </p>
            </div>

            <div className="shrink-0">
              <Link
                to="/cyber-safety/security-checkup"
                className="inline-flex items-center gap-2 px-6 py-3.5 rounded-xl bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-bold text-sm transition-colors shadow-md shadow-blue-600/30"
              >
                <span>Launch Guided Checkup</span>
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </Container>
      </section>

      {/* ── 6. Latest Safety Guidance ────────────────────────────── */}
      <section className="py-8">
        <Container>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-bold text-slate-900">Featured Security Guides</h2>
              <p className="text-xs sm:text-sm text-slate-500 mt-0.5">
                In-depth technical guides with actionable step-by-step checklists.
              </p>
            </div>
            <Link
              to="/cyber-safety/guides"
              className="text-xs font-bold text-blue-600 hover:text-blue-700 inline-flex items-center gap-1"
            >
              <span>View All Guides</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {featuredGuides.map((guide, idx) => (
              <div
                key={idx}
                className="bg-white rounded-2xl border border-slate-200 p-6 flex flex-col justify-between hover:border-slate-300 hover:shadow-xs transition-all"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="font-semibold text-blue-600 bg-blue-50 px-2 py-0.5 rounded">
                      {guide.category}
                    </span>
                    <span className="flex items-center gap-1 text-slate-400">
                      <Clock className="w-3 h-3" />
                      <span>{guide.readTime}</span>
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-slate-900 leading-snug">
                    {guide.title}
                  </h3>

                  <p className="text-xs text-slate-500 leading-relaxed">
                    {guide.summary}
                  </p>
                </div>

                <div className="pt-6 mt-4 border-t border-slate-100 flex items-center justify-between text-xs">
                  <Link
                    to={guide.href}
                    className="font-bold text-slate-700 hover:text-blue-600 transition-colors"
                  >
                    Read Guide →
                  </Link>

                  <Link
                    to={guide.scannerHref}
                    className="font-bold text-blue-600 hover:underline inline-flex items-center gap-1"
                  >
                    <span>{guide.scannerLabel}</span>
                    <ExternalLink className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </Container>
      </section>

      {/* ── 7. Enterprise Security Principles ─────────────────────── */}
      <section className="py-8">
        <Container>
          <div className="bg-slate-100/70 rounded-2xl border border-slate-200 p-6 sm:p-8 space-y-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-blue-600" />
              <span>CyberWatch Product Integrity &amp; Transparency Standard</span>
            </h3>
            <p className="text-xs sm:text-sm text-slate-600 leading-relaxed max-w-3xl">
              CyberWatch adheres to strict honest security reporting. We never convert missing data to "Safe",
              never fabricate artificial protection scores, and execute password entropy analysis 100% locally in your browser.
              All security assessments are linked directly to deterministic scanners and multi-provider Threat Intelligence.
            </p>
          </div>
        </Container>
      </section>
    </div>
  );
}
