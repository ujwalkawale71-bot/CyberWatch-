import { Link } from 'react-router-dom';
import {
  Globe,
  ShieldAlert,
  Terminal,
  FileSearch,
  Puzzle,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';
import { Container } from '../components/ui/Container';

interface ScannerItem {
  id: string;
  slug: string;
  name: string;
  description: string;
  analyzes: string[];
  status: 'Available';
  icon: React.ComponentType<{ className?: string }>;
  iconColor: string;
  iconBg: string;
  targetBadge: string;
}

interface ServiceCategory {
  id: string;
  title: string;
  categoryNumber: string;
  scanners: ScannerItem[];
}

const SERVICE_CATEGORIES: ServiceCategory[] = [
  {
    id: 'category-web-security',
    title: 'WEB SECURITY',
    categoryNumber: '01',
    scanners: [
      {
        id: 'service-url-phishing-scanner',
        slug: 'url-phishing',
        name: 'URL & Phishing Mega Scanner',
        description: 'Comprehensive analysis of URLs, domains, redirects, page DOM, and phishing threat deception indicators.',
        analyzes: ['URL & Lexical Patterns', 'DNS & Transport Encryption', 'Credential & Brand Deception'],
        status: 'Available',
        icon: Globe,
        iconColor: 'text-blue-600',
        iconBg: 'bg-blue-50 border-blue-100',
        targetBadge: 'URL & Phishing Target',
      },
      {
        id: 'service-website-scanner',
        slug: 'website-scanner',
        name: 'Website Security Scanner',
        description: 'Analyze public website responses, security headers, cookies, HTML structure, and TLS configurations.',
        analyzes: ['HTTP Headers & Cookies', 'HTML Forms & Scripts', 'TLS & Web Overview'],
        status: 'Available',
        icon: ShieldAlert,
        iconColor: 'text-indigo-600',
        iconBg: 'bg-indigo-50 border-indigo-100',
        targetBadge: 'Website Target',
      },
    ],
  },
  {
    id: 'category-application-security',
    title: 'APPLICATION SECURITY',
    categoryNumber: '02',
    scanners: [
      {
        id: 'service-api-scanner',
        slug: 'api-scanner',
        name: 'API Security Scanner',
        description: 'Audit user-provided API endpoints for CORS configuration, rate limits, headers, and excessive info exposure.',
        analyzes: ['CORS & Method Audit', 'Auth & Rate-Limit Cues', 'Data Exposure Checks'],
        status: 'Available',
        icon: Terminal,
        iconColor: 'text-cyan-600',
        iconBg: 'bg-cyan-50 border-cyan-100',
        targetBadge: 'API Endpoint',
      },
    ],
  },
  {
    id: 'category-file-security',
    title: 'FILE SECURITY',
    categoryNumber: '03',
    scanners: [
      {
        id: 'service-file-scanner',
        slug: 'file',
        name: 'File Security Scanner',
        description: 'Analyze downloadable files and user-provided assets for extension risks, MIME types, and signature anomalies.',
        analyzes: ['File Format & Extensions', 'Binary & Script Risk', 'Hashes & Magic Bytes'],
        status: 'Available',
        icon: FileSearch,
        iconColor: 'text-blue-600',
        iconBg: 'bg-blue-50 border-blue-100',
        targetBadge: 'File Target',
      },
    ],
  },
  {
    id: 'category-browser-security',
    title: 'BROWSER SECURITY',
    categoryNumber: '04',
    scanners: [
      {
        id: 'service-extension-scanner',
        slug: 'extension',
        name: 'Browser Extension Scanner',
        description: 'Audit browser extension packages and Manifest V3 metadata for sensitive permissions and excessive privileges.',
        analyzes: ['Manifest V3 Permissions', 'Host & Script Scope', 'Privilege Combinations'],
        status: 'Available',
        icon: Puzzle,
        iconColor: 'text-sky-600',
        iconBg: 'bg-sky-50 border-sky-100',
        targetBadge: 'Extension Audit',
      },
    ],
  },
];

export function SecurityServicesPage() {
  const totalScanners = SERVICE_CATEGORIES.reduce((acc, cat) => acc + cat.scanners.length, 0);

  return (
    <main className="min-h-screen bg-slate-50/50 pb-24 pt-24 sm:pt-28">
      <Container>
        <div className="space-y-12 w-full">
          {/* ── Page Header ─────────────────────────────────────────────── */}
          <header className="bg-white border border-slate-200/90 rounded-2xl sm:rounded-3xl p-6 sm:p-8 lg:p-10 shadow-sm relative overflow-hidden">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
              <div className="max-w-2xl space-y-3">
                <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-50 text-blue-700 text-xs font-bold uppercase tracking-wider border border-blue-100">
                  <ShieldCheck className="w-3.5 h-3.5 text-blue-600 shrink-0" />
                  <span>Security Services Directory</span>
                </div>
                <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-900 tracking-tight">
                  Security Services
                </h1>
                <p className="text-sm sm:text-base text-slate-600 leading-relaxed pt-0.5">
                  Explore CyberWatch security scanners designed to analyze websites, URLs, domains, files, browser extensions, and related web security risks.
                </p>
              </div>

              {/* Scanner Count Badge */}
              <div className="shrink-0 bg-slate-50 border border-slate-200/80 rounded-2xl p-4 sm:p-5 flex flex-col items-start sm:items-center justify-center min-w-[190px]">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                  </span>
                  <span className="text-xs font-bold text-slate-800 tracking-tight">
                    {totalScanners} Scanners Available
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1">Ready for dedicated inspection</p>
              </div>
            </div>
          </header>

          {/* ── Categorized Service Sections ─────────────────────────────── */}
          <div className="space-y-12">
            {SERVICE_CATEGORIES.map((category) => (
              <section
                key={category.id}
                id={category.id}
                aria-labelledby={`${category.id}-heading`}
                className="space-y-5"
              >
                {/* Category Header */}
                <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-2 border-b border-slate-200/80 pb-3">
                  <div className="flex items-center gap-2.5">
                    <span className="text-xs font-mono font-bold text-blue-600 bg-blue-50 border border-blue-100 px-2 py-0.5 rounded-md shrink-0">
                      {category.categoryNumber}
                    </span>
                    <h2
                      id={`${category.id}-heading`}
                      className="text-base sm:text-lg font-bold text-slate-900 tracking-tight"
                    >
                      {category.title}
                    </h2>
                  </div>
                  <span className="text-xs font-medium text-slate-500">
                    {category.scanners.length} {category.scanners.length === 1 ? 'Scanner' : 'Scanners'}
                  </span>
                </div>

                {/* Scanners Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 items-stretch">
                  {category.scanners.map((scanner) => {
                    const Icon = scanner.icon;
                    return (
                      <div
                        key={scanner.id}
                        id={scanner.id}
                        className="flex flex-col h-full min-w-0 w-full bg-white border border-slate-200/90 rounded-2xl p-6 shadow-xs hover:shadow-md hover:border-blue-300 transition-all duration-200 group"
                      >
                        {/* Top / Content Section */}
                        <div className="flex flex-col flex-1 min-w-0 space-y-4">
                          {/* Header row: Icon & Target Badge */}
                          <div className="flex items-center justify-between gap-2">
                            <div
                              className={`w-12 h-12 rounded-xl flex items-center justify-center border ${scanner.iconBg} shrink-0 transition-transform group-hover:scale-105 duration-200`}
                            >
                              <Icon className={`w-6 h-6 ${scanner.iconColor}`} />
                            </div>
                            <span className="text-[11px] font-semibold text-slate-600 bg-slate-50 border border-slate-200/70 px-2.5 py-1 rounded-full shrink-0">
                              {scanner.targetBadge}
                            </span>
                          </div>

                          {/* Scanner Title & Description */}
                          <div className="min-w-0 space-y-2">
                            <h3 className="text-base sm:text-lg font-bold text-slate-900 group-hover:text-blue-600 transition-colors break-words">
                              {scanner.name}
                            </h3>
                            <p className="text-xs sm:text-sm text-slate-600 leading-relaxed break-words [overflow-wrap:anywhere]">
                              {scanner.description}
                            </p>
                          </div>

                          {/* "What it analyzes" Section */}
                          <div className="pt-2 min-w-0">
                            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-2">
                              What it analyzes
                            </span>
                            <div className="flex flex-wrap gap-1.5 min-w-0">
                              {scanner.analyzes.map((item, idx) => (
                                <span
                                  key={idx}
                                  className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-700 bg-slate-50 border border-slate-200/80 px-2.5 py-1 rounded-lg break-words"
                                >
                                  <CheckCircle2 className="w-3 h-3 text-blue-600 shrink-0" />
                                  <span>{item}</span>
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>

                        {/* Bottom Action Footer */}
                        <div className="mt-auto pt-5 border-t border-slate-100 flex items-center justify-between gap-3 min-w-0">
                          <div className="flex items-center gap-1.5 shrink-0">
                            <span className="w-2 h-2 rounded-full bg-emerald-500" />
                            <span className="text-xs font-semibold text-slate-600">
                              {scanner.status}
                            </span>
                          </div>

                          <Link
                            to={`/services/${scanner.slug}`}
                            id={`btn-scan-${scanner.slug}`}
                            aria-label={`Launch ${scanner.name}`}
                            className="inline-flex items-center gap-1.5 text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 active:bg-blue-800 px-4 py-2 rounded-xl shadow-xs shadow-blue-600/20 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:ring-offset-2 transition-all duration-200 shrink-0"
                          >
                            <span>Scan Now</span>
                            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                          </Link>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
        </div>
      </Container>
    </main>
  );
}
