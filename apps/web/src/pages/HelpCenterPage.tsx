import { useState, useMemo } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Container } from '../components/ui/Container';
import {
  Search,
  BookOpen,
  HelpCircle,
  Bot,
  Headphones,
  Globe,
  ArrowRight,
  ChevronRight,
  X,
  ArrowLeft,
} from 'lucide-react';
import { cn } from '../lib/utils';

interface HelpArticle {
  id: string;
  title: string;
  category: 'getting-started' | 'scanners' | 'threat-intel' | 'reports' | 'privacy';
  summary: string;
  readTime: string;
  content: string;
  relatedLinks?: Array<{ title: string; href: string }>;
}

const HELP_ARTICLES: HelpArticle[] = [
  {
    id: 'intro-scanners',
    title: 'Getting Started: Which Scanner Should I Use?',
    category: 'getting-started',
    summary: 'A quick guide to selecting the right scanner for web applications, APIs, files, or browser extensions.',
    readTime: '3 min read',
    content: `### Choosing the Right CyberWatch Scanner

CyberWatch provides 6 purpose-built security scanners to cover your attack surface:

1. **URL & Phishing Mega Scanner (\`/services/url-phishing\`):** Best for analyzing suspicious URLs, links sent in emails, domain spoofing, and redirect chains.
2. **Website Security Scanner V2 (\`/services/website-scanner\`):** Best for full web application posture auditing, including HTTP security headers (HSTS, CSP), cookie security flags, and TLS certificate expiration.
3. **API Security Scanner (\`/services/api-scanner\`):** Audits REST and GraphQL endpoints for CORS policy leaks, authentication requirements, and rate limit telemetry.
4. **File Security Scanner (\`/services/file\`):** Static analysis for executables, PDFs, office documents, and archives using multi-engine hashes, entropy, and YARA rules.
5. **Browser Extension Scanner (\`/services/extension\`):** Analyzes Chrome Web Store and Firefox extensions for high-risk permissions and dynamic code injection risks.
6. **Threat Intelligence Correlation (\`/threat-intelligence\`):** Real-time multi-source IOC lookup across AbuseIPDB, VirusTotal, AlienVault OTX, and URLhaus.`,
    relatedLinks: [
      { title: 'Interactive Scanner Guide', href: '/help/guide' },
      { title: 'Security Services Directory', href: '/services' },
    ],
  },
  {
    id: 'risk-scoring-explained',
    title: 'Understanding CyberWatch Risk Scores (0-100)',
    category: 'scanners',
    summary: 'Learn how CyberWatch calculates risk scores and how finding severities impact your overall security score.',
    readTime: '4 min read',
    content: `### Risk Scoring Methodology

CyberWatch normalizes all audit findings into a standardized **0 to 100 Risk Score**:

- **0 – 19 (SAFE):** Target exhibits robust security controls, valid TLS, proper headers, and zero threat indicators.
- **20 – 39 (LOW):** Minor hardening recommendations (e.g. missing optional Permissions-Policy header or informational headers).
- **40 – 69 (MODERATE / SUSPICIOUS):** Significant configuration flaws, such as missing HSTS/CSP, missing HttpOnly/Secure flags on sensitive cookies, or permissive CORS headers.
- **70 – 89 (HIGH RISK):** High-severity vulnerabilities, unauthenticated sensitive endpoints, or dangerous extension permissions (\`<all_urls>\`).
- **90 – 100 (CRITICAL):** Confirmed active malware hashes, verified phishing landing pages, or critical vulnerabilities requiring immediate action.

Points are additive based on verified technical evidence items. CyberWatch never fabricates or hallucinates risk metrics.`,
    relatedLinks: [
      { title: 'Frequently Asked Questions', href: '/help/faq' },
      { title: 'Ask AI Assistant About Risk Scores', href: '/help/ai' },
    ],
  },
  {
    id: 'headers-hardening',
    title: 'How to Implement Recommended HTTP Security Headers',
    category: 'scanners',
    summary: 'Step-by-step configuration snippets for HSTS, Content Security Policy, X-Frame-Options, and Referrer-Policy.',
    readTime: '5 min read',
    content: `### Hardening HTTP Security Headers

When the Website Security Scanner flags missing headers, apply the following industry-standard configurations:

#### 1. Strict-Transport-Security (HSTS)
Forces browsers to only communicate over encrypted HTTPS:
\`\`\`http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
\`\`\`

#### 2. Content-Security-Policy (CSP)
Prevents Cross-Site Scripting (XSS) and data injection:
\`\`\`http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;
\`\`\`

#### 3. X-Frame-Options
Protects against clickjacking attacks:
\`\`\`http
X-Frame-Options: SAMEORIGIN
\`\`\`

#### 4. X-Content-Type-Options
Prevents MIME type sniffing:
\`\`\`http
X-Content-Type-Options: nosniff
\`\`\``,
    relatedLinks: [
      { title: 'Website Security Scanner', href: '/services/website-scanner' },
      { title: 'Talk to Support Engineer', href: '/support' },
    ],
  },
  {
    id: 'threat-intel-integration',
    title: 'How Threat Intelligence Correlation Works',
    category: 'threat-intel',
    summary: 'Discover how CyberWatch cross-correlates indicators of compromise (IOCs) across global telemetry feeds.',
    readTime: '4 min read',
    content: `### Real-Time Threat Intelligence Correlation

CyberWatch queries and correlates indicators across leading global security providers:

- **AbuseIPDB:** Analyzes IPv4/IPv6 address abuse confidence scores and attack telemetry reported by network operators worldwide.
- **VirusTotal & MalwareBazaar:** Checks cryptographic hashes (MD5, SHA-1, SHA-256) against dozens of AV detection engines.
- **AlienVault OTX:** Correlates IP and domain indicators against security community threat pulses.
- **URLhaus:** Checks URLs against real-time active malware distribution blacklists.
- **CISA Advisories:** Automatically flags CVEs listed on CISA's Known Exploited Vulnerabilities catalog.

Correlated indicators appear automatically in your scan reports and the Threat Intelligence dashboard.`,
    relatedLinks: [
      { title: 'Threat Intelligence Suite', href: '/threat-intelligence' },
      { title: 'Security Advisories', href: '/advisories' },
    ],
  },
  {
    id: 'exporting-audit-reports',
    title: 'Generating & Exporting Professional Audit Reports (PDF/JSON)',
    category: 'reports',
    summary: 'Export tamper-evident PDF security reports and machine-readable JSON exports for compliance audits.',
    readTime: '3 min read',
    content: `### Exporting Security Reports

CyberWatch provides enterprise-grade reporting capabilities:

- **Executive PDF Summaries:** Formatted executive summaries with risk scoring breakdowns, visual charts, and prioritized remediation matrices.
- **Full Technical Audit PDFs:** Comprehensive finding-by-finding technical evidence logs suitable for compliance and pen-test audits.
- **JSON Telemetry Exports:** Raw structured JSON output ideal for CI/CD integration and SIEM ingestion.
- **CSV Data Tables:** Tabular findings data for spreadsheet tracking and ticketing system imports.

To export a report, open any scan result or visit the **Export Reports** center in your workspace.`,
    relatedLinks: [
      { title: 'Export Reports Center', href: '/reports/export' },
      { title: 'Scan History', href: '/reports/history' },
    ],
  },
  {
    id: 'privacy-responsible-disclosure',
    title: 'Data Privacy & Responsible Vulnerability Disclosure',
    category: 'privacy',
    summary: 'Understand CyberWatch data retention policies and how to responsibly disclose security vulnerabilities.',
    readTime: '4 min read',
    content: `### Security, Privacy & Responsible Disclosure

CyberWatch is committed to protecting sensitive scan data and maintaining transparent security practices:

- **Data Isolation:** Scan results and support tickets are isolated per authenticated user with strict server-side ownership verification.
- **Encrypted Transmission:** All client-server communication and live support chat traffic is encrypted using TLS 1.3.
- **Responsible Disclosure:** If you identify a vulnerability in CyberWatch itself or a protected perimeter, submit a confidential disclosure via our **Security Report Form**.
- **No Unauthorized Disclosures:** Security reports are handled by senior security engineering staff under strict non-disclosure SLAs.`,
    relatedLinks: [
      { title: 'Security Vulnerability Report Form', href: '/support?tab=security' },
      { title: 'Contact Support Desk', href: '/support' },
    ],
  },
];

export function HelpCenterPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [activeArticle, setActiveArticle] = useState<HelpArticle | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated } = useAuth();

  const handleBack = () => {
    // 1. If router state explicitly provided an origin/previous route, navigate to it
    if ((location.state as any)?.from) {
      navigate((location.state as any).from);
      return;
    }

    // 2. If user has browser/router history in the current session
    const historyState = window.history.state;
    if (historyState && typeof historyState.idx === 'number' && historyState.idx > 0) {
      navigate(-1);
      return;
    }

    // 3. Fallback when opened directly without prior navigation history
    if (isAuthenticated) {
      navigate('/dashboard');
    } else {
      navigate('/support');
    }
  };

  const filteredArticles = useMemo(() => {
    return HELP_ARTICLES.filter((article) => {
      const matchesCategory =
        selectedCategory === 'all' || article.category === selectedCategory;
      const matchesSearch =
        !searchQuery.trim() ||
        article.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        article.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        article.content.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [searchQuery, selectedCategory]);

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20 pt-20 sm:pt-24">
      <Container>
        {/* Previous Step / Back Navigation Control */}
        <div className="mb-4 sm:mb-5">
          <button
            type="button"
            onClick={handleBack}
            aria-label="Go back"
            title="Go back"
            id="help-center-back-btn"
            className="group inline-flex items-center gap-2 px-3.5 py-2 text-xs sm:text-sm font-semibold text-slate-700 hover:text-blue-600 bg-white hover:bg-slate-50 border border-slate-200/90 hover:border-slate-300 rounded-xl shadow-2xs hover:shadow-xs transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 focus-visible:border-blue-500 active:scale-[0.98] cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4 text-slate-500 group-hover:text-blue-600 group-hover:-translate-x-0.5 transition-all" />
            <span>Back</span>
          </button>
        </div>

        <div className="space-y-8 sm:space-y-10">
          {/* 1. Help Center Hero Banner */}
          <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/90 shadow-sm relative overflow-hidden">
            <div className="max-w-3xl relative z-10">
              <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-md bg-cyan-50 border border-cyan-200/70 text-cyan-800 text-xs font-bold uppercase tracking-wider mb-2.5">
                <BookOpen className="w-3.5 h-3.5 text-cyan-600" />
                <span>CyberWatch Help Center &amp; Documentation</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight mb-2">
                How can we assist your security operations today?
              </h1>
              <p className="text-sm sm:text-base text-slate-600 leading-relaxed mb-4">
                Explore comprehensive scanner guides, risk scoring methodologies, technical documentation, and direct support channels.
              </p>

              {/* Search Bar */}
              <div className="relative max-w-xl">
                <Search className="w-5 h-5 text-slate-400 absolute left-4 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search articles, headers, scanners, scoring, threat intel..."
                  className="w-full pl-12 pr-4 py-3.5 bg-slate-50 hover:bg-slate-100/60 focus:bg-white text-slate-900 text-sm rounded-2xl border border-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 focus:border-cyan-500 shadow-2xs transition-all"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => setSearchQuery('')}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* 2. Four Main Hub Portals */}
          <div>
            <div className="mb-5">
              <h2 className="text-lg font-bold text-slate-900">Explore Help &amp; Support Hub</h2>
              <p className="text-xs text-slate-500">
                Choose a dedicated resource or launch real-time technical assistance.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-5">
              {/* Scanner Guide */}
              <Link
                to="/help/guide"
                className="group flex flex-col justify-between bg-white rounded-2xl p-6 border border-slate-200/90 shadow-2xs hover:shadow-md hover:border-cyan-400 transition-all text-left"
              >
                <div>
                  <div className="w-11 h-11 rounded-xl bg-cyan-50 text-cyan-700 flex items-center justify-center mb-4 group-hover:scale-105 transition-transform">
                    <Globe className="w-5 h-5" />
                  </div>
                  <h3 className="text-base font-bold text-slate-900 mb-1.5 group-hover:text-cyan-700 transition-colors">
                    Scanner Guide
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mb-4">
                    In-depth documentation for URL, Website, API, File, and Extension scanners with technical checks.
                  </p>
                </div>
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-cyan-700">
                  <span>View Guides</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>

              {/* FAQ */}
              <Link
                to="/help/faq"
                className="group flex flex-col justify-between bg-white rounded-2xl p-6 border border-slate-200/90 shadow-2xs hover:shadow-md hover:border-indigo-400 transition-all text-left"
              >
                <div>
                  <div className="w-11 h-11 rounded-xl bg-indigo-50 text-indigo-700 flex items-center justify-center mb-4 group-hover:scale-105 transition-transform">
                    <HelpCircle className="w-5 h-5" />
                  </div>
                  <h3 className="text-base font-bold text-slate-900 mb-1.5 group-hover:text-indigo-700 transition-colors">
                    Security FAQ
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mb-4">
                    Instant answers to frequently asked questions about scans, scoring, reports, and troubleshooting.
                  </p>
                </div>
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-indigo-700">
                  <span>Read FAQ</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>

              {/* AI Support Assistant */}
              <Link
                to="/help/ai"
                className="group flex flex-col justify-between bg-white rounded-2xl p-6 border border-slate-200/90 shadow-2xs hover:shadow-md hover:border-emerald-400 transition-all text-left"
              >
                <div>
                  <div className="w-11 h-11 rounded-xl bg-emerald-50 text-emerald-700 flex items-center justify-center mb-4 group-hover:scale-105 transition-transform">
                    <Bot className="w-5 h-5" />
                  </div>
                  <h3 className="text-base font-bold text-slate-900 mb-1.5 group-hover:text-emerald-700 transition-colors">
                    AI Support Assistant
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mb-4">
                    Grounded AI assistant ready to analyze your recent scans, explain risk scores, and guide fixes.
                  </p>
                </div>
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-emerald-700">
                  <span>Chat with AI</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>

              {/* Contact Support & Live Desk */}
              <Link
                to="/support"
                className="group flex flex-col justify-between bg-white rounded-2xl p-6 border border-slate-200/90 shadow-2xs hover:shadow-md hover:border-blue-400 transition-all text-left"
              >
                <div>
                  <div className="w-11 h-11 rounded-xl bg-blue-50 text-blue-700 flex items-center justify-center mb-4 group-hover:scale-105 transition-transform">
                    <Headphones className="w-5 h-5" />
                  </div>
                  <h3 className="text-base font-bold text-slate-900 mb-1.5 group-hover:text-blue-700 transition-colors">
                    Contact Support Desk
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed mb-4">
                    Connect with real support operators, create tickets, and submit vulnerability disclosures.
                  </p>
                </div>
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-blue-700">
                  <span>Open Desk</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>
            </div>
          </div>

          {/* 3. Knowledge Base Articles Section */}
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-3">
              <div>
                <h2 className="text-lg font-bold text-slate-900">Knowledge Base Articles</h2>
                <p className="text-xs text-slate-500">
                  Detailed technical articles, remediation blueprints, and security guidance.
                </p>
              </div>

              {/* Category Filter Pills */}
              <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-none">
                {[
                  { id: 'all', label: 'All Topics' },
                  { id: 'getting-started', label: 'Getting Started' },
                  { id: 'scanners', label: 'Scanners & Scoring' },
                  { id: 'threat-intel', label: 'Threat Intel' },
                  { id: 'reports', label: 'Reports' },
                  { id: 'privacy', label: 'Privacy & Security' },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setSelectedCategory(tab.id)}
                    className={cn(
                      'px-3 py-1.5 rounded-xl text-xs font-semibold transition-all whitespace-nowrap cursor-pointer',
                      selectedCategory === tab.id
                        ? 'bg-cyan-600 text-white shadow-2xs'
                        : 'bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200/80'
                    )}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Articles Grid */}
            {filteredArticles.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                {filteredArticles.map((art) => (
                  <div
                    key={art.id}
                    onClick={() => setActiveArticle(art)}
                    className="bg-white rounded-2xl p-5 sm:p-6 border border-slate-200/90 shadow-2xs hover:shadow-md hover:border-slate-300 transition-all flex flex-col justify-between cursor-pointer text-left group"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2 mb-3">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-700 bg-cyan-50 px-2.5 py-0.5 rounded-full border border-cyan-100">
                          {art.category.replace('-', ' ')}
                        </span>
                        <span className="text-[11px] text-slate-400 font-medium">
                          {art.readTime}
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-900 group-hover:text-cyan-700 transition-colors mb-2 leading-snug">
                        {art.title}
                      </h3>
                      <p className="text-xs text-slate-600 leading-relaxed line-clamp-3 mb-4">
                        {art.summary}
                      </p>
                    </div>

                    <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs font-semibold text-cyan-700">
                      <span>Read Guide</span>
                      <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="bg-white rounded-2xl p-10 border border-slate-200 text-center space-y-3">
                <Search className="w-8 h-8 text-slate-300 mx-auto" />
                <h3 className="text-sm font-bold text-slate-800">No matching articles found</h3>
                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                  Try adjusting your search keywords or reach out to our support engineers directly.
                </p>
                <button
                  type="button"
                  onClick={() => {
                    setSearchQuery('');
                    setSelectedCategory('all');
                  }}
                  className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition-colors cursor-pointer"
                >
                  Clear Filters
                </button>
              </div>
            )}
          </div>
        </div>
      </Container>

      {/* 4. Article Modal Viewer */}
      {activeArticle && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white rounded-3xl max-w-2xl w-full max-h-[90vh] overflow-y-auto border border-slate-200 shadow-2xl p-6 sm:p-8 space-y-6">
            <div className="flex items-start justify-between gap-4 border-b border-slate-100 pb-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-700 bg-cyan-50 px-2.5 py-0.5 rounded-full border border-cyan-100">
                    {activeArticle.category.replace('-', ' ')}
                  </span>
                  <span className="text-xs text-slate-400 font-medium">
                    {activeArticle.readTime}
                  </span>
                </div>
                <h3 className="text-lg sm:text-xl font-bold text-slate-900 leading-snug">
                  {activeArticle.title}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setActiveArticle(null)}
                className="p-1.5 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
                aria-label="Close article modal"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Content Body */}
            <div className="prose prose-slate max-w-none text-xs sm:text-sm leading-relaxed whitespace-pre-line text-slate-800 space-y-3">
              {activeArticle.content}
            </div>

            {/* Related Actions */}
            {activeArticle.relatedLinks && activeArticle.relatedLinks.length > 0 && (
              <div className="pt-4 border-t border-slate-100">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                  Related Navigation
                </h4>
                <div className="flex flex-wrap gap-2">
                  {activeArticle.relatedLinks.map((link, idx) => (
                    <Link
                      key={idx}
                      to={link.href}
                      onClick={() => setActiveArticle(null)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-50 hover:bg-cyan-50 text-slate-700 hover:text-cyan-800 border border-slate-200/80 text-xs font-bold transition-colors"
                    >
                      <span>{link.title}</span>
                      <ArrowRight className="w-3.5 h-3.5 text-cyan-600" />
                    </Link>
                  ))}
                </div>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                type="button"
                onClick={() => setActiveArticle(null)}
                className="px-5 py-2 bg-slate-900 text-white hover:bg-slate-800 rounded-xl text-xs font-bold transition-colors cursor-pointer"
              >
                Close Article
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
