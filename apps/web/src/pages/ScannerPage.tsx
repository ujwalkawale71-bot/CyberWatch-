import { useState, useMemo } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Globe,
  ShieldAlert,
  Activity,
  Shield,
  FileSearch,
  ArrowRight,
  ArrowLeft,
  Loader2,
  CheckCircle2,
  AlertCircle,
  X,
  HelpCircle,
  Layers,
  FileCode,
  ShieldCheck,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { scanService } from '../services/scan.service';
import { UrlSecurityScanner } from '../components/scanners/UrlSecurityScanner';
import { WebsiteSecurityScanner } from '../components/scanners/WebsiteSecurityScanner';
import { FileSecurityScanner } from '../components/scanners/FileSecurityScanner';
import { ExtensionSecurityScanner } from '../components/scanners/ExtensionSecurityScanner';
import type { ScanTargetType } from '../types';

interface ScannerConfig {
  slug: string;
  name: string;
  category: string;
  targetType: ScanTargetType;
  icon: React.ComponentType<{ className?: string }>;
  iconColor: string;
  iconBg: string;
  placeholder: string;
  exampleUrl: string;
  whatIsIt: string;
  whatItAnalyzes: string[];
  whyUseful: string;
  inputGuidance: string;
  howItWorks: { step: number; title: string; desc: string }[];
}

const SCANNER_CONFIGS: Record<string, ScannerConfig> = {
  'url-phishing': {
    slug: 'url-phishing',
    name: 'URL & Phishing Mega Scanner',
    category: 'Web Security',
    targetType: 'URL',
    icon: Globe,
    iconColor: 'text-blue-600',
    iconBg: 'bg-blue-50 border-blue-100',
    placeholder: 'Enter URL (e.g. https://example.com/login)',
    exampleUrl: 'https://example.com/login',
    whatIsIt: 'Unified web threat detection engine combining URL security analysis, domain DNS & TLS audit, redirect journey inspection, and credential/brand phishing analysis.',
    whatItAnalyzes: [
      'URL structure, suspicious tokens, and evasion patterns',
      'Live DNS resolution, TLS certificates, and server response',
      'Redirect path verification and cross-domain tracking',
      'Credential forms, password inputs, and brand identity consistency',
      'Heuristic social engineering lures and external threat intelligence',
    ],
    whyUseful: 'Provides an all-in-one evidence-based security verdict covering both link infrastructure and deceptive phishing mechanics before visiting.',
    inputGuidance: 'Provide any public URL or web address, starting with http:// or https://, or a domain name.',
    howItWorks: [
      { step: 1, title: 'URL Validation & Normalization', desc: 'Validates structure and normalizes host, path, and parameters.' },
      { step: 2, title: 'Parallel Evidence Collection', desc: 'Queries DNS, TLS handshake, and configured threat feeds.' },
      { step: 3, title: 'Safe Page & Phishing Audit', desc: 'Inspects DOM forms, password inputs, and brand authenticity.' },
      { step: 4, title: 'Unified Risk Synthesis', desc: 'Calculates a deterministic 0–100 risk score and findings.' },
    ],
  },
  'url-scanner': {
    slug: 'url-phishing',
    name: 'URL & Phishing Mega Scanner',
    category: 'Web Security',
    targetType: 'URL',
    icon: Globe,
    iconColor: 'text-blue-600',
    iconBg: 'bg-blue-50 border-blue-100',
    placeholder: 'Enter URL (e.g. https://example.com/login)',
    exampleUrl: 'https://example.com/login',
    whatIsIt: 'Unified web threat detection engine combining URL security analysis, domain DNS & TLS audit, redirect journey inspection, and credential/brand phishing analysis.',
    whatItAnalyzes: [
      'URL structure, suspicious tokens, and evasion patterns',
      'Live DNS resolution, TLS certificates, and server response',
      'Redirect path verification and cross-domain tracking',
      'Credential forms, password inputs, and brand identity consistency',
      'Heuristic social engineering lures and external threat intelligence',
    ],
    whyUseful: 'Provides an all-in-one evidence-based security verdict covering both link infrastructure and deceptive phishing mechanics before visiting.',
    inputGuidance: 'Provide any public URL or web address, starting with http:// or https://, or a domain name.',
    howItWorks: [
      { step: 1, title: 'URL Validation & Normalization', desc: 'Validates structure and normalizes host, path, and parameters.' },
      { step: 2, title: 'Parallel Evidence Collection', desc: 'Queries DNS, TLS handshake, and configured threat feeds.' },
      { step: 3, title: 'Safe Page & Phishing Audit', desc: 'Inspects DOM forms, password inputs, and brand authenticity.' },
      { step: 4, title: 'Unified Risk Synthesis', desc: 'Calculates a deterministic 0–100 risk score and findings.' },
    ],
  },
  'website-scanner': {
    slug: 'website-scanner',
    name: 'Website Security Scanner',
    category: 'Web Security',
    targetType: 'Website',
    icon: ShieldAlert,
    iconColor: 'text-indigo-600',
    iconBg: 'bg-indigo-50 border-indigo-100',
    placeholder: 'Enter website domain (e.g. https://portal.company.com)',
    exampleUrl: 'https://portal.company.com',
    whatIsIt: 'A comprehensive website security assessment module examining exposed infrastructure signals, web response headers, TLS configurations, and HTML structures.',
    whatItAnalyzes: [
      'HTTP status, response time, server information, and redirects',
      'HTTPS implementation and TLS certificate parameters',
      'HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)',
      'Cookie security flags (Secure, HttpOnly, SameSite)',
      'HTML structure, password forms, mixed content, and external scripts',
      'Website intelligence, page title, and meta descriptions',
    ],
    whyUseful: 'Ensures public web properties adhere to safe communication standards and do not exhibit defensive misconfigurations.',
    inputGuidance: 'Enter the base domain or public website URL of the target web property.',
    howItWorks: [
      { step: 1, title: 'Network Resolution', desc: 'Resolves web host and confirms accessible public endpoint.' },
      { step: 2, title: 'Security Posture Audit', desc: 'Inspects encryption layer, security headers, and cookies.' },
      { step: 3, title: 'Content & Form Inspection', desc: 'Scans DOM structure, forms, and external asset links.' },
      { step: 4, title: 'Synthesis & Reporting', desc: 'Synthesizes security findings and mitigation guidelines.' },
    ],
  },
  'api-scanner': {
    slug: 'api-scanner',
    name: 'API Security Scanner',
    category: 'Application Security',
    targetType: 'API',
    icon: Activity,
    iconColor: 'text-emerald-600',
    iconBg: 'bg-emerald-50 border-emerald-100',
    placeholder: 'Enter API endpoint (e.g. https://api.example.com/v1/users)',
    exampleUrl: 'https://api.example.com/v1/users',
    whatIsIt: 'A specialized scanner for public API endpoints performing safe, controlled requests to evaluate CORS policies, authentication requirements, rate-limiting indicators, and information disclosure.',
    whatItAnalyzes: [
      'CORS configuration (Access-Control-Allow-Origin, wildcard exposure)',
      'Authentication headers and WWW-Authenticate challenge schemes',
      'Rate-limiting headers (X-RateLimit, RateLimit-Limit, Retry-After)',
      'Excessive information disclosure and error stack traces in payloads',
      'Structured response format validation (JSON/XML/Text)',
    ],
    whyUseful: 'Identifies common API security misconfigurations and data exposure risks without performing destructive or invasive attacks.',
    inputGuidance: 'Enter any public REST or HTTP API endpoint URL to audit its response security posture.',
    howItWorks: [
      { step: 1, title: 'Safe Endpoint Request', desc: 'Sends controlled non-destructive HTTP request to the API.' },
      { step: 2, title: 'CORS & Header Audit', desc: 'Audits cross-origin sharing rules and security headers.' },
      { step: 3, title: 'Auth & Rate-Limit Check', desc: 'Passively verifies challenge schemes and throttling headers.' },
      { step: 4, title: 'Data Exposure Analysis', desc: 'Inspects response structure for unhandled error disclosures.' },
    ],
  },
  'phishing': {
    slug: 'phishing',
    name: 'Phishing Scanner',
    category: 'Threat Detection',
    targetType: 'Phishing',
    icon: Shield,
    iconColor: 'text-amber-600',
    iconBg: 'bg-amber-50 border-amber-100',
    placeholder: 'Enter suspicious link or login URL (e.g. https://account-verification-alert.com)',
    exampleUrl: 'https://account-verification-alert.com',
    whatIsIt: 'A targeted threat detection engine identifying deceptive login forms, brand impersonation lures, credential harvesting keywords, and high-risk URL patterns.',
    whatItAnalyzes: [
      'Deceptive authentication and account verification keywords in URLs',
      'Target domain similarity and brand impersonation signals',
      'Deceptive subdomains and lookalike character combinations',
      'Absence of legitimate ownership or transport encryption',
    ],
    whyUseful: 'Prevents credential harvesting and identity fraud by assessing deceptive markers on suspicious web links.',
    inputGuidance: 'Paste suspicious links received via email, SMS, or chat platforms.',
    howItWorks: [
      { step: 1, title: 'Target Ingestion', desc: 'Parses the target URL structure and query parameters.' },
      { step: 2, title: 'Deception Keyword Audit', desc: 'Compares tokens against credential harvesting signatures.' },
      { step: 3, title: 'Confidence Scoring', desc: 'Computes phishing risk confidence and flags critical indicators.' },
      { step: 4, title: 'Actionable Advice', desc: 'Provides immediate safety recommendations for end users.' },
    ],
  },
  'file': {
    slug: 'file',
    name: 'File Security Scanner',
    category: 'File Security',
    targetType: 'File',
    icon: FileSearch,
    iconColor: 'text-blue-600',
    iconBg: 'bg-blue-50 border-blue-100',
    placeholder: 'Enter downloadable file URL or asset path (e.g. https://example.com/update.zip)',
    exampleUrl: 'https://example.com/assets/package.zip',
    whatIsIt: 'An asset and file security inspection scanner assessing file extensions, MIME types, cryptographic hashes, and static signature indicators.',
    whatItAnalyzes: [
      'Filename, extension risk level, and double-extension evasion',
      'MIME type and content-type alignment',
      'File signature / magic bytes consistency',
      'Cryptographic checksum generation (SHA-256 / MD5)',
    ],
    whyUseful: 'Verifies file characteristics and identifies potentially dangerous executable formats before execution or distribution.',
    inputGuidance: 'Enter the direct URL pointing to a downloadable file or binary asset.',
    howItWorks: [
      { step: 1, title: 'File Link Parsing', desc: 'Extracts file extension, path, and hosting destination.' },
      { step: 2, title: 'Signature Verification', desc: 'Audits magic bytes, MIME headers, and extension risks.' },
      { step: 3, title: 'Hash Computation', desc: 'Generates cryptographic fingerprints for verification.' },
      { step: 4, title: 'Safety Verdict', desc: 'Returns structural findings and safe handling guidance.' },
    ],
  },
  'extension': {
    slug: 'extension',
    name: 'Browser Extension Scanner',
    category: 'Browser Security',
    targetType: 'Extension',
    icon: ShieldCheck,
    iconColor: 'text-purple-600',
    iconBg: 'bg-purple-50 border-purple-100',
    placeholder: 'Enter extension store URL or manifest link (e.g. https://chromewebstore.google.com/detail/...)',
    exampleUrl: 'https://chromewebstore.google.com/detail/sample-extension-id',
    whatIsIt: 'A dedicated browser security scanner analyzing browser extension manifests, declared capabilities, Manifest V3 compliance, and high-risk API permissions.',
    whatItAnalyzes: [
      'Extension manifest version (Manifest V3 vs V2)',
      'Dangerous permissions (debugger, webRequestBlocking, cookies, storage)',
      'Broad host access permissions (<all_urls>, wildcard domain access)',
      'Background service workers and content script injection scope',
    ],
    whyUseful: 'Prevents untrusted browser add-ons from intercepting user credentials, injecting unwanted DOM scripts, or monitoring web browsing activity.',
    inputGuidance: 'Enter the extension store URL, package link, or manifest URL to evaluate declared permissions.',
    howItWorks: [
      { step: 1, title: 'Manifest Ingestion', desc: 'Parses extension package metadata and manifest definition.' },
      { step: 2, title: 'Permissions Audit', desc: 'Evaluates declared APIs and flags high-risk capabilities.' },
      { step: 3, title: 'Host Scope Analysis', desc: 'Inspects host matching patterns and injection scopes.' },
      { step: 4, title: 'Verdict Formulation', desc: 'Delivers a security assessment with permission warnings.' },
    ],
  },
};

const DEFAULT_SCANNER = SCANNER_CONFIGS['url-phishing'];

export function ScannerPage() {
  const { scannerSlug } = useParams<{ scannerSlug?: string }>();
  const navigate = useNavigate();

  const config = useMemo(() => {
    if (!scannerSlug) return DEFAULT_SCANNER;
    if (scannerSlug === 'url-scanner' || scannerSlug === 'phishing' || scannerSlug === 'url-phishing') {
      return SCANNER_CONFIGS['url-phishing'];
    }
    return SCANNER_CONFIGS[scannerSlug] || DEFAULT_SCANNER;
  }, [scannerSlug]);

  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  function validateTarget(raw: string): { valid: boolean; normalized?: string; error?: string } {
    const trimmed = raw.trim();
    if (!trimmed) {
      return { valid: false, error: 'Please enter a target to scan.' };
    }
    let test = trimmed;
    if (!test.startsWith('http://') && !test.startsWith('https://')) {
      test = `https://${test}`;
    }
    try {
      const parsed = new URL(test);
      if (!parsed.hostname || !parsed.hostname.includes('.')) {
        return {
          valid: false,
          error: 'Please enter a valid target URL or domain (e.g. https://example.com).',
        };
      }
      return { valid: true, normalized: trimmed };
    } catch {
      return { valid: false, error: 'Please enter a valid target.' };
    }
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setErrorMessage(null);

    const validation = validateTarget(target);
    if (!validation.valid) {
      setErrorMessage(validation.error || 'Please enter a valid target.');
      return;
    }

    setIsScanning(true);
    setScanStage('Initializing scanner engine...');

    const stages = [
      'Normalizing target parameters...',
      'Auditing structural indicators & patterns...',
      'Verifying transport encryption & domain records...',
      'Evaluating threat indicators & risk score...',
      'Finalizing detailed security report...',
    ];

    let current = 0;
    const interval = setInterval(() => {
      current++;
      if (current < stages.length) {
        setScanStage(stages[current]);
      }
    }, 400);

    try {
      const result = await scanService.analyzeUrl(validation.normalized!, config.targetType);
      clearInterval(interval);
      setScanStage('Scan completed! Loading detailed report...');

      setTimeout(() => {
        setIsScanning(false);
        navigate(`/reports/scans/${result.id}`, { state: { scan: result } });
      }, 350);
    } catch (err: any) {
      clearInterval(interval);
      setIsScanning(false);
      let userFriendlyMessage = 'Security scan failed. Please try again.';
      if (err.response?.data?.message) {
        userFriendlyMessage = err.response.data.message;
      } else if (err.response?.data?.error?.message) {
        userFriendlyMessage = err.response.data.error.message;
      } else if (err.code === 'ECONNABORTED' || err.message?.toLowerCase().includes('timeout')) {
        userFriendlyMessage = 'Scan timed out: The target server took too long to respond. Please verify the target is online and try again.';
      } else if (err.message === 'Network Error' || err.code === 'ERR_NETWORK') {
        userFriendlyMessage = 'Connection error: Unable to reach the CyberWatch API server at http://localhost:5000. Please ensure the backend service is running.';
      } else if (err.message) {
        userFriendlyMessage = err.message;
      }
      setErrorMessage(userFriendlyMessage);
    }
  }

  if (config.slug === 'url-phishing' || config.slug === 'url-scanner' || config.slug === 'phishing') {
    return (
      <div className="min-h-screen bg-slate-50/60 pb-24 pt-24 sm:pt-28">
        <Container>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to="/services"
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-blue-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-sm transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>All Security Services</span>
              </Link>
              <span className="text-xs font-semibold text-slate-500 bg-blue-50 text-blue-700 px-3 py-1 rounded-full border border-blue-100">
                {config.category}
              </span>
            </div>

            <UrlSecurityScanner />
          </div>
        </Container>
      </div>
    );
  }

  if (config.slug === 'website-scanner') {
    return (
      <div className="min-h-screen bg-slate-50/60 pb-24 pt-24 sm:pt-28">
        <Container>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to="/services"
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-indigo-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-sm transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>All Security Services</span>
              </Link>
              <span className="text-xs font-semibold text-slate-500 bg-indigo-50 text-indigo-700 px-3 py-1 rounded-full border border-indigo-100">
                {config.category}
              </span>
            </div>

            <WebsiteSecurityScanner />
          </div>
        </Container>
      </div>
    );
  }

  if (config.slug === 'file') {
    return (
      <div className="min-h-screen bg-slate-50/60 pb-24 pt-24 sm:pt-28">
        <Container>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to="/services"
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-blue-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-sm transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>All Security Services</span>
              </Link>
              <span className="text-xs font-semibold text-slate-500 bg-blue-50 text-blue-700 px-3 py-1 rounded-full border border-blue-100">
                {config.category}
              </span>
            </div>

            <FileSecurityScanner />
          </div>
        </Container>
      </div>
    );
  }

  if (config.slug === 'extension') {
    return (
      <div className="min-h-screen bg-slate-50/60 pb-24 pt-24 sm:pt-28">
        <Container>
          <div className="space-y-6 w-full">
            {/* Breadcrumb Navigation */}
            <div className="flex items-center justify-between">
              <Link
                to="/services"
                className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-blue-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-xs transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>All Security Services</span>
              </Link>
              <span className="text-xs font-semibold text-slate-500 bg-blue-50 text-blue-700 px-3 py-1 rounded-full border border-blue-100">
                {config.category}
              </span>
            </div>

            <ExtensionSecurityScanner />
          </div>
        </Container>
      </div>
    );
  }

  const Icon = config.icon;

  return (
    <div className="min-h-screen bg-slate-50/60 pb-24 pt-24 sm:pt-28">
      <Container>
        <div className="space-y-10 w-full">
          {/* Breadcrumb Navigation */}
          <div className="flex items-center justify-between">
            <Link
              to="/services"
              className="inline-flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-blue-600 bg-white border border-slate-200 px-3.5 py-2 rounded-xl shadow-sm transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>All Security Services</span>
            </Link>
            <span className="text-xs font-semibold text-slate-500 bg-blue-50 text-blue-700 px-3 py-1 rounded-full border border-blue-100">
              {config.category}
            </span>
          </div>

          {/* Scanner Header Banner */}
          <div className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-sm relative overflow-hidden">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-6">
              <div className="space-y-3 max-w-2xl">
                <div className="flex items-center gap-3">
                  <div className={`w-12 h-12 rounded-2xl flex items-center justify-center border ${config.iconBg}`}>
                    <Icon className={`w-6 h-6 ${config.iconColor}`} />
                  </div>
                  <div>
                    <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
                      {config.name}
                    </h1>
                    <span className="text-xs font-semibold text-slate-500">
                      Module: {config.slug}
                    </span>
                  </div>
                </div>
                <p className="text-sm sm:text-base text-slate-600 leading-relaxed pt-1">
                  {config.whatIsIt}
                </p>
              </div>

              <div className="shrink-0 bg-slate-50 border border-slate-200/80 rounded-2xl p-4 text-center min-w-[200px]">
                <ShieldCheck className="w-6 h-6 text-emerald-600 mx-auto mb-1" />
                <span className="text-xs font-bold text-slate-900 block">Active Engine</span>
                <span className="text-[11px] text-slate-500">Real-time threat evaluation</span>
              </div>
            </div>
          </div>

          {/* Interactive Scanner Interface */}
          <div className="bg-white border-2 border-blue-100 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-md shadow-blue-500/5 relative">
            <div className="max-w-3xl">
              <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
                Launch {config.name}
              </h2>
              <p className="text-xs sm:text-sm text-slate-500 mt-1">
                {config.inputGuidance}
              </p>

              <form onSubmit={handleScan} className="mt-6 space-y-4">
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="relative flex-1">
                    <input
                      id="scanner-target-input"
                      type="text"
                      value={target}
                      onChange={(e) => {
                        setTarget(e.target.value);
                        if (errorMessage) setErrorMessage(null);
                      }}
                      disabled={isScanning}
                      placeholder={config.placeholder}
                      className="w-full px-4 py-3.5 sm:py-4 text-sm sm:text-base bg-slate-50 border border-slate-200 rounded-2xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent text-slate-900 placeholder:text-slate-400 font-medium transition-all"
                    />
                    {target && !isScanning && (
                      <button
                        type="button"
                        onClick={() => setTarget('')}
                        className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1 rounded-md"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    )}
                  </div>

                  <button
                    id="scanner-submit-btn"
                    type="submit"
                    disabled={isScanning}
                    className="inline-flex items-center justify-center gap-2 px-7 py-3.5 sm:py-4 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-bold text-sm sm:text-base rounded-2xl shadow-md shadow-blue-600/25 transition-all duration-200 shrink-0 disabled:opacity-75 disabled:cursor-not-allowed"
                  >
                    {isScanning ? (
                      <>
                        <Loader2 className="w-5 h-5 animate-spin" />
                        <span>Analyzing...</span>
                      </>
                    ) : (
                      <>
                        <span>Scan Target</span>
                        <ArrowRight className="w-5 h-5" />
                      </>
                    )}
                  </button>
                </div>

                {errorMessage && (
                  <div className="flex items-center gap-2 text-xs sm:text-sm text-red-600 bg-red-50 border border-red-200 rounded-xl px-4 py-3">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>{errorMessage}</span>
                  </div>
                )}

                {isScanning && (
                  <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 sm:p-5 space-y-2 animate-in fade-in duration-200">
                    <div className="flex items-center gap-2 text-xs font-bold text-blue-700">
                      <span className="w-2 h-2 rounded-full bg-blue-600 animate-ping" />
                      <span>{scanStage}</span>
                    </div>
                    <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-600 rounded-full animate-pulse w-3/4" />
                    </div>
                  </div>
                )}
              </form>
            </div>
          </div>

          {/* Educational & Technical Specifications Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* What It Analyzes */}
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 space-y-4 shadow-sm">
              <div className="flex items-center gap-2">
                <Layers className="w-5 h-5 text-blue-600" />
                <h3 className="text-base font-bold text-slate-900">What Does This Scanner Analyze?</h3>
              </div>
              <ul className="space-y-2.5">
                {config.whatItAnalyzes.map((item, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-xs sm:text-sm text-slate-600">
                    <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Why Is It Useful */}
            <div className="bg-white border border-slate-200/90 rounded-2xl p-6 space-y-4 shadow-sm">
              <div className="flex items-center gap-2">
                <HelpCircle className="w-5 h-5 text-indigo-600" />
                <h3 className="text-base font-bold text-slate-900">Why Is This Scanner Useful?</h3>
              </div>
              <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
                {config.whyUseful}
              </p>
              <div className="pt-2">
                <span className="text-xs font-bold text-slate-900 block mb-1">Target Classification Type:</span>
                <span className="px-2.5 py-1 rounded-md bg-slate-100 text-slate-700 font-mono text-xs font-bold">
                  {config.targetType}
                </span>
              </div>
            </div>
          </div>

          {/* How The Scan Works Step-by-Step */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 space-y-6 shadow-sm">
            <div className="flex items-center gap-2">
              <FileCode className="w-5 h-5 text-slate-700" />
              <h3 className="text-base sm:text-lg font-bold text-slate-900">How Does The Scan Work?</h3>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {config.howItWorks.map((step) => (
                <div key={step.step} className="bg-slate-50 border border-slate-200/70 rounded-xl p-4 space-y-2">
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
      </Container>
    </div>
  );
}
