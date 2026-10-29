import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Container } from '../components/ui/Container';
import {
  Globe,
  ShieldAlert,
  Terminal,
  FileSearch,
  Puzzle,
  Fingerprint,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  BookOpen,
  Bot,
} from 'lucide-react';
import { cn } from '../lib/utils';

interface ScannerInfo {
  id: string;
  name: string;
  slug: string;
  route: string;
  icon: any;
  badge: string;
  theme: 'cyan' | 'blue' | 'indigo' | 'sky' | 'purple' | 'amber';
  tagline: string;
  description: string;
  targetFormat: string;
  sampleTarget: string;
  technicalChecks: Array<{
    name: string;
    description: string;
    severityImpact: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  }>;
  scoringBreakdown: string;
  commonIssues: Array<{ issue: string; resolution: string }>;
}

const SCANNERS_GUIDE: ScannerInfo[] = [
  {
    id: 'url-phishing',
    name: 'URL & Phishing Mega Scanner',
    slug: 'url-phishing',
    route: '/services/url-phishing',
    icon: Globe,
    badge: 'Multi-Hop Telemetry',
    theme: 'cyan',
    tagline: 'Deep URL structure, redirect journeys, and phishing heuristics.',
    description:
      'Analyzes URLs and hostnames for social engineering indicators, IDN homograph spoofing, redirect downgrade chains, and direct IP/custom port exposures.',
    targetFormat: 'Full URL or Domain (e.g. https://example.com/login or example.com)',
    sampleTarget: 'https://example.com',
    technicalChecks: [
      {
        name: 'Redirect Journey & Protocol Downgrades',
        description: 'Traces multi-hop redirects and flags transitions from HTTPS to unencrypted HTTP.',
        severityImpact: 'HIGH',
      },
      {
        name: 'Punycode & Homograph Deception',
        description: 'Detects internationalized domain names (IDN) mimicking trusted commercial brands.',
        severityImpact: 'CRITICAL',
      },
      {
        name: 'Live TLS Certificate Validation',
        description: 'Verifies certificate authority trust chain, host matching, and remaining validity days.',
        severityImpact: 'HIGH',
      },
      {
        name: 'Domain Age & URL Entropy',
        description: 'Flags newly registered domains (<30 days) and high-entropy randomized path segments.',
        severityImpact: 'MEDIUM',
      },
      {
        name: 'Direct IP & Custom Port Exposure',
        description: 'Identifies URLs using raw IP addresses or non-standard web ports (e.g. :8080, :8443).',
        severityImpact: 'MEDIUM',
      },
    ],
    scoringBreakdown:
      'Scored 0-100 based on redirect integrity, TLS health, domain age, and correlated threat intelligence blacklist matches.',
    commonIssues: [
      {
        issue: 'Target Unreachable / Timeout',
        resolution: 'Ensure the domain resolves over public DNS and is not behind a geo-blocking firewall.',
      },
      {
        issue: 'SSRF Blocked Target',
        resolution: 'CyberWatch prevents scanning internal/private IP ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16).',
      },
    ],
  },
  {
    id: 'website-scanner',
    name: 'Website Security Scanner V2',
    slug: 'website-scanner',
    route: '/services/website-scanner',
    icon: ShieldAlert,
    badge: 'Evidence-Based Engine',
    theme: 'blue',
    tagline: 'HTTP security headers, cookies, scripts, forms, and TLS configurations.',
    description:
      'Comprehensive evidence-based posture audit verifying OWASP Top 10 web defenses, cookie security attributes, mixed content, and server technology stack leakage.',
    targetFormat: 'Website URL (e.g. https://mycompany.com)',
    sampleTarget: 'https://example.com',
    technicalChecks: [
      {
        name: 'HTTP Security Headers Audit',
        description: 'Validates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.',
        severityImpact: 'HIGH',
      },
      {
        name: 'Cookie Security Attributes',
        description: 'Checks that all session cookies enforce Secure, HttpOnly, and SameSite protection.',
        severityImpact: 'HIGH',
      },
      {
        name: 'Form Action Security & Password Fields',
        description: 'Flags password inputs transmitting over plaintext HTTP or submitting cross-domain.',
        severityImpact: 'CRITICAL',
      },
      {
        name: 'Mixed Content Detection',
        description: 'Detects active or passive unencrypted HTTP resources loaded within HTTPS pages.',
        severityImpact: 'MEDIUM',
      },
      {
        name: 'Server Fingerprinting & Error Leakage',
        description: 'Detects disclosed backend versions, framework banners, and verbose debug stack traces.',
        severityImpact: 'LOW',
      },
    ],
    scoringBreakdown:
      'Additive score combining missing mandatory headers (15-25 pts), insecure cookie flags (15-20 pts), and insecure forms (30 pts).',
    commonIssues: [
      {
        issue: 'Cloudflare / Bot Challenge Detected',
        resolution: 'Automated crawlers may receive a 403 or challenge page if your WAF has strict bot protection rules.',
      },
    ],
  },
  {
    id: 'api-scanner',
    name: 'API Security Scanner',
    slug: 'api-scanner',
    route: '/services/api-scanner',
    icon: Terminal,
    badge: 'Endpoint Audit',
    theme: 'indigo',
    tagline: 'CORS misconfigurations, authentication indicators, and data exposure.',
    description:
      'Audits REST and GraphQL API endpoints for permissive CORS wildcard origins, missing authentication schemes, and rate limiting headers.',
    targetFormat: 'API Endpoint URL (e.g. https://api.example.com/v1/health or /v1/users)',
    sampleTarget: 'https://httpbin.org/get',
    technicalChecks: [
      {
        name: 'CORS Access-Control-Allow-Origin Audit',
        description: 'Flags wildcard origins (*) combined with Access-Control-Allow-Credentials: true.',
        severityImpact: 'HIGH',
      },
      {
        name: 'Authentication Requirement Indicators',
        description: 'Verifies whether endpoints enforce Bearer tokens, API keys, or OAuth headers.',
        severityImpact: 'HIGH',
      },
      {
        name: 'Rate Limiting Telemetry',
        description: 'Inspects presence of X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers.',
        severityImpact: 'MEDIUM',
      },
      {
        name: 'Response Data Structure & Error Leakage',
        description: 'Detects disclosed secrets, internal stack traces, and database connection strings.',
        severityImpact: 'CRITICAL',
      },
    ],
    scoringBreakdown:
      'Permissive CORS with credentials contributes 30 pts; unauthenticated sensitive data adds 40 pts.',
    commonIssues: [
      {
        issue: 'Requires Custom Request Headers',
        resolution: 'For protected APIs, audit the unauthenticated entrypoint to verify that unauthorized requests are rejected with 401.',
      },
    ],
  },
  {
    id: 'file-scanner',
    name: 'File Security Scanner',
    slug: 'file',
    route: '/services/file',
    icon: FileSearch,
    badge: 'Static Analysis',
    theme: 'sky',
    tagline: 'Multi-stage static analysis for binaries, archives, scripts, and documents.',
    description:
      'Multi-stage inspection combining cryptographic hashing (MD5, SHA-256), multi-provider malware verdicts, Shannon entropy, and format-specific inspection.',
    targetFormat: 'Downloadable File URL or Direct Upload (up to 25MB)',
    sampleTarget: 'https://example.com/sample.pdf',
    technicalChecks: [
      {
        name: 'Cryptographic Hashing & Multi-Provider Reputation',
        description: 'Computes MD5, SHA-1, SHA-256, and queries VirusTotal and MalwareBazaar databases.',
        severityImpact: 'CRITICAL',
      },
      {
        name: 'MIME Type vs Extension Masquerading',
        description: 'Flags executable files masquerading as harmless images or documents (.jpg.exe).',
        severityImpact: 'HIGH',
      },
      {
        name: 'Shannon Entropy & Packed Payload Analysis',
        description: 'Detects encrypted or packed binary sections indicative of obfuscated malware.',
        severityImpact: 'HIGH',
      },
      {
        name: 'YARA Signature Matching & Strings Extraction',
        description: 'Scans for shell commands, base64 blobs, embedded URLs, and suspicious Windows APIs.',
        severityImpact: 'HIGH',
      },
    ],
    scoringBreakdown:
      'Known malware hash matches score 100/100 (CRITICAL); high entropy combined with masquerading scores 85/100.',
    commonIssues: [
      {
        issue: 'File Exceeds Size Limit',
        resolution: 'CyberWatch static scanning supports files up to 25MB.',
      },
    ],
  },
  {
    id: 'extension-scanner',
    name: 'Browser Extension Scanner',
    slug: 'extension',
    route: '/services/extension',
    icon: Puzzle,
    badge: 'Manifest V2/V3',
    theme: 'purple',
    tagline: 'Audit Chrome Web Store & Firefox extensions for excessive privileges.',
    description:
      'Analyzes extension manifests for declared permissions (<all_urls>, webRequestBlocking) and parses JavaScript files for dynamic code execution and data exfiltration.',
    targetFormat: 'Chrome Web Store URL (e.g. https://chromewebstore.google.com/detail/...) or Extension ID',
    sampleTarget: 'https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm',
    technicalChecks: [
      {
        name: 'High-Risk Declared Permissions',
        description: 'Audits <all_urls>, debugger, nativeMessaging, and webRequestBlocking capabilities.',
        severityImpact: 'HIGH',
      },
      {
        name: 'Dynamic Code Execution (eval & new Function)',
        description: 'Flags dynamic script evaluation that bypasses Content Security Policy.',
        severityImpact: 'CRITICAL',
      },
      {
        name: 'Developer Verification & Store Telemetry',
        description: 'Verifies active user count, store rating, publisher verification, and privacy policy links.',
        severityImpact: 'MEDIUM',
      },
      {
        name: 'Covert Network Transmission',
        description: 'Identifies unauthorized external endpoints contacted by background service workers.',
        severityImpact: 'HIGH',
      },
    ],
    scoringBreakdown:
      'Excessive broad host permissions contribute 20-30 pts; dynamic eval() usage contributes 40 pts.',
    commonIssues: [
      {
        issue: 'Invalid Store Link Format',
        resolution: 'Provide the official Chrome Web Store or Microsoft Edge Add-ons URL.',
      },
    ],
  },
  {
    id: 'threat-intel',
    name: 'Threat Intelligence Correlation',
    slug: 'threat-intel',
    route: '/threat-intelligence',
    icon: Fingerprint,
    badge: 'Global Feeds',
    theme: 'amber',
    tagline: 'Correlate IOC indicators across real-time global intelligence streams.',
    description:
      'Centralized multi-source threat investigation querying AbuseIPDB, VirusTotal, AlienVault OTX, URLhaus, and CISA Known Exploited Vulnerabilities.',
    targetFormat: 'IP Address (1.1.1.1), Domain (example.com), or Hash (SHA-256)',
    sampleTarget: '8.8.8.8',
    technicalChecks: [
      {
        name: 'IPv4 / IPv6 Abuse Confidence',
        description: 'Evaluates report frequency and malicious activity classification from AbuseIPDB.',
        severityImpact: 'HIGH',
      },
      {
        name: 'Multi-Engine Reputation Registry',
        description: 'Checks IOC against 70+ antivirus and network security provider databases.',
        severityImpact: 'CRITICAL',
      },
      {
        name: 'Community Pulse & Threat Feeds',
        description: 'Correlates indicators with active APT campaigns and ransomware infrastructure.',
        severityImpact: 'HIGH',
      },
    ],
    scoringBreakdown:
      'Correlated threat score reflects provider consensus and confidence percentages.',
    commonIssues: [
      {
        issue: 'Provider Rate Limits',
        resolution: 'CyberWatch caches threat intelligence lookups for 1 hour to ensure responsive queries.',
      },
    ],
  },
];

export function ScannerGuidePage() {
  const [selectedScannerId, setSelectedScannerId] = useState<string>('url-phishing');

  const currentScanner = SCANNERS_GUIDE.find((s) => s.id === selectedScannerId) || SCANNERS_GUIDE[0];

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20 pt-24 sm:pt-28">
      <Container>
        <div className="space-y-8 sm:space-y-10">
          {/* 1. Header Banner */}
          <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/90 shadow-sm">
            <div className="max-w-4xl">
              <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-md bg-cyan-50 border border-cyan-200/70 text-cyan-800 text-xs font-bold uppercase tracking-wider mb-2.5">
                <BookOpen className="w-3.5 h-3.5 text-cyan-600" />
                <span>CyberWatch Technical Scanner Guide</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight mb-2">
                Comprehensive Scanner Documentation &amp; Architecture
              </h1>
              <p className="text-sm sm:text-base text-slate-600 leading-relaxed mb-5">
                Understand how CyberWatch executes technical checks across web perimeters, files, APIs, and browser extensions without false positives.
              </p>

              <div className="flex flex-wrap items-center gap-3">
                <Link
                  to="/help/faq"
                  className="inline-flex items-center gap-1.5 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition-colors"
                >
                  <span>Frequently Asked Questions</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
                <Link
                  to="/help/ai"
                  className="inline-flex items-center gap-1.5 px-4 py-2 bg-cyan-50 hover:bg-cyan-100 text-cyan-800 rounded-xl text-xs font-bold transition-colors"
                >
                  <Bot className="w-3.5 h-3.5 text-cyan-600" />
                  <span>Ask AI Assistant About Scanners</span>
                </Link>
              </div>
            </div>
          </div>

          {/* 2. Scanner Navigation Tabs */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 sm:gap-3">
            {SCANNERS_GUIDE.map((scanner) => {
              const Icon = scanner.icon;
              const isActive = selectedScannerId === scanner.id;

              return (
                <button
                  key={scanner.id}
                  type="button"
                  onClick={() => setSelectedScannerId(scanner.id)}
                  className={cn(
                    'flex flex-col items-center text-center p-3.5 rounded-2xl border transition-all cursor-pointer',
                    isActive
                      ? 'bg-cyan-600 text-white border-cyan-600 shadow-sm ring-2 ring-cyan-600/20'
                      : 'bg-white text-slate-700 hover:bg-slate-50 border-slate-200/90 shadow-2xs'
                  )}
                >
                  <div
                    className={cn(
                      'w-9 h-9 rounded-xl flex items-center justify-center mb-2',
                      isActive ? 'bg-white/20 text-white' : 'bg-slate-100 text-slate-700'
                    )}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-xs font-bold leading-snug line-clamp-2">
                    {scanner.name}
                  </span>
                </button>
              );
            })}
          </div>

          {/* 3. Detailed Scanner Specification Panel */}
          <div className="bg-white rounded-3xl p-6 sm:p-10 border border-slate-200/90 shadow-sm space-y-8">
            {/* Top Bar with Launch Button */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-100 pb-6">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-2xl bg-cyan-50 text-cyan-700 flex items-center justify-center shrink-0 shadow-2xs">
                  <currentScanner.icon className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900">
                      {currentScanner.name}
                    </h2>
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-cyan-50 text-cyan-800 border border-cyan-200/70">
                      {currentScanner.badge}
                    </span>
                  </div>
                  <p className="text-xs sm:text-sm text-slate-600">{currentScanner.tagline}</p>
                </div>
              </div>

              {/* Direct Launch CTA */}
              <Link
                to={currentScanner.route}
                className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-xl text-xs font-bold transition-all shadow-xs shadow-cyan-600/25 shrink-0"
              >
                <span>Launch {currentScanner.name}</span>
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>

            {/* Target Format & Capabilities */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="p-5 rounded-2xl bg-slate-50/70 border border-slate-200/80 space-y-2">
                <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                  Target Input Format
                </div>
                <div className="text-xs font-bold text-slate-800 font-mono bg-white p-2.5 rounded-xl border border-slate-200">
                  {currentScanner.targetFormat}
                </div>
                <p className="text-xs text-slate-500">{currentScanner.description}</p>
              </div>

              <div className="p-5 rounded-2xl bg-slate-50/70 border border-slate-200/80 space-y-2">
                <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                  Risk Scoring Model
                </div>
                <p className="text-xs text-slate-700 leading-relaxed font-medium">
                  {currentScanner.scoringBreakdown}
                </p>
                <div className="flex items-center gap-2 text-[11px] text-cyan-700 font-semibold pt-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Standardized 0-100 Normalization</span>
                </div>
              </div>
            </div>

            {/* Technical Checks Table */}
            <div>
              <div className="mb-4">
                <h3 className="text-base font-bold text-slate-900">
                  Technical Checks &amp; Audit Scope
                </h3>
                <p className="text-xs text-slate-500">
                  List of automated checks performed during scan execution.
                </p>
              </div>

              <div className="space-y-3">
                {currentScanner.technicalChecks.map((check, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-2xl bg-white border border-slate-200/90 shadow-2xs flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-900">{check.name}</span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">{check.description}</p>
                    </div>

                    <span
                      className={cn(
                        'text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-lg shrink-0 w-fit',
                        check.severityImpact === 'CRITICAL'
                          ? 'bg-rose-50 text-rose-700 border border-rose-200'
                          : check.severityImpact === 'HIGH'
                          ? 'bg-orange-50 text-orange-700 border border-orange-200'
                          : check.severityImpact === 'MEDIUM'
                          ? 'bg-amber-50 text-amber-700 border border-amber-200'
                          : 'bg-cyan-50 text-cyan-700 border border-cyan-200'
                      )}
                    >
                      {check.severityImpact} Weight
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Common Issues & Troubleshooting */}
            {currentScanner.commonIssues.length > 0 && (
              <div className="pt-4 border-t border-slate-100">
                <div className="mb-4">
                  <h3 className="text-base font-bold text-slate-900">
                    Troubleshooting &amp; FAQs
                  </h3>
                  <p className="text-xs text-slate-500">
                    Common edge cases and how to resolve scanning errors.
                  </p>
                </div>

                <div className="space-y-3">
                  {currentScanner.commonIssues.map((issue, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-2xl bg-amber-50/40 border border-amber-200/70 space-y-1 text-xs"
                    >
                      <div className="font-bold text-amber-950 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                        <span>{issue.issue}</span>
                      </div>
                      <p className="text-amber-800 leading-relaxed pl-5">{issue.resolution}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </Container>
    </div>
  );
}
