import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  BookOpen,
  Search,
  Clock,
  ArrowRight,
  ExternalLink,
  Shield,
  X,
  ChevronRight,
} from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { CyberSafetyHeader } from '../../components/cyber-safety/CyberSafetyHeader';

export type GuideCategory =
  | 'All'
  | 'Web Security'
  | 'Phishing'
  | 'Passwords'
  | 'Browser Security'
  | 'Privacy'
  | 'Account Security'
  | 'Mobile Security'
  | 'Downloads'
  | 'Social Engineering';

interface SecurityGuide {
  id: string;
  title: string;
  category: Exclude<GuideCategory, 'All'>;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  readTime: string;
  summary: string;
  steps: Array<{ stepNumber: number; title: string; instruction: string }>;
  scannerLabel: string;
  scannerHref: string;
  scannerType: string;
}

const GUIDES: SecurityGuide[] = [
  {
    id: 'safe-link-verification',
    title: 'How to Check Whether a Link Is Safe Before Clicking',
    category: 'Web Security',
    difficulty: 'Beginner',
    readTime: '4 min read',
    summary: 'A definitive protocol for examining suspicious URLs, verifying domain root structures, and inspecting redirect journeys.',
    steps: [
      {
        stepNumber: 1,
        title: 'Isolate and Extract the Root Domain',
        instruction: 'Look past subdomains (e.g., "auth.login.company.com.xyz") to identify the actual registered domain directly preceding the top-level domain.',
      },
      {
        stepNumber: 2,
        title: 'Audit Transport Encryption & Certificate Issuer',
        instruction: 'Confirm the site serves HTTPS with a valid certificate matching the destination host. Avoid sites displaying certificate name mismatches.',
      },
      {
        stepNumber: 3,
        title: 'Run CyberWatch URL Mega Scanner',
        instruction: 'Paste the destination link into CyberWatch to automatically trace redirect hops and evaluate heuristic risk scores.',
      },
      {
        stepNumber: 4,
        title: 'Check for Known Malicious IOCs',
        instruction: 'Review Threat Intelligence correlation results for blacklisted IPs, hosting ASNs, and recent malware distribution associations.',
      },
    ],
    scannerLabel: 'Scan Suspicious Link',
    scannerHref: '/cyber-safety/safe-browsing',
    scannerType: 'URL Mega Scanner',
  },
  {
    id: 'spotting-modern-phishing',
    title: 'Recognizing Advanced Adversary-in-the-Middle (AiTM) Phishing',
    category: 'Phishing',
    difficulty: 'Intermediate',
    readTime: '6 min read',
    summary: 'Understand modern reverse-proxy phishing architectures that harvest both passwords and real-time session tokens.',
    steps: [
      {
        stepNumber: 1,
        title: 'Examine the Full Browser Address Bar',
        instruction: 'AiTM proxy kits replicate legitimate Microsoft/Google login screens but host them under unauthorized domains. Never trust page visuals alone.',
      },
      {
        stepNumber: 2,
        title: 'Look for Uncharacteristic Authentication Prompts',
        instruction: 'If prompted for unexpected MFA push approvals when accessing standard shared documents, immediately abort the session.',
      },
      {
        stepNumber: 3,
        title: 'Verify Links with CyberWatch Phishing Scanner',
        instruction: 'Submit the link to CyberWatch to check for credential harvesting keyword densities and deceptive form action targets.',
      },
      {
        stepNumber: 4,
        title: 'Enforce FIDO2 / Passkey Authentication',
        instruction: 'Transition accounts to hardware security keys (YubiKey) or WebAuthn Passkeys, which are cryptographically bound to the origin domain and immune to AiTM.',
      },
    ],
    scannerLabel: 'Analyze Phishing Link',
    scannerHref: '/cyber-safety/phishing-awareness',
    scannerType: 'Phishing Scanner',
  },
  {
    id: 'passphrase-entropy-mastery',
    title: 'Creating Mathematically Resilient Passphrases',
    category: 'Passwords',
    difficulty: 'Beginner',
    readTime: '5 min read',
    summary: 'Why multi-word random passphrases outperform complex short passwords against high-speed GPU cluster attacks.',
    steps: [
      {
        stepNumber: 1,
        title: 'Prioritize Character Length Over Obscure Substitution',
        instruction: 'A 4-word passphrase has over 50 bits of entropy, requiring decades to brute force compared to a 8-character string with symbols.',
      },
      {
        stepNumber: 2,
        title: 'Use Purely Random Uncorrelated Dictionary Words',
        instruction: 'Select 4 to 5 unrelated words (e.g. "beacon-matrix-harbor-crystal") generated via cryptographically secure random sources.',
      },
      {
        stepNumber: 3,
        title: 'Test Entropy in Client-Side Password Analyzer',
        instruction: 'Input your proposed pattern into our zero-knowledge client-side analyzer to confirm bits of entropy and crack-time metrics.',
      },
      {
        stepNumber: 4,
        title: 'Store Master Secrets in a Dedicated Vault',
        instruction: 'Rely on a zero-knowledge password manager with argon2id key derivation to maintain distinct secrets across every single service.',
      },
    ],
    scannerLabel: 'Test Password Strength',
    scannerHref: '/cyber-safety/password-safety',
    scannerType: 'Client-Side Analyzer',
  },
  {
    id: 'browser-extension-audit-playbook',
    title: 'Auditing High-Risk Browser Extensions and Declared Permissions',
    category: 'Browser Security',
    difficulty: 'Advanced',
    readTime: '7 min read',
    summary: 'How malicious add-ons abuse webRequest and broad host permissions to intercept corporate credentials and telemetry.',
    steps: [
      {
        stepNumber: 1,
        title: 'Audit chrome://extensions for Broad Host Access',
        instruction: 'Inspect permissions declared by every extension. Flag any extension with access to "all websites" or "<all_urls>".',
      },
      {
        stepNumber: 2,
        title: 'Run CyberWatch Browser Extension Scanner',
        instruction: 'Submit the Web Store link or manifest payload to analyze Manifest V3 compliance and dangerous API flags.',
      },
      {
        stepNumber: 3,
        title: 'Restrict Permissions to Explicit Click-to-Run',
        instruction: 'Adjust browser extension settings from "On all sites" to "On specific sites" or "When you click the extension".',
      },
      {
        stepNumber: 4,
        title: 'Purge Dormant or Unmaintained Utilities',
        instruction: 'Uninstall add-ons with low download counts, unverified publishers, or lack of recent security updates.',
      },
    ],
    scannerLabel: 'Audit Extension Manifest',
    scannerHref: '/cyber-safety/browser-security',
    scannerType: 'Extension Scanner',
  },
  {
    id: 'online-privacy-hardening',
    title: 'Reducing Digital Fingerprint and Tracker Exposure',
    category: 'Privacy',
    difficulty: 'Intermediate',
    readTime: '6 min read',
    summary: 'A step-by-step checklist to dismantle behavioral tracking graphs and block cross-site telemetry scrapers.',
    steps: [
      {
        stepNumber: 1,
        title: 'Enforce Global Privacy Control (GPC) and Do-Not-Track',
        instruction: 'Enable GPC in browser settings to legally signal opt-outs under CCPA/GDPR frameworks.',
      },
      {
        stepNumber: 2,
        title: 'Audit Web Properties with Website Security Scanner',
        instruction: 'Scan your public portals to verify cookie flags (Secure, HttpOnly, SameSite) and external tracking script inclusions.',
      },
      {
        stepNumber: 3,
        title: 'Adopt Encrypted DNS (DoH / DoT)',
        instruction: 'Switch browser and OS DNS resolution to encrypted DNS providers with built-in tracking domain filtering.',
      },
      {
        stepNumber: 4,
        title: 'Execute Account Data Minimization',
        instruction: 'Complete our Privacy Exposure self-assessment checklist and revoke obsolete third-party OAuth access tokens.',
      },
    ],
    scannerLabel: 'Audit Site Privacy',
    scannerHref: '/cyber-safety/online-privacy',
    scannerType: 'Website Scanner',
  },
  {
    id: 'account-takeover-hardening',
    title: 'Hardening Cloud & Email Accounts Against Account Takeover (ATO)',
    category: 'Account Security',
    difficulty: 'Intermediate',
    readTime: '5 min read',
    summary: 'Eliminate single points of failure across primary email, cloud workspace identities, and recovery backdoors.',
    steps: [
      {
        stepNumber: 1,
        title: 'Audit Active Session Tokens & Authorized Devices',
        instruction: 'Open account security consoles and terminate unverified legacy sessions and unfamiliar IP addresses.',
      },
      {
        stepNumber: 2,
        title: 'Remove SMS as a Recovery Mechanism',
        instruction: 'Disable SMS phone recovery due to SIM-swapping risks. Transition to passkeys or physical hardware security keys.',
      },
      {
        stepNumber: 3,
        title: 'Lock Down Email Auto-Forwarding Rules',
        instruction: 'Inspect mailbox rules for hidden forwarding rules created by attackers to silently exfiltrate password reset emails.',
      },
      {
        stepNumber: 4,
        title: 'Generate Offline Emergency Recovery Codes',
        instruction: 'Store one-time emergency backup recovery codes in an encrypted physical or digital vault.',
      },
    ],
    scannerLabel: 'Run Security Checkup',
    scannerHref: '/cyber-safety/security-checkup',
    scannerType: 'Security Checkup',
  },
  {
    id: 'mobile-threat-defense',
    title: 'Mobile Device Security Hardening and Smishing Defense',
    category: 'Mobile Security',
    difficulty: 'Beginner',
    readTime: '4 min read',
    summary: 'Protecting smartphones from malicious SMS links, rogue configuration profiles, and unverified sideloaded apps.',
    steps: [
      {
        stepNumber: 1,
        title: 'Never Tap Shortened SMS Tracking Links',
        instruction: 'Copy suspicious SMS links and analyze them in CyberWatch before navigating on mobile browsers.',
      },
      {
        stepNumber: 2,
        title: 'Audit Installed MDM & Configuration Profiles',
        instruction: 'Inspect Settings > General > VPN & Device Management to ensure no unauthorized root certificates are installed.',
      },
      {
        stepNumber: 3,
        title: 'Restrict Clipboard and Location Permissions',
        instruction: 'Set location permissions to "While Using" and block background clipboard read access across social apps.',
      },
      {
        stepNumber: 4,
        title: 'Enable Automatic OS Rapid Security Responses',
        instruction: 'Ensure iOS / Android automatic security patch installation is toggled on.',
      },
    ],
    scannerLabel: 'Scan Link on Mobile',
    scannerHref: '/cyber-safety/safe-browsing',
    scannerType: 'URL Scanner',
  },
  {
    id: 'safe-download-inspection',
    title: 'Inspecting File Downloads and Cryptographic Checksums',
    category: 'Downloads',
    difficulty: 'Intermediate',
    readTime: '5 min read',
    summary: 'How to detect double extensions, verify SHA-256 hashes, and analyze file metadata before execution.',
    steps: [
      {
        stepNumber: 1,
        title: 'Inspect Direct File URL and Double Extensions',
        instruction: 'Watch for evasion filenames such as "Invoice_2024.pdf.exe" or compressed archives containing script payloads.',
      },
      {
        stepNumber: 2,
        title: 'Verify Cryptographic SHA-256 Checksum',
        instruction: 'Compute the file hash locally (certutil -hashfile on Windows) and compare against published vendor hashes.',
      },
      {
        stepNumber: 3,
        title: 'Execute CyberWatch File Security Scanner',
        instruction: 'Submit the downloadable asset or hash to CyberWatch to audit file signatures, MIME types, and threat records.',
      },
      {
        stepNumber: 4,
        title: 'Isolate Untrusted Binaries in a Sandbox',
        instruction: 'Run unfamiliar binaries in an isolated sandbox or virtual machine environment prior to production execution.',
      },
    ],
    scannerLabel: 'Scan File Asset',
    scannerHref: '/services/file',
    scannerType: 'File Scanner',
  },
  {
    id: 'social-engineering-defense',
    title: 'Defending Against Voice Phishing (Vishing) & Executive Impersonation',
    category: 'Social Engineering',
    difficulty: 'Advanced',
    readTime: '6 min read',
    summary: 'Protocols for establishing out-of-band verification when confronted with urgent executive or IT helpdesk requests.',
    steps: [
      {
        stepNumber: 1,
        title: 'Establish Out-of-Band Callback Protocols',
        instruction: 'Never verify caller identity using the phone number they provide. Call back using official internal corporate directories.',
      },
      {
        stepNumber: 2,
        title: 'Strict Verification for Financial & Credential Changes',
        instruction: 'Enforce multi-party verbal authorization for any changes to banking routing numbers or executive gift requests.',
      },
      {
        stepNumber: 3,
        title: 'Be Alert to AI Voice Cloning Signals',
        instruction: 'Notice unnatural cadence, background noise loops, or uncharacteristic urgency from supposed family or executives.',
      },
      {
        stepNumber: 4,
        title: 'Log and Report Social Engineering Telemetry',
        instruction: 'Submit indicator details to Threat Intelligence to help protect the broader community from ongoing campaigns.',
      },
    ],
    scannerLabel: 'Search Threat Intel',
    scannerHref: '/threat-intelligence',
    scannerType: 'Threat Intelligence',
  },
];

const CATEGORIES: GuideCategory[] = [
  'All',
  'Web Security',
  'Phishing',
  'Passwords',
  'Browser Security',
  'Privacy',
  'Account Security',
  'Mobile Security',
  'Downloads',
  'Social Engineering',
];

export function SecurityGuidesPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<GuideCategory>('All');
  const [activeGuide, setActiveGuide] = useState<SecurityGuide | null>(null);

  const filteredGuides = useMemo(() => {
    return GUIDES.filter((guide) => {
      const matchesCategory = selectedCategory === 'All' || guide.category === selectedCategory;
      const matchesSearch =
        guide.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        guide.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        guide.category.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [searchQuery, selectedCategory]);

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      <CyberSafetyHeader
        title="Security Guides"
        subtitle="Actionable, enterprise-grade step-by-step security guidance and threat defense best practices."
        breadcrumbs={[{ label: 'Cyber Safety', href: '/cyber-safety' }]}
        primaryCta={{
          label: 'Run Security Checkup',
          href: '/cyber-safety/security-checkup',
          icon: Shield,
        }}
      />

      <Container className="py-8 md:py-10 space-y-8">
        {/* ── Search & Filter Controls ────────────────────────────── */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            {/* Search Input */}
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search security guides, topics, and tactics..."
                className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white transition-all"
              />
            </div>

            <div className="text-xs text-slate-500 font-semibold">
              Showing {filteredGuides.length} of {GUIDES.length} guides
            </div>
          </div>

          {/* Category Filter Pills */}
          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-100">
            {CATEGORIES.map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  selectedCategory === cat
                    ? 'bg-blue-600 text-white shadow-2xs'
                    : 'bg-slate-50 hover:bg-slate-100 text-slate-600 border border-slate-200/70'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* ── Guides Grid ─────────────────────────────────────────── */}
        {filteredGuides.length === 0 ? (
          <div className="bg-white rounded-2xl border border-slate-200 p-12 text-center space-y-3">
            <BookOpen className="w-8 h-8 text-slate-300 mx-auto" />
            <h3 className="text-base font-bold text-slate-800">No security guides found</h3>
            <p className="text-xs text-slate-500">
              Try adjusting your search terms or filter category.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredGuides.map((guide) => (
              <div
                key={guide.id}
                className="bg-white rounded-2xl border border-slate-200 p-6 flex flex-col justify-between hover:border-slate-300 hover:shadow-xs transition-all space-y-4"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-blue-700 bg-blue-50 px-2.5 py-0.5 rounded border border-blue-100">
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

                  <p className="text-xs text-slate-500 leading-relaxed line-clamp-3">
                    {guide.summary}
                  </p>
                </div>

                <div className="pt-4 border-t border-slate-100 flex items-center justify-between text-xs">
                  <button
                    type="button"
                    onClick={() => setActiveGuide(guide)}
                    className="font-bold text-slate-800 hover:text-blue-600 inline-flex items-center gap-1 transition-colors"
                  >
                    <span>Read Guide</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>

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
        )}
      </Container>

      {/* ── Guide Reader Modal / Drawer ─────────────────────────── */}
      {activeGuide && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 animate-in fade-in duration-150">
          <div className="bg-white rounded-2xl border border-slate-200 max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
            {/* Header */}
            <div className="p-6 border-b border-slate-100 flex items-start justify-between gap-4 sticky top-0 bg-white z-10">
              <div>
                <div className="flex items-center gap-2 text-xs mb-1.5">
                  <span className="font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
                    {activeGuide.category}
                  </span>
                  <span className="text-slate-400">•</span>
                  <span className="text-slate-500 font-medium">{activeGuide.readTime}</span>
                  <span className="text-slate-400">•</span>
                  <span className="text-slate-700 font-semibold">{activeGuide.difficulty}</span>
                </div>
                <h2 className="text-xl font-bold text-slate-900 leading-snug">
                  {activeGuide.title}
                </h2>
              </div>

              <button
                type="button"
                onClick={() => setActiveGuide(null)}
                className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition-colors"
                aria-label="Close guide reader"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Body */}
            <div className="p-6 space-y-6 flex-1">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700 leading-relaxed">
                <span className="font-bold text-slate-900">Summary: </span>
                {activeGuide.summary}
              </div>

              <div className="space-y-4">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                  Step-by-Step Action Checklist
                </h3>

                <div className="space-y-3">
                  {activeGuide.steps.map((s) => (
                    <div key={s.stepNumber} className="p-4 rounded-xl bg-white border border-slate-200 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 font-bold text-[11px] flex items-center justify-center shrink-0">
                          {s.stepNumber}
                        </span>
                        <h4 className="text-xs font-bold text-slate-900">{s.title}</h4>
                      </div>
                      <p className="text-xs text-slate-600 pl-7 leading-relaxed">
                        {s.instruction}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Footer with Contextual Scanner Link */}
            <div className="p-6 border-t border-slate-100 bg-slate-50/60 flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-b-2xl">
              <div className="text-xs text-slate-500">
                Connected tool: <span className="font-bold text-slate-800">{activeGuide.scannerType}</span>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setActiveGuide(null)}
                  className="px-4 py-2 border border-slate-200 hover:bg-white text-slate-700 text-xs font-semibold rounded-xl transition-colors"
                >
                  Close
                </button>

                <Link
                  to={activeGuide.scannerHref}
                  onClick={() => setActiveGuide(null)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-xl transition-colors shadow-xs"
                >
                  <span>{activeGuide.scannerLabel}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
