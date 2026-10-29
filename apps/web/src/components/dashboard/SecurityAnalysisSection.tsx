import {
  Globe,
  ShieldAlert,
  Terminal,
  Shield,
  FileSearch,
  Puzzle,
  KeyRound,
  Cpu,
  CheckCircle2,
  Lock,
} from 'lucide-react';

interface AnalysisModule {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  tag: string;
  iconColor: string;
  iconBg: string;
  engine: string;
}

interface AnalysisCategory {
  id: string;
  title: string;
  badge: string;
  description: string;
  modules: AnalysisModule[];
}

const ANALYSIS_CATEGORIES: AnalysisCategory[] = [
  {
    id: 'category-web-security',
    title: 'Web Security',
    badge: 'Web Security',
    description: 'Core evaluation modules for link structures, website response parameters, TLS, and security configurations.',
    modules: [
      {
        id: 'module-url-security',
        name: 'URL Security Analysis',
        description: 'Analyzes full URL structures, path syntax, query parameters, hex obfuscation, and suspicious keywords to detect evasion techniques.',
        icon: Globe,
        tag: 'Link & URL Audit',
        iconColor: 'text-blue-600',
        iconBg: 'bg-blue-50 border-blue-100',
        engine: 'CyberWatch URL Core',
      },
      {
        id: 'module-website-security',
        name: 'Website Security & TLS',
        description: 'Evaluates live web page headers, cookies, inline scripts, form actions, mixed content, and SSL/TLS certificate validity.',
        icon: ShieldAlert,
        tag: 'Response & TLS Audit',
        iconColor: 'text-indigo-600',
        iconBg: 'bg-indigo-50 border-indigo-100',
        engine: 'Web Perimeter Engine',
      },
    ],
  },
  {
    id: 'category-application-security',
    title: 'Application Security',
    badge: 'API Security',
    description: 'Specialized analysis for API endpoints, CORS policies, response structures, and technical exposure risks.',
    modules: [
      {
        id: 'module-api-security',
        name: 'API Endpoint Analysis',
        description: 'Safely inspects HTTP/HTTPS API endpoints, response structures (JSON/XML), CORS headers, and rate-limit indicators.',
        icon: Terminal,
        tag: 'API Audit',
        iconColor: 'text-cyan-600',
        iconBg: 'bg-cyan-50 border-cyan-100',
        engine: 'API Sentinel Guard',
      },
      {
        id: 'module-api-exposure',
        name: 'Technical Exposure Audit',
        description: 'Audits error handling to detect stack trace leakage, database error disclosures, and insecure wildcard cross-origin access.',
        icon: Lock,
        tag: 'Exposure Inspection',
        iconColor: 'text-teal-600',
        iconBg: 'bg-teal-50 border-teal-100',
        engine: 'Exposure Evaluator',
      },
    ],
  },
  {
    id: 'category-threat-detection',
    title: 'Threat Detection',
    badge: 'Threat Intel',
    description: 'Targeted threat inspection engines for deceptive portals, credential harvesting, and social engineering lures.',
    modules: [
      {
        id: 'module-phishing-detection',
        name: 'Phishing & Deception Defense',
        description: 'Detects brand impersonation cues, fraudulent login interfaces, credential harvesting forms, and typosquatted domains.',
        icon: Shield,
        tag: 'Deception Defense',
        iconColor: 'text-amber-600',
        iconBg: 'bg-amber-50 border-amber-100',
        engine: 'Phishing Signature Engine',
      },
    ],
  },
  {
    id: 'category-file-security',
    title: 'File Security',
    badge: 'File Security',
    description: 'Structural and static analysis of downloadable assets and user-uploaded file formats.',
    modules: [
      {
        id: 'module-file-security',
        name: 'Download & Asset Inspection',
        description: 'Inspects downloadable files for executable extension risks, double-extension cloaking, MIME mismatches, and magic bytes.',
        icon: FileSearch,
        tag: 'Payload Analysis',
        iconColor: 'text-blue-600',
        iconBg: 'bg-blue-50 border-blue-100',
        engine: 'Static File Inspector',
      },
    ],
  },
  {
    id: 'category-browser-security',
    title: 'Browser Security',
    badge: 'Browser Guard',
    description: 'Specialized inspection for browser extensions, Manifest V3 packages, and declared extension privileges.',
    modules: [
      {
        id: 'module-extension-analysis',
        name: 'Extension Package & Permissions',
        description: 'Inspects Chrome Manifest V3 service workers, content scripts, and declared permissions (storage, activeTab, debugger, webRequest).',
        icon: Puzzle,
        tag: 'Manifest V3 Audit',
        iconColor: 'text-sky-600',
        iconBg: 'bg-sky-50 border-sky-100',
        engine: 'Extension Guard',
      },
      {
        id: 'module-permission-scope',
        name: 'Permission & Domain Scope Audit',
        description: 'Scrutinizes broad host permissions (<all_urls>, *://*/*) and identifies excessive permission combination risks.',
        icon: KeyRound,
        tag: 'Privilege Scrutiny',
        iconColor: 'text-violet-600',
        iconBg: 'bg-violet-50 border-violet-100',
        engine: 'Permission Evaluator',
      },
    ],
  },
];

export function SecurityAnalysisSection() {
  return (
    <div id="security-analysis-section" className="space-y-8">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-2">
        <div>
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-50 text-blue-700 text-xs font-bold uppercase tracking-wider border border-blue-100 mb-2">
            <Cpu className="w-3.5 h-3.5" />
            <span>Platform Capabilities</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight">
            Security Analysis
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Understand what CyberWatch analyzes to assess potential security risks across Web &amp; Browser domains.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 bg-white border border-slate-200/80 px-3 py-1.5 rounded-xl shadow-2xs">
          <CheckCircle2 className="w-4 h-4 text-blue-600" />
          <span>5 Core Security Domains Active</span>
        </div>
      </div>

      {/* Grouped Category Panels */}
      <div className="space-y-8">
        {ANALYSIS_CATEGORIES.map((category) => (
          <div key={category.id} className="space-y-4">
            {/* Category Subheader */}
            <div className="border-b border-slate-200/80 pb-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
              <div className="flex items-center gap-2.5">
                <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
                  {category.title}
                </h3>
                <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 border border-slate-200">
                  {category.badge}
                </span>
              </div>
              <p className="text-xs text-slate-500">
                {category.description}
              </p>
            </div>

            {/* Modules Grid */}
            <div
              className={`grid grid-cols-1 ${
                category.modules.length === 3
                  ? 'md:grid-cols-3'
                  : 'md:grid-cols-2'
              } gap-4 sm:gap-5`}
            >
              {category.modules.map((module) => {
                const Icon = module.icon;
                return (
                  <div
                    key={module.id}
                    id={module.id}
                    className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 flex flex-col justify-between gap-4 shadow-sm hover:border-slate-300 transition-all duration-200"
                  >
                    <div className="space-y-3.5">
                      {/* Top Row: Icon & Informational Indicator */}
                      <div className="flex items-center justify-between">
                        <div
                          className={`w-11 h-11 rounded-xl flex items-center justify-center border ${module.iconBg}`}
                        >
                          <Icon className={`w-5 h-5 ${module.iconColor}`} />
                        </div>
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold bg-slate-50 text-slate-600 border border-slate-200/70">
                          <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                          {module.tag}
                        </span>
                      </div>

                      {/* Content */}
                      <div>
                        <h4 className="text-base font-bold text-slate-900 tracking-tight">
                          {module.name}
                        </h4>
                        <p className="text-xs sm:text-sm text-slate-600 mt-1.5 leading-relaxed">
                          {module.description}
                        </p>
                      </div>
                    </div>

                    {/* Informational Sub-label instead of a button */}
                    <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400 font-medium">
                      <span>Engine: {module.engine}</span>
                      <span className="text-emerald-600 font-semibold flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />
                        Integrated
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
