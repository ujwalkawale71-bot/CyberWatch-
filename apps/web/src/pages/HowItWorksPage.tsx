import { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Shield,
  ArrowRight,
  Send,
  Activity,
  Layers,
  Search,
  CheckCircle2,
  AlertTriangle,
  Globe,
  ShieldAlert,
  Terminal,
  FileSearch,
  Puzzle,
  ChevronRight,
  Info,
  SlidersHorizontal,
  FileCheck,
  Zap,
  Cpu,
  Eye,
  CheckCircle,
  HelpCircle,
  Sparkles,
} from 'lucide-react';
import { Container } from '../components/ui/Container';

// --- Data for Scanners ---
const SCANNERS_LIST = [
  {
    id: 'url-scanner',
    name: 'URL Security Scanner',
    description: 'Analyze URLs for security-related indicators, redirection loops, and risk signals.',
    icon: Globe,
    iconColor: 'text-blue-600',
    iconBg: 'bg-blue-50 border-blue-100',
    badge: 'URL Target',
    link: '/services/url-phishing',
  },
  {
    id: 'website-scanner',
    name: 'Website Security Scanner',
    description: 'Assess websites through relevant technical checks, TLS posture, headers, and script origins.',
    icon: ShieldAlert,
    iconColor: 'text-indigo-600',
    iconBg: 'bg-indigo-50 border-indigo-100',
    badge: 'Website Target',
    link: '/services/website-scanner',
  },
  {
    id: 'api-scanner',
    name: 'API Security Scanner',
    description: 'Analyze API targets for security-related indicators, CORS policies, and configuration issues.',
    icon: Terminal,
    iconColor: 'text-cyan-600',
    iconBg: 'bg-cyan-50 border-cyan-100',
    badge: 'API Endpoint',
    link: '/services/api-scanner',
  },
  {
    id: 'phishing-scanner',
    name: 'Phishing Scanner',
    description: 'Evaluate phishing-related signals and deceptive patterns associated with a submitted target.',
    icon: Shield,
    iconColor: 'text-amber-600',
    iconBg: 'bg-amber-50 border-amber-100',
    badge: 'Phishing Target',
    link: '/services/url-phishing',
  },
  {
    id: 'file-scanner',
    name: 'File Security Scanner',
    description: 'Analyze uploaded files and downloadable payloads for relevant security indicators and checksums.',
    icon: FileSearch,
    iconColor: 'text-blue-600',
    iconBg: 'bg-blue-50 border-blue-100',
    badge: 'File Target',
    link: '/services/file',
  },
  {
    id: 'extension-scanner',
    name: 'Browser Extension Scanner',
    description: 'Inspect browser extensions through manifest, permissions, code, network, and other available evidence.',
    icon: Puzzle,
    iconColor: 'text-sky-600',
    iconBg: 'bg-sky-50 border-sky-100',
    badge: 'Extension Audit',
    link: '/services/extension',
  },
];

// --- Data for Principles ---
const PRINCIPLES = [
  {
    title: 'Evidence-Based',
    description: 'Results are derived from security evidence collected during analysis without guesswork.',
    icon: FileCheck,
    color: 'text-blue-600',
    bg: 'bg-blue-50 border-blue-100',
  },
  {
    title: 'Transparent',
    description: 'Findings and risk factors are presented so users can understand why a result was produced.',
    icon: Eye,
    color: 'text-indigo-600',
    bg: 'bg-indigo-50 border-indigo-100',
  },
  {
    title: 'Modular',
    description: 'Specialized scanners handle different security target types with domain-tailored heuristics.',
    icon: SlidersHorizontal,
    color: 'text-cyan-600',
    bg: 'bg-cyan-50 border-cyan-100',
  },
  {
    title: 'Actionable',
    description: 'Results are designed to help users understand potential security concerns and next steps.',
    icon: CheckCircle2,
    color: 'text-emerald-600',
    bg: 'bg-emerald-50 border-emerald-100',
  },
];

// --- Data for Behind the Scenes Pipeline ---
const PIPELINE_STAGES = [
  {
    step: '01',
    title: 'INPUT VALIDATION',
    desc: 'Validate and sanitize the submitted target format, protocol, and structure before processing.',
    icon: CheckCircle,
    color: 'text-blue-600',
    bg: 'bg-blue-50 border-blue-100',
  },
  {
    step: '02',
    title: 'SCANNER ROUTING',
    desc: 'Select the appropriate security scanner based on the target type and requested analysis profile.',
    icon: SlidersHorizontal,
    color: 'text-indigo-600',
    bg: 'bg-indigo-50 border-indigo-100',
  },
  {
    step: '03',
    title: 'EVIDENCE COLLECTION',
    desc: 'Collect relevant technical signals across network parameters, headers, permissions, or structures.',
    icon: Activity,
    color: 'text-cyan-600',
    bg: 'bg-cyan-50 border-cyan-100',
  },
  {
    step: '04',
    title: 'FINDING GENERATION',
    desc: 'Identify and classify security findings against established risk patterns and vulnerability signatures.',
    icon: Search,
    color: 'text-amber-600',
    bg: 'bg-amber-50 border-amber-100',
  },
  {
    step: '05',
    title: 'RISK EVALUATION',
    desc: 'Apply severity levels and weighted risk contributions according to CyberWatch platform evaluation rules.',
    icon: Cpu,
    color: 'text-purple-600',
    bg: 'bg-purple-50 border-purple-100',
  },
  {
    step: '06',
    title: 'RESULT',
    desc: 'Present a transparent risk score (0-100), risk tier verdict, and clear contextual recommendations.',
    icon: Zap,
    color: 'text-emerald-600',
    bg: 'bg-emerald-50 border-emerald-100',
  },
];

export function HowItWorksPage() {
  const [activeEvidenceTab, setActiveEvidenceTab] = useState<'config' | 'indicators' | 'permissions' | 'network' | 'other'>('config');
  const location = useLocation();

  useEffect(() => {
    if (location.hash) {
      const targetId = location.hash.replace('#', '');
      const element = document.getElementById(targetId);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }, [location.pathname, location.hash]);

  return (
    <main className="min-h-screen bg-white pb-28 pt-24 sm:pt-28">
      {/* ── 1. HERO SECTION ────────────────────────────────────────── */}
      <section className="relative overflow-hidden border-b border-slate-100 pb-16 sm:pb-24">
        {/* Subtle Background Radial Highlights */}
        <div className="absolute top-10 left-1/2 -translate-x-1/2 w-[800px] h-[350px] bg-gradient-to-b from-blue-50/70 to-transparent rounded-full blur-3xl -z-10 pointer-events-none" />

        <Container>
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
            {/* Left Column: Eyebrow, Heading, Description, Flow Badges */}
            <div className="lg:col-span-7 space-y-5 text-center lg:text-left">
              {/* Eyebrow */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-blue-50 border border-blue-200/80 text-blue-700 text-xs font-bold uppercase tracking-wider shadow-xs">
                <Shield className="w-3.5 h-3.5 text-blue-600 shrink-0" />
                <span>HOW CYBERWATCH WORKS</span>
              </div>

              {/* Heading */}
              <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-900 tracking-tight leading-tight">
                From Security Target to Actionable Risk Assessment
              </h1>

              {/* Description */}
              <p className="text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl mx-auto lg:mx-0">
                CyberWatch analyzes security targets through specialized scanners, collects relevant technical evidence, evaluates the findings, and presents the results as an understandable risk assessment.
              </p>

              {/* Supporting Line Flow */}
              <div className="pt-2">
                <div className="inline-flex flex-wrap items-center justify-center lg:justify-start gap-2 sm:gap-2.5 p-2 bg-slate-50 border border-slate-200/80 rounded-2xl">
                  <span className="px-3 py-1 bg-white border border-slate-200 text-slate-800 text-xs font-bold rounded-lg shadow-xs">
                    Submit
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                  <span className="px-3 py-1 bg-white border border-slate-200 text-slate-800 text-xs font-bold rounded-lg shadow-xs">
                    Analyze
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                  <span className="px-3 py-1 bg-white border border-slate-200 text-slate-800 text-xs font-bold rounded-lg shadow-xs">
                    Evaluate
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                  <span className="px-3 py-1 bg-blue-600 text-white text-xs font-bold rounded-lg shadow-xs shadow-blue-500/20">
                    Understand
                  </span>
                </div>
              </div>

              {/* Quick Jump Links */}
              <div className="flex flex-wrap items-center justify-center lg:justify-start gap-4 pt-4 text-xs font-semibold text-slate-500">
                <span className="text-slate-400 font-medium">Quick navigation:</span>
                <a href="#submit" className="text-slate-700 hover:text-blue-600 transition-colors">01. Submit</a>
                <span className="text-slate-300">•</span>
                <a href="#analyze" className="text-slate-700 hover:text-blue-600 transition-colors">02. Analysis</a>
                <span className="text-slate-300">•</span>
                <a href="#evaluate" className="text-slate-700 hover:text-blue-600 transition-colors">03. Evaluate</a>
                <span className="text-slate-300">•</span>
                <a href="#example" className="text-slate-700 hover:text-blue-600 transition-colors">04. Example</a>
              </div>
            </div>

            {/* Right Column: Hero Workflow Visualization */}
            <div className="lg:col-span-5">
              <div className="relative mx-auto max-w-md bg-slate-50/90 border border-slate-200/90 rounded-3xl p-6 sm:p-7 shadow-lg shadow-slate-100/80">
                {/* Visual Header */}
                <div className="flex items-center justify-between pb-4 mb-5 border-b border-slate-200/70">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                      Target Flow Engine
                    </span>
                  </div>
                  <span className="text-[10px] font-bold text-blue-600 bg-blue-50 border border-blue-100 px-2 py-0.5 rounded-full">
                    Deterministic
                  </span>
                </div>

                {/* 5-Step Vertical Node Stack with Connecting Line */}
                <div className="relative space-y-3.5">
                  {/* Vertical Track Line */}
                  <div className="absolute left-[19px] top-4 bottom-4 w-0.5 bg-gradient-to-b from-blue-300 via-indigo-300 to-emerald-400 -z-0" />

                  {/* Node 1: Security Target */}
                  <div className="relative z-10 flex items-center gap-3.5 bg-white border border-slate-200/90 rounded-2xl p-3 shadow-xs hover:border-blue-300 transition-all">
                    <div className="w-9 h-9 rounded-xl bg-slate-100 border border-slate-200 flex items-center justify-center shrink-0">
                      <Search className="w-4 h-4 text-slate-700" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">STAGE 01</div>
                      <div className="text-xs font-bold text-slate-900">SECURITY TARGET</div>
                    </div>
                    <span className="text-[10px] font-semibold text-slate-500 bg-slate-50 border border-slate-200 px-2 py-0.5 rounded-md">
                      URL, Web, File, Ext
                    </span>
                  </div>

                  {/* Node 2: Submit */}
                  <div className="relative z-10 flex items-center gap-3.5 bg-white border border-slate-200/90 rounded-2xl p-3 shadow-xs hover:border-blue-300 transition-all">
                    <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center shrink-0">
                      <Send className="w-4 h-4 text-blue-600" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-[10px] font-bold text-blue-500 uppercase tracking-wider">STAGE 02</div>
                      <div className="text-xs font-bold text-slate-900">SUBMIT</div>
                    </div>
                    <span className="text-[10px] font-semibold text-blue-600 bg-blue-50 px-2 py-0.5 rounded-md border border-blue-100">
                      Input Sanitization
                    </span>
                  </div>

                  {/* Node 3: Analyze */}
                  <div className="relative z-10 flex items-center gap-3.5 bg-white border border-slate-200/90 rounded-2xl p-3 shadow-xs hover:border-indigo-300 transition-all">
                    <div className="w-9 h-9 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center shrink-0">
                      <Activity className="w-4 h-4 text-indigo-600" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-[10px] font-bold text-indigo-500 uppercase tracking-wider">STAGE 03</div>
                      <div className="text-xs font-bold text-slate-900">ANALYZE</div>
                    </div>
                    <span className="text-[10px] font-semibold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded-md border border-indigo-100">
                      Evidence Collection
                    </span>
                  </div>

                  {/* Node 4: Evaluate */}
                  <div className="relative z-10 flex items-center gap-3.5 bg-white border border-slate-200/90 rounded-2xl p-3 shadow-xs hover:border-purple-300 transition-all">
                    <div className="w-9 h-9 rounded-xl bg-purple-50 border border-purple-100 flex items-center justify-center shrink-0">
                      <Cpu className="w-4 h-4 text-purple-600" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-[10px] font-bold text-purple-500 uppercase tracking-wider">STAGE 04</div>
                      <div className="text-xs font-bold text-slate-900">EVALUATE</div>
                    </div>
                    <span className="text-[10px] font-semibold text-purple-600 bg-purple-50 px-2 py-0.5 rounded-md border border-purple-100">
                      Risk Weighting
                    </span>
                  </div>

                  {/* Node 5: Security Result */}
                  <div className="relative z-10 flex items-center gap-3.5 bg-gradient-to-r from-emerald-50 to-teal-50 border border-emerald-200 rounded-2xl p-3 shadow-xs">
                    <div className="w-9 h-9 rounded-xl bg-emerald-600 text-white flex items-center justify-center shrink-0 shadow-sm shadow-emerald-600/30">
                      <Shield className="w-4 h-4 text-white" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-[10px] font-bold text-emerald-700 uppercase tracking-wider">OUTCOME</div>
                      <div className="text-xs font-bold text-slate-900">SECURITY RESULT</div>
                    </div>
                    <span className="text-[10px] font-bold text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded-md">
                      Score &amp; Verdict
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Container>
      </section>

      {/* ── 2. FOUR-STEP WORKFLOW ─────────────────────────────────── */}
      <section className="py-20 bg-slate-50/60 border-b border-slate-100">
        <Container>
          <div className="max-w-3xl mx-auto text-center mb-16 space-y-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 text-blue-700 text-xs font-bold uppercase tracking-wider border border-blue-100">
              <span>Step-by-Step Architecture</span>
            </div>
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-900 tracking-tight">
              The Four Stages of Threat Analysis
            </h2>
            <p className="text-sm sm:text-base text-slate-600 leading-relaxed">
              Explore how CyberWatch transitions transparently from raw inputs to comprehensive security intelligence.
            </p>
          </div>

          <div className="space-y-10 w-full">
            {/* ── STAGE 01: SUBMIT ────────────────────────────────────── */}
            <div
              id="submit"
              className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-sm hover:shadow-md transition-shadow"
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 pb-6 border-b border-slate-100">
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-blue-50 border border-blue-100 flex items-center justify-center shrink-0">
                    <Send className="w-6 h-6 text-blue-600" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-bold text-blue-600 bg-blue-50 border border-blue-100 px-2 py-0.5 rounded-md">
                        STAGE 01
                      </span>
                      <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider bg-slate-100 px-2.5 py-0.5 rounded-md">
                        INPUT
                      </span>
                    </div>
                    <h3 className="text-xl sm:text-2xl font-bold text-slate-900">
                      Submit a Security Target
                    </h3>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 pt-6">
                <div className="lg:col-span-6 space-y-4">
                  <p className="text-sm sm:text-base text-slate-600 leading-relaxed">
                    Start by providing the target you want CyberWatch to analyze. Depending on the selected scanner, this can include a URL, website, API, phishing target, file, or browser extension.
                  </p>
                  <div className="bg-slate-50 border border-slate-200/80 rounded-2xl p-4 space-y-2">
                    <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                      <Info className="w-3.5 h-3.5 text-blue-600" />
                      Supported Target Formats
                    </h4>
                    <ul className="text-xs text-slate-600 space-y-1.5 leading-relaxed">
                      <li>• <strong>Public URLs &amp; Websites:</strong> Fully qualified domain names (FQDN) or complete HTTP/HTTPS links.</li>
                      <li>• <strong>API Endpoints:</strong> REST or HTTP endpoint URLs with safe query parameters.</li>
                      <li>• <strong>Files &amp; Packages:</strong> Direct downloadable file links, binaries, or uploaded documents.</li>
                      <li>• <strong>Browser Extensions:</strong> Chrome Web Store links, extension IDs, or Manifest V3 definitions.</li>
                    </ul>
                  </div>
                </div>

                {/* Interactive Target Submission Preview */}
                <div className="lg:col-span-6 bg-slate-50 border border-slate-200/80 rounded-2xl p-5 flex flex-col justify-between">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs text-slate-500 pb-2 border-b border-slate-200/60">
                      <span className="font-semibold text-slate-700">Target Ingestion Simulation</span>
                      <span className="font-mono text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">READY</span>
                    </div>
                    <div className="relative">
                      <input
                        type="text"
                        readOnly
                        value="https://security-test-target.example.org"
                        aria-label="Example target input"
                        className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-xs font-mono text-slate-800 shadow-inner"
                      />
                      <div className="absolute right-2 top-2 bg-blue-600 text-white text-[11px] font-bold px-3 py-1 rounded-lg">
                        Analyze
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      <span className="text-[10px] font-medium bg-white border border-slate-200 text-slate-600 px-2 py-1 rounded-md">URL: Validated</span>
                      <span className="text-[10px] font-medium bg-white border border-slate-200 text-slate-600 px-2 py-1 rounded-md">DNS: Resolvable</span>
                      <span className="text-[10px] font-medium bg-white border border-slate-200 text-slate-600 px-2 py-1 rounded-md">Protocol: HTTPS</span>
                    </div>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-4 italic">
                    Safe non-destructive handling is automatically applied to all submitted targets.
                  </p>
                </div>
              </div>
            </div>

            {/* ── STAGE 02: ANALYSIS ──────────────────────────────────── */}
            <div
              id="analyze"
              className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-sm hover:shadow-md transition-shadow"
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 pb-6 border-b border-slate-100">
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-indigo-50 border border-indigo-100 flex items-center justify-center shrink-0">
                    <Activity className="w-6 h-6 text-indigo-600" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-bold text-indigo-600 bg-indigo-50 border border-indigo-100 px-2 py-0.5 rounded-md">
                        STAGE 02
                      </span>
                      <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider bg-slate-100 px-2.5 py-0.5 rounded-md">
                        EVIDENCE COLLECTION
                      </span>
                    </div>
                    <h3 className="text-xl sm:text-2xl font-bold text-slate-900">
                      Analyze Technical Evidence
                    </h3>
                  </div>
                </div>
              </div>

              <div className="space-y-6 pt-6">
                <p className="text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
                  CyberWatch routes the target to the appropriate security scanner and collects relevant technical evidence. The analysis focuses on signals that can help identify security weaknesses, suspicious behavior, configuration issues, or other risk indicators.
                </p>

                {/* Visual Pipeline: Target -> Scanner -> Technical Evidence */}
                <div className="p-4 sm:p-6 bg-slate-50 border border-slate-200/80 rounded-2xl">
                  <div className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4">
                    Visual Evidence Flow
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
                    <div className="bg-white border border-slate-200 rounded-xl p-4 text-center shadow-xs">
                      <span className="text-[10px] font-bold text-slate-400 block uppercase">Step A</span>
                      <span className="text-sm font-bold text-slate-900">Target</span>
                      <p className="text-xs text-slate-500 mt-1">Submitted URI / Asset</p>
                    </div>

                    <div className="flex items-center justify-center">
                      <div className="hidden md:flex items-center gap-2 text-indigo-600 font-bold text-xs bg-indigo-50 border border-indigo-100 px-3 py-1.5 rounded-full">
                        <span>Routed to</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </div>
                      <div className="md:hidden text-center text-slate-400 py-1">↓</div>
                    </div>

                    <div className="bg-white border border-slate-200 rounded-xl p-4 text-center shadow-xs">
                      <span className="text-[10px] font-bold text-indigo-500 block uppercase">Step B</span>
                      <span className="text-sm font-bold text-slate-900">Specialized Scanner</span>
                      <p className="text-xs text-slate-500 mt-1">Dedicated Heuristics Engine</p>
                    </div>
                  </div>

                  <div className="my-4 text-center text-slate-400 font-bold text-sm">↓ Resulting in</div>

                  <div className="bg-indigo-600 text-white rounded-xl p-4 text-center shadow-sm">
                    <span className="text-[10px] font-bold text-indigo-200 block uppercase">Step C</span>
                    <span className="text-sm font-bold">Technical Evidence Extraction</span>
                    <p className="text-xs text-indigo-100 mt-0.5">Categorized signals for risk formulation</p>
                  </div>
                </div>

                {/* Evidence Categories (Interactive/Visual) */}
                <div className="space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                      Example Evidence Categories
                    </span>
                    <span className="text-[11px] text-amber-700 bg-amber-50 border border-amber-200/70 px-2.5 py-0.5 rounded-md font-medium">
                      * Available evidence depends on the selected scanner
                    </span>
                  </div>

                  {/* Category Tabs */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
                    {[
                      { key: 'config', name: 'Configuration' },
                      { key: 'indicators', name: 'Security Indicators' },
                      { key: 'permissions', name: 'Permissions' },
                      { key: 'network', name: 'Network Signals' },
                      { key: 'other', name: 'Other Findings' },
                    ].map((tab) => (
                      <button
                        key={tab.key}
                        onClick={() => setActiveEvidenceTab(tab.key as any)}
                        className={`px-3 py-2 text-xs font-bold rounded-xl border text-center transition-all ${
                          activeEvidenceTab === tab.key
                            ? 'bg-blue-600 text-white border-blue-600 shadow-xs'
                            : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                        }`}
                      >
                        {tab.name}
                      </button>
                    ))}
                  </div>

                  {/* Category Details View */}
                  <div className="bg-slate-50 border border-slate-200/80 rounded-2xl p-5 text-xs text-slate-700">
                    {activeEvidenceTab === 'config' && (
                      <div className="space-y-2">
                        <div className="font-bold text-slate-900 text-sm">Configuration Signals</div>
                        <p className="text-slate-600 leading-relaxed">
                          Checks for Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), X-Frame-Options, secure cookie attributes (SameSite, HttpOnly), and server information disclosure headers.
                        </p>
                      </div>
                    )}
                    {activeEvidenceTab === 'indicators' && (
                      <div className="space-y-2">
                        <div className="font-bold text-slate-900 text-sm">Security Indicators</div>
                        <p className="text-slate-600 leading-relaxed">
                          Identifies suspicious keyword patterns in URLs, credential harvesting form structures, brand impersonation markers, lookalike typography, or unusual URL parameters.
                        </p>
                      </div>
                    )}
                    {activeEvidenceTab === 'permissions' && (
                      <div className="space-y-2">
                        <div className="font-bold text-slate-900 text-sm">Permissions &amp; Capabilities</div>
                        <p className="text-slate-600 leading-relaxed">
                          Inspects browser extension manifest declarations, host access scopes (e.g. broad wildcard domains), background service worker capabilities, and elevated API privileges.
                        </p>
                      </div>
                    )}
                    {activeEvidenceTab === 'network' && (
                      <div className="space-y-2">
                        <div className="font-bold text-slate-900 text-sm">Network Signals</div>
                        <p className="text-slate-600 leading-relaxed">
                          Evaluates TLS certificate validity, redirect chain length, cross-domain redirection journeys, IP address reputation, and DNS record posture.
                        </p>
                      </div>
                    )}
                    {activeEvidenceTab === 'other' && (
                      <div className="space-y-2">
                        <div className="font-bold text-slate-900 text-sm">Other Relevant Findings</div>
                        <p className="text-slate-600 leading-relaxed">
                          Analyzes file extensions, MIME type consistency, cryptographic hash records (SHA-256), DOM script dependencies, and external asset integrity.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* ── STAGE 03: EVALUATE ──────────────────────────────────── */}
            <div
              id="evaluate"
              className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-sm hover:shadow-md transition-shadow"
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 pb-6 border-b border-slate-100">
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-purple-50 border border-purple-100 flex items-center justify-center shrink-0">
                    <Cpu className="w-6 h-6 text-purple-600" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-bold text-purple-600 bg-purple-50 border border-purple-100 px-2 py-0.5 rounded-md">
                        STAGE 03
                      </span>
                      <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider bg-slate-100 px-2.5 py-0.5 rounded-md">
                        RISK SYNTHESIS
                      </span>
                    </div>
                    <h3 className="text-xl sm:text-2xl font-bold text-slate-900">
                      Turn Evidence Into Risk
                    </h3>
                  </div>
                </div>
              </div>

              <div className="space-y-6 pt-6">
                <p className="text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
                  CyberWatch converts detected evidence into security findings, assigns appropriate severity, applies the platform's risk evaluation rules, and calculates an overall risk score and security verdict.
                </p>

                {/* Visual Pipeline */}
                <div className="bg-slate-50 border border-slate-200/80 rounded-2xl p-6">
                  <div className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-5">
                    Platform Evaluation Pipeline
                  </div>

                  {/* Horizontal on md+, stacked on mobile */}
                  <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                    {[
                      { step: '1', title: 'Evidence', desc: 'Observed Signals' },
                      { step: '2', title: 'Finding', desc: 'Identified Issue' },
                      { step: '3', title: 'Severity', desc: 'High/Med/Low' },
                      { step: '4', title: 'Risk Contribution', desc: 'Weighted Value' },
                      { step: '5', title: 'Risk Score', desc: '0 – 100 Index' },
                      { step: '6', title: 'Verdict', desc: 'Safe / Warning / Suspicious' },
                    ].map((item, idx) => (
                      <div key={idx} className="relative bg-white border border-slate-200 rounded-xl p-3.5 flex flex-col justify-between shadow-xs">
                        <div>
                          <span className="text-[10px] font-mono font-bold text-blue-600 block mb-1">
                            0{item.step}
                          </span>
                          <span className="text-xs font-bold text-slate-900 block leading-tight">
                            {item.title}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-500 mt-2 font-medium">
                          {item.desc}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Supporting Note */}
                <div className="flex items-start gap-3 bg-blue-50/70 border border-blue-100 rounded-2xl p-4">
                  <Info className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
                  <p className="text-xs text-blue-900 leading-relaxed">
                    <strong>Supporting Note:</strong> Risk assessments are based on the evidence available to CyberWatch during the scan. The platform calculates deterministic scores using weighted severity formulas without synthetic randomness.
                  </p>
                </div>
              </div>
            </div>

            {/* ── STAGE 04: EXAMPLE ───────────────────────────────────── */}
            <div
              id="example"
              data-alias="explain"
              className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-sm hover:shadow-md transition-shadow relative"
            >
              <span id="explain" className="absolute -top-24 left-0 w-0 h-0 pointer-events-none" />
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 pb-6 border-b border-slate-100">
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 rounded-2xl bg-amber-50 border border-amber-100 flex items-center justify-center shrink-0">
                    <Sparkles className="w-6 h-6 text-amber-600" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-bold text-amber-600 bg-amber-50 border border-amber-100 px-2 py-0.5 rounded-md">
                        STAGE 04
                      </span>
                      <span className="text-[11px] font-bold text-amber-800 uppercase tracking-wider bg-amber-100/70 px-2.5 py-0.5 rounded-md">
                        ILLUSTRATIVE EXAMPLE
                      </span>
                    </div>
                    <h3 className="text-xl sm:text-2xl font-bold text-slate-900">
                      From Evidence to a Security Decision
                    </h3>
                  </div>
                </div>
              </div>

              <div className="space-y-6 pt-6">
                {/* Prominent Disclaimer */}
                <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                  <div className="text-xs text-amber-900">
                    <span className="font-bold">Disclaimer:</span> This example is illustrative and does not represent a live scan result. The example is for explaining the workflow only.
                  </div>
                </div>

                {/* Illustrative Walkthrough Card */}
                <div className="bg-slate-50 border border-slate-200/80 rounded-2xl p-6 space-y-6">
                  {/* Step 1: Target */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">TARGET</div>
                    <div className="bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-xs font-mono font-bold text-slate-800">
                      Example Website (https://example-demo-portal.net)
                    </div>
                  </div>

                  <div className="text-center text-slate-400 font-bold">↓</div>

                  {/* Step 2: Detected Evidence */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">DETECTED EVIDENCE</div>
                    <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2">
                      <div className="flex items-center gap-2 text-xs text-slate-700">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                        <span>Missing security configuration (HSTS &amp; Strict CSP absent)</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-slate-700">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                        <span>Suspicious external resource loaded from unverified host</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-slate-700">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                        <span>Broad website access with permissive cross-origin policies</span>
                      </div>
                    </div>
                  </div>

                  <div className="text-center text-slate-400 font-bold">↓</div>

                  {/* Step 3: Findings */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">FINDINGS</div>
                    <div className="bg-white border border-slate-200 rounded-xl p-3.5 flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-800">3 security findings detected</span>
                      <span className="text-[11px] font-bold text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">
                        2 Medium, 1 Low
                      </span>
                    </div>
                  </div>

                  <div className="text-center text-slate-400 font-bold">↓</div>

                  {/* Step 4: Risk Assessment Output */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">RISK ASSESSMENT</div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                      <div className="bg-white border border-slate-200 rounded-xl p-4 text-center">
                        <span className="text-[10px] font-bold text-slate-400 uppercase block">Risk Score</span>
                        <span className="text-2xl font-extrabold text-amber-600">42 / 100</span>
                        <span className="text-[10px] text-slate-400 block mt-0.5">Calculated Index</span>
                      </div>
                      <div className="bg-white border border-slate-200 rounded-xl p-4 text-center">
                        <span className="text-[10px] font-bold text-slate-400 uppercase block">Risk Level</span>
                        <span className="text-lg font-extrabold text-amber-600">MEDIUM</span>
                        <span className="text-[10px] text-slate-400 block mt-0.5">Tier 2 Warning</span>
                      </div>
                      <div className="bg-white border border-slate-200 rounded-xl p-4 text-center">
                        <span className="text-[10px] font-bold text-slate-400 uppercase block">Verdict</span>
                        <span className="text-lg font-extrabold text-amber-600">SUSPICIOUS</span>
                        <span className="text-[10px] text-slate-400 block mt-0.5">Inspection Suggested</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Container>
      </section>

      {/* ── 3. WHAT HAPPENS BEHIND THE SCENES ─────────────────────── */}
      <section className="py-20 bg-white border-b border-slate-100" id="pipeline">
        <Container>
          <div className="max-w-3xl mx-auto text-center mb-16 space-y-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 text-blue-700 text-xs font-bold uppercase tracking-wider border border-blue-100">
              <Cpu className="w-3.5 h-3.5 text-blue-600" />
              <span>Platform Pipeline</span>
            </div>
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-900 tracking-tight">
              What Happens Behind the Scenes
            </h2>
            <p className="text-sm sm:text-base text-slate-600 leading-relaxed">
              CyberWatch uses a structured analysis pipeline so that technical evidence can be transformed into a consistent security assessment.
            </p>
          </div>

          {/* 6-Stage Pipeline Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 w-full">
            {PIPELINE_STAGES.map((stage, idx) => {
              const Icon = stage.icon;
              return (
                <div
                  key={idx}
                  className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-xs hover:shadow-md hover:border-blue-300 transition-all group flex flex-col justify-between"
                >
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${stage.bg}`}>
                        <Icon className={`w-5 h-5 ${stage.color}`} />
                      </div>
                      <span className="text-xs font-mono font-bold text-slate-400 group-hover:text-blue-600 transition-colors">
                        STAGE {stage.step}
                      </span>
                    </div>

                    <div className="space-y-1.5">
                      <h3 className="text-base font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
                        {stage.title}
                      </h3>
                      <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
                        {stage.desc}
                      </p>
                    </div>
                  </div>

                  <div className="pt-4 mt-4 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
                    <span>Platform Layer</span>
                    <span className="font-semibold text-slate-600">Deterministic</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Pipeline Conceptual Disclaimer */}
          <div className="mt-10 max-w-3xl mx-auto text-center">
            <p className="text-xs text-slate-500 leading-relaxed">
              * Note: The workflow above is conceptual and represents the platform-level process. Specialized scanners implement tailored low-level verification steps suitable for their specific target types.
            </p>
          </div>
        </Container>
      </section>

      {/* ── 4. SIX CYBERWATCH SCANNERS ────────────────────────────── */}
      <section className="py-20 bg-slate-50/60 border-b border-slate-100" id="scanners">
        <Container>
          <div className="max-w-3xl mx-auto text-center mb-16 space-y-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 text-blue-700 text-xs font-bold uppercase tracking-wider border border-blue-100">
              <Layers className="w-3.5 h-3.5 text-blue-600" />
              <span>Specialized Capabilities</span>
            </div>
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-900 tracking-tight">
              One Platform, Multiple Security Scanners
            </h2>
            <p className="text-sm sm:text-base text-slate-600 leading-relaxed">
              CyberWatch provides specialized scanners for different types of security targets.
            </p>
          </div>

          {/* 6 Scanner Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 w-full">
            {SCANNERS_LIST.map((scanner) => {
              const Icon = scanner.icon;
              return (
                <div
                  key={scanner.id}
                  className="flex flex-col h-full bg-white border border-slate-200/90 rounded-2xl p-6 shadow-xs hover:shadow-md hover:border-blue-300 transition-all group"
                >
                  <div className="flex-1 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className={`w-12 h-12 rounded-xl flex items-center justify-center border ${scanner.iconBg} transition-transform group-hover:scale-105`}>
                        <Icon className={`w-6 h-6 ${scanner.iconColor}`} />
                      </div>
                      <span className="text-[11px] font-semibold text-slate-600 bg-slate-50 border border-slate-200/70 px-2.5 py-1 rounded-full">
                        {scanner.badge}
                      </span>
                    </div>

                    <div className="space-y-2">
                      <h3 className="text-base sm:text-lg font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
                        {scanner.name}
                      </h3>
                      <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
                        {scanner.description}
                      </p>
                    </div>
                  </div>

                  <div className="pt-5 mt-5 border-t border-slate-100 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-500">
                      Standardized Evaluation
                    </span>
                    <Link
                      to={scanner.link}
                      className="inline-flex items-center gap-1 text-xs font-bold text-blue-600 hover:text-blue-700 transition-colors"
                    >
                      <span>Launch Scanner</span>
                      <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        </Container>
      </section>

      {/* ── 5. RESULT VISUALIZATION ───────────────────────────────── */}
      <section className="py-20 bg-white border-b border-slate-100" id="result">
        <Container>
          <div className="max-w-3xl mx-auto text-center mb-16 space-y-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 text-blue-700 text-xs font-bold uppercase tracking-wider border border-blue-100">
              <Eye className="w-3.5 h-3.5 text-blue-600" />
              <span>Assessment Interface</span>
            </div>
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-900 tracking-tight">
              Understand the Result
            </h2>
            <p className="text-sm sm:text-base text-slate-600 leading-relaxed">
              Review findings in an accessible, actionable format designed to clearly communicate technical posture.
            </p>
          </div>

          {/* Polished Illustrative Result Interface */}
          <div className="max-w-3xl mx-auto bg-slate-50 border border-slate-200/90 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-lg shadow-slate-100/80">
            {/* Header / Label */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-6 border-b border-slate-200/70">
              <div>
                <span className="text-[10px] font-bold text-amber-700 bg-amber-100/80 px-2.5 py-0.5 rounded-full border border-amber-200">
                  ILLUSTRATIVE RESULT INTERFACE
                </span>
                <h3 className="text-lg sm:text-xl font-bold text-slate-900 mt-1.5">
                  SECURITY ASSESSMENT
                </h3>
              </div>
              <div className="text-xs font-semibold text-slate-500">
                Mock Report ID: <span className="font-mono text-slate-700">CW-SAMPLE-042</span>
              </div>
            </div>

            {/* Score & Verdict Row */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 py-6 border-b border-slate-200/70">
              <div className="bg-white border border-slate-200 rounded-2xl p-4 text-center">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Risk Score</span>
                <div className="text-3xl font-extrabold text-amber-600 my-1">42 / 100</div>
                <span className="text-[11px] font-medium text-slate-500">Moderate Cumulative Risk</span>
              </div>

              <div className="bg-white border border-slate-200 rounded-2xl p-4 text-center">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Risk Level</span>
                <div className="text-2xl font-extrabold text-amber-600 my-1">MEDIUM</div>
                <span className="text-[11px] font-medium text-slate-500">Requires Attention</span>
              </div>

              <div className="bg-white border border-slate-200 rounded-2xl p-4 text-center">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Verdict</span>
                <div className="text-2xl font-extrabold text-amber-600 my-1">SUSPICIOUS</div>
                <span className="text-[11px] font-medium text-slate-500">Review Recommended</span>
              </div>
            </div>

            {/* Why This Score? Breakdown */}
            <div className="py-6 border-b border-slate-200/70 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                  <HelpCircle className="w-4 h-4 text-blue-600" />
                  WHY THIS SCORE?
                </h4>
                <span className="text-xs text-slate-500">3 Contributing Signals</span>
              </div>

              <div className="space-y-2">
                <div className="bg-white border border-slate-200 rounded-xl p-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="w-2 h-2 rounded-full bg-amber-500" />
                    <span className="text-xs font-semibold text-slate-800">Finding 01 — Missing Security Headers</span>
                  </div>
                  <span className="text-[11px] font-bold text-amber-700 bg-amber-50 px-2.5 py-0.5 rounded border border-amber-100">
                    Medium
                  </span>
                </div>

                <div className="bg-white border border-slate-200 rounded-xl p-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="w-2 h-2 rounded-full bg-amber-500" />
                    <span className="text-xs font-semibold text-slate-800">Finding 02 — Unverified Third-Party Script Reference</span>
                  </div>
                  <span className="text-[11px] font-bold text-amber-700 bg-amber-50 px-2.5 py-0.5 rounded border border-amber-100">
                    Medium
                  </span>
                </div>

                <div className="bg-white border border-slate-200 rounded-xl p-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="w-2 h-2 rounded-full bg-blue-500" />
                    <span className="text-xs font-semibold text-slate-800">Finding 03 — Broad Access Scope Configuration</span>
                  </div>
                  <span className="text-[11px] font-bold text-blue-700 bg-blue-50 px-2.5 py-0.5 rounded border border-blue-100">
                    Low
                  </span>
                </div>
              </div>
            </div>

            {/* Recommendation Box */}
            <div className="pt-6">
              <div className="bg-blue-50/80 border border-blue-100 rounded-2xl p-4 flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="text-xs font-bold text-blue-900 uppercase tracking-wider">
                    RECOMMENDATION
                  </div>
                  <p className="text-xs text-blue-800 leading-relaxed">
                    Review the detected security issues. Address missing HTTP security headers and inspect external script dependencies before approving target usage.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </Container>
      </section>

      {/* ── 6. PRINCIPLES ─────────────────────────────────────────── */}
      <section className="py-20 bg-slate-50/60 border-b border-slate-100" id="principles">
        <Container>
          <div className="max-w-3xl mx-auto text-center mb-16 space-y-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 text-blue-700 text-xs font-bold uppercase tracking-wider border border-blue-100">
              <Shield className="w-3.5 h-3.5 text-blue-600" />
              <span>Core Methodology</span>
            </div>
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-900 tracking-tight">
              Built Around Evidence, Not Assumptions
            </h2>
            <p className="text-sm sm:text-base text-slate-600 leading-relaxed">
              CyberWatch adheres to foundational security principles designed to ensure transparency and reliability across all scans.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 w-full">
            {PRINCIPLES.map((principle, idx) => {
              const Icon = principle.icon;
              return (
                <div
                  key={idx}
                  className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-xs hover:shadow-md hover:border-blue-300 transition-all flex flex-col justify-between"
                >
                  <div className="space-y-4">
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center border ${principle.bg}`}>
                      <Icon className={`w-6 h-6 ${principle.color}`} />
                    </div>
                    <div className="space-y-2">
                      <h3 className="text-base sm:text-lg font-bold text-slate-900">
                        {principle.title}
                      </h3>
                      <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
                        {principle.description}
                      </p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </Container>
      </section>

      {/* ── 7. FINAL CTA ──────────────────────────────────────────── */}
      <section className="py-20 bg-white">
        <Container>
          <div className="max-w-4xl mx-auto bg-gradient-to-br from-slate-900 via-slate-800 to-blue-950 text-white rounded-3xl p-8 sm:p-12 text-center shadow-xl relative overflow-hidden">
            {/* Background glowing rings */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-blue-500/10 rounded-full blur-3xl -z-0 pointer-events-none" />

            <div className="relative z-10 space-y-6 max-w-2xl mx-auto">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/20 border border-blue-400/30 text-blue-300 text-xs font-bold uppercase tracking-wider">
                <Shield className="w-3.5 h-3.5 text-blue-400" />
                <span>Start Analyzing</span>
              </div>

              <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight text-white leading-tight">
                Ready to Analyze a Target?
              </h2>

              <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
                Choose the appropriate CyberWatch scanner and start your security analysis.
              </p>

              <div className="flex flex-col sm:flex-row items-center justify-center gap-3.5 pt-2">
                <Link
                  to="/services/url-phishing"
                  id="btn-howitworks-start-scan"
                  className="w-full sm:w-auto inline-flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-bold text-sm px-6 py-3.5 rounded-xl shadow-lg shadow-blue-600/30 transition-all duration-200"
                >
                  <Globe className="w-4 h-4" />
                  <span>Start a Scan</span>
                </Link>

                <Link
                  to="/services"
                  id="btn-howitworks-explore-scanners"
                  className="w-full sm:w-auto inline-flex items-center justify-center gap-2 bg-white/10 hover:bg-white/20 active:bg-white/25 border border-white/20 text-white font-bold text-sm px-6 py-3.5 rounded-xl backdrop-blur-sm transition-all duration-200"
                >
                  <span>Explore Scanners</span>
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          </div>
        </Container>
      </section>
    </main>
  );
}
