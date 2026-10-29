import { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import {
  Search,
  Menu,
  X,
  Shield,
  ChevronDown,
  Activity,
  Globe,
  ShieldAlert,
  FileSearch,
  AlertTriangle,
  Fingerprint,
  CheckCircle,
  Lightbulb,
  MessageSquare,
  BarChart3,
  Clock,
  Download,
  Key,
  LockKeyhole,
  EyeOff,
  HelpCircle,
  Book,
  FileQuestion,
  Mail,
  LogOut,
  LayoutDashboard,
  Bell,
  ArrowRight,
  Puzzle,
  Terminal,
  Server,
  Network,
  Rss,
  Database,
  GitCompare,
} from 'lucide-react';

import { cn } from '../../lib/utils';
import { useAuth } from '../../context/AuthContext';
import { NotificationDropdown } from './NotificationDropdown';

const DROPDOWNS = {
  services: [
    {
      title: 'Web Security',
      items: [
        {
          name: 'URL & Phishing Mega Scanner',
          desc: 'Unified analysis of URLs, domains, redirects, page structure, and phishing threat indicators.',
          icon: Globe,
          iconColor: 'text-blue-600',
          iconBg: 'bg-blue-50 border-blue-100/70',
          href: '/services/url-phishing',
        },
        {
          name: 'Website Security Scanner',
          desc: 'Analyze a website for security posture, headers, cookies, scripts, and TLS configurations.',
          icon: ShieldAlert,
          iconColor: 'text-indigo-600',
          iconBg: 'bg-indigo-50 border-indigo-100/70',
          href: '/services/website-scanner',
        },
      ],
    },
    {
      title: 'Application Security',
      items: [
        {
          name: 'API Security Scanner',
          desc: 'Audit API endpoints for CORS, exposed data, headers, and access controls.',
          icon: Terminal,
          iconColor: 'text-cyan-600',
          iconBg: 'bg-cyan-50 border-cyan-100/70',
          href: '/services/api-scanner',
        },
      ],
    },
    {
      title: 'File Security',
      items: [
        {
          name: 'File Security Scanner',
          desc: 'Analyze downloadable files and metadata for executable and payload risks.',
          icon: FileSearch,
          iconColor: 'text-blue-600',
          iconBg: 'bg-blue-50 border-blue-100/70',
          href: '/services/file',
        },
      ],
    },
    {
      title: 'Browser Security',
      items: [
        {
          name: 'Browser Extension Scanner',
          desc: 'Audit browser extensions and declared permissions for excessive privilege risks.',
          icon: Puzzle,
          iconColor: 'text-sky-600',
          iconBg: 'bg-sky-50 border-sky-100/70',
          href: '/services/extension',
        },
      ],
    },
  ],
  howItWorks: [
    { name: 'Submit', desc: 'Enter a URL or security target.', icon: Search, href: '/how-it-works#submit' },
    { name: 'Analyze', desc: 'CyberWatch runs multiple security checks.', icon: Activity, href: '/how-it-works#analyze' },
    { name: 'Evaluate', desc: 'Evidence is combined into a unified risk assessment.', icon: CheckCircle, href: '/how-it-works#evaluate' },
    { name: 'Explain', desc: 'Security findings are presented in understandable language.', icon: MessageSquare, href: '/how-it-works#explain' },
  ],
  threatIntel: [
    { name: 'Threat Intelligence', desc: 'Centralized multi-source IOC investigation.', icon: Globe, href: '/threat-intelligence' },
    { name: 'Threat Indicators', desc: 'Analyzed IOC history and threat records.', icon: Fingerprint, href: '/threat-indicators' },
    { name: 'Domain Reputation', desc: 'Domain analysis & DNS infrastructure.', icon: Activity, href: '/domain-reputation' },
    { name: 'IP Reputation', desc: 'IPv4/IPv6 abuse scores and hosting telemetry.', icon: Server, href: '/ip-reputation' },
    { name: 'Threat Correlation', desc: 'Evidence-linked indicator relationships.', icon: Network, href: '/threat-correlation' },
    { name: 'Threat Feeds', desc: 'Real-time telemetry and malware streams.', icon: Rss, href: '/threat-feeds' },
    { name: 'Intelligence Sources', desc: 'Provider registry and connection health.', icon: Database, href: '/intelligence-sources' },
    { name: 'Security Advisories', desc: 'CVE vulnerability intelligence & alerts.', icon: AlertTriangle, href: '/advisories' },
  ],
  reports: [
    { name: 'Reports Overview', desc: 'Centralized reports and metrics dashboard.', icon: LayoutDashboard, href: '/reports' },
    { name: 'Security Findings', desc: 'Aggregated findings and vulnerability repository.', icon: BarChart3, href: '/reports/findings' },
    { name: 'Scan History', desc: 'Audit log of previously executed scans.', icon: Clock, href: '/reports/history' },
    { name: 'Compare Scans', desc: 'Side-by-side delta analysis between scans.', icon: GitCompare, href: '/reports/compare' },
    { name: 'Export Reports', desc: 'Download PDF, JSON, or CSV audit reports.', icon: Download, href: '/reports/export' },
  ],
  cyberSafety: {
    protect: [
      { name: 'Safe Browsing', desc: 'Identify risky websites and links.', icon: Globe, iconColor: 'text-blue-600', iconBg: 'bg-blue-50 border-blue-100', href: '/cyber-safety/safe-browsing' },
      { name: 'Phishing Awareness', desc: 'Learn to spot deceptive tactics.', icon: Lightbulb, iconColor: 'text-amber-600', iconBg: 'bg-amber-50 border-amber-100', href: '/cyber-safety/phishing-awareness' },
      { name: 'Password Safety', desc: 'Guidelines for secure credentials.', icon: Key, iconColor: 'text-indigo-600', iconBg: 'bg-indigo-50 border-indigo-100', href: '/cyber-safety/password-safety' },
      { name: 'Browser Security', desc: 'Hardening your web browser.', icon: LockKeyhole, iconColor: 'text-sky-600', iconBg: 'bg-sky-50 border-sky-100', href: '/cyber-safety/browser-security' },
      { name: 'Online Privacy', desc: 'Protecting your digital footprint.', icon: EyeOff, iconColor: 'text-purple-600', iconBg: 'bg-purple-50 border-purple-100', href: '/cyber-safety/online-privacy' },
    ],
    tools: [
      { name: 'Security Checkup', desc: 'Step-by-step guided assessment.', icon: CheckCircle, iconColor: 'text-blue-600', iconBg: 'bg-blue-50 border-blue-100', href: '/cyber-safety/security-checkup' },
      { name: 'Security Guides', desc: 'Comprehensive defense library.', icon: Book, iconColor: 'text-slate-600', iconBg: 'bg-slate-50 border-slate-100', href: '/cyber-safety/guides' },
      { name: 'Safety Alerts', desc: 'Live alerts & security advisories.', icon: Bell, iconColor: 'text-rose-600', iconBg: 'bg-rose-50 border-rose-100', href: '/cyber-safety/alerts' },
    ],
  },
  help: [
    { name: 'Help Center', desc: 'Documentation and guides.', icon: HelpCircle, href: '/help' },
    { name: 'Scanner Guide', desc: 'How to use our tools effectively.', icon: Book, href: '/help/guide' },
    { name: 'FAQ', desc: 'Frequently asked questions.', icon: FileQuestion, href: '/help/faq' },
    { name: 'Contact Support', desc: 'Get in touch with our team.', icon: Mail, href: '/help/contact' },
  ],
};

export function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const { isAuthenticated, user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const navRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 10);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Close open dropdowns on route change
  useEffect(() => {
    setSearchOpen(false);
    setProfileMenuOpen(false);
    setMobileMenuOpen(false);
    setActiveDropdown(null);
  }, [location.pathname]);

  const DropdownItem = ({ item }: { item: any }) => (
    <Link
      to={item.href}
      className="group/item flex items-start gap-3 p-2.5 rounded-xl hover:bg-slate-50 border border-transparent hover:border-slate-100 transition-colors w-full min-w-0"
      onClick={() => setActiveDropdown(null)}
    >
      <div
        className={cn(
          'w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 border',
          item.iconBg || 'bg-blue-50 text-blue-600 border-blue-100/60'
        )}
      >
        <item.icon className={cn('w-4 h-4', item.iconColor || 'text-blue-600')} />
      </div>
      <div className="min-w-0 flex-1 whitespace-normal">
        <div className="text-[13px] font-bold text-slate-800 group-hover/item:text-blue-600 transition-colors leading-snug break-words">
          {item.name}
        </div>
        <div className="text-[11px] text-slate-500 mt-0.5 leading-relaxed break-words [overflow-wrap:anywhere]">
          {item.desc}
        </div>
      </div>
    </Link>
  );

  async function handleLogout() {
    await logout();
    navigate('/login', { replace: true });
  }

  function handleScanUrlClick() {
    if (location.pathname === '/dashboard') {
      const input = document.getElementById('dashboard-url-input');
      if (input) {
        input.focus();
        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    } else {
      navigate('/dashboard');
    }
  }

  const displayName = user?.name || user?.email?.split('@')[0] || 'User';
  const initial = (user?.name?.[0] || user?.email?.[0] || 'U').toUpperCase();

  return (
    <header
      className={cn(
        'fixed top-0 left-0 right-0 w-full z-50 transition-all duration-200 border-b',
        isScrolled
          ? 'bg-white/95 backdrop-blur-md border-slate-200/90 shadow-sm'
          : 'bg-white border-slate-100'
      )}
    >
      <div className="w-full px-4 sm:px-6 lg:px-8 xl:px-10 h-[72px] flex items-center" ref={navRef}>
        {/* ── DESKTOP 3-ZONE CSS GRID (xl and up: 1280px+) ──────────────── */}
        <div className="hidden xl:grid grid-cols-[1fr_auto_1fr] items-center w-full h-full">
          {/* ── ZONE 1: LEFT CORNER — CYBERWATCH BRAND ────────────────── */}
          <div className="justify-self-start flex items-center shrink-0">
            <Link to={isAuthenticated ? '/dashboard' : '/'} className="flex items-center gap-2.5 group shrink-0">
              <div className="bg-blue-600 p-2 rounded-xl group-hover:bg-blue-700 transition-colors shadow-sm shadow-blue-500/20">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div className="flex flex-col">
                <span className="font-bold text-lg tracking-tight text-slate-900 leading-tight">CYBERWATCH</span>
                <span className="text-[10px] font-medium text-slate-500 tracking-normal whitespace-nowrap">
                  Unified Web &amp; Browser Threat Detection
                </span>
              </div>
            </Link>
          </div>

          {/* ── ZONE 2: CENTER — MATHEMATICALLY CENTERED NAVIGATION ───── */}
          <nav className="justify-self-center flex items-center space-x-0.5 2xl:space-x-1 whitespace-nowrap">
            <Link
              to="/"
              className={cn(
                'px-2.5 2xl:px-3 py-1.5 text-[13px] 2xl:text-sm font-semibold rounded-lg transition-colors',
                location.pathname === '/'
                  ? 'text-blue-600 bg-blue-50'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              )}
            >
              Home
            </Link>

            {/* Security Services */}
            <div className="relative group">
              <button
                type="button"
                className={cn(
                  'flex items-center gap-1 px-2.5 2xl:px-3 py-1.5 text-[13px] 2xl:text-sm font-semibold rounded-lg transition-colors',
                  activeDropdown === 'services'
                    ? 'text-blue-600 bg-blue-50'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                )}
                onClick={() => setActiveDropdown(activeDropdown === 'services' ? null : 'services')}
                onMouseEnter={() => setActiveDropdown('services')}
              >
                Security Services <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>
              {/* Security Services Mega-Menu */}
              {activeDropdown === 'services' && (
                <div
                  className="absolute top-full left-1/2 -translate-x-1/2 w-[760px] xl:w-[820px] 2xl:w-[860px] bg-white border border-slate-200 shadow-xl rounded-2xl p-6 z-50 animate-in fade-in slide-in-from-top-1 duration-150 whitespace-normal"
                  onMouseEnter={() => setActiveDropdown('services')}
                  onMouseLeave={() => setActiveDropdown(null)}
                >
                  <div className="grid grid-cols-2 gap-x-8 gap-y-5">
                    {DROPDOWNS.services.map((group, i) => (
                      <div key={i} className="min-w-0">
                        <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-100">
                          <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                            {group.title}
                          </h3>
                          <span className="text-[10px] font-semibold text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full">
                            {group.items.length} {group.items.length === 1 ? 'Scanner' : 'Scanners'}
                          </span>
                        </div>
                        <div className="space-y-1">
                          {group.items.map((item, j) => (
                            <DropdownItem key={j} item={item} />
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="mt-5 pt-3.5 border-t border-slate-100 flex items-center justify-between text-xs">
                    <span className="text-slate-500 font-medium">
                      All 6 scanners powered by CyberWatch unified threat detection engine.
                    </span>
                    <Link
                      to="/services"
                      onClick={() => setActiveDropdown(null)}
                      className="font-bold text-blue-600 hover:text-blue-700 inline-flex items-center gap-1 transition-colors"
                    >
                      <span>Explore Security Directory</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Link>
                  </div>
                </div>
              )}
            </div>

            {/* How It Works */}
            <div className="relative group">
              <button
                type="button"
                className={cn(
                  'flex items-center gap-1 px-2.5 2xl:px-3 py-1.5 text-[13px] 2xl:text-sm font-semibold rounded-lg transition-colors',
                  activeDropdown === 'howItWorks'
                    ? 'text-blue-600 bg-blue-50'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                )}
                onClick={() => setActiveDropdown(activeDropdown === 'howItWorks' ? null : 'howItWorks')}
                onMouseEnter={() => setActiveDropdown('howItWorks')}
              >
                How It Works <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>
              {activeDropdown === 'howItWorks' && (
                <div
                  className="absolute top-full left-1/2 -translate-x-1/2 w-[290px] bg-white border border-slate-200 shadow-xl rounded-2xl p-4 space-y-2 z-50 animate-in fade-in slide-in-from-top-1 duration-150 whitespace-normal"
                  onMouseEnter={() => setActiveDropdown('howItWorks')}
                  onMouseLeave={() => setActiveDropdown(null)}
                >
                  {DROPDOWNS.howItWorks.map((item, i) => (
                    <DropdownItem key={i} item={item} />
                  ))}
                </div>
              )}
            </div>

            {/* Threat Intelligence */}
            <div className="relative group">
              <button
                type="button"
                className={cn(
                  'flex items-center gap-1 px-2.5 2xl:px-3 py-1.5 text-[13px] 2xl:text-sm font-semibold rounded-lg transition-colors',
                  activeDropdown === 'threatIntel'
                    ? 'text-blue-600 bg-blue-50'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                )}
                onClick={() => setActiveDropdown(activeDropdown === 'threatIntel' ? null : 'threatIntel')}
                onMouseEnter={() => setActiveDropdown('threatIntel')}
              >
                Threat Intelligence <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>
              {activeDropdown === 'threatIntel' && (
                <div
                  className="absolute top-full left-1/2 -translate-x-1/2 w-[290px] bg-white border border-slate-200 shadow-xl rounded-2xl p-4 space-y-2 z-50 animate-in fade-in slide-in-from-top-1 duration-150 whitespace-normal"
                  onMouseEnter={() => setActiveDropdown('threatIntel')}
                  onMouseLeave={() => setActiveDropdown(null)}
                >
                  {DROPDOWNS.threatIntel.map((item, i) => (
                    <DropdownItem key={i} item={item} />
                  ))}
                </div>
              )}
            </div>

            {/* Reports */}
            <div className="relative group">
              <button
                type="button"
                className={cn(
                  'flex items-center gap-1 px-2.5 2xl:px-3 py-1.5 text-[13px] 2xl:text-sm font-semibold rounded-lg transition-colors',
                  activeDropdown === 'reports'
                    ? 'text-blue-600 bg-blue-50'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                )}
                onClick={() => setActiveDropdown(activeDropdown === 'reports' ? null : 'reports')}
                onMouseEnter={() => setActiveDropdown('reports')}
              >
                Reports <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>
              {activeDropdown === 'reports' && (
                <div
                  className="absolute top-full left-1/2 -translate-x-1/2 w-[290px] bg-white border border-slate-200 shadow-xl rounded-2xl p-4 space-y-2 z-50 animate-in fade-in slide-in-from-top-1 duration-150 whitespace-normal"
                  onMouseEnter={() => setActiveDropdown('reports')}
                  onMouseLeave={() => setActiveDropdown(null)}
                >
                  {DROPDOWNS.reports.map((item, i) => (
                    <DropdownItem key={i} item={item} />
                  ))}
                </div>
              )}
            </div>

            {/* Cyber Safety */}
            <div className="relative group">
              <button
                type="button"
                className={cn(
                  'flex items-center gap-1 px-2.5 2xl:px-3 py-1.5 text-[13px] 2xl:text-sm font-semibold rounded-lg transition-colors',
                  location.pathname.startsWith('/cyber-safety') || activeDropdown === 'cyberSafety'
                    ? 'text-blue-600 bg-blue-50'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                )}
                onClick={() => setActiveDropdown(activeDropdown === 'cyberSafety' ? null : 'cyberSafety')}
                onMouseEnter={() => setActiveDropdown('cyberSafety')}
              >
                Cyber Safety <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>
              {activeDropdown === 'cyberSafety' && (
                <div
                  className="absolute top-full left-1/2 -translate-x-1/2 w-[540px] bg-white border border-slate-200 shadow-xl rounded-2xl p-5 z-50 animate-in fade-in slide-in-from-top-1 duration-150 whitespace-normal"
                  onMouseEnter={() => setActiveDropdown('cyberSafety')}
                  onMouseLeave={() => setActiveDropdown(null)}
                >
                  {/* Security Center Hub */}
                  <Link
                    to="/cyber-safety"
                    className="group flex items-center justify-between p-3 rounded-xl bg-blue-50/60 border border-blue-100 hover:bg-blue-50 transition-colors mb-4"
                    onClick={() => setActiveDropdown(null)}
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-xs">
                        <Shield className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="text-xs font-bold text-blue-900 group-hover:text-blue-700">
                          Cyber Safety Center
                        </div>
                        <div className="text-[11px] text-blue-600/80">
                          Your security guidance &amp; posture dashboard
                        </div>
                      </div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-blue-600 group-hover:translate-x-0.5 transition-transform" />
                  </Link>

                  <div className="grid grid-cols-2 gap-x-6 gap-y-4">
                    {/* PROTECT Column */}
                    <div>
                      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 pb-1 mb-2 border-b border-slate-100">
                        Protect
                      </div>
                      <div className="space-y-1">
                        {DROPDOWNS.cyberSafety.protect.map((item, i) => (
                          <DropdownItem key={i} item={item} />
                        ))}
                      </div>
                    </div>

                    {/* TOOLS Column */}
                    <div>
                      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 pb-1 mb-2 border-b border-slate-100">
                        Tools &amp; Guidance
                      </div>
                      <div className="space-y-1">
                        {DROPDOWNS.cyberSafety.tools.map((item, i) => (
                          <DropdownItem key={i} item={item} />
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Help & Support */}
            <div className="relative group">
              <button
                type="button"
                className={cn(
                  'flex items-center gap-1 px-2.5 2xl:px-3 py-1.5 text-[13px] 2xl:text-sm font-semibold rounded-lg transition-colors',
                  activeDropdown === 'help'
                    ? 'text-blue-600 bg-blue-50'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                )}
                onClick={() => setActiveDropdown(activeDropdown === 'help' ? null : 'help')}
                onMouseEnter={() => setActiveDropdown('help')}
              >
                Help &amp; Support <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>
              {activeDropdown === 'help' && (
                <div
                  className="absolute top-full right-0 w-[280px] bg-white border border-slate-200 shadow-xl rounded-2xl p-4 space-y-2 z-50 animate-in fade-in slide-in-from-top-1 duration-150 whitespace-normal"
                  onMouseEnter={() => setActiveDropdown('help')}
                  onMouseLeave={() => setActiveDropdown(null)}
                >
                  {DROPDOWNS.help.map((item, i) => (
                    <DropdownItem key={i} item={item} />
                  ))}
                </div>
              )}
            </div>
          </nav>

          {/* ── ZONE 3: RIGHT CORNER — USER CONTROLS ──────────────────── */}
          <div className="justify-self-end flex items-center space-x-2.5 2xl:space-x-3 shrink-0">
            {/* 1. Search */}
            <div className="relative">
              <button
                id="navbar-search-btn"
                aria-label="Search CyberWatch"
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-600 hover:text-slate-900 transition-colors rounded-xl hover:bg-slate-100"
                onClick={() => {
                  setSearchOpen(!searchOpen);
                  setProfileMenuOpen(false);
                }}
              >
                <Search className="w-4 h-4 text-slate-500" />
                <span>Search</span>
              </button>
              {searchOpen && (
                <div className="absolute top-full right-0 mt-2 w-72 bg-white border border-slate-200 shadow-xl rounded-2xl p-3 z-50 animate-in fade-in duration-150">
                  <div className="relative">
                    <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search URLs, scanners, reports..."
                      className="w-full pl-9 pr-4 py-2 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
                      autoFocus
                    />
                  </div>
                  <p className="text-[11px] text-slate-400 mt-2 px-1">Press Enter to search platform</p>
                </div>
              )}
            </div>

            {/* 2. Real Security Notifications */}
            {isAuthenticated && <NotificationDropdown />}

            {/* 3. User Profile / Guest Links */}
            {isAuthenticated ? (
              <>
                <div className="relative">
                  <button
                    id="navbar-user-menu-btn"
                    onClick={() => {
                      setProfileMenuOpen(!profileMenuOpen);
                      setSearchOpen(false);
                    }}
                    className="flex items-center gap-2 bg-slate-50 hover:bg-slate-100 rounded-full pl-1 pr-2.5 py-1 transition-colors border border-slate-200/80"
                  >
                    <div className="w-7 h-7 rounded-full bg-blue-600 text-white font-bold text-xs flex items-center justify-center shadow-xs">
                      {initial}
                    </div>
                    <span className="text-xs font-semibold text-slate-800 max-w-[100px] 2xl:max-w-[120px] truncate">
                      {displayName}
                    </span>
                    <ChevronDown
                      className={cn(
                        'w-3 h-3 text-slate-400 transition-transform duration-150',
                        profileMenuOpen && 'rotate-180'
                      )}
                    />
                  </button>

                  {profileMenuOpen && (
                    <div className="absolute top-full right-0 mt-2 w-64 bg-white border border-slate-200 shadow-xl rounded-2xl p-2 z-50 animate-in fade-in duration-150">
                      <div className="p-3 bg-slate-50 rounded-xl mb-2">
                        <div className="flex items-center gap-2.5">
                          <div className="w-9 h-9 rounded-full bg-blue-600 text-white font-bold text-sm flex items-center justify-center">
                            {initial}
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-bold text-slate-900 truncate">
                              {user?.name || displayName}
                            </p>
                            <p className="text-[11px] text-slate-500 truncate">{user?.email}</p>
                          </div>
                        </div>
                        <div className="mt-2 flex items-center justify-between text-[11px] pt-2 border-t border-slate-200/60">
                          <span className="text-slate-500 font-medium">Status:</span>
                          <span className="font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded text-[10px]">
                            AUTHENTICATED
                          </span>
                        </div>
                      </div>

                      <div className="space-y-1">
                        <Link
                          to="/dashboard"
                          onClick={() => setProfileMenuOpen(false)}
                          className="flex items-center gap-2 px-3 py-2 text-xs font-semibold text-slate-700 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                        >
                          <LayoutDashboard className="w-3.5 h-3.5 text-blue-600" />
                          User Dashboard
                        </Link>
                        <Link
                          to="/notifications"
                          onClick={() => setProfileMenuOpen(false)}
                          className="flex items-center gap-2 px-3 py-2 text-xs font-semibold text-slate-700 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                        >
                          <Bell className="w-3.5 h-3.5 text-indigo-600" />
                          Notifications
                        </Link>
                        <Link
                          to="/reports/history"
                          onClick={() => setProfileMenuOpen(false)}
                          className="flex items-center gap-2 px-3 py-2 text-xs font-semibold text-slate-700 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                        >
                          <Clock className="w-3.5 h-3.5 text-slate-500" />
                          Scan History
                        </Link>
                      </div>

                      <div className="pt-2 mt-2 border-t border-slate-100">
                        <button
                          id="navbar-profile-signout-btn"
                          onClick={async () => {
                            setProfileMenuOpen(false);
                            await handleLogout();
                          }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-xs font-semibold text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                        >
                          <LogOut className="w-3.5 h-3.5" />
                          Sign out
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* 4. Primary "Scan URL" Action Button */}
                <button
                  id="navbar-scan-url-btn"
                  onClick={handleScanUrlClick}
                  className="inline-flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white text-xs font-bold px-3.5 py-2 rounded-xl shadow-xs shadow-blue-600/25 transition-all duration-200 shrink-0"
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Scan URL</span>
                </button>
              </>
            ) : (
              <>
                <Link
                  to="/login"
                  id="navbar-login-link"
                  className="text-xs font-bold text-slate-600 hover:text-slate-900 transition-colors px-3 py-2 rounded-lg hover:bg-slate-100"
                >
                  Login
                </Link>
                <Link
                  to="/register"
                  id="navbar-register-link"
                  className="inline-flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold px-4 py-2.5 rounded-xl shadow-sm shadow-blue-600/20 transition-all duration-200"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>Get Started</span>
                </Link>
              </>
            )}
          </div>
        </div>

        {/* ── TABLET / MOBILE LAYOUT (< xl / < 1280px) ─────────────────── */}
        <div className="flex xl:hidden items-center justify-between w-full h-full">
          {/* Left: Brand */}
          <div className="flex items-center shrink-0">
            <Link to={isAuthenticated ? '/dashboard' : '/'} className="flex items-center gap-2.5 group shrink-0">
              <div className="bg-blue-600 p-2 rounded-xl group-hover:bg-blue-700 transition-colors shadow-sm shadow-blue-500/20">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div className="flex flex-col">
                <span className="font-bold text-base sm:text-lg tracking-tight text-slate-900 leading-tight">CYBERWATCH</span>
                <span className="hidden sm:inline text-[10px] font-medium text-slate-500 tracking-normal whitespace-nowrap">
                  Unified Web &amp; Browser Threat Detection
                </span>
              </div>
            </Link>
          </div>

          {/* Right: Controls & Mobile Menu Toggle */}
          <div className="flex items-center space-x-1.5 sm:space-x-2.5">
            {/* Real Security Notifications */}
            {isAuthenticated && <NotificationDropdown />}

            {/* Quick Scan Action if authenticated */}
            {isAuthenticated && (
              <button
                onClick={handleScanUrlClick}
                className="inline-flex items-center gap-1 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold px-2.5 sm:px-3 py-1.5 rounded-lg shadow-xs"
              >
                <Globe className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Scan URL</span>
              </button>
            )}

            {/* Mobile Hamburger Button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="text-slate-700 p-2 rounded-xl hover:bg-slate-100 transition-colors border border-slate-200/60"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="xl:hidden bg-white border-t border-slate-100 shadow-xl absolute w-full max-h-[calc(100vh-4rem)] overflow-y-auto pb-6">
          <div className="px-4 py-4 space-y-2">
            <Link
              to="/"
              className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-900 hover:bg-slate-50"
              onClick={() => setMobileMenuOpen(false)}
            >
              Home
            </Link>
            <Link
              to="/services"
              className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-900 hover:bg-slate-50"
              onClick={() => setMobileMenuOpen(false)}
            >
              Security Services
            </Link>
            <Link
              to="/how-it-works"
              className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-900 hover:bg-slate-50"
              onClick={() => setMobileMenuOpen(false)}
            >
              How It Works
            </Link>
            <Link
              to="/threat-intelligence"
              className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-900 hover:bg-slate-50"
              onClick={() => setMobileMenuOpen(false)}
            >
              Threat Intelligence
            </Link>
            <Link
              to="/reports"
              className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-900 hover:bg-slate-50"
              onClick={() => setMobileMenuOpen(false)}
            >
              Reports
            </Link>
            <Link
              to="/cyber-safety"
              className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-900 hover:bg-slate-50"
              onClick={() => setMobileMenuOpen(false)}
            >
              Cyber Safety
            </Link>
            <Link
              to="/help"
              className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-900 hover:bg-slate-50"
              onClick={() => setMobileMenuOpen(false)}
            >
              Help &amp; Support
            </Link>

            <div className="border-t border-slate-100 pt-3 mt-3">
              {isAuthenticated ? (
                <>
                  <div className="flex items-center gap-3 px-3 py-2.5 bg-slate-50 rounded-xl mb-3">
                    <div className="w-8 h-8 rounded-full bg-blue-600 text-white font-bold text-xs flex items-center justify-center">
                      {initial}
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-bold text-slate-900 truncate">{displayName}</p>
                      <p className="text-[11px] text-slate-500 truncate">{user?.email}</p>
                    </div>
                  </div>
                  <Link
                    to="/dashboard"
                    className="block px-3 py-2 rounded-lg text-sm font-semibold text-blue-600 hover:bg-blue-50"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    Dashboard
                  </Link>
                  <Link
                    to="/notifications"
                    className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-700 hover:bg-slate-50"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    Notifications
                  </Link>
                  <Link
                    to="/reports/history"
                    className="block px-3 py-2 rounded-lg text-sm font-semibold text-slate-700 hover:bg-slate-50"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    Scan History
                  </Link>
                  <button
                    type="button"
                    className="block w-full text-left px-3 py-2 rounded-lg text-sm font-semibold text-red-600 hover:bg-red-50 mt-1"
                    onClick={async () => {
                      setMobileMenuOpen(false);
                      await handleLogout();
                    }}
                  >
                    Sign out
                  </button>
                </>
              ) : (
                <div className="space-y-2 pt-2">
                  <Link
                    to="/login"
                    className="block w-full text-center px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    Login
                  </Link>
                  <Link
                    to="/register"
                    className="flex items-center justify-center gap-2 w-full bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold px-4 py-2.5 rounded-xl shadow-sm"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    <Shield className="w-4 h-4" />
                    Get Started
                  </Link>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
