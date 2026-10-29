import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Container } from '../components/ui/Container';
import {
  HelpCircle,
  Search,
  ChevronDown,
  ThumbsUp,
  ThumbsDown,
  Bot,
  Headphones,
  X,
} from 'lucide-react';
import { cn } from '../lib/utils';

interface FAQItem {
  id: string;
  category: 'scanning' | 'scoring' | 'threat-intel' | 'reports' | 'account' | 'support';
  question: string;
  answer: string;
}

const FAQ_DATA: FAQItem[] = [
  {
    id: 'faq-1',
    category: 'scanning',
    question: 'How do CyberWatch scanners audit targets without causing downtime?',
    answer:
      'CyberWatch uses non-destructive, passive-and-active HTTP/TLS telemetry auditing. We inspect publicly exposed DNS records, TLS certificates, HTTP response headers, cookie flags, and static HTML structure. We do NOT perform aggressive port flooding or denial-of-service tests.',
  },
  {
    id: 'faq-2',
    category: 'scoring',
    question: 'How is the 0-100 Risk Score calculated?',
    answer:
      'The CyberWatch Risk Score is a deterministic additive score based on verified technical evidence. Missing critical headers (HSTS, CSP) contribute 15-25 points each; insecure cookies contribute 15-20 points; confirmed malware or high-risk extension permissions contribute 40-100 points. 0-19 is Safe, 20-39 is Low, 40-69 is Moderate/Suspicious, 70-89 is High Risk, and 90-100 is Critical.',
  },
  {
    id: 'faq-3',
    category: 'scanning',
    question: 'Why did my scan return "Target Unreachable" or "Timeout"?',
    answer:
      'Common causes include: (1) The target hostname does not resolve over public DNS; (2) The target is protected by a WAF/bot challenge that blocks automated probes; (3) The target protocol is missing (ensure you specify http:// or https://); or (4) The IP belongs to an internal private range (SSRF guard prevents scanning 127.0.0.1 or 192.168.x.x).',
  },
  {
    id: 'faq-4',
    category: 'threat-intel',
    question: 'Where does CyberWatch get its Threat Intelligence data?',
    answer:
      'CyberWatch aggregates real-time indicators of compromise (IOCs) from premier global intelligence networks, including AbuseIPDB (IP abuse confidence), VirusTotal & MalwareBazaar (malware hashes), AlienVault OTX (community threat pulses), URLhaus (malicious distribution URLs), and CISA Known Exploited Vulnerabilities (KEV).',
  },
  {
    id: 'faq-5',
    category: 'reports',
    question: 'Can I export PDF reports for compliance or client audits?',
    answer:
      'Yes! Navigate to any completed scan result or visit the Reports Center (/reports/export) to download executive PDF summaries, technical audit logs, or machine-readable JSON data exports.',
  },
  {
    id: 'faq-6',
    category: 'account',
    question: 'Are my scan targets and findings kept private?',
    answer:
      'Yes. All scan results, historical reports, and support tickets are protected with strict server-side authentication and tenant isolation. User A can never view or modify User B scans or tickets.',
  },
  {
    id: 'faq-7',
    category: 'support',
    question: 'How does Live Support Chat and Ticketing work?',
    answer:
      'CyberWatch provides real-time operator support backed by persistent Socket.IO connections and MongoDB message history. When you open a Live Chat session, you are queued for a support engineer. If an agent is not immediately available, you can seamlessly convert your chat into a permanent Support Ticket.',
  },
  {
    id: 'faq-8',
    category: 'support',
    question: 'How do I responsibly report a security vulnerability in CyberWatch?',
    answer:
      'Use the Security Vulnerability Reporting tab on the Contact Support page (/support?tab=security). Submissions are routed directly to our senior security engineering team under strict confidential disclosure SLAs.',
  },
];

export function FAQPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>('faq-1');
  const [feedback, setFeedback] = useState<Record<string, 'helpful' | 'not-helpful'>>({});

  const filteredFAQs = useMemo(() => {
    return FAQ_DATA.filter((item) => {
      const matchesCategory =
        selectedCategory === 'all' || item.category === selectedCategory;
      const matchesSearch =
        !searchQuery.trim() ||
        item.question.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.answer.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [searchQuery, selectedCategory]);

  function toggleExpand(id: string) {
    setExpandedId((prev) => (prev === id ? null : id));
  }

  function handleFeedback(id: string, type: 'helpful' | 'not-helpful') {
    setFeedback((prev) => ({ ...prev, [id]: type }));
  }

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20 pt-24 sm:pt-28">
      <Container>
        <div className="space-y-6 sm:space-y-8 w-full">
          {/* 1. Header Banner */}
          <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/90 shadow-sm text-center">
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-md bg-indigo-50 border border-indigo-200/70 text-indigo-800 text-xs font-bold uppercase tracking-wider mb-3">
              <HelpCircle className="w-3.5 h-3.5 text-indigo-600" />
              <span>CyberWatch Knowledge Center</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight mb-2.5">
              Frequently Asked Questions
            </h1>
            <p className="text-sm sm:text-base text-slate-600 max-w-3xl mx-auto leading-relaxed mb-5">
              Instant answers regarding scanner execution, risk scoring mathematics, threat intelligence feeds, and support desk procedures.
            </p>

            {/* Search Filter */}
            <div className="relative max-w-lg mx-auto">
              <Search className="w-4 h-4 text-slate-400 absolute left-4 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search FAQ questions & answers..."
                className="w-full pl-11 pr-4 py-3 bg-slate-50 hover:bg-slate-100/60 focus:bg-white text-slate-900 text-xs sm:text-sm rounded-2xl border border-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
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

          {/* 2. Category Filter Tabs */}
          <div className="flex items-center justify-center gap-1.5 overflow-x-auto scrollbar-none pb-1">
            {[
              { id: 'all', label: 'All FAQs' },
              { id: 'scanning', label: 'Scanning & Engines' },
              { id: 'scoring', label: 'Risk Scoring' },
              { id: 'threat-intel', label: 'Threat Intel' },
              { id: 'reports', label: 'Reports' },
              { id: 'support', label: 'Support & SLAs' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setSelectedCategory(tab.id)}
                className={cn(
                  'px-3.5 py-2 rounded-xl text-xs font-semibold transition-all whitespace-nowrap cursor-pointer',
                  selectedCategory === tab.id
                    ? 'bg-indigo-600 text-white shadow-2xs'
                    : 'bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200/80'
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* 3. Accordion List */}
          <div className="space-y-3">
            {filteredFAQs.length > 0 ? (
              filteredFAQs.map((item) => {
                const isOpen = expandedId === item.id;
                const userFeedback = feedback[item.id];

                return (
                  <div
                    key={item.id}
                    className="bg-white rounded-2xl border border-slate-200/90 shadow-2xs overflow-hidden transition-all"
                  >
                    <button
                      type="button"
                      onClick={() => toggleExpand(item.id)}
                      className="w-full px-5 sm:px-6 py-4 flex items-center justify-between gap-4 text-left hover:bg-slate-50/70 transition-colors cursor-pointer"
                      aria-expanded={isOpen}
                    >
                      <span className="text-xs sm:text-sm font-bold text-slate-900 leading-snug">
                        {item.question}
                      </span>
                      <ChevronDown
                        className={cn(
                          'w-4 h-4 text-slate-400 shrink-0 transition-transform duration-200',
                          isOpen && 'rotate-180 text-indigo-600'
                        )}
                      />
                    </button>

                    {isOpen && (
                      <div className="px-5 sm:px-6 pb-5 pt-1 text-xs sm:text-sm text-slate-600 leading-relaxed border-t border-slate-100 space-y-4 animate-in fade-in duration-150">
                        <p>{item.answer}</p>

                        {/* Was this helpful feedback */}
                        <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
                          <span>Was this answer helpful?</span>
                          <div className="flex items-center gap-1">
                            <button
                              type="button"
                              onClick={() => handleFeedback(item.id, 'helpful')}
                              className={cn(
                                'inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border text-[11px] font-semibold transition-colors cursor-pointer',
                                userFeedback === 'helpful'
                                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                  : 'bg-white text-slate-600 hover:bg-slate-50 border-slate-200'
                              )}
                            >
                              <ThumbsUp className="w-3 h-3" />
                              <span>Yes</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleFeedback(item.id, 'not-helpful')}
                              className={cn(
                                'inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border text-[11px] font-semibold transition-colors cursor-pointer',
                                userFeedback === 'not-helpful'
                                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                                  : 'bg-white text-slate-600 hover:bg-slate-50 border-slate-200'
                              )}
                            >
                              <ThumbsDown className="w-3 h-3" />
                              <span>No</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              <div className="bg-white rounded-2xl p-10 border border-slate-200 text-center space-y-3">
                <HelpCircle className="w-8 h-8 text-slate-300 mx-auto" />
                <h3 className="text-sm font-bold text-slate-800">No matching questions found</h3>
                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                  Try adjusting your search terms or talk to our AI Assistant.
                </p>
              </div>
            )}
          </div>

          {/* 4. Bottom Escalation Card */}
          <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/90 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-6">
            <div className="space-y-1 text-center sm:text-left">
              <h3 className="text-base font-bold text-slate-900">
                Still have unanswered questions?
              </h3>
              <p className="text-xs text-slate-500">
                Our AI Security Assistant and human technical engineers are available 24/7.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3 shrink-0">
              <Link
                to="/help/ai"
                className="inline-flex items-center gap-1.5 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-xl text-xs font-bold transition-all shadow-xs"
              >
                <Bot className="w-3.5 h-3.5" />
                <span>Ask AI Assistant</span>
              </Link>
              <Link
                to="/support"
                className="inline-flex items-center gap-1.5 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-bold transition-all shadow-xs"
              >
                <Headphones className="w-3.5 h-3.5" />
                <span>Open Support Ticket</span>
              </Link>
            </div>
          </div>
        </div>
      </Container>
    </div>
  );
}
