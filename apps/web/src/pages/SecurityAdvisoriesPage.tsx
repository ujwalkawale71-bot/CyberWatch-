import { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  RefreshCw,
  Info,
  ExternalLink,
  Filter,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { threatIntelService } from '../services/threat-intel.service';
import type { SecurityAdvisoryItem } from '../types';

export function SecurityAdvisoriesPage() {
  const [advisories, setAdvisories] = useState<SecurityAdvisoryItem[]>([]);
  const [isConfigured, setIsConfigured] = useState(false);
  const [providerName, setProviderName] = useState('None Configured');
  const [notice, setNotice] = useState('Loading advisory configuration...');
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  useEffect(() => {
    loadAdvisories();
  }, []);

  async function loadAdvisories() {
    setIsLoading(true);
    try {
      const res = await threatIntelService.getAdvisories();
      setIsConfigured(res.configured);
      setProviderName(res.provider);
      setNotice(res.notice);
      setAdvisories(res.advisories || []);
    } catch {
      setIsConfigured(false);
      setProviderName('None Configured');
      setNotice('Security advisory provider is not configured.');
      setAdvisories([]);
    } finally {
      setIsLoading(false);
    }
  }

  const filteredAdvisories = advisories.filter((adv) => {
    if (severityFilter !== 'ALL' && adv.severity !== severityFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        adv.cveId.toLowerCase().includes(q) ||
        adv.title.toLowerCase().includes(q) ||
        adv.summary.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="min-h-screen bg-slate-50/50 pb-24 pt-28">
      {/* Hero Header */}
      <section className="relative overflow-hidden bg-white border-b border-slate-200/80 py-8 md:py-10">
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />
        <Container>
          <div className="max-w-4xl">
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-md bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider mb-2.5">
              <AlertTriangle className="w-3.5 h-3.5 text-blue-600" />
              <span>Vulnerability Intelligence &amp; Advisories</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
              Security Advisories &amp; Vulnerability Feed
            </h1>
            <p className="mt-2.5 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              Real-time Common Vulnerabilities and Exposures (CVE) intelligence, severity scores, affected package matrices, and vendor remediation advisories.
            </p>
          </div>
        </Container>
      </section>

      <Container className="mt-8">
        {/* Search & Filter Bar */}
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm mb-6">
          <div className="flex flex-col sm:flex-row items-center gap-4">
            <div className="relative flex-1 w-full">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-400">
                <Search className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search CVE ID, package, product (e.g. CVE-2024-, openssl)..."
                className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 focus:border-blue-600 rounded-xl text-xs font-mono text-slate-900 focus:outline-none focus:ring-4 focus:ring-blue-600/10 transition-all"
              />
            </div>

            <div className="flex items-center gap-3 w-full sm:w-auto">
              <div className="flex items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-medium text-slate-700 focus:outline-none"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <button
                type="button"
                onClick={loadAdvisories}
                disabled={isLoading}
                className="inline-flex items-center gap-1.5 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition-colors shrink-0"
              >
                <RefreshCw className={isLoading ? 'w-3.5 h-3.5 animate-spin' : 'w-3.5 h-3.5'} />
                <span>Refresh</span>
              </button>
            </div>
          </div>
        </div>

        {/* Content View */}
        <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100">
            <div>
              <h3 className="text-base font-bold text-slate-900">Advisories Feed</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Source Provider: <span className="font-semibold text-slate-700">{providerName}</span>
              </p>
            </div>
            <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-3 py-1 rounded-full">
              {filteredAdvisories.length} Advisories
            </span>
          </div>

          {isLoading ? (
            <div className="py-16 text-center space-y-3">
              <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto" />
              <p className="text-xs font-medium text-slate-500">Checking vulnerability advisory feeds...</p>
            </div>
          ) : !isConfigured ? (
            <div className="py-16 text-center space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-amber-50 text-amber-600 flex items-center justify-center mx-auto">
                <Info className="w-6 h-6" />
              </div>
              <h4 className="text-sm font-bold text-slate-800">Security advisory provider is not configured.</h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                {notice || 'No external CVE vulnerability advisory API key is configured in this environment. CyberWatch honestly reports this status without fabricating mock CVE entries.'}
              </p>
            </div>
          ) : filteredAdvisories.length > 0 ? (
            <div className="space-y-4">
              {filteredAdvisories.map((adv, i) => (
                <div key={i} className="p-5 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-sm text-slate-900">{adv.cveId}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200 uppercase">
                          {adv.severity}
                        </span>
                        {adv.cvssScore && (
                          <span className="text-xs font-semibold text-slate-500">CVSS: {adv.cvssScore}</span>
                        )}
                      </div>
                      <h5 className="text-xs font-bold text-slate-800 mt-1">{adv.title}</h5>
                    </div>
                    {adv.references && adv.references[0] && (
                      <a
                        href={adv.references[0]}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-700 text-xs font-bold shrink-0"
                      >
                        <span>Details</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">{adv.summary}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-16 text-center space-y-2">
              <p className="text-xs font-bold text-slate-700">No matching advisories found.</p>
              <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
                No active security bulletins matched your current filter criteria.
              </p>
            </div>
          )}
        </div>
      </Container>
    </div>
  );
}
