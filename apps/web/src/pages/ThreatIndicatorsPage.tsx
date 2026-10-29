import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Fingerprint,
  Search,
  RefreshCw,
  ExternalLink,
  Copy,
  Check,
  Database,
  Filter,
  Radio,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { threatIntelService } from '../services/threat-intel.service';
import { cn } from '../lib/utils';
import type { StoredThreatIndicatorItem } from '../types';

export function ThreatIndicatorsPage() {
  const navigate = useNavigate();
  const [indicators, setIndicators] = useState<StoredThreatIndicatorItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState('ALL');
  const [selectedStatus, setSelectedStatus] = useState('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    loadIndicators();
  }, [selectedType, selectedStatus]);

  async function loadIndicators() {
    setIsLoading(true);
    try {
      const res = await threatIntelService.listIndicators({
        type: selectedType,
        status: selectedStatus,
        search: searchQuery,
      });
      setIndicators(res.items || []);
    } catch {
      setIndicators([]);
    } finally {
      setIsLoading(false);
    }
  }

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    loadIndicators();
  }

  function handleCopy(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  return (
    <div className="min-h-screen bg-slate-50/50 pb-24 pt-28">
      {/* Hero Header */}
      <section className="relative overflow-hidden bg-white border-b border-slate-200/80 py-10 sm:py-12">
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />
        <Container>
          <div className="max-w-4xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider mb-3">
              <Fingerprint className="w-3.5 h-3.5 text-blue-600" />
              <span>Persistent Threat Intelligence Registry</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight leading-tight">
              Threat Indicators &amp; IOC Registry
            </h1>
            <p className="mt-2.5 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              Historical intelligence repository storing real analyzed indicators, multi-engine verdicts, and corroboration evidence evaluated across CyberWatch.
            </p>
          </div>
        </Container>
      </section>

      <Container className="mt-8">
        {/* Filter / Search Bar */}
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm mb-6">
          <form onSubmit={handleSearchSubmit} className="flex flex-col lg:flex-row items-center gap-4">
            <div className="relative flex-1 w-full">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-400">
                <Search className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search indicator, canonical hash, domain..."
                className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 focus:border-blue-600 rounded-xl text-xs font-mono text-slate-900 focus:outline-none focus:ring-4 focus:ring-blue-600/10 transition-all"
              />
            </div>

            <div className="flex items-center gap-3 w-full lg:w-auto flex-wrap sm:flex-nowrap">
              <div className="flex items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <select
                  value={selectedType}
                  onChange={(e) => setSelectedType(e.target.value)}
                  className="bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-medium text-slate-700 focus:outline-none"
                >
                  <option value="ALL">All Types</option>
                  <option value="DOMAIN">Domain</option>
                  <option value="URL">URL</option>
                  <option value="IP">IP Address</option>
                  <option value="HASH_SHA256">SHA-256</option>
                  <option value="HASH_MD5">MD5</option>
                  <option value="EXTENSION_ID">Extension ID</option>
                </select>
              </div>

              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                className="bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-medium text-slate-700 focus:outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="MATCH_FOUND">Match Found</option>
                <option value="NO_MATCH">No Match</option>
                <option value="NOT_CONFIGURED">Not Configured</option>
                <option value="UNAVAILABLE">Unavailable</option>
              </select>

              <button
                type="submit"
                disabled={isLoading}
                className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-xs transition-colors shrink-0"
              >
                <RefreshCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin')} />
                <span>Search</span>
              </button>
            </div>
          </form>
        </div>

        {/* Indicators Table */}
        <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100">
            <div>
              <h3 className="text-base font-bold text-slate-900">Analyzed Indicators</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Real database records from indicator lookups and scanner intelligence enrichments.
              </p>
            </div>
            <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-3 py-1 rounded-full">
              {indicators.length} Records
            </span>
          </div>

          {isLoading ? (
            <div className="py-16 text-center space-y-3">
              <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto" />
              <p className="text-xs font-medium text-slate-500">Loading threat indicators from database...</p>
            </div>
          ) : indicators.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/70 text-[11px] font-bold uppercase tracking-wider text-slate-500">
                    <th className="py-3 px-4">Indicator</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Reputation Status</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Evidence Items</th>
                    <th className="py-3 px-4">Sources</th>
                    <th className="py-3 px-4">Last Analysis</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {indicators.map((item, idx) => {
                    const isMal = item.overallReputation === 'MALICIOUS';
                    const isSusp = item.overallReputation === 'SUSPICIOUS';
                    const isNotConf = item.status === 'NOT_CONFIGURED';

                    return (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-3.5 px-4 font-mono font-bold text-slate-900 max-w-[200px] truncate" title={item.indicator}>
                          {item.indicator}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 border border-slate-200">
                            {item.indicatorType}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span
                            className={cn(
                              'px-2.5 py-0.5 rounded-full text-[10px] font-bold border',
                              isMal
                                ? 'bg-rose-50 text-rose-700 border-rose-200'
                                : isSusp
                                ? 'bg-amber-50 text-amber-700 border-amber-200'
                                : isNotConf
                                ? 'bg-slate-100 text-slate-500 border-slate-200'
                                : item.status === 'MATCH_FOUND'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-slate-100 text-slate-600 border-slate-200'
                            )}
                          >
                            {isNotConf ? 'NOT CONFIGURED' : item.overallReputation}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap font-semibold text-slate-700">
                          {item.confidence}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap font-bold text-slate-800">
                          {item.evidenceCount}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap text-slate-600 text-[11px]">
                          {item.sourcesCount} checked
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap text-slate-600 text-[11px]">
                          {item.lastAnalysisDate ? new Date(item.lastAnalysisDate).toLocaleDateString() : 'Recent'}
                        </td>
                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => handleCopy(item.indicator, item.id)}
                              className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 transition-colors"
                              title="Copy Indicator"
                            >
                              {copiedId === item.id ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                            <button
                              type="button"
                              onClick={() => navigate(`/threat-intelligence?q=${encodeURIComponent(item.indicator)}`)}
                              className="inline-flex items-center gap-1 px-2.5 py-1 bg-blue-50 hover:bg-blue-100 text-blue-700 rounded-lg text-xs font-bold transition-colors"
                            >
                              <span>Inspect</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-16 text-center space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                <Database className="w-6 h-6" />
              </div>
              <h4 className="text-sm font-bold text-slate-800">No threat indicators have been analyzed yet.</h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Submit a target indicator on the Threat Intelligence page or run any CyberWatch security scan to populate the persistent intelligence registry.
              </p>
              <button
                type="button"
                onClick={() => navigate('/threat-intelligence')}
                className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-semibold shadow-xs transition-colors mt-2"
              >
                <Radio className="w-3.5 h-3.5" />
                <span>Launch Threat Intelligence</span>
              </button>
            </div>
          )}
        </div>
      </Container>
    </div>
  );
}
