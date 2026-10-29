import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Network,
  Search,
  RefreshCw,
  AlertTriangle,
  ExternalLink,
  Filter,
  Share2,
  Database,
  Layers,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { threatIntelService } from '../services/threat-intel.service';
import { cn } from '../lib/utils';
import type { ThreatIntelAnalysisReport } from '../types';

export function ThreatCorrelationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const [targetInput, setTargetInput] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ThreatIntelAnalysisReport | null>(null);
  const [selectedNode, setSelectedNode] = useState<{
    id: string;
    label: string;
    type: string;
    source: string;
    relationship?: string;
  } | null>(null);

  useEffect(() => {
    const q = searchParams.get('target') || searchParams.get('q');
    if (q && q.trim()) {
      setTargetInput(q.trim());
      handleCorrelate(q.trim());
    }
  }, [searchParams]);

  async function handleCorrelate(target?: string) {
    const raw = (target || targetInput).trim();
    if (!raw) {
      setError('Please enter a target indicator to correlate.');
      return;
    }

    setIsLoading(true);
    setError(null);
    setSearchParams({ target: raw });

    try {
      const result = await threatIntelService.analyzeIndicator(raw, false);
      setReport(result);
      // Select central primary node by default
      setSelectedNode({
        id: result.canonicalValue,
        label: result.displayValue || result.canonicalValue,
        type: result.indicatorType,
        source: 'Primary Target',
        relationship: 'Analyzed Subject',
      });
    } catch (err: any) {
      setError(err.message || 'Correlation analysis failed. Please verify connectivity.');
    } finally {
      setIsLoading(false);
    }
  }

  const isMalicious = report?.overallReputation === 'MALICIOUS';
  const isSuspicious = report?.overallReputation === 'SUSPICIOUS';

  // Filter connected nodes
  const relatedNodes = (report?.relatedIndicators || []).filter((node) => {
    if (filterType === 'ALL') return true;
    if (filterType === 'DOMAIN' && node.type === 'DOMAIN') return true;
    if (filterType === 'IP' && node.type === 'IP') return true;
    if (filterType === 'URL' && node.type === 'URL') return true;
    if (filterType === 'HASH' && (node.type.startsWith('HASH') || node.type.includes('HASH'))) return true;
    if (filterType === 'EXTENSION' && (node.type.startsWith('EXTENSION') || node.type.includes('EXTENSION'))) return true;
    return false;
  });

  return (
    <div className="min-h-screen bg-slate-50/50 pb-24 pt-28">
      {/* Hero Header */}
      <section className="relative overflow-hidden bg-white border-b border-slate-200/80 py-10 sm:py-12">
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />
        <Container>
          <div className="max-w-4xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider mb-3">
              <Network className="w-3.5 h-3.5 text-blue-600" />
              <span>Multi-Source Threat Correlation Graph</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight leading-tight">
              Threat Correlation Engine
            </h1>
            <p className="mt-2.5 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              Map and correlate relationships between domains, IP addresses, binary payload checksums, and browser extensions grounded strictly in verified evidence.
            </p>
          </div>
        </Container>
      </section>

      <Container className="mt-8">
        {/* Search Panel */}
        <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm mb-8">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleCorrelate();
            }}
            className="flex flex-col sm:flex-row gap-4"
          >
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-400">
                <Search className="w-5 h-5" />
              </div>
              <input
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                placeholder="Enter domain, URL, IP, file hash, or extension to correlate..."
                className="w-full pl-12 pr-4 py-3.5 bg-slate-50 border border-slate-200 focus:border-blue-600 rounded-2xl text-sm font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-600/10 transition-all"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="inline-flex items-center justify-center gap-2 px-8 py-3.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-2xl shadow-sm hover:shadow transition-all disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Mapping Graph...</span>
                </>
              ) : (
                <>
                  <Share2 className="w-4 h-4" />
                  <span>Correlate</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Target Samples */}
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span className="font-semibold text-slate-700">Quick Samples:</span>
            {['bad-domain.com', '8.8.8.8', 'https://example.com', '44d88612fea8a8f36de82e1278abb02f'].map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => {
                  setTargetInput(sample);
                  handleCorrelate(sample);
                }}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono transition-colors"
              >
                {sample}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="p-4 mb-6 rounded-2xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-medium flex items-center gap-3">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{error}</span>
          </div>
        )}

        {/* Results View */}
        {report && (
          <div className="space-y-6">
            {/* Filter Bar */}
            <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-white border border-slate-200 rounded-2xl shadow-sm">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-700">
                <Filter className="w-4 h-4 text-slate-400" />
                <span>Relationship Filter:</span>
                <div className="flex flex-wrap gap-1 ml-2">
                  {['ALL', 'DOMAIN', 'IP', 'URL', 'HASH', 'EXTENSION'].map((type) => (
                    <button
                      key={type}
                      type="button"
                      onClick={() => setFilterType(type)}
                      className={cn(
                        'px-3 py-1 rounded-lg text-xs font-medium transition-colors',
                        filterType === type
                          ? 'bg-blue-600 text-white shadow-sm'
                          : 'bg-slate-100 hover:bg-slate-200 text-slate-600'
                      )}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>

              <div className="text-xs font-mono text-slate-500">
                Connected Nodes: <span className="font-bold text-slate-900">{relatedNodes.length + 1}</span>
              </div>
            </div>

            {/* Interactive Correlation Canvas / Graph Container */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
              <div className="mb-6 flex items-center justify-between">
                <div>
                  <h3 className="text-base font-extrabold text-slate-900 flex items-center gap-2">
                    <Layers className="w-5 h-5 text-blue-600" />
                    <span>Evidence-Linked Relationship Topology</span>
                  </h3>
                  <p className="text-xs text-slate-500 mt-1">
                    Nodes represent substantiated relationships extracted directly from active intelligence feeds.
                  </p>
                </div>

                <span
                  className={cn(
                    'px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wide border',
                    isMalicious
                      ? 'bg-rose-50 text-rose-700 border-rose-200'
                      : isSuspicious
                      ? 'bg-amber-50 text-amber-700 border-amber-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  )}
                >
                  {report.overallReputation}
                </span>
              </div>

              {/* Node Visualizer Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Visual Topology Diagram */}
                <div className="lg:col-span-2 p-6 rounded-3xl bg-slate-900 text-white min-h-[380px] flex flex-col justify-between relative overflow-hidden">
                  <div className="absolute inset-0 bg-[radial-gradient(#334155_1px,transparent_1px)] [background-size:20px_20px] opacity-40 pointer-events-none" />

                  {/* Central Node */}
                  <div className="relative z-10 text-center my-auto py-6">
                    <div className="inline-block relative">
                      <div
                        onClick={() =>
                          setSelectedNode({
                            id: report.canonicalValue,
                            label: report.displayValue || report.canonicalValue,
                            type: report.indicatorType,
                            source: 'Primary Target',
                            relationship: 'Investigation Target',
                          })
                        }
                        className={cn(
                          'cursor-pointer px-6 py-4 rounded-3xl border-2 transition-all shadow-xl max-w-md mx-auto',
                          selectedNode?.id === report.canonicalValue
                            ? 'bg-blue-950 border-blue-400 ring-4 ring-blue-500/20'
                            : 'bg-slate-800/90 border-slate-600 hover:border-slate-400'
                        )}
                      >
                        <div className="text-[10px] font-mono uppercase tracking-widest text-blue-400 font-bold mb-1">
                          Primary Subject • {report.indicatorType}
                        </div>
                        <div className="text-sm sm:text-base font-mono font-black text-white truncate max-w-xs">
                          {report.displayValue || report.canonicalValue}
                        </div>
                        <div className="text-[11px] text-slate-300 mt-1">
                          Verdict: <span className="font-bold text-amber-400">{report.overallReputation}</span> ({report.confidence} Confidence)
                        </div>
                      </div>
                    </div>

                    {/* Connected Satellite Nodes Grid */}
                    {relatedNodes.length > 0 ? (
                      <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-xl mx-auto">
                        {relatedNodes.map((rel, idx) => (
                          <div
                            key={idx}
                            onClick={() =>
                              setSelectedNode({
                                id: rel.indicator,
                                label: rel.indicator,
                                type: rel.type,
                                source: rel.source,
                                relationship: rel.relationship,
                              })
                            }
                            className={cn(
                              'cursor-pointer p-3 rounded-2xl border text-left transition-all',
                              selectedNode?.id === rel.indicator
                                ? 'bg-cyan-950 border-cyan-400 ring-2 ring-cyan-500/30'
                                : 'bg-slate-800/70 border-slate-700/80 hover:bg-slate-800'
                            )}
                          >
                            <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
                              <span className="truncate max-w-[120px]">{rel.relationship || 'Connected'}</span>
                              <span className="px-1.5 py-0.5 rounded bg-slate-700 text-[9px] text-slate-200 uppercase font-bold">
                                {rel.type}
                              </span>
                            </div>
                            <div className="font-mono text-xs font-bold text-slate-100 truncate mt-1">
                              {rel.indicator}
                            </div>
                            <div className="text-[10px] text-cyan-400 mt-0.5">Source: {rel.source}</div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="mt-6 text-xs text-slate-400 italic">
                        No secondary relationships reported by active intelligence providers for this indicator.
                      </div>
                    )}
                  </div>

                  <div className="relative z-10 flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-800 pt-3">
                    <span>Click any node to inspect technical evidence &amp; attribution</span>
                    <span>Provider Corroborated</span>
                  </div>
                </div>

                {/* Node Inspector Sidebar */}
                <div className="p-6 rounded-3xl bg-slate-50 border border-slate-200 flex flex-col justify-between">
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">
                      Selected Node Inspector
                    </h4>

                    {selectedNode ? (
                      <div className="space-y-4">
                        <div className="p-4 rounded-2xl bg-white border border-slate-200">
                          <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">
                            Indicator Value
                          </div>
                          <div className="font-mono text-xs font-bold text-slate-900 break-all mt-1">
                            {selectedNode.label}
                          </div>
                        </div>

                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between py-1.5 border-b border-slate-200">
                            <span className="text-slate-500">Indicator Type:</span>
                            <span className="font-mono font-bold text-slate-800">{selectedNode.type}</span>
                          </div>
                          <div className="flex justify-between py-1.5 border-b border-slate-200">
                            <span className="text-slate-500">Relationship:</span>
                            <span className="font-medium text-slate-800">{selectedNode.relationship || 'Direct'}</span>
                          </div>
                          <div className="flex justify-between py-1.5 border-b border-slate-200">
                            <span className="text-slate-500">Originating Source:</span>
                            <span className="font-medium text-blue-600">{selectedNode.source}</span>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="p-4 rounded-2xl bg-white border border-slate-200 text-xs text-slate-500">
                        Select a node from the topology diagram to view its technical properties.
                      </div>
                    )}
                  </div>

                  {selectedNode && (
                    <button
                      onClick={() => navigate(`/threat-intelligence?q=${encodeURIComponent(selectedNode.id)}`)}
                      className="mt-6 w-full py-2.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm"
                    >
                      <span>Investigate in CTI Workspace</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Evidence Corroboration List */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2">
                <Database className="w-4 h-4 text-blue-600" />
                <span>Substantiated Intelligence Evidence</span>
              </h3>

              {report.evidence && report.evidence.length > 0 ? (
                <div className="space-y-3">
                  {report.evidence.map((ev, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-2xl bg-slate-50 border border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-blue-100 text-blue-800 text-[10px] font-bold uppercase">
                            {ev.provider}
                          </span>
                          <span className="text-xs font-bold text-slate-900">{ev.value}</span>
                        </div>
                        <p className="text-xs text-slate-600">{ev.description}</p>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        {ev.sourceReference && (
                          <a
                            href={ev.sourceReference}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-xs text-blue-600 hover:underline font-semibold"
                          >
                            <span>Provider Ref</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 rounded-2xl bg-slate-50 border border-slate-100 text-center text-xs text-slate-500">
                  No individual threat flags or evidence items recorded by active providers for this indicator.
                </div>
              )}
            </div>
          </div>
        )}
      </Container>
    </div>
  );
}
