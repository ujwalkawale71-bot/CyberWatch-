import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Rss,
  RefreshCw,
  AlertTriangle,
  ExternalLink,
  ArrowRight,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { threatIntelService } from '../services/threat-intel.service';
import { cn } from '../lib/utils';

export function ThreatFeedsPage() {
  const navigate = useNavigate();
  const [feeds, setFeeds] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadFeeds();
  }, []);

  async function loadFeeds() {
    setIsLoading(true);
    setError(null);
    try {
      const result = await threatIntelService.getFeeds();
      setFeeds(result);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve intelligence feed metadata.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50/50 pb-24 pt-28">
      {/* Hero Header */}
      <section className="relative overflow-hidden bg-white border-b border-slate-200/80 py-8 md:py-10">
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />
        <Container>
          <div className="max-w-4xl">
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-md bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider mb-2.5">
              <Rss className="w-3.5 h-3.5 text-blue-600" />
              <span>Continuous Threat Feeds &amp; Telemetry Streams</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
              Active Threat Feeds
            </h1>
            <p className="mt-2.5 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              Inspect upstream Cyber Threat Intelligence (CTI) feeds, open telemetry streams, and signature providers integrated into the CyberWatch enrichment engine.
            </p>
          </div>
        </Container>
      </section>

      <Container className="mt-8">
        {/* Controls Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-6 bg-white border border-slate-200 rounded-3xl shadow-sm mb-8">
          <div>
            <h2 className="text-base font-extrabold text-slate-900">
              Registered Intelligence Telemetry Streams
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Live multi-vendor streams queried in real-time during indicator investigations.
            </p>
          </div>

          <button
            onClick={loadFeeds}
            disabled={isLoading}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-all disabled:opacity-50"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin')} />
            <span>Refresh Feeds</span>
          </button>
        </div>

        {error && (
          <div className="p-4 mb-6 rounded-2xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-medium flex items-center gap-3">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{error}</span>
          </div>
        )}

        {/* Feed Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {feeds.map((feed) => (
            <div
              key={feed.id}
              className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm flex flex-col justify-between hover:border-slate-300 transition-all"
            >
              <div>
                <div className="flex items-start justify-between gap-4 mb-4">
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">
                      {feed.provider}
                    </span>
                    <h3 className="text-lg font-bold text-slate-900 mt-0.5">{feed.name}</h3>
                  </div>

                  <span
                    className={cn(
                      'px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border flex items-center gap-1.5 shrink-0',
                      feed.configured
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
                    )}
                  >
                    {feed.configured ? (
                      <>
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                        <span>Active Stream</span>
                      </>
                    ) : (
                      <>
                        <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                        <span>Requires Key</span>
                      </>
                    )}
                  </span>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed mb-6">
                  {feed.description}
                </p>

                {/* Supported Indicator Badges */}
                <div className="mb-6">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">
                    Supported Indicator Types
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {feed.supportedIndicators?.map((type: string) => (
                      <span
                        key={type}
                        className="px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-[10px] font-mono font-semibold text-slate-700"
                      >
                        {type}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-3.5 rounded-2xl bg-slate-50 border border-slate-100 text-xs space-y-1.5 mb-6">
                  <div className="flex justify-between">
                    <span className="text-slate-500 font-medium">Evaluation Model:</span>
                    <span className="font-semibold text-slate-800">{feed.frequency}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 font-medium">Data Scope:</span>
                    <span className="font-semibold text-slate-800">{feed.type}</span>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-100 flex items-center justify-between">
                {feed.sourceUrl && (
                  <a
                    href={feed.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-600 hover:text-blue-700"
                  >
                    <span>Feed Reference</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}

                <button
                  onClick={() => navigate('/threat-intelligence')}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-slate-700 hover:text-slate-900"
                >
                  <span>Query in CTI</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </Container>
    </div>
  );
}
