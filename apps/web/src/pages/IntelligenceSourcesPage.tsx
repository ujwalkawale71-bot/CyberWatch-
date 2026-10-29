import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Database,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Radio,
  Lock,
  Zap,
  ArrowRight,
} from 'lucide-react';
import { Container } from '../components/ui/Container';
import { threatIntelService, type ThreatIntelProviderMeta } from '../services/threat-intel.service';
import { cn } from '../lib/utils';

interface ProviderStatusWithTest extends ThreatIntelProviderMeta {
  testing?: boolean;
  testResult?: {
    status: 'ONLINE' | 'NOT_CONFIGURED' | 'ERROR';
    latencyMs: number;
    message: string;
  };
}

export function IntelligenceSourcesPage() {
  const navigate = useNavigate();
  const [providers, setProviders] = useState<ProviderStatusWithTest[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadProviders();
  }, []);

  async function loadProviders() {
    setIsLoading(true);
    setError(null);
    try {
      const data = await threatIntelService.getProviders();
      setProviders(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load intelligence provider registry.');
    } finally {
      setIsLoading(false);
    }
  }

  async function handleTestConnection(providerId: string) {
    setProviders((prev) =>
      prev.map((p) => (p.id === providerId ? { ...p, testing: true } : p))
    );

    try {
      const testRes = await threatIntelService.testProvider(providerId);
      setProviders((prev) =>
        prev.map((p) =>
          p.id === providerId
            ? {
                ...p,
                testing: false,
                testResult: testRes,
              }
            : p
        )
      );
    } catch (err: any) {
      setProviders((prev) =>
        prev.map((p) =>
          p.id === providerId
            ? {
                ...p,
                testing: false,
                testResult: {
                  status: 'ERROR',
                  latencyMs: 0,
                  message: err.message || 'Connection test failed.',
                },
              }
            : p
        )
      );
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
              <Database className="w-3.5 h-3.5 text-blue-600" />
              <span>Provider Registry &amp; Health Matrix</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
              Intelligence Sources
            </h1>
            <p className="mt-2.5 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              Inspect upstream Threat Intelligence providers, check endpoint configuration states, and test live connection latencies securely without exposing credentials.
            </p>
          </div>
        </Container>
      </section>

      <Container className="mt-8">
        {/* Security Assurance Banner */}
        <div className="p-5 rounded-3xl bg-blue-50/60 border border-blue-100 text-blue-900 flex items-start gap-4 mb-8">
          <Lock className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
          <div className="text-xs leading-relaxed">
            <strong className="font-bold text-blue-950">Zero-Trust Credential Isolation: </strong>
            All external threat intelligence API keys and tokens are stored securely in backend server environment variables. API credentials are never sent to the browser, stored in client bundles, or logged to disk.
          </div>
        </div>

        {/* Controls Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-6 bg-white border border-slate-200 rounded-3xl shadow-sm mb-8">
          <div>
            <h2 className="text-base font-extrabold text-slate-900">
              Registered Intelligence Provider Adapters
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              5 standardized provider adapters registered in CyberWatch Threat Intelligence Orchestrator.
            </p>
          </div>

          <button
            onClick={loadProviders}
            disabled={isLoading}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-all disabled:opacity-50"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin')} />
            <span>Refresh Registry</span>
          </button>
        </div>

        {error && (
          <div className="p-4 mb-6 rounded-2xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-medium flex items-center gap-3">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{error}</span>
          </div>
        )}

        {/* Providers Table / Cards */}
        <div className="space-y-4">
          {providers.map((p) => (
            <div
              key={p.id}
              className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-6 hover:border-slate-300 transition-all"
            >
              <div className="space-y-3 max-w-xl">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-slate-50 border border-slate-100 text-blue-600">
                    <Radio className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-slate-900">{p.name}</h3>
                    <span className="text-[11px] font-mono text-slate-400 font-medium">
                      Adapter ID: {p.id}
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
                    Supported Indicator Types
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {p.supportedTypes?.map((t) => (
                      <span
                        key={t}
                        className="px-2.5 py-0.5 rounded-md bg-slate-50 border border-slate-200 text-[10px] font-mono font-semibold text-slate-700"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                {p.testResult && (
                  <div
                    className={cn(
                      'p-3 rounded-2xl text-xs flex items-center justify-between gap-3 border',
                      p.testResult.status === 'ONLINE'
                        ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        : p.testResult.status === 'NOT_CONFIGURED'
                        ? 'bg-slate-50 text-slate-700 border-slate-200'
                        : 'bg-rose-50 text-rose-800 border-rose-200'
                    )}
                  >
                    <span>{p.testResult.message}</span>
                    {p.testResult.latencyMs > 0 && (
                      <span className="font-mono font-bold shrink-0">
                        {p.testResult.latencyMs}ms
                      </span>
                    )}
                  </div>
                )}
              </div>

              <div className="flex flex-col sm:flex-row md:flex-col items-end gap-3 shrink-0">
                <span
                  className={cn(
                    'px-3 py-1.5 rounded-xl text-xs font-bold uppercase tracking-wider border flex items-center gap-2',
                    p.configured
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-slate-100 text-slate-600 border-slate-200'
                  )}
                >
                  {p.configured ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Configured</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3.5 h-3.5 text-slate-400" />
                      <span>Not Configured</span>
                    </>
                  )}
                </span>

                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <button
                    onClick={() => handleTestConnection(p.id)}
                    disabled={p.testing}
                    className="flex-1 sm:flex-initial px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50"
                  >
                    {p.testing ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Zap className="w-3.5 h-3.5 text-amber-400" />
                    )}
                    <span>{p.testing ? 'Testing...' : 'Test Connection'}</span>
                  </button>

                  <button
                    onClick={() => navigate('/threat-intelligence')}
                    className="px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-colors"
                    title="Investigate in CTI Workspace"
                  >
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Container>
    </div>
  );
}
