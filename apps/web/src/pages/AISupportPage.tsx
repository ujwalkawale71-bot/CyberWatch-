import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import { Container } from '../components/ui/Container';
import { AISupportAssistant } from '../components/support/AISupportAssistant';
import {
  BookOpen,
  Headphones,
  Sparkles,
} from 'lucide-react';

export function AISupportPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scanIdParam = searchParams.get('scanId') || undefined;

  function handleEscalateToHuman(initialContext?: { scanId?: string; topic?: string }) {
    if (initialContext?.scanId) {
      navigate(`/support?tab=create&scanId=${initialContext.scanId}`);
    } else {
      navigate('/support?tab=chat');
    }
  }

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20 pt-24 sm:pt-28">
      <Container>
        <div className="space-y-8 max-w-5xl mx-auto">
          {/* Top Hero Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white p-6 rounded-3xl border border-slate-200/90 shadow-sm">
            <div className="space-y-1">
              <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-50 border border-cyan-200/70 text-cyan-800 text-xs font-bold mb-1">
                <Sparkles className="w-3.5 h-3.5 text-cyan-600" />
                <span>Grounded AI Security Diagnostics</span>
              </div>
              <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight">
                CyberWatch AI Support Assistant
              </h1>
              <p className="text-xs text-slate-500">
                Ask questions about your scan findings, scoring rules, or cybersecurity remediation.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <Link
                to="/help/guide"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200/80 transition-colors"
              >
                <BookOpen className="w-3.5 h-3.5 text-cyan-600" />
                <span>Scanner Guide</span>
              </Link>
              <Link
                to="/support"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200/80 transition-colors"
              >
                <Headphones className="w-3.5 h-3.5 text-blue-600" />
                <span>Human Desk</span>
              </Link>
            </div>
          </div>

          {/* AI Assistant Main Component */}
          <AISupportAssistant
            prefillScanId={scanIdParam}
            onEscalateToHuman={handleEscalateToHuman}
          />
        </div>
      </Container>
    </div>
  );
}
