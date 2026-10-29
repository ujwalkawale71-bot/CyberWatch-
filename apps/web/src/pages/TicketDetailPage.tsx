import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Container } from '../components/ui/Container';
import { supportService } from '../services/support.service';
import type { SupportTicket } from '../types';
import {
  SupportStatusBadge,
  SupportPriorityBadge,
  formatCategoryLabel,
} from '../components/support/SupportStatusBadge';
import { SupportConversation } from '../components/support/SupportConversation';
import { SupportMessageComposer } from '../components/support/SupportMessageComposer';
import {
  ArrowLeft,
  Clock,
  Globe,
  FileText,
  Shield,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';

export function TicketDetailPage() {
  const { ticketId } = useParams<{ ticketId: string }>();

  const [ticket, setTicket] = useState<SupportTicket | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadTicket() {
    if (!ticketId) return;
    try {
      setLoading(true);
      setError(null);
      const data = await supportService.getTicketById(ticketId);
      setTicket(data);
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Unable to load ticket details.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadTicket();
  }, [ticketId]);

  async function handleSendMessage(messageText: string, files: File[]) {
    if (!ticket) return;
    const updated = await supportService.addTicketMessage(ticket.ticketNumber, messageText, files);
    setTicket(updated);
  }

  async function handleReopenTicket() {
    if (!ticket) return;
    const updated = await supportService.reopenTicket(ticket.ticketNumber);
    setTicket(updated);
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50/60 pb-20 pt-24 sm:pt-28">
        <Container>
          <div className="w-full space-y-6 animate-pulse">
            <div className="h-6 bg-slate-200 rounded w-48" />
            <div className="bg-white rounded-3xl p-8 border border-slate-200 space-y-4">
              <div className="h-6 bg-slate-200 rounded w-1/3" />
              <div className="h-8 bg-slate-200 rounded w-3/4" />
              <div className="h-20 bg-slate-100 rounded w-full" />
            </div>
          </div>
        </Container>
      </div>
    );
  }

  if (error || !ticket) {
    return (
      <div className="min-h-screen bg-slate-50/60 pb-20 pt-24 sm:pt-28">
        <Container>
          <div className="max-w-xl mx-auto bg-white rounded-3xl border border-slate-200 p-8 text-center space-y-4 shadow-sm">
            <div className="w-12 h-12 rounded-2xl bg-rose-50 text-rose-600 border border-rose-100 flex items-center justify-center mx-auto">
              <AlertCircle className="w-6 h-6" />
            </div>
            <h2 className="text-lg font-bold text-slate-900">Unable to View Support Request</h2>
            <p className="text-xs text-slate-500 leading-relaxed">
              {error || 'The requested ticket could not be found or you do not have permission to access it.'}
            </p>
            <div className="pt-2">
              <Link
                to="/support"
                className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-bold text-cyan-700 bg-cyan-50 hover:bg-cyan-100 rounded-xl transition-colors cursor-pointer"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Return to Support Center</span>
              </Link>
            </div>
          </div>
        </Container>
      </div>
    );
  }

  const isResolvedOrClosed = ticket.status === 'RESOLVED' || ticket.status === 'CLOSED';

  const createdDate = new Date(ticket.createdAt).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  const updatedDate = new Date(ticket.updatedAt).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20 pt-24 sm:pt-28">
      <Container>
        <div className="w-full space-y-6">
          {/* Back Action */}
          <div>
            <Link
              to="/support?tab=tickets"
              className="inline-flex items-center gap-1.5 text-xs font-bold text-slate-500 hover:text-slate-900 transition-colors cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Support Requests</span>
            </Link>
          </div>

          {/* Ticket Header Card */}
          <div className="bg-white rounded-3xl border border-slate-200/90 p-6 sm:p-8 shadow-xs space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs font-bold text-cyan-800 bg-cyan-50 border border-cyan-200 px-3 py-1 rounded-lg">
                  #{ticket.ticketNumber}
                </span>
                <span className="text-xs font-semibold text-slate-600 bg-slate-50 border border-slate-200 px-2.5 py-1 rounded-lg">
                  {formatCategoryLabel(ticket.category)}
                </span>
                <SupportPriorityBadge priority={ticket.priority} />
              </div>

              <SupportStatusBadge status={ticket.status} />
            </div>

            {/* Subject & Core Description */}
            <div>
              <h1 className="text-xl sm:text-2xl font-black text-slate-900 leading-snug">
                {ticket.subject}
              </h1>
              <p className="text-xs text-slate-600 leading-relaxed mt-2.5 bg-slate-50/80 p-4 rounded-2xl border border-slate-100 whitespace-pre-wrap">
                {ticket.description}
              </p>
            </div>

            {/* Telemetry / Scan Metadata */}
            {(ticket.targetUrl || ticket.scanId || ticket.reportId) && (
              <div className="flex flex-wrap items-center gap-3 pt-2 text-xs">
                {ticket.targetUrl && (
                  <div className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 text-slate-700 rounded-xl font-medium">
                    <Globe className="w-3.5 h-3.5 text-cyan-600" />
                    <span>Target: {ticket.targetUrl}</span>
                  </div>
                )}

                {ticket.scanId && (
                  <Link
                    to={`/reports/scans/${ticket.scanId}`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-50 text-cyan-800 hover:bg-cyan-100 rounded-xl font-mono transition-colors"
                  >
                    <FileText className="w-3.5 h-3.5 text-cyan-600" />
                    <span>Scan: {ticket.scanId}</span>
                    <ExternalLink className="w-3 h-3" />
                  </Link>
                )}

                {ticket.reportId && (
                  <div className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 text-slate-700 rounded-xl font-mono">
                    <FileText className="w-3.5 h-3.5 text-slate-500" />
                    <span>Report: {ticket.reportId}</span>
                  </div>
                )}
              </div>
            )}

            {/* Dates & Agent Footer */}
            <div className="pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-[11px] text-slate-500">
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  <span>Created {createdDate}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  <span>Last updated {updatedDate}</span>
                </div>
              </div>

              {ticket.assignedAgentName && (
                <div className="inline-flex items-center gap-1 px-2.5 py-1 bg-cyan-50 text-cyan-800 font-bold rounded-lg border border-cyan-100">
                  <Shield className="w-3.5 h-3.5 text-cyan-600" />
                  <span>Assigned: {ticket.assignedAgentName}</span>
                </div>
              )}
            </div>
          </div>

          {/* Conversation Timeline */}
          <div className="space-y-4">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider px-1">
              Conversation Timeline ({ticket.messages?.length || 0})
            </h2>

            <SupportConversation messages={ticket.messages || []} />
          </div>

          {/* Reply Composer */}
          <div className="pt-2">
            <SupportMessageComposer
              onSendMessage={handleSendMessage}
              onReopenTicket={handleReopenTicket}
              isResolved={isResolvedOrClosed}
            />
          </div>
        </div>
      </Container>
    </div>
  );
}
