import { Link } from 'react-router-dom';
import type { SupportTicket } from '../../types';
import { SupportStatusBadge, SupportPriorityBadge, formatCategoryLabel } from './SupportStatusBadge';
import { MessageSquare, Paperclip, Clock, ArrowRight, User } from 'lucide-react';

export function SupportTicketCard({ ticket }: { ticket: SupportTicket }) {
  const createdDate = new Date(ticket.createdAt).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  const messageCount = ticket.messages?.length || 0;
  const attachmentCount = (ticket.attachments?.length || 0) +
    (ticket.messages || []).reduce((acc, m) => acc + (m.attachments?.length || 0), 0);

  return (
    <div className="bg-white rounded-2xl border border-slate-200/90 p-5 shadow-xs hover:border-blue-200 hover:shadow-md transition-all duration-150">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 border border-blue-200/80 px-2.5 py-0.5 rounded-lg">
            #{ticket.ticketNumber}
          </span>
          <span className="text-xs font-semibold text-slate-600 bg-slate-50 border border-slate-100 px-2.5 py-0.5 rounded-lg">
            {formatCategoryLabel(ticket.category)}
          </span>
          <SupportPriorityBadge priority={ticket.priority} />
        </div>

        <SupportStatusBadge status={ticket.status} />
      </div>

      <div className="py-3">
        <Link
          to={`/support/tickets/${ticket.ticketNumber}`}
          className="text-sm font-bold text-slate-900 hover:text-blue-600 transition-colors line-clamp-1"
        >
          {ticket.subject}
        </Link>
        <p className="text-xs text-slate-500 line-clamp-2 mt-1 leading-relaxed">
          {ticket.description}
        </p>
      </div>

      <div className="pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-[11px] text-slate-500">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>Created {createdDate}</span>
          </div>

          <div className="flex items-center gap-1">
            <MessageSquare className="w-3.5 h-3.5 text-slate-400" />
            <span>{messageCount} {messageCount === 1 ? 'message' : 'messages'}</span>
          </div>

          {attachmentCount > 0 && (
            <div className="flex items-center gap-1 text-slate-600 font-medium">
              <Paperclip className="w-3.5 h-3.5 text-slate-400" />
              <span>{attachmentCount} {attachmentCount === 1 ? 'file' : 'files'}</span>
            </div>
          )}

          {ticket.assignedAgentName && (
            <div className="flex items-center gap-1 text-blue-700 font-medium bg-blue-50 px-2 py-0.5 rounded">
              <User className="w-3 h-3" />
              <span>Agent: {ticket.assignedAgentName}</span>
            </div>
          )}
        </div>

        <Link
          to={`/support/tickets/${ticket.ticketNumber}`}
          className="inline-flex items-center gap-1 font-bold text-xs text-blue-600 hover:text-blue-700 transition-colors ml-auto"
        >
          <span>View Ticket</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  );
}
