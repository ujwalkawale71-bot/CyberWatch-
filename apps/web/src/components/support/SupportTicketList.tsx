import { useState, useEffect } from 'react';
import { supportService } from '../../services/support.service';
import type { SupportTicket } from '../../types';
import { SupportTicketCard } from './SupportTicketCard';
import {
  Search,
  Inbox,
  RefreshCw,
  PlusCircle,
  AlertCircle,
  SlidersHorizontal,
} from 'lucide-react';
import { cn } from '../../lib/utils';

interface SupportTicketListProps {
  onCreateClick: () => void;
}

export function SupportTicketList({ onCreateClick }: SupportTicketListProps) {
  const [tickets, setTickets] = useState<SupportTicket[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'newest' | 'oldest' | 'updated'>('newest');

  async function loadTickets() {
    try {
      setLoading(true);
      setError(null);
      const res = await supportService.getUserTickets({
        status: selectedStatus === 'ALL' ? undefined : selectedStatus,
        search: searchTerm.trim() || undefined,
        sortBy,
      });
      setTickets(res.tickets);
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Failed to load support requests.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadTickets();
  }, [selectedStatus, sortBy]);

  // Debounced search trigger
  useEffect(() => {
    const timer = setTimeout(() => {
      loadTickets();
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  const statusFilters = [
    { key: 'ALL', label: 'All Tickets' },
    { key: 'OPEN', label: 'Open' },
    { key: 'INVESTIGATING', label: 'Investigating' },
    { key: 'WAITING_FOR_USER', label: 'Waiting for User' },
    { key: 'RESOLVED', label: 'Resolved' },
    { key: 'CLOSED', label: 'Closed' },
  ];

  return (
    <div className="space-y-5">
      {/* Header & Controls */}
      <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-slate-900">My Support Requests</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Track real-time updates and ongoing investigations for your account.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadTickets}
              className="p-2 text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-xl transition-colors cursor-pointer"
              title="Refresh tickets list"
            >
              <RefreshCw className={cn('w-4 h-4', loading && 'animate-spin text-cyan-600')} />
            </button>

            <button
              type="button"
              onClick={onCreateClick}
              className="inline-flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-700 active:bg-cyan-800 text-white text-xs font-bold px-3.5 py-2 rounded-xl shadow-xs transition-colors cursor-pointer"
            >
              <PlusCircle className="w-4 h-4" />
              <span>New Ticket</span>
            </button>
          </div>
        </div>

        {/* Search & Sort Row */}
        <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-3 pt-2 border-t border-slate-100">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by ticket number (e.g. CW-2026-...) or subject..."
              className="w-full pl-9 pr-4 py-2 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 text-slate-900"
            />
          </div>

          <div className="flex items-center gap-2">
            <SlidersHorizontal className="w-4 h-4 text-slate-400 shrink-0" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="px-3 py-2 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 font-medium text-slate-700"
            >
              <option value="newest">Newest First</option>
              <option value="updated">Recently Updated</option>
              <option value="oldest">Oldest First</option>
            </select>
          </div>
        </div>

        {/* Status Filter Badges */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
          {statusFilters.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => setSelectedStatus(tab.key)}
              className={cn(
                'px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors cursor-pointer',
                selectedStatus === tab.key
                  ? 'bg-cyan-600 text-white shadow-2xs'
                  : 'text-slate-600 hover:bg-slate-100 bg-slate-50/80'
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content Area */}
      {error && (
        <div className="flex items-center gap-2 p-4 rounded-xl bg-rose-50 border border-rose-100 text-xs text-rose-700">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs animate-pulse space-y-3"
            >
              <div className="h-4 bg-slate-200 rounded w-1/3" />
              <div className="h-5 bg-slate-200 rounded w-2/3" />
              <div className="h-3 bg-slate-100 rounded w-full" />
            </div>
          ))}
        </div>
      ) : tickets.length === 0 ? (
        <div className="bg-white rounded-2xl border border-slate-200 p-10 text-center space-y-4 shadow-xs">
          <div className="w-12 h-12 rounded-2xl bg-slate-50 border border-slate-100 flex items-center justify-center text-slate-400 mx-auto">
            <Inbox className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900">No support requests found</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              {searchTerm || selectedStatus !== 'ALL'
                ? 'No tickets matched your current search or filter criteria.'
                : "You don't have any support requests yet. If you have an inquiry or technical issue, start a ticket below."}
            </p>
          </div>
          <button
            type="button"
            onClick={onCreateClick}
            className="inline-flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-700 text-white text-xs font-bold px-4 py-2.5 rounded-xl shadow-xs transition-colors cursor-pointer"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Create Support Request</span>
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {tickets.map((ticket) => (
            <SupportTicketCard key={ticket.id} ticket={ticket} />
          ))}
        </div>
      )}
    </div>
  );
}
