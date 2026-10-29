import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { supportService } from '../../services/support.service';
import { AttachmentUploader } from './AttachmentUploader';
import {
  SUPPORT_CATEGORIES,
  type SupportCategory,
  type SupportPriority,
  type SupportTicket,
} from '../../types';
import { formatCategoryLabel } from './SupportStatusBadge';
import {
  Send,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Info,
  Terminal,
} from 'lucide-react';
import { Link } from 'react-router-dom';

interface SupportTicketFormProps {
  initialCategory?: SupportCategory;
  initialScanId?: string;
  initialReportId?: string;
  initialTargetUrl?: string;
  onSuccess?: (ticket: SupportTicket) => void;
}

export function SupportTicketForm({
  initialCategory = 'TECHNICAL_ISSUE',
  initialScanId = '',
  initialReportId = '',
  initialTargetUrl = '',
  onSuccess,
}: SupportTicketFormProps) {
  const { user } = useAuth();

  const [name, setName] = useState(user?.name || '');
  const [email, setEmail] = useState(user?.email || '');
  const [category, setCategory] = useState<SupportCategory>(initialCategory);
  const [priority, setPriority] = useState<SupportPriority>('MEDIUM');
  const [subject, setSubject] = useState('');
  const [description, setDescription] = useState('');
  const [scanId, setScanId] = useState(initialScanId);
  const [reportId, setReportId] = useState(initialReportId);
  const [targetUrl, setTargetUrl] = useState(initialTargetUrl);
  const [browserEnvironment, setBrowserEnvironment] = useState('');
  const [attachments, setAttachments] = useState<File[]>([]);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [createdTicket, setCreatedTicket] = useState<SupportTicket | null>(null);

  // Auto-fill user information when authenticated
  useEffect(() => {
    if (user?.name && !name) setName(user.name);
    if (user?.email && !email) setEmail(user.email);
  }, [user]);

  // Detect environment automatically
  useEffect(() => {
    if (typeof navigator !== 'undefined') {
      const ua = navigator.userAgent;
      const os = navigator.platform || 'Desktop';
      setBrowserEnvironment(`${os} • ${ua.slice(0, 100)}`);
    }
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);

    if (!name.trim()) {
      setFormError('Please provide your full name.');
      return;
    }
    if (!email.trim() || !/^\S+@\S+\.\S+$/.test(email.trim())) {
      setFormError('Please provide a valid email address.');
      return;
    }
    if (subject.trim().length < 5) {
      setFormError('Subject must be at least 5 characters long.');
      return;
    }
    if (description.trim().length < 10) {
      setFormError('Description must be at least 10 characters long.');
      return;
    }

    try {
      setIsSubmitting(true);
      const ticket = await supportService.createTicket(
        {
          name: name.trim(),
          email: email.trim(),
          category,
          priority,
          subject: subject.trim(),
          description: description.trim(),
          scanId: scanId.trim() || undefined,
          reportId: reportId.trim() || undefined,
          targetUrl: targetUrl.trim() || undefined,
          browserEnvironment: browserEnvironment.trim() || undefined,
        },
        attachments
      );

      setCreatedTicket(ticket);
      if (onSuccess) onSuccess(ticket);
    } catch (err: any) {
      setFormError(err.response?.data?.message || err.message || 'Failed to submit support request.');
    } finally {
      setIsSubmitting(false);
    }
  }

  if (createdTicket) {
    return (
      <div className="bg-white rounded-2xl border border-slate-200 p-8 text-center space-y-5 animate-in fade-in duration-200">
        <div className="w-14 h-14 rounded-2xl bg-emerald-50 text-emerald-600 border border-emerald-100 flex items-center justify-center mx-auto shadow-xs">
          <CheckCircle2 className="w-8 h-8" />
        </div>
        <div>
          <span className="text-xs font-bold text-blue-600 bg-blue-50 border border-blue-100 px-3 py-1 rounded-full uppercase tracking-wider">
            Ticket #{createdTicket.ticketNumber}
          </span>
          <h3 className="text-xl font-bold text-slate-900 mt-3 mb-1">Support Request Submitted</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
            Your ticket has been routed to our technical engineering queue. We have sent an acknowledgement to{' '}
            <span className="font-semibold text-slate-700">{createdTicket.email}</span>.
          </p>
        </div>

        <div className="pt-2 flex flex-wrap items-center justify-center gap-3">
          <Link
            to={`/support/tickets/${createdTicket.ticketNumber}`}
            className="inline-flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white text-xs font-bold px-4 py-2.5 rounded-xl shadow-xs transition-colors cursor-pointer"
          >
            <span>View Ticket &amp; Conversation</span>
          </Link>
          <button
            type="button"
            onClick={() => {
              setCreatedTicket(null);
              setSubject('');
              setDescription('');
              setAttachments([]);
            }}
            className="px-4 py-2.5 text-xs font-semibold text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-xl transition-colors cursor-pointer"
          >
            Create Another Request
          </button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="bg-white rounded-2xl border border-slate-200/90 p-6 sm:p-8 shadow-xs space-y-6">
      <div className="border-b border-slate-100 pb-4">
        <h2 className="text-lg font-bold text-slate-900">Submit a Support Ticket</h2>
        <p className="text-xs text-slate-500 mt-1">
          Provide as much technical detail as possible so our security team can investigate efficiently.
        </p>
      </div>

      {formError && (
        <div className="flex items-start gap-2.5 p-3 rounded-xl bg-rose-50 border border-rose-100 text-xs text-rose-700">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{formError}</span>
        </div>
      )}

      {/* Row 1: Name & Email */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-bold text-slate-700 mb-1.5">
            Full Name <span className="text-rose-500">*</span>
          </label>
          <input
            type="text"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Alex Rivera"
            className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 text-slate-900"
          />
        </div>

        <div>
          <label className="block text-xs font-bold text-slate-700 mb-1.5">
            Email Address <span className="text-rose-500">*</span>
          </label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="e.g. alex@example.com"
            className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 text-slate-900"
          />
        </div>
      </div>

      {/* Row 2: Category & Priority */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-bold text-slate-700 mb-1.5">
            Issue Category <span className="text-rose-500">*</span>
          </label>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value as SupportCategory)}
            className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 text-slate-900"
          >
            {SUPPORT_CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>
                {formatCategoryLabel(cat)}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-bold text-slate-700 mb-1.5">
            Priority <span className="text-rose-500">*</span>
          </label>
          <select
            value={priority}
            onChange={(e) => setPriority(e.target.value as SupportPriority)}
            className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 text-slate-900"
          >
            <option value="LOW">Low (General question / Feature suggestion)</option>
            <option value="MEDIUM">Medium (Normal workflow problem)</option>
            <option value="HIGH">High (Scanner or report issue blocking operations)</option>
            <option value="URGENT">Urgent (Critical production security impact)</option>
          </select>
        </div>
      </div>

      {/* Row 3: Subject */}
      <div>
        <label className="block text-xs font-bold text-slate-700 mb-1.5">
          Subject <span className="text-rose-500">*</span>
        </label>
        <input
          type="text"
          required
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          placeholder="Brief summary of the issue (e.g. Website Scanner timeout on subdomains)"
          className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 text-slate-900"
        />
      </div>

      {/* Row 4: Description */}
      <div>
        <label className="block text-xs font-bold text-slate-700 mb-1.5">
          Description <span className="text-rose-500">*</span>
        </label>
        <textarea
          required
          rows={5}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Detailed description of what occurred, expected outcome, and steps to reproduce..."
          className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 font-sans leading-relaxed text-slate-900"
        />
        <p className="text-[11px] text-slate-400 mt-1">Minimum 10 characters.</p>
      </div>

      {/* Row 5: Optional Context */}
      <div className="bg-slate-50/70 rounded-xl p-4 border border-slate-200/70 space-y-3">
        <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
          <Terminal className="w-3.5 h-3.5 text-cyan-600" />
          <span>Optional Context &amp; Telemetry</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-[11px] font-semibold text-slate-600 mb-1">Target URL / Domain</label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-3 py-2 text-xs rounded-lg bg-white border border-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 text-slate-900"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-600 mb-1">Scan ID (if relevant)</label>
            <input
              type="text"
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              placeholder="e.g. 660f..."
              className="w-full px-3 py-2 text-xs rounded-lg bg-white border border-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 font-mono text-slate-900"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-600 mb-1">Report ID (if relevant)</label>
            <input
              type="text"
              value={reportId}
              onChange={(e) => setReportId(e.target.value)}
              placeholder="e.g. REP-..."
              className="w-full px-3 py-2 text-xs rounded-lg bg-white border border-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 font-mono text-slate-900"
            />
          </div>
        </div>
      </div>

      {/* Row 6: Attachments */}
      <div>
        <label className="block text-xs font-bold text-slate-700 mb-1.5">Attachments (Optional)</label>
        <AttachmentUploader files={attachments} onChange={setAttachments} maxFiles={3} />
      </div>

      {/* Submit Button */}
      <div className="pt-2 flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-xs text-slate-500">
          <Info className="w-3.5 h-3.5 text-cyan-600" />
          <span>Tickets are private to your authenticated account.</span>
        </div>

        <button
          type="submit"
          disabled={isSubmitting}
          className="inline-flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 active:bg-cyan-800 disabled:opacity-60 text-white text-xs font-bold px-6 py-3 rounded-xl shadow-xs transition-colors cursor-pointer"
        >
          {isSubmitting ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Submitting Request...</span>
            </>
          ) : (
            <>
              <Send className="w-4 h-4" />
              <span>Submit Support Request</span>
            </>
          )}
        </button>
      </div>
    </form>
  );
}
