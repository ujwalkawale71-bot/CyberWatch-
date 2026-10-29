import { Mail, ShieldAlert, Phone, MessageSquare, ArrowRight, ExternalLink } from 'lucide-react';
import type { SupportPublicConfig } from '../../types';
import { buildWhatsAppLink } from '../../services/support.service';

interface SupportContactCardsProps {
  config: SupportPublicConfig;
  onStartChatClick: () => void;
  onSecurityReportClick: () => void;
  onStartTicketClick?: () => void;
}

export function SupportContactCards({
  config,
  onStartChatClick,
  onSecurityReportClick,
}: SupportContactCardsProps) {
  const whatsappUrl = config.supportWhatsapp ? buildWhatsAppLink(config.supportWhatsapp) : '';
  const emailMailto = config.supportEmail
    ? `mailto:${config.supportEmail}?subject=${encodeURIComponent('CyberWatch Support Request')}`
    : '';

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-5">
      {/* 1. Email Support Card */}
      <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-xs hover:shadow-sm transition-all flex flex-col justify-between">
        <div>
          <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 mb-4">
            <Mail className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-slate-900 mb-1">Email Support</h3>
          <p className="text-xs text-slate-500 mb-3 leading-relaxed">
            Direct technical desk assistance for scanners and accounts.
          </p>
          <div className="text-xs font-semibold text-slate-700 break-all bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-100 mb-4">
            {config.supportEmail || 'Contact information currently unavailable.'}
          </div>
        </div>
        {config.supportEmail ? (
          <a
            href={emailMailto}
            className="inline-flex items-center justify-center gap-1.5 w-full py-2 px-3 text-xs font-bold text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-xl transition-colors cursor-pointer"
          >
            <span>Send Email</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        ) : (
          <span className="text-center text-xs text-slate-400 py-2">Email disabled</span>
        )}
      </div>

      {/* 2. Security Reporting Card */}
      <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-xs hover:shadow-sm transition-all flex flex-col justify-between">
        <div>
          <div className="w-10 h-10 rounded-xl bg-rose-50 border border-rose-100 flex items-center justify-center text-rose-600 mb-4">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-slate-900 mb-1">Security Reporting</h3>
          <p className="text-xs text-slate-500 mb-3 leading-relaxed">
            Report a suspected vulnerability or security finding in CyberWatch.
          </p>
          <div className="text-xs font-semibold text-slate-700 break-all bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-100 mb-4">
            {config.securityEmail ? 'Confidential Security Desk' : 'Contact information currently unavailable.'}
          </div>
        </div>
        <button
          type="button"
          onClick={onSecurityReportClick}
          className="inline-flex items-center justify-center gap-1.5 w-full py-2 px-3 text-xs font-bold text-rose-700 bg-rose-50 hover:bg-rose-100 rounded-xl transition-colors cursor-pointer"
        >
          <span>Report Vulnerability</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* 3. Phone / WhatsApp Card */}
      <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-xs hover:shadow-sm transition-all flex flex-col justify-between">
        <div>
          <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600 mb-4">
            <Phone className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-slate-900 mb-1">Phone / WhatsApp</h3>
          <p className="text-xs text-slate-500 mb-3 leading-relaxed">
            Mobile response channel for technical inquiry and emergency escalation.
          </p>
          <div className="text-xs font-semibold text-slate-700 bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-100 mb-4">
            {config.supportPhone || 'Contact information currently unavailable.'}
          </div>
        </div>
        {whatsappUrl ? (
          <a
            href={whatsappUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-1.5 w-full py-2 px-3 text-xs font-bold text-emerald-700 bg-emerald-50 hover:bg-emerald-100 rounded-xl transition-colors cursor-pointer"
          >
            <span>Contact via WhatsApp</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        ) : (
          <span className="text-center text-xs text-slate-400 py-2">WhatsApp unavailable</span>
        )}
      </div>

      {/* 4. Live Chat Card */}
      <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-xs hover:shadow-sm transition-all flex flex-col justify-between">
        <div>
          <div className="w-10 h-10 rounded-xl bg-cyan-50 border border-cyan-100 flex items-center justify-center text-cyan-600 mb-4">
            <MessageSquare className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-slate-900 mb-1">Live Chat</h3>
          <p className="text-xs text-slate-500 mb-3 leading-relaxed">
            Real-time chat with our cybersecurity technical team.
          </p>
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-100 mb-4">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Support Desk • {config.supportHours || '24/7 Operations'}</span>
          </div>
        </div>
        <button
          type="button"
          onClick={onStartChatClick}
          className="inline-flex items-center justify-center gap-1.5 w-full py-2 px-3 text-xs font-bold text-cyan-700 bg-cyan-50 hover:bg-cyan-100 rounded-xl transition-colors cursor-pointer"
        >
          <span>Start Live Chat</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
