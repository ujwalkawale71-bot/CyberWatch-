import { Headphones, MessageSquare, ShieldAlert, CheckCircle } from 'lucide-react';
import type { SupportPublicConfig } from '../../types';

interface SupportHeroProps {
  config: SupportPublicConfig;
  onStartTicketClick: () => void;
  onLiveChatClick: () => void;
  onSecurityReportClick: () => void;
}

export function SupportHero({
  config,
  onStartTicketClick,
  onLiveChatClick,
  onSecurityReportClick,
}: SupportHeroProps) {
  return (
    <div className="relative overflow-hidden bg-white rounded-3xl p-8 sm:p-10 lg:p-12 shadow-sm border border-slate-200/90">
      {/* Subtle soft gradient highlight */}
      <div className="absolute top-0 right-0 -mt-16 -mr-16 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 left-0 -mb-16 -ml-16 w-80 h-80 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="relative z-10 max-w-3xl">
        {/* Badges */}
        <div className="flex flex-wrap items-center gap-2.5 mb-5">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-50 border border-cyan-200/80 text-cyan-800 text-xs font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>CyberWatch Support Desk • {config.supportHours || '24/7 Operations'}</span>
          </div>

          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200 text-slate-700 text-xs font-medium">
            <CheckCircle className="w-3.5 h-3.5 text-cyan-600" />
            <span>Technical Security Engineering Team</span>
          </div>
        </div>

        {/* Title */}
        <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-slate-900 leading-tight mb-4">
          Help &amp; Support Center
        </h1>

        {/* Description */}
        <p className="text-sm sm:text-base text-slate-600 leading-relaxed mb-8 max-w-2xl">
          Get assistance with CyberWatch security scanners, vulnerability findings, threat intelligence reports, account access, and technical investigations.
        </p>

        {/* Primary Action Buttons */}
        <div className="flex flex-wrap items-center gap-3 sm:gap-4">
          <button
            type="button"
            onClick={onStartTicketClick}
            className="inline-flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-700 active:bg-cyan-800 text-white font-bold text-sm px-6 py-3 rounded-xl shadow-sm transition-all duration-150 cursor-pointer"
          >
            <Headphones className="w-4 h-4" />
            <span>Start a Support Request</span>
          </button>

          <button
            type="button"
            onClick={onLiveChatClick}
            className="inline-flex items-center justify-center gap-2 bg-slate-100 hover:bg-slate-200/80 active:bg-slate-200 text-slate-800 font-semibold text-sm px-5 py-3 rounded-xl border border-slate-200/80 transition-all duration-150 cursor-pointer"
          >
            <MessageSquare className="w-4 h-4 text-cyan-600" />
            <span>Start Live Chat</span>
          </button>

          <button
            type="button"
            onClick={onSecurityReportClick}
            className="inline-flex items-center justify-center gap-2 bg-rose-50 hover:bg-rose-100/80 border border-rose-200 text-rose-700 font-semibold text-sm px-4 py-3 rounded-xl transition-all duration-150 cursor-pointer"
          >
            <ShieldAlert className="w-4 h-4 text-rose-600" />
            <span>Report Vulnerability</span>
          </button>
        </div>
      </div>
    </div>
  );
}
