import { Shield, Lock, CheckCircle2, Plus } from 'lucide-react';
import type { User } from '../../types';

interface DashboardHeaderProps {
  user: User | null;
  onScanClick?: () => void;
}

export function DashboardHeader({ user, onScanClick }: DashboardHeaderProps) {
  // Use authenticated user's actual name, or email prefix fallback
  const userName = user?.name?.trim() || user?.email?.split('@')[0] || 'User';

  // Dynamic greeting based on current local hour
  const currentHour = new Date().getHours();
  let timeGreeting = 'Good morning';
  if (currentHour >= 12 && currentHour < 17) {
    timeGreeting = 'Good afternoon';
  } else if (currentHour >= 17 || currentHour < 4) {
    timeGreeting = 'Good evening';
  }

  const headingText = `${timeGreeting}, ${userName}`;

  return (
    <div className="bg-gradient-to-br from-blue-50/70 via-white to-sky-50/50 rounded-3xl p-6 sm:p-8 lg:p-10 border border-blue-100/90 shadow-sm relative overflow-hidden transition-all duration-300">
      {/* Subtle light circular background elements */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-blue-100/30 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
      <div className="absolute bottom-0 left-1/3 w-64 h-64 bg-sky-100/30 rounded-full blur-2xl pointer-events-none -mb-20" />

      <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
        {/* Left Column: Greeting, Subtitle, Context Message & Action */}
        <div className="max-w-2xl space-y-4">
          {/* Small dashboard & platform badge */}
          <div className="flex items-center gap-2">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-100/80 text-blue-700 text-xs font-bold uppercase tracking-wider border border-blue-200/60">
              <span className="w-2 h-2 rounded-full bg-blue-600 inline-block animate-pulse" />
              CyberWatch Security Dashboard
            </div>
          </div>

          {/* Main Heading */}
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-900 tracking-tight">
            {headingText}
          </h1>

          {/* Subheading & Contextual Security Message */}
          <div className="space-y-1.5">
            <p className="text-slate-700 text-sm sm:text-base font-medium">
              Here&apos;s your security activity for today.
            </p>
            <p className="text-slate-500 text-xs sm:text-sm leading-relaxed">
              Monitor, analyze and understand your digital security activity with CyberWatch.
            </p>
          </div>

          {/* Action Row: Prominent + Scan a URL button & small trust badge */}
          <div className="pt-2 flex flex-wrap items-center gap-3">
            <button
              id="dashboard-header-scan-btn"
              type="button"
              onClick={() => {
                if (onScanClick) {
                  onScanClick();
                } else {
                  const input = document.getElementById('dashboard-url-input');
                  if (input) {
                    input.focus();
                    input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                  }
                }
              }}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white text-sm font-bold rounded-xl shadow-md shadow-blue-600/20 hover:shadow-blue-600/30 transition-all duration-200 transform hover:-translate-y-0.5"
            >
              <Plus className="w-4 h-4 stroke-[3]" />
              <span>+ Scan a URL</span>
            </button>

            <div className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-white/80 border border-slate-200/80 text-xs font-medium text-slate-600 shadow-xs">
              <Shield className="w-3.5 h-3.5 text-blue-600" />
              <span>Unified Web &amp; Browser Protection</span>
            </div>
          </div>
        </div>

        {/* Right Side Security Visual: Laptop/browser screen + Cyber shield + subtle circular security elements */}
        <div className="shrink-0 w-full lg:w-auto flex justify-center lg:justify-end">
          <div className="relative w-72 sm:w-80 h-44 sm:h-48 flex items-center justify-center">
            {/* Subtle concentric circular security ripples */}
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="w-48 h-48 rounded-full border border-blue-200/50 animate-[pulse_4s_ease-in-out_infinite]" />
              <div className="absolute w-60 h-60 rounded-full border border-blue-100/60" />
              <div className="absolute w-72 h-72 rounded-full border border-slate-100" />
            </div>

            {/* Laptop / Browser Screen Graphic */}
            <div className="relative z-10 w-64 sm:w-72 bg-white rounded-2xl border border-blue-200/80 shadow-lg shadow-blue-500/10 p-3.5 space-y-2.5">
              {/* Browser window header with dots & address bar */}
              <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-400/80" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400/80" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400/80" />
                </div>
                <div className="flex-1 flex items-center gap-1 bg-slate-50 border border-slate-200/70 rounded-md px-2 py-0.5 text-[10px] text-slate-500 font-mono">
                  <Lock className="w-2.5 h-2.5 text-emerald-600 shrink-0" />
                  <span className="truncate">cyberwatch.security/guard</span>
                </div>
              </div>

              {/* Security Shield & Status Inside Screen */}
              <div className="flex items-center gap-3 bg-gradient-to-r from-blue-50/80 to-sky-50/60 rounded-xl p-2.5 border border-blue-100">
                <div className="relative shrink-0">
                  <div className="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-md shadow-blue-500/30">
                    <Shield className="w-5 h-5" />
                  </div>
                  <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-emerald-500 border-2 border-white flex items-center justify-center">
                    <CheckCircle2 className="w-2.5 h-2.5 text-white" />
                  </div>
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="text-[11px] font-bold text-slate-900 tracking-tight">Active Perimeter</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-0.5">Continuous Threat Analysis</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
