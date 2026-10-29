import { Link } from 'react-router-dom';
import { ArrowRight, Globe, AlertTriangle, ShieldCheck, CheckCircle2 } from 'lucide-react';
import type { ScanStats } from '../../types';

interface SecurityOverviewProps {
  stats: ScanStats | null;
  isLoading: boolean;
}

export function SecurityOverview({ stats, isLoading }: SecurityOverviewProps) {
  const scansTodayVal = stats?.scansToday !== undefined ? stats.scansToday : (stats?.totalScans !== undefined ? stats.totalScans : 0);
  const securityFindingsVal = stats?.securityFindings !== undefined ? stats.securityFindings : (stats?.threatsDetected !== undefined ? stats.threatsDetected : 0);
  const safeResultsVal = stats?.safeResults !== undefined ? stats.safeResults : Math.max(0, (stats?.totalScans || 0) - (stats?.threatsDetected || 0));
  const monitoringStatusVal = stats?.monitoringStatus || stats?.activeMonitoring || 'Active';

  const cards = [
    {
      id: 'stat-scans-today',
      title: 'Scans Today',
      value: isLoading ? '...' : scansTodayVal.toString(),
      subtitle: scansTodayVal === 1 ? '1 scan analyzed today' : `${scansTodayVal} scans analyzed today`,
      actionLabel: 'View Today\'s Scans',
      actionHref: '/activity?timeframe=today',
      icon: Globe,
      color: 'text-blue-600',
      bg: 'bg-blue-50/80 border-blue-100',
    },
    {
      id: 'stat-security-findings',
      title: 'Security Findings',
      value: isLoading ? '...' : securityFindingsVal.toString(),
      subtitle: securityFindingsVal === 0 ? 'No active threats detected' : `${securityFindingsVal} findings flagged`,
      actionLabel: 'Review Findings',
      actionHref: '/activity?type=findings',
      icon: AlertTriangle,
      color: securityFindingsVal > 0 ? 'text-amber-600' : 'text-slate-400',
      bg: securityFindingsVal > 0 ? 'bg-amber-50/80 border-amber-100' : 'bg-slate-50 border-slate-100',
    },
    {
      id: 'stat-safe-results',
      title: 'Safe Results',
      value: isLoading ? '...' : safeResultsVal.toString(),
      subtitle: `${safeResultsVal} verified safe targets`,
      actionLabel: 'View Safe Logs',
      actionHref: '/reports/history',
      icon: CheckCircle2,
      color: 'text-emerald-600',
      bg: 'bg-emerald-50/80 border-emerald-100',
    },
    {
      id: 'stat-monitoring-status',
      title: 'Monitoring Status',
      value: isLoading ? '...' : monitoringStatusVal,
      subtitle: 'Real-time perimeter guard',
      actionLabel: 'Security Settings',
      actionHref: '/help',
      icon: ShieldCheck,
      color: 'text-emerald-600',
      bg: 'bg-emerald-50/80 border-emerald-100',
      isStatusBadge: true,
    },
  ];

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-1">
        <div>
          <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight">
            Today&apos;s Security Overview
          </h2>
          <p className="text-sm text-slate-500 mt-0.5">
            Real-time breakdown of your security workload, findings, and monitoring status.
          </p>
        </div>
        <span className="text-xs font-semibold text-slate-400 hidden sm:inline">
          Live Backend Telemetry
        </span>
      </div>

      {/* 4 Horizontal Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.id}
              id={card.id}
              className="bg-white border border-slate-200/90 rounded-2xl p-5 sm:p-6 flex flex-col justify-between gap-4 shadow-sm hover:shadow-md hover:border-slate-300 transition-all duration-200 group"
            >
              {/* Card Top: Title & Icon */}
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-600 uppercase tracking-wider">
                  {card.title}
                </span>
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${card.bg}`}>
                  <Icon className={`w-5 h-5 ${card.color}`} />
                </div>
              </div>

              {/* Card Middle: Value & Subtitle */}
              <div>
                {card.isStatusBadge ? (
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse inline-block" />
                    <span className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
                      {card.value}
                    </span>
                  </div>
                ) : (
                  <div className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
                    {card.value}
                  </div>
                )}
                <p className="text-xs text-slate-400 mt-1 font-medium">
                  {card.subtitle}
                </p>
              </div>

              {/* Card Bottom: Action Link */}
              <div className="pt-3 border-t border-slate-100">
                <Link
                  to={card.actionHref}
                  className="inline-flex items-center gap-1.5 text-xs font-bold text-blue-600 group-hover:text-blue-700 transition-colors"
                >
                  <span>{card.actionLabel}</span>
                  <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                </Link>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
