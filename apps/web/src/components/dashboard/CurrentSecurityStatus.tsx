import { Link } from 'react-router-dom';
import { Shield, ShieldCheck, ShieldAlert, AlertTriangle, ArrowRight, Clock, Info } from 'lucide-react';
import type { ScanRecord, ScanStats } from '../../types';

interface CurrentSecurityStatusProps {
  latestScan: ScanRecord | null | undefined;
  stats: ScanStats | null;
  isLoading: boolean;
}

export function CurrentSecurityStatus({ latestScan, stats, isLoading }: CurrentSecurityStatusProps) {
  if (isLoading) {
    return (
      <div className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-7 shadow-sm flex flex-col justify-center items-center gap-3 min-h-[200px]">
        <div className="w-8 h-8 border-3 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
        <p className="text-xs text-slate-400 font-medium">Evaluating posture...</p>
      </div>
    );
  }

  // Determine posture strictly from real scan data
  const hasScans = Boolean(latestScan || (stats && stats.totalScans > 0));

  let statusLevel: 'none' | 'safe' | 'low' | 'medium' | 'high' | 'critical' = 'none';

  if (hasScans && latestScan) {
    const verdict = latestScan.result.toLowerCase();
    if (verdict === 'critical') statusLevel = 'critical';
    else if (verdict === 'high risk') statusLevel = 'high';
    else if (verdict === 'suspicious') statusLevel = 'medium';
    else if (verdict === 'low risk') statusLevel = 'low';
    else statusLevel = 'safe';
  }

  const statusConfig = {
    none: {
      badge: 'No Recent Activity',
      badgeClass: 'bg-slate-100 text-slate-700 border-slate-200',
      title: 'No Recent Security Activity',
      description: 'Run a security assessment against a URL, website, or domain to establish your baseline security posture.',
      icon: Shield,
      iconColor: 'text-slate-400',
      iconBg: 'bg-slate-100 border-slate-200',
      ringColor: 'border-slate-200',
      textColor: 'text-slate-700',
    },
    safe: {
      badge: 'Low Risk',
      badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      title: 'Standard Security Posture',
      description: 'Your recent scans show no critical anomalies, active deceptive forms, or unencrypted transport flags.',
      icon: ShieldCheck,
      iconColor: 'text-emerald-600',
      iconBg: 'bg-emerald-50 border-emerald-200',
      ringColor: 'border-emerald-200/80',
      textColor: 'text-emerald-800',
    },
    low: {
      badge: 'Low Risk',
      badgeClass: 'bg-cyan-50 text-cyan-700 border-cyan-200',
      title: 'Low Risk Baseline',
      description: 'Minor non-critical indicators detected (e.g. uncommon TLD). Overall target integrity remains stable.',
      icon: ShieldCheck,
      iconColor: 'text-cyan-600',
      iconBg: 'bg-cyan-50 border-cyan-200',
      ringColor: 'border-cyan-200/80',
      textColor: 'text-cyan-800',
    },
    medium: {
      badge: 'Medium Risk',
      badgeClass: 'bg-amber-50 text-amber-700 border-amber-200',
      title: 'Suspicious Indicators Flagged',
      description: 'Recent analysis detected potential deception, credential keywords, or unencrypted communications requiring review.',
      icon: AlertTriangle,
      iconColor: 'text-amber-600',
      iconBg: 'bg-amber-50 border-amber-200',
      ringColor: 'border-amber-200/80',
      textColor: 'text-amber-800',
    },
    high: {
      badge: 'High Risk',
      badgeClass: 'bg-orange-50 text-orange-700 border-orange-200',
      title: 'High Risk Indicators Detected',
      description: 'Elevated threat signals found in recent scans. Verify target origin and avoid submitting sensitive credentials.',
      icon: ShieldAlert,
      iconColor: 'text-orange-600',
      iconBg: 'bg-orange-50 border-orange-200',
      ringColor: 'border-orange-200/80',
      textColor: 'text-orange-800',
    },
    critical: {
      badge: 'Critical Risk',
      badgeClass: 'bg-rose-50 text-rose-700 border-rose-200',
      title: 'Critical Threat Level',
      description: 'Active malicious flags or phishing characteristics detected in analyzed targets. Immediate isolation recommended.',
      icon: ShieldAlert,
      iconColor: 'text-rose-600',
      iconBg: 'bg-rose-50 border-rose-200',
      ringColor: 'border-rose-200/80',
      textColor: 'text-rose-800',
    },
  }[statusLevel];

  const Icon = statusConfig.icon;

  function formatTime(dateValue?: string | Date | null) {
    if (!dateValue) return 'N/A';
    const d = new Date(dateValue);
    if (isNaN(d.getTime())) return 'N/A';
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  return (
    <div className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-7 shadow-sm flex flex-col justify-between gap-6 transition-all duration-300">
      {/* Top Header */}
      <div className="flex items-center justify-between">
        <div>
          <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block">
            Posture Assessment
          </span>
          <h3 className="text-lg font-bold text-slate-900 tracking-tight mt-0.5">
            Current Security Status
          </h3>
        </div>

        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${statusConfig.badgeClass}`}>
          <span className={`w-2 h-2 rounded-full ${statusLevel === 'none' ? 'bg-slate-400' : statusLevel === 'safe' || statusLevel === 'low' ? 'bg-emerald-500' : 'bg-amber-500'} inline-block`} />
          {statusConfig.badge}
        </span>
      </div>

      {/* Center Visual & Details */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5 py-2">
        {/* Shield Visual with concentric circle */}
        <div className="relative shrink-0 flex items-center justify-center">
          <div className={`w-16 h-16 rounded-2xl flex items-center justify-center border-2 ${statusConfig.iconBg} shadow-xs`}>
            <Icon className={`w-8 h-8 ${statusConfig.iconColor}`} />
          </div>
          <div className={`absolute -inset-1 rounded-3xl border ${statusConfig.ringColor} pointer-events-none opacity-60`} />
        </div>

        {/* Text & Posture info */}
        <div className="space-y-1.5 flex-1">
          <h4 className={`text-base font-bold ${statusConfig.textColor}`}>
            {statusConfig.title}
          </h4>
          <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
            {statusConfig.description}
          </p>

          {/* Last Analyzed metadata */}
          <div className="pt-2 flex flex-wrap items-center gap-4 text-[11px] text-slate-500 font-medium">
            <div className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span>
                Last analyzed: {formatTime(latestScan?.scannedAt || latestScan?.createdAt || stats?.lastScannedAt)}
              </span>
            </div>

            {latestScan && (
              <div className="flex items-center gap-1 text-slate-600 font-semibold truncate max-w-[200px]">
                <span>Target:</span>
                <span className="truncate text-blue-700">{latestScan.target}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Card Footer: Action + Security Notice */}
      <div className="pt-4 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
          <Info className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <span>Postures reflect heuristic and rule-based evaluation of user scans.</span>
        </div>

        {latestScan ? (
          <Link
            to={`/reports/scans/${latestScan.id}`}
            state={{ scan: latestScan }}
            className="inline-flex items-center gap-1 font-bold text-blue-600 hover:text-blue-700 shrink-0 group"
          >
            <span>View Security Report</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
          </Link>
        ) : (
          <Link
            to="/reports/history"
            className="inline-flex items-center gap-1 font-bold text-blue-600 hover:text-blue-700 shrink-0 group"
          >
            <span>Scan Audit Trail</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
          </Link>
        )}
      </div>
    </div>
  );
}
