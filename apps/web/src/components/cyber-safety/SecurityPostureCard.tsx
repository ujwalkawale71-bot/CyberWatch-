import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  ShieldCheck,
  ArrowRight,
  RefreshCw,
  HelpCircle,
} from 'lucide-react';
import { scanService } from '../../services/scan.service';
import type { ScanRecord, ScanStats } from '../../types';

export function SecurityPostureCard() {
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [stats, setStats] = useState<ScanStats | null>(null);

  useEffect(() => {
    let mounted = true;
    async function loadData() {
      try {
        setLoading(true);
        const [recentRes, statsRes] = await Promise.allSettled([
          scanService.getRecentScans(10, 1),
          scanService.getScanStats(),
        ]);

        if (mounted) {
          if (recentRes.status === 'fulfilled') {
            setScans(recentRes.value.scans || []);
          }
          if (statsRes.status === 'fulfilled') {
            setStats(statsRes.value);
          }
        }
      } catch (err) {
        console.error('Failed to load posture data', err);
      } finally {
        if (mounted) setLoading(false);
      }
    }
    loadData();
    return () => {
      mounted = false;
    };
  }, []);

  // Compute verified metrics ONLY from actual recorded scans
  const hasScans = scans.length > 0;

  // Calculate assessed posture only when data exists
  const evaluatedTargetTypes = Array.from(new Set(scans.map((s) => s.targetType)));
  const totalAvailablePillars = 6; // URL, Website, Phishing, File, Extension, API
  const checksCompletedCount = evaluatedTargetTypes.length;

  // Verified risk score average:
  // In CyberWatch risk score 0 = Lowest Risk, 100 = Highest Risk.
  // Security Posture Score (0-100 where 100 is healthiest posture):
  const avgRiskScore = hasScans
    ? Math.round(scans.reduce((acc, s) => acc + s.riskScore, 0) / scans.length)
    : 0;
  const postureScore = Math.max(0, 100 - avgRiskScore);

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (avgRiskScore > 75) riskLevel = 'CRITICAL';
  else if (avgRiskScore > 50) riskLevel = 'HIGH';
  else if (avgRiskScore > 25) riskLevel = 'MEDIUM';
  else riskLevel = 'LOW';

  const riskBadgeStyles = {
    LOW: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    MEDIUM: 'bg-amber-50 text-amber-700 border-amber-200',
    HIGH: 'bg-orange-50 text-orange-700 border-orange-200',
    CRITICAL: 'bg-red-50 text-red-700 border-red-200',
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-100">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center shrink-0 text-blue-600">
            {hasScans ? <ShieldCheck className="w-6 h-6 text-blue-600" /> : <Shield className="w-6 h-6 text-slate-400" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-900 uppercase tracking-wider">
                Your Security Posture
              </h2>
              <span
                className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${
                  hasScans ? 'bg-blue-50 text-blue-700 border-blue-200' : 'bg-slate-100 text-slate-600 border-slate-200'
                }`}
              >
                {loading ? 'ANALYZING...' : hasScans ? 'ASSESSED' : 'NOT ASSESSED'}
              </span>
            </div>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              {hasScans
                ? 'Derived strictly from your verified CyberWatch security scans and evaluated targets.'
                : 'Run a Security Checkup or scan your active assets to evaluate your security posture.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <Link
            to="/cyber-safety/security-checkup"
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white text-xs sm:text-sm font-bold rounded-xl transition-colors shadow-xs"
          >
            <span>{hasScans ? 'Update Checkup' : 'Start Security Checkup'}</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      {loading ? (
        <div className="py-12 flex flex-col items-center justify-center text-center space-y-3">
          <RefreshCw className="w-6 h-6 text-blue-600 animate-spin" />
          <p className="text-xs text-slate-500 font-medium">Loading verified security telemetry...</p>
        </div>
      ) : !hasScans ? (
        /* State: NOT ASSESSED */
        <div className="pt-6 grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          <div className="md:col-span-2 space-y-3">
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80">
              <div className="flex items-start gap-3">
                <HelpCircle className="w-5 h-5 text-slate-400 shrink-0 mt-0.5" />
                <div className="text-xs text-slate-600 leading-relaxed">
                  <span className="font-bold text-slate-800">No active scan telemetry detected. </span>
                  CyberWatch never fabricates security metrics or assumes safe status without empirical scan evidence.
                  Choose a target type below to begin your first assessment.
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 pt-1">
              <span className="font-semibold text-slate-700">Available Scanners:</span>
              <span className="bg-slate-100 text-slate-600 px-2 py-0.5 rounded">URL &amp; Phishing</span>
              <span className="bg-slate-100 text-slate-600 px-2 py-0.5 rounded">Website Security</span>
              <span className="bg-slate-100 text-slate-600 px-2 py-0.5 rounded">Browser Extension</span>
              <span className="bg-slate-100 text-slate-600 px-2 py-0.5 rounded">File Security</span>
              <span className="bg-slate-100 text-slate-600 px-2 py-0.5 rounded">API Endpoint</span>
            </div>
          </div>

          <div className="bg-slate-50 rounded-xl p-4 border border-slate-200/60 text-center space-y-2">
            <div className="text-2xl font-bold text-slate-400">-- / 100</div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
              Posture Score
            </div>
            <div className="text-[11px] text-slate-400">
              0 of {totalAvailablePillars} target pillars assessed
            </div>
          </div>
        </div>
      ) : (
        /* State: ASSESSED (Strictly verified data) */
        <div className="pt-6 grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 flex flex-col justify-between">
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">
              Security Posture
            </div>
            <div className="my-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-slate-900">{postureScore}</span>
              <span className="text-sm font-semibold text-slate-400">/ 100</span>
            </div>
            <div className="text-[11px] text-slate-500">
              Calculated across {scans.length} verified scan{scans.length === 1 ? '' : 's'}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 flex flex-col justify-between">
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">
              Assessed Risk Level
            </div>
            <div className="my-2">
              <span className={`inline-block text-xs font-bold px-2.5 py-1 rounded-md border ${riskBadgeStyles[riskLevel]}`}>
                {riskLevel} RISK
              </span>
            </div>
            <div className="text-[11px] text-slate-500">
              Avg target risk index: {avgRiskScore} / 100
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 flex flex-col justify-between">
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">
              Pillars Assessed
            </div>
            <div className="my-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-blue-600">{checksCompletedCount}</span>
              <span className="text-sm font-semibold text-slate-400">/ {totalAvailablePillars}</span>
            </div>
            <div className="text-[11px] text-slate-500">
              {evaluatedTargetTypes.join(', ')}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 flex flex-col justify-between">
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">
              Verified Threats Flagged
            </div>
            <div className="my-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-slate-900">
                {stats?.threatsDetected ?? scans.filter((s) => s.riskScore >= 50).length}
              </span>
              <span className="text-xs font-semibold text-slate-400">detected</span>
            </div>
            <Link
              to="/reports/findings"
              className="text-[11px] font-bold text-blue-600 hover:text-blue-700 flex items-center gap-1"
            >
              <span>View Security Findings</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
