import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { Container } from '../components/ui/Container';
import { DashboardHeader } from '../components/dashboard/DashboardHeader';
import { URLScannerCard } from '../components/dashboard/URLScannerCard';
import { SecurityOverview } from '../components/dashboard/SecurityOverview';
import { CurrentSecurityStatus } from '../components/dashboard/CurrentSecurityStatus';
import { SecurityActivityList } from '../components/dashboard/SecurityActivityList';
import { RecentScansTable } from '../components/dashboard/RecentScansTable';
import { SecurityAnalysisSection } from '../components/dashboard/SecurityAnalysisSection';
import { AttentionRequired } from '../components/dashboard/AttentionRequired';
import { scanService } from '../services/scan.service';
import type { ScanRecord, ScanStats } from '../types';

export function DashboardPage() {
  const { user } = useAuth();

  const [stats, setStats] = useState<ScanStats | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [hasError, setHasError] = useState(false);

  const fetchDashboardData = useCallback(async () => {
    setHasError(false);
    try {
      const [statsRes, scansRes] = await Promise.all([
        scanService.getScanStats(),
        scanService.getRecentScans(10, 1),
      ]);
      setStats(statsRes);
      setScans(scansRes.scans);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      setHasError(true);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();

    function handleVisibility() {
      if (document.visibilityState === 'visible') {
        fetchDashboardData();
      }
    }

    window.addEventListener('focus', handleVisibility);
    document.addEventListener('visibilitychange', handleVisibility);
    return () => {
      window.removeEventListener('focus', handleVisibility);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [fetchDashboardData]);

  function handleFocusScanner() {
    const input = document.getElementById('dashboard-url-input');
    if (input) {
      input.focus();
      input.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }

  // Get the latest scan record for real posture evaluation
  const latestScan = scans.length > 0 ? scans[0] : (stats?.latestScan || null);

  return (
    <div className="min-h-screen bg-slate-50/60 pb-24 pt-24 sm:pt-28">
      <Container>
        <div className="space-y-10">
          {/* 1. Welcome & Greeting Header */}
          <DashboardHeader user={user} onScanClick={handleFocusScanner} />

          {/* 2. Primary URL / Target Scanner Card */}
          <URLScannerCard onScanComplete={fetchDashboardData} />

          {/* Error Banner if API Fails */}
          {hasError && (
            <div className="bg-rose-50 border border-rose-200 text-rose-800 rounded-2xl p-4 text-sm flex items-center justify-between">
              <span>Unable to load latest security activity. Please check your connection.</span>
              <button
                type="button"
                onClick={fetchDashboardData}
                className="font-bold underline hover:text-rose-900 ml-4"
              >
                Retry
              </button>
            </div>
          )}

          {/* 3. Today's Security Overview (4 real metrics) */}
          <SecurityOverview stats={stats} isLoading={isLoading} />

          {/* 4. Two-Column Row: Current Security Status + Your Security Activity */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <CurrentSecurityStatus
              latestScan={latestScan}
              stats={stats}
              isLoading={isLoading}
            />
            <SecurityActivityList
              scans={scans}
              isLoading={isLoading}
              onScanClick={handleFocusScanner}
            />
          </div>

          {/* 5. Recent Scans Table */}
          <RecentScansTable
            scans={scans}
            isLoading={isLoading}
            onScanFirstUrl={handleFocusScanner}
          />

          {/* 6. Security Analysis Categorized Panels (No Scan Now buttons) */}
          <SecurityAnalysisSection />

          {/* 7. Attention Required Contextual Section */}
          <AttentionRequired scans={scans} isLoading={isLoading} />
        </div>
      </Container>
    </div>
  );
}
