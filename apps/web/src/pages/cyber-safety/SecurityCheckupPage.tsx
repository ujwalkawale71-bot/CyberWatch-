import { useSearchParams } from 'react-router-dom';
import {
  Shield,
  BookOpen,
  Bell,
} from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { CyberSafetyHeader } from '../../components/cyber-safety/CyberSafetyHeader';
import { CheckupScannerRunner, type CheckupTargetCategory } from '../../components/cyber-safety/CheckupScannerRunner';

export function SecurityCheckupPage() {
  const [searchParams] = useSearchParams();
  const targetParam = (searchParams.get('type') as CheckupTargetCategory) || 'URL';

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      <CyberSafetyHeader
        title="Security Checkup"
        subtitle="Guided, evidence-backed security assessment connecting your targets directly to CyberWatch detection engines."
        breadcrumbs={[{ label: 'Cyber Safety', href: '/cyber-safety' }]}
        primaryCta={{
          label: 'Explore Safety Guides',
          href: '/cyber-safety/guides',
          icon: BookOpen,
        }}
        secondaryCta={{
          label: 'View Safety Alerts',
          href: '/cyber-safety/alerts',
          icon: Bell,
        }}
      />

      <Container className="py-8 md:py-10 space-y-10">
        {/* ── Guidance Banner ─────────────────────────────────────── */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex items-start gap-4">
          <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center shrink-0 text-blue-600">
            <Shield className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Empirical Evidence-Based Evaluation
            </h2>
            <p className="text-xs text-slate-600 leading-relaxed">
              CyberWatch Security Checkup executes real-time security scans across our 6 specialized engines and multi-source Threat Intelligence feeds.
              We never fabricate scores or assume safety without verifiable technical evidence.
            </p>
          </div>
        </div>

        {/* ── Guided Assessment Engine ────────────────────────────── */}
        <CheckupScannerRunner initialTargetType={targetParam} />
      </Container>
    </div>
  );
}
