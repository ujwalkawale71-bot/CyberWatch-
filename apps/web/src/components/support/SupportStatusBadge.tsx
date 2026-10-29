import { cn } from '../../lib/utils';
import type { SupportStatus, SupportPriority, SupportCategory, SecurityReportSeverity } from '../../types';
import {
  Clock,
  Search,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  UserCheck,
} from 'lucide-react';

export function SupportStatusBadge({ status, className }: { status: SupportStatus; className?: string }) {
  const configs: Record<SupportStatus, { label: string; bg: string; text: string; border: string; icon: any }> = {
    OPEN: {
      label: 'Open',
      bg: 'bg-blue-50',
      text: 'text-blue-700',
      border: 'border-blue-200',
      icon: Clock,
    },
    INVESTIGATING: {
      label: 'Investigating',
      bg: 'bg-amber-50',
      text: 'text-amber-700',
      border: 'border-amber-200',
      icon: Search,
    },
    WAITING_FOR_USER: {
      label: 'Waiting for User',
      bg: 'bg-purple-50',
      text: 'text-purple-700',
      border: 'border-purple-200',
      icon: UserCheck,
    },
    RESOLVED: {
      label: 'Resolved',
      bg: 'bg-emerald-50',
      text: 'text-emerald-700',
      border: 'border-emerald-200',
      icon: CheckCircle2,
    },
    CLOSED: {
      label: 'Closed',
      bg: 'bg-slate-100',
      text: 'text-slate-600',
      border: 'border-slate-200',
      icon: XCircle,
    },
  };

  const config = configs[status] || configs.OPEN;
  const Icon = config.icon;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border',
        config.bg,
        config.text,
        config.border,
        className
      )}
    >
      <Icon className="w-3.5 h-3.5" />
      <span>{config.label}</span>
    </span>
  );
}

export function SupportPriorityBadge({ priority, className }: { priority: SupportPriority; className?: string }) {
  const configs: Record<SupportPriority, { label: string; bg: string; text: string; border: string }> = {
    LOW: {
      label: 'Low',
      bg: 'bg-slate-50',
      text: 'text-slate-600',
      border: 'border-slate-200',
    },
    MEDIUM: {
      label: 'Medium',
      bg: 'bg-blue-50',
      text: 'text-blue-700',
      border: 'border-blue-200',
    },
    HIGH: {
      label: 'High',
      bg: 'bg-amber-50',
      text: 'text-amber-700',
      border: 'border-amber-200',
    },
    URGENT: {
      label: 'Urgent',
      bg: 'bg-rose-50',
      text: 'text-rose-700',
      border: 'border-rose-200',
    },
  };

  const config = configs[priority] || configs.MEDIUM;

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-bold uppercase tracking-wider border',
        config.bg,
        config.text,
        config.border,
        className
      )}
    >
      {config.label}
    </span>
  );
}

export function SecuritySeverityBadge({ severity, className }: { severity: SecurityReportSeverity; className?: string }) {
  const configs: Record<SecurityReportSeverity, { label: string; bg: string; text: string; border: string }> = {
    LOW: {
      label: 'Low Severity',
      bg: 'bg-blue-50',
      text: 'text-blue-700',
      border: 'border-blue-200',
    },
    MEDIUM: {
      label: 'Medium Severity',
      bg: 'bg-amber-50',
      text: 'text-amber-700',
      border: 'border-amber-200',
    },
    HIGH: {
      label: 'High Severity',
      bg: 'bg-orange-50',
      text: 'text-orange-700',
      border: 'border-orange-200',
    },
    CRITICAL: {
      label: 'Critical Severity',
      bg: 'bg-rose-50',
      text: 'text-rose-700',
      border: 'border-rose-200',
    },
  };

  const config = configs[severity] || configs.MEDIUM;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider border',
        config.bg,
        config.text,
        config.border,
        className
      )}
    >
      <ShieldAlert className="w-3.5 h-3.5" />
      <span>{config.label}</span>
    </span>
  );
}

export function formatCategoryLabel(category: SupportCategory): string {
  const labels: Record<SupportCategory, string> = {
    SCANNER_ISSUE: 'Scanner Problem',
    INCORRECT_SCAN_RESULT: 'Incorrect Scan Result',
    THREAT_INTELLIGENCE: 'Threat Intelligence Inquiry',
    REPORT_EXPORT: 'Report / Export Issue',
    ACCOUNT_LOGIN: 'Account & Access',
    BILLING_SUBSCRIPTION: 'Billing & Plan',
    TECHNICAL_ISSUE: 'Technical Investigation',
    FEATURE_REQUEST: 'Feature Request',
    SECURITY_VULNERABILITY: 'Security Vulnerability Disclosure',
    OTHER: 'General Support',
  };
  return labels[category] || category;
}
