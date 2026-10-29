import { useState } from 'react';
import {
  ShieldAlert,
  Send,
  AlertCircle,
  Lock,
  Shield,
} from 'lucide-react';
import type {
  SecurityVulnerabilityType,
  SecurityReportSeverity,
  SecurityReport,
  SupportPublicConfig,
} from '../../types';
import { SECURITY_VULNERABILITY_TYPES, SECURITY_REPORT_SEVERITIES } from '../../types';
import { supportService } from '../../services/support.service';
import { AttachmentUploader } from './AttachmentUploader';

interface SecurityReportFormProps {
  config: SupportPublicConfig;
  onSuccess?: (report: SecurityReport) => void;
  defaultEmail?: string;
}

export function SecurityReportForm({ config, onSuccess, defaultEmail = '' }: SecurityReportFormProps) {
  const [email, setEmail] = useState(defaultEmail);
  const [vulnerabilityType, setVulnerabilityType] = useState<SecurityVulnerabilityType>('AUTHENTICATION');
  const [severity, setSeverity] = useState<SecurityReportSeverity>('MEDIUM');
  const [affectedComponent, setAffectedComponent] = useState('');
  const [affectedUrl, setAffectedUrl] = useState('');
  const [description, setDescription] = useState('');
  const [stepsToReproduce, setStepsToReproduce] = useState('');
  const [impact, setImpact] = useState('');
  const [suggestedFix, setSuggestedFix] = useState('');
  const [attachments, setAttachments] = useState<File[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submittedReport, setSubmittedReport] = useState<SecurityReport | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email.trim() || !/^\S+@\S+\.\S+$/.test(email.trim())) {
      setError('Please provide a valid security contact email address.');
      return;
    }

    if (affectedComponent.trim().length < 2) {
      setError('Please specify the affected component or subsystem.');
      return;
    }

    if (description.trim().length < 20) {
      setError('Vulnerability description must be at least 20 characters.');
      return;
    }

    if (stepsToReproduce.trim().length < 20) {
      setError('Steps to reproduce must be at least 20 characters for technical verification.');
      return;
    }

    if (impact.trim().length < 10) {
      setError('Security impact assessment must be at least 10 characters.');
      return;
    }

    try {
      setIsSubmitting(true);
      const report = await supportService.createSecurityReport({
        email: email.trim(),
        vulnerabilityType,
        severity,
        affectedComponent: affectedComponent.trim(),
        affectedUrl: affectedUrl.trim() || undefined,
        description: description.trim(),
        stepsToReproduce: stepsToReproduce.trim(),
        impact: impact.trim(),
        suggestedFix: suggestedFix.trim() || undefined,
      });

      setSubmittedReport(report);
      if (onSuccess) onSuccess(report);
    } catch (err: any) {
      const msg =
        err?.response?.data?.message ||
        err?.message ||
        'Security disclosure submission failed. Please check network connectivity.';
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (submittedReport) {
    return (
      <div className="bg-white border border-slate-200/90 rounded-2xl p-8 sm:p-10 shadow-sm text-center space-y-5">
        <div className="w-14 h-14 rounded-2xl bg-rose-50 border border-rose-100 flex items-center justify-center text-rose-600 mx-auto">
          <Shield className="w-7 h-7" />
        </div>

        <div className="max-w-md mx-auto space-y-2">
          <span className="text-[11px] font-mono font-bold uppercase tracking-wider px-3 py-1 rounded-full bg-rose-50 text-rose-700 border border-rose-200">
            CONFIDENTIAL DISCLOSURE RECEIVED
          </span>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900">
            Thank you for responsible disclosure
          </h2>
          <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
            Your report has been encrypted and routed directly to the CyberWatch Security Response Team.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 max-w-sm mx-auto text-left space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="text-slate-500">Report Reference:</span>
            <span className="font-mono font-bold text-rose-700 select-all">{submittedReport.reportNumber}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="text-slate-500">Severity Rating:</span>
            <span className="font-bold text-slate-800">{submittedReport.severity}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="text-slate-500">Status:</span>
            <span className="font-semibold text-emerald-700">{submittedReport.status}</span>
          </div>
        </div>

        <button
          type="button"
          onClick={() => {
            setSubmittedReport(null);
            setDescription('');
            setStepsToReproduce('');
            setImpact('');
            setSuggestedFix('');
            setAttachments([]);
          }}
          className="px-5 py-2.5 text-xs font-bold text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-xl transition-colors border border-slate-200 cursor-pointer"
        >
          Submit Another Disclosure
        </button>
      </div>
    );
  }

  return (
    <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 lg:p-10 shadow-sm space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-50 border border-rose-200 text-rose-700 text-xs font-semibold mb-2">
            <Lock className="w-3.5 h-3.5" />
            <span>CONFIDENTIAL SECURITY DISCLOSURE CHANNEL</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900">Report a Security Vulnerability</h2>
          <p className="text-xs sm:text-sm text-slate-600 mt-1 max-w-xl leading-relaxed">
            If you believe you have discovered a security vulnerability affecting CyberWatch systems, please submit technical
            details below. We practice coordinated vulnerability disclosure.
          </p>
        </div>

        <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 text-left shrink-0">
          <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Security Contact</p>
          <p className="text-xs font-mono font-bold text-rose-700 select-all mt-0.5">
            {config.securityEmail || 'Confidential Security Desk'}
          </p>
        </div>
      </div>

      {error && (
        <div className="flex items-start gap-2.5 p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Row 1: Email & Vulnerability Type */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1.5">
              Contact Email <span className="text-rose-600">*</span>
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="security-researcher@domain.com"
              className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-rose-500/30 focus:border-rose-500"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1.5">
              Vulnerability Classification <span className="text-rose-600">*</span>
            </label>
            <select
              value={vulnerabilityType}
              onChange={(e) => setVulnerabilityType(e.target.value as SecurityVulnerabilityType)}
              className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:ring-2 focus:ring-rose-500/30 focus:border-rose-500"
            >
              {SECURITY_VULNERABILITY_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Row 2: Severity & Affected Component */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1.5">
              Assessed Severity <span className="text-rose-600">*</span>
            </label>
            <div className="grid grid-cols-4 gap-2">
              {SECURITY_REPORT_SEVERITIES.map((sev) => {
                const isSelected = severity === sev;
                return (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSeverity(sev)}
                    className={`py-2 text-xs font-bold rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? sev === 'CRITICAL'
                          ? 'bg-rose-600 text-white border-rose-600'
                          : sev === 'HIGH'
                          ? 'bg-orange-600 text-white border-orange-600'
                          : sev === 'MEDIUM'
                          ? 'bg-amber-600 text-white border-amber-600'
                          : 'bg-emerald-600 text-white border-emerald-600'
                        : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
                    }`}
                  >
                    {sev}
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1.5">
              Affected Component / Feature <span className="text-rose-600">*</span>
            </label>
            <input
              type="text"
              required
              value={affectedComponent}
              onChange={(e) => setAffectedComponent(e.target.value)}
              placeholder="e.g. API Scanner JWT parser / URL Redirect Engine"
              className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-rose-500/30 focus:border-rose-500"
            />
          </div>
        </div>

        {/* Row 3: Affected URL */}
        <div>
          <label className="block text-xs font-bold text-slate-700 mb-1.5">
            Affected Endpoint or URL <span className="text-slate-400">(Optional)</span>
          </label>
          <input
            type="url"
            value={affectedUrl}
            onChange={(e) => setAffectedUrl(e.target.value)}
            placeholder="https://app.cyberwatch.security/api/v1/..."
            className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-rose-500/30 focus:border-rose-500"
          />
        </div>

        {/* Row 4: Summary Description */}
        <div>
          <label className="block text-xs font-bold text-slate-700 mb-1.5">
            Technical Vulnerability Summary <span className="text-rose-600">*</span>
          </label>
          <textarea
            required
            rows={3}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Provide a clear, high-level summary of the vulnerability, root cause, and prerequisite conditions..."
            className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-rose-500/30 focus:border-rose-500"
          />
        </div>

        {/* Row 5: Steps to Reproduce */}
        <div>
          <label className="block text-xs font-bold text-slate-700 mb-1.5">
            Step-by-Step Reproduction Proof-of-Concept <span className="text-rose-600">*</span>
          </label>
          <textarea
            required
            rows={4}
            value={stepsToReproduce}
            onChange={(e) => setStepsToReproduce(e.target.value)}
            placeholder="1. Send HTTP POST request with payload...&#10;2. Observe unhandled response...&#10;3. Verify authorization bypass state..."
            className="w-full px-3.5 py-2.5 text-xs font-mono rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-rose-500/30 focus:border-rose-500"
          />
        </div>

        {/* Row 6: Impact & Suggested Fix */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1.5">
              Security Impact Assessment <span className="text-rose-600">*</span>
            </label>
            <textarea
              required
              rows={3}
              value={impact}
              onChange={(e) => setImpact(e.target.value)}
              placeholder="Explain the potential risk, confidentiality, integrity, or availability impact if exploited..."
              className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-rose-500/30 focus:border-rose-500"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1.5">
              Suggested Technical Remediation <span className="text-slate-400">(Optional)</span>
            </label>
            <textarea
              rows={3}
              value={suggestedFix}
              onChange={(e) => setSuggestedFix(e.target.value)}
              placeholder="e.g. Implement strict HMAC verification prior to parsing payload..."
              className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-rose-500/30 focus:border-rose-500"
            />
          </div>
        </div>

        {/* Attachments */}
        <div className="pt-2">
          <label className="block text-xs font-bold text-slate-700 mb-2">
            Proof of Concept Attachments (Screenshots, Logs, HTTP Requests)
          </label>
          <AttachmentUploader
            files={attachments}
            onChange={setAttachments}
            maxFiles={3}
          />
        </div>

        {/* Submit Button */}
        <div className="pt-4 border-t border-slate-100 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-[11px] text-slate-500">
            <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
            <span>Encrypted transmission with strict responsible disclosure confidentiality.</span>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 bg-rose-600 hover:bg-rose-700 active:bg-rose-800 disabled:opacity-60 text-white font-bold text-xs px-6 py-3 rounded-xl shadow-xs transition-colors cursor-pointer"
          >
            <Send className="w-4 h-4" />
            <span>{isSubmitting ? 'Encrypting & Transmitting...' : 'Submit Confidential Report'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
