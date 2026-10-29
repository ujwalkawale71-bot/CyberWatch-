import { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  ArrowRight,
  RotateCcw,
} from 'lucide-react';

interface Scenario {
  id: string;
  title: string;
  lureType: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  isPhishing: boolean;
  senderName: string;
  senderEmail: string;
  subject: string;
  date: string;
  bodySnippet: string;
  actionUrl: string;
  actionButtonText: string;
  redFlags: string[];
  authenticSigns: string[];
  technicalExplanation: string;
}

const SCENARIOS: Scenario[] = [
  {
    id: 'payroll-update',
    title: 'Urgent Direct Deposit Re-Verification',
    lureType: 'Financial Urgency & Credential Harvesting',
    difficulty: 'Beginner',
    isPhishing: true,
    senderName: 'Internal HR Payroll Team',
    senderEmail: 'hr-payroll@payro11-internal-corp.com',
    subject: 'ACTION REQUIRED: Confirm your direct deposit details within 24 hours',
    date: 'Today, 08:42 AM',
    bodySnippet:
      'We noticed an error in your recent tax withholding profile. To prevent missed payroll disbursements for the upcoming pay cycle, you must confirm your banking credentials immediately.',
    actionUrl: 'https://payro11-internal-corp.com/login/auth-verify?uid=99281',
    actionButtonText: 'Verify Direct Deposit Portal',
    redFlags: [
      'Sender domain uses typo-squatting ("payro11" with two ones instead of letters "ll")',
      'Artificial deadline pressure ("within 24 hours to prevent missed pay")',
      'Demands credentials via an external link rather than standard authenticated HR portal',
      'Generic greeting and urgent tone designed to induce panic',
    ],
    authenticSigns: [],
    technicalExplanation:
      'This is a classic credential harvesting campaign targeting employee payroll accounts. Attackers register typo-squatted domains containing numbers substituted for letters and create fake single-sign-on login pages.',
  },
  {
    id: 'cloud-alert-legit',
    title: 'Legitimate Cloud Provider Storage Notice',
    lureType: 'Routine Infrastructure Notification',
    difficulty: 'Intermediate',
    isPhishing: false,
    senderName: 'Google Cloud Platform',
    senderEmail: 'cloud-notifications@google.com',
    subject: 'Storage quota warning for project: analytics-prod-01',
    date: 'Yesterday, 03:15 PM',
    bodySnippet:
      'Your Cloud Storage bucket "prod-backups" has reached 88% of configured quota. You can review your usage and adjust lifecycle rules in your Google Cloud Console at any time.',
    actionUrl: 'https://console.cloud.google.com/storage/browser/prod-backups',
    actionButtonText: 'Open Cloud Console',
    redFlags: [],
    authenticSigns: [
      'Sender domain matches official root domain (google.com) with valid SPF/DKIM/DMARC headers',
      'Link targets official HTTPS endpoint (console.cloud.google.com) without redirects',
      'No coercive deadline or threat of immediate account suspension',
      'References specific, accurate internal project metadata without demanding password re-entry',
    ],
    technicalExplanation:
      'This is an authentic system notification. Notice that it does not ask for emergency credential input and directs users strictly to the official authenticated subdomain.',
  },
  {
    id: 'package-delivery-sms',
    title: 'Failed Delivery & Customs Fee Request',
    lureType: 'Parcel Delivery & Payment Extortion',
    difficulty: 'Beginner',
    isPhishing: true,
    senderName: 'Express Parcel Tracking',
    senderEmail: 'notifications@delivery-tracking-update77.info',
    subject: 'Package ID #US-991823: Delivery on hold (Unpaid $1.85 fee)',
    date: '2 hours ago',
    bodySnippet:
      'Your shipment could not be delivered due to an incomplete street address and an outstanding customs processing fee of $1.85. Update your details to authorize redelivery.',
    actionUrl: 'https://tinyurl.com/express-parcel-customs-pay',
    actionButtonText: 'Pay $1.85 & Authorize Delivery',
    redFlags: [
      'Obfuscated destination URL using generic URL shortener (tinyurl.com)',
      'Sender uses disposable .info domain unrelated to any legitimate national postal carrier',
      'Micro-payment trap ($1.85 fee) designed to harvest full credit card numbers and CVVs',
      'Vague package identifier sent without recipient having ordered corresponding cross-border items',
    ],
    authenticSigns: [],
    technicalExplanation:
      'Delivery fee scams are among the highest volume consumer threats. The minor fee is psychological bait: users consider $1.85 insignificant, but entering credit card details yields full card data to card-skimming operations.',
  },
  {
    id: 'mfa-session-reset',
    title: 'Suspicious Session & Multi-Factor Reset Prompt',
    lureType: 'Session Hijacking & Adversary-in-the-Middle (AiTM)',
    difficulty: 'Advanced',
    isPhishing: true,
    senderName: 'Microsoft 365 Security Team',
    senderEmail: 'security-alerts@microsoft-session-support.org',
    subject: 'Suspicious sign-in blocked from Frankfurt, Germany: Reset MFA Token',
    date: 'Today, 11:05 AM',
    bodySnippet:
      'A login attempt from IP 185.220.101.5 was blocked. Your Multi-Factor Authentication device token has been temporarily revoked. You must re-authenticate your authenticator app now to maintain account access.',
    actionUrl: 'https://login.microsoftonline.com.auth-token-refresh.xyz/common/oauth2',
    actionButtonText: 'Re-authenticate MFA Token',
    redFlags: [
      'Subdomain spoofing: "login.microsoftonline.com" is actually a subdomain of the attacker-controlled root domain "auth-token-refresh.xyz"',
      'Sender uses .org domain ("microsoft-session-support.org") instead of official microsoft.com infrastructure',
      'Adversary-in-the-Middle (AiTM) proxy tactic designed to capture both password and real-time TOTP/push codes',
    ],
    authenticSigns: [],
    technicalExplanation:
      'This is an advanced AiTM (Adversary-in-the-Middle) phishing attempt. Attackers create realistic subdomains mimicking legitimate login portals to proxy authentication requests and capture session cookies in real time.',
  },
];

export function PhishingQuiz() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [answers, setAnswers] = useState<Record<string, boolean | null>>({});

  const scenario = SCENARIOS[currentIndex];
  const currentAnswer = answers[scenario.id];
  const hasAnswered = currentAnswer !== undefined && currentAnswer !== null;
  const isCorrect = hasAnswered && currentAnswer === scenario.isPhishing;

  function handleAnswer(chosePhishing: boolean) {
    setAnswers((prev) => ({ ...prev, [scenario.id]: chosePhishing }));
  }

  function handleNext() {
    if (currentIndex < SCENARIOS.length - 1) {
      setCurrentIndex(currentIndex + 1);
    }
  }

  function handlePrevious() {
    if (currentIndex > 0) {
      setCurrentIndex(currentIndex - 1);
    }
  }

  function handleReset() {
    setAnswers({});
    setCurrentIndex(0);
  }

  const completedCount = Object.keys(answers).length;
  const correctCount = Object.entries(answers).filter(
    ([id, ans]) => ans === SCENARIOS.find((s) => s.id === id)?.isPhishing
  ).length;

  return (
    <div className="space-y-6">
      {/* Simulation Notice Banner */}
      <div className="p-3.5 rounded-xl bg-amber-50/70 border border-amber-200 flex items-start gap-3">
        <Info className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-900 leading-relaxed">
          <span className="font-bold">SIMULATED TRAINING EXERCISE — Not a live threat: </span>
          The examples below are curated educational scenarios designed to train your threat detection skills.
          Never enter real credentials or execute actions on unverified emails.
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
        {/* Quiz Progress Header */}
        <div className="p-4 sm:p-6 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-blue-600">
                Interactive Training Module
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-xs font-semibold text-slate-500">
                Scenario {currentIndex + 1} of {SCENARIOS.length}
              </span>
            </div>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 mt-1">
              "Would You Trust This?"
            </h3>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-xs text-slate-500 text-right">
              <div>Progress: <span className="font-bold text-slate-900">{completedCount} / {SCENARIOS.length}</span></div>
              <div>Score: <span className="font-bold text-emerald-600">{correctCount} correct</span></div>
            </div>

            <button
              onClick={handleReset}
              className="p-2 text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 rounded-lg transition-colors"
              title="Reset quiz"
              aria-label="Reset training quiz"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Email Simulation Card */}
        <div className="p-6 md:p-8 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b border-slate-100 text-xs">
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-500">CATEGORY:</span>
              <span className="bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-medium">
                {scenario.lureType}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-500">DIFFICULTY:</span>
              <span className="bg-blue-50 text-blue-700 border border-blue-200 px-2 py-0.5 rounded font-bold">
                {scenario.difficulty}
              </span>
            </div>
          </div>

          {/* Email Client Wrapper */}
          <div className="border border-slate-200 rounded-xl bg-slate-50/50 p-4 sm:p-6 space-y-4">
            <div className="space-y-2 text-xs">
              <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2">
                <span className="font-bold text-slate-500 w-16 shrink-0">From:</span>
                <span className="font-semibold text-slate-900">{scenario.senderName}</span>
                <span className="text-slate-500 font-mono text-[11px]">&lt;{scenario.senderEmail}&gt;</span>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2">
                <span className="font-bold text-slate-500 w-16 shrink-0">Subject:</span>
                <span className="font-bold text-slate-900">{scenario.subject}</span>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2">
                <span className="font-bold text-slate-500 w-16 shrink-0">Date:</span>
                <span className="text-slate-500">{scenario.date}</span>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-200 text-sm text-slate-700 leading-relaxed space-y-4">
              <p>{scenario.bodySnippet}</p>

              <div className="pt-2">
                <div className="inline-block p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
                  <div className="text-xs font-bold text-blue-600 underline">
                    [{scenario.actionButtonText}]
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 bg-slate-100 px-2.5 py-1 rounded border border-slate-200 break-all">
                    Link Destination: {scenario.actionUrl}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* User Decision Buttons */}
          {!hasAnswered ? (
            <div className="pt-4 flex flex-col sm:flex-row items-center gap-4">
              <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                What is your verdict?
              </span>

              <div className="flex items-center gap-3 w-full sm:w-auto">
                <button
                  type="button"
                  onClick={() => handleAnswer(true)}
                  className="flex-1 sm:flex-initial inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white text-xs sm:text-sm font-bold rounded-xl transition-colors shadow-xs"
                >
                  <ShieldAlert className="w-4 h-4" />
                  <span>Flag as Phishing / Deceptive</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleAnswer(false)}
                  className="flex-1 sm:flex-initial inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 text-white text-xs sm:text-sm font-bold rounded-xl transition-colors shadow-xs"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>Trust as Legitimate</span>
                </button>
              </div>
            </div>
          ) : (
            /* Result and Explanation Section */
            <div className="space-y-6 pt-2">
              <div
                className={`p-4 rounded-xl border flex items-start gap-3.5 ${
                  isCorrect
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
                    : 'bg-red-50 border-red-200 text-red-950'
                }`}
              >
                {isCorrect ? (
                  <CheckCircle2 className="w-6 h-6 text-emerald-600 shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-6 h-6 text-red-600 shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="text-sm font-bold">
                    {isCorrect ? 'Correct Decision!' : 'Security Detection Missed!'}
                  </div>
                  <div className="text-xs mt-1 leading-relaxed">
                    This message was actually{' '}
                    <span className="font-bold">
                      {scenario.isPhishing ? 'A MALICIOUS PHISHING ATTEMPT' : 'A LEGITIMATE NOTIFICATION'}
                    </span>.
                  </div>
                </div>
              </div>

              {/* Technical Analysis Breakdown */}
              <div className="bg-slate-50 rounded-xl p-5 border border-slate-200 space-y-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-blue-600" />
                  <span>Security Analysis &amp; Technical Breakdown</span>
                </h4>

                <p className="text-xs text-slate-700 leading-relaxed">
                  {scenario.technicalExplanation}
                </p>

                {scenario.isPhishing && scenario.redFlags.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-slate-200/80">
                    <div className="text-xs font-bold text-red-700 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>Key Red Flags in this Target:</span>
                    </div>
                    <ul className="list-disc list-inside space-y-1 text-xs text-slate-600 pl-1">
                      {scenario.redFlags.map((flag, idx) => (
                        <li key={idx}>{flag}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {!scenario.isPhishing && scenario.authenticSigns.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-slate-200/80">
                    <div className="text-xs font-bold text-emerald-700 flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Verified Authentic Indicators:</span>
                    </div>
                    <ul className="list-disc list-inside space-y-1 text-xs text-slate-600 pl-1">
                      {scenario.authenticSigns.map((sign, idx) => (
                        <li key={idx}>{sign}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Navigation Controls */}
              <div className="flex items-center justify-between pt-2">
                <button
                  type="button"
                  onClick={handlePrevious}
                  disabled={currentIndex === 0}
                  className="px-4 py-2 border border-slate-200 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-50 disabled:opacity-40 disabled:pointer-events-none transition-colors"
                >
                  ← Previous Example
                </button>

                {currentIndex < SCENARIOS.length - 1 ? (
                  <button
                    type="button"
                    onClick={handleNext}
                    className="inline-flex items-center gap-1.5 px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-xl transition-colors shadow-xs"
                  >
                    <span>Next Example</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={handleReset}
                    className="inline-flex items-center gap-1.5 px-5 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-xl transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Restart Training</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
