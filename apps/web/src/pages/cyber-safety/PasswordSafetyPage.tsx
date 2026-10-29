import { Key } from 'lucide-react';
import { Container } from '../../components/ui/Container';
import { CyberSafetyHeader } from '../../components/cyber-safety/CyberSafetyHeader';
import { PasswordStrengthMeter } from '../../components/cyber-safety/PasswordStrengthMeter';

export function PasswordSafetyPage() {
  const fundamentals = [
    {
      title: 'Generate Unique Passwords for Every Account',
      desc: 'Credential stuffing attacks reuse leaked email/password pairs across thousands of services. A breach at an obscure service must never compromise your primary identity.',
    },
    {
      title: 'Prefer Long Multi-Word Passphrases',
      desc: 'Length exponentially dominates entropy. A 4-word random passphrase (e.g., "beacon-crystal-pathway-quantum-42") possesses superior entropy compared to a complex 8-character password.',
    },
    {
      title: 'Never Reuse Important Passwords',
      desc: 'Strictly isolate credentials for your primary email, banking portals, cloud identity providers, and password manager master keys.',
    },
    {
      title: 'Adopt a Reputable Password Manager',
      desc: 'Humans cannot memorize hundreds of high-entropy 20-character strings. A password manager generates, encrypts, and auto-fills credentials securely.',
    },
    {
      title: 'Enforce Multi-Factor Authentication (MFA)',
      desc: 'Always pair credentials with strong MFA (FIDO2/WebAuthn hardware security keys or authenticator apps like TOTP), avoiding SMS-based verification where possible.',
    },
    {
      title: 'Rotate Compromised Credentials Promptly',
      desc: 'If a service notifies you of a security incident or if your credentials appear in threat telemetry, immediately change the password and revoke active sessions.',
    },
  ];

  const strengthTiers = [
    {
      tier: 'Weak',
      bits: '< 36 bits entropy',
      crackTime: 'Instant to seconds',
      description: 'Short passwords (< 8 chars), common dictionary words, or predictable sequences (e.g., "Password123"). Easily cracked by automated brute-force tools.',
      color: 'border-red-200 bg-red-50/50 text-red-900',
      badgeColor: 'bg-red-100 text-red-700',
    },
    {
      tier: 'Moderate',
      bits: '36 – 56 bits entropy',
      crackTime: 'Minutes to hours',
      description: 'Passwords with 8–11 mixed characters without common words. Vulnerable to GPU-accelerated hashcat clusters and targeted hybrid dictionary attacks.',
      color: 'border-amber-200 bg-amber-50/50 text-amber-900',
      badgeColor: 'bg-amber-100 text-amber-700',
    },
    {
      tier: 'Strong',
      bits: '56 – 80 bits entropy',
      crackTime: 'Months to centuries',
      description: '14+ character strings or 3-word passphrases with mixed character spaces. Resilient against offline rainbow tables and brute force.',
      color: 'border-blue-200 bg-blue-50/50 text-blue-900',
      badgeColor: 'bg-blue-100 text-blue-700',
    },
    {
      tier: 'Very Strong',
      bits: '80+ bits entropy',
      crackTime: 'Millions of centuries',
      description: '16+ character complex strings or 4+ word random dictionary passphrases. Mathematically infeasible to crack through any modern offline attack.',
      color: 'border-emerald-200 bg-emerald-50/50 text-emerald-900',
      badgeColor: 'bg-emerald-100 text-emerald-700',
    },
  ];

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20">
      <CyberSafetyHeader
        title="Password Safety"
        subtitle="Strengthen credential architecture, understand mathematical entropy, and eliminate single-point account takeover risks."
        breadcrumbs={[{ label: 'Cyber Safety', href: '/cyber-safety' }]}
        primaryCta={{
          label: 'Run Security Checkup',
          href: '/cyber-safety/security-checkup',
          icon: Key,
        }}
      />

      <Container className="py-8 md:py-10 space-y-10">
        {/* ── Client-Side Password Analyzer Component ────────────── */}
        <section className="space-y-4">
          <div>
            <h2 className="text-xl font-bold text-slate-900">
              Interactive Client-Side Entropy Analyzer
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-0.5">
              Calculate search-space entropy and offline crack times with zero network transmission.
            </p>
          </div>

          <PasswordStrengthMeter />
        </section>

        {/* ── Password Fundamentals ──────────────────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
              Best Practice Principles
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Password Fundamentals
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Core operational disciplines to defend against credential harvesting and account takeover.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {fundamentals.map((item, idx) => (
              <div key={idx} className="p-5 rounded-xl bg-slate-50 border border-slate-200/80 space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-md bg-blue-100 text-blue-700 font-bold text-xs flex items-center justify-center shrink-0">
                    {idx + 1}
                  </div>
                  <h3 className="text-sm font-bold text-slate-900">{item.title}</h3>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed pt-1">
                  {item.desc}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Password Strength Guidance Matrix ───────────────────── */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-blue-600 mb-1">
              Mathematical Model
            </div>
            <h2 className="text-xl font-bold text-slate-900">
              Password Strength &amp; Entropy Guidance
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              How search-space entropy correlates to practical attack resistance.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {strengthTiers.map((tier, idx) => (
              <div key={idx} className={`p-5 rounded-xl border flex flex-col justify-between space-y-4 ${tier.color}`}>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className={`text-xs font-bold px-2 py-0.5 rounded ${tier.badgeColor}`}>
                      {tier.tier}
                    </span>
                    <span className="text-[11px] font-mono font-semibold">
                      {tier.bits}
                    </span>
                  </div>
                  <div className="text-xs font-bold text-slate-800">
                    Crack Time: <span className="font-normal">{tier.crackTime}</span>
                  </div>
                  <p className="text-xs leading-relaxed opacity-90">
                    {tier.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>
      </Container>
    </div>
  );
}
