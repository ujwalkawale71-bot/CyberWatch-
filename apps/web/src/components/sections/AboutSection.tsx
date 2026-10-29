import { Container } from '../ui/Container'
import { ShieldCheck, Search, BarChart3, Lightbulb } from 'lucide-react'

const pillars = [
  { icon: ShieldCheck, label: 'Multi-Layer Detection', desc: 'Multiple security checks per scan' },
  { icon: Search, label: 'Evidence-Based Analysis', desc: 'Grounded in observable indicators' },
  { icon: BarChart3, label: 'Risk Assessment', desc: 'Unified risk scoring per target' },
  { icon: Lightbulb, label: 'Security Insights', desc: 'Findings explained in plain language' },
]

export function AboutSection() {
  return (
    <section className="py-20 md:py-28 bg-white" id="about">
      <Container>
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left */}
          <div className="max-w-xl">
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-6">
              About CyberWatch
            </div>
            <h2 className="text-3xl md:text-4xl font-bold text-slate-900 leading-tight mb-6">
              Security That Helps You Understand the Web
            </h2>
            <p className="text-lg text-slate-600 leading-relaxed mb-4">
              CyberWatch is a unified web and browser threat detection platform designed to analyze websites, URLs, domains, browser activity, and files through multiple security layers.
            </p>
            <p className="text-base text-slate-500 leading-relaxed">
              Rather than presenting a simple pass/fail result, CyberWatch combines security evidence from multiple checks into understandable risk information — so users can see not just what was detected, but why it matters.
            </p>
          </div>

          {/* Right — Capability Card */}
          <div className="bg-slate-50 border border-slate-100 rounded-2xl p-8 shadow-sm">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-6">Platform Capabilities</p>
            <div className="space-y-4">
              {pillars.map((p, i) => (
                <div key={i} className="flex items-start gap-4 bg-white rounded-xl px-5 py-4 border border-slate-100 shadow-sm hover:border-blue-100 hover:shadow-md transition-all duration-200">
                  <div className="bg-blue-50 p-2.5 rounded-lg shrink-0 border border-blue-100/60">
                    <p.icon className="w-4 h-4 text-blue-600" />
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-slate-900">{p.label}</div>
                    <div className="text-xs text-slate-500 mt-0.5">{p.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Container>
    </section>
  )
}
