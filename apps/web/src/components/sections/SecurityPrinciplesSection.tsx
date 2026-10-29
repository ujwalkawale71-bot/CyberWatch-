import { Container } from '../ui/Container'
import { EyeOff, Search, MessageSquare, Layers } from 'lucide-react'

const principles = [
  {
    icon: EyeOff,
    title: 'Privacy-Aware',
    desc: 'Minimize unnecessary data exposure during analysis.',
  },
  {
    icon: Search,
    title: 'Evidence-Driven',
    desc: 'Base security decisions on observable, verifiable indicators.',
  },
  {
    icon: MessageSquare,
    title: 'Transparent',
    desc: 'Explain why a result was produced, not just what it is.',
  },
  {
    icon: Layers,
    title: 'Layered',
    desc: 'Use multiple security signals instead of relying on a single check.',
  },
]

export function SecurityPrinciplesSection() {
  return (
    <section className="py-16 md:py-20 bg-slate-900 border-t border-slate-800" id="security-principles">
      <Container>
        <div className="text-center mb-12 max-w-xl mx-auto">
          <h2 className="text-2xl md:text-3xl font-bold text-white mb-3">Security Principles</h2>
          <p className="text-slate-400 text-sm leading-relaxed">
            The values that guide how CyberWatch approaches security analysis.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {principles.map((p, i) => (
            <div
              key={i}
              className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-6 hover:border-blue-500/30 transition-all duration-200"
            >
              <div className="bg-blue-600/10 w-10 h-10 rounded-lg flex items-center justify-center border border-blue-500/20 mb-4">
                <p.icon className="w-4 h-4 text-blue-400" />
              </div>
              <h3 className="text-sm font-semibold text-white mb-1.5">{p.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{p.desc}</p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  )
}
