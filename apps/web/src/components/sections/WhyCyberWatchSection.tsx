import { Container } from '../ui/Container'
import { Search, BarChart3, MessageSquare, Shield } from 'lucide-react'

const benefits = [
  {
    icon: Search,
    title: 'Evidence-Based Analysis',
    desc: 'Security findings are backed by observable indicators, not assumptions.',
  },
  {
    icon: BarChart3,
    title: 'Unified Risk Assessment',
    desc: 'Multiple security layers contribute to one understandable result.',
  },
  {
    icon: MessageSquare,
    title: 'Clear Explanations',
    desc: 'Technical findings are presented in language users can understand.',
  },
  {
    icon: Shield,
    title: 'Centralized Protection',
    desc: 'Web and browser security workflows can work through one platform.',
  },
]

export function WhyCyberWatchSection() {
  return (
    <section className="py-20 md:py-28 bg-slate-50/60 border-t border-slate-100" id="why-cyberwatch">
      <Container>
        <div className="text-center mb-14 max-w-xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-6">
            Why CyberWatch
          </div>
          <h2 className="text-3xl md:text-4xl font-bold text-slate-900 leading-tight">
            Built to Make Security Easier to Understand
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {benefits.map((b, i) => (
            <div
              key={i}
              className="bg-white rounded-xl border border-slate-100 p-7 shadow-sm hover:shadow-md hover:border-blue-100 transition-all duration-200"
            >
              <div className="bg-blue-50 w-11 h-11 rounded-lg flex items-center justify-center border border-blue-100/60 mb-5">
                <b.icon className="w-5 h-5 text-blue-600" />
              </div>
              <h3 className="text-[15px] font-semibold text-slate-900 mb-2">{b.title}</h3>
              <p className="text-[13px] text-slate-500 leading-relaxed">{b.desc}</p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  )
}
