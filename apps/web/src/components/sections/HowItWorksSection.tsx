import { Container } from '../ui/Container'
import { Search, Activity, CheckCircle, MessageSquare } from 'lucide-react'

const steps = [
  {
    number: '01',
    icon: Search,
    title: 'Submit',
    desc: 'Enter a URL or security target into CyberWatch.',
  },
  {
    number: '02',
    icon: Activity,
    title: 'Analyze',
    desc: 'CyberWatch runs multiple security checks across layers.',
  },
  {
    number: '03',
    icon: CheckCircle,
    title: 'Evaluate',
    desc: 'Security evidence is combined into a unified risk assessment.',
  },
  {
    number: '04',
    icon: MessageSquare,
    title: 'Understand',
    desc: 'Clear findings explain what was detected and why it matters.',
  },
]

export function HowItWorksSection() {
  return (
    <section className="py-20 md:py-28 bg-white border-t border-slate-100" id="how-it-works">
      <Container>
        <div className="text-center mb-14 max-w-xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-6">
            How It Works
          </div>
          <h2 className="text-3xl md:text-4xl font-bold text-slate-900 leading-tight mb-4">
            One Platform. Multiple Security Layers.
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 relative">
          {/* Connector line (desktop) */}
          <div className="hidden lg:block absolute top-10 left-[calc(12.5%+1rem)] right-[calc(12.5%+1rem)] h-px bg-slate-200 z-0" />

          {steps.map((step, i) => (
            <div key={i} className="relative z-10 flex flex-col items-center text-center">
              {/* Step number circle */}
              <div className="w-20 h-20 rounded-full bg-white border-2 border-blue-100 flex flex-col items-center justify-center mb-5 shadow-sm">
                <span className="text-[10px] font-bold text-blue-400 tracking-widest">{step.number}</span>
                <step.icon className="w-5 h-5 text-blue-600 mt-0.5" />
              </div>
              <h3 className="text-base font-semibold text-slate-900 mb-2">{step.title}</h3>
              <p className="text-[13px] text-slate-500 leading-relaxed max-w-[200px]">{step.desc}</p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  )
}
