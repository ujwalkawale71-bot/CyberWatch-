import { Container } from '../ui/Container'
import { Globe, Shield, Lock, EyeOff } from 'lucide-react'
import { Link } from 'react-router-dom'

const topics = [
  {
    icon: Globe,
    title: 'Safe Browsing',
    desc: 'Learn how to recognize suspicious websites and links before you click.',
    href: '/cyber-safety/safe-browsing',
  },
  {
    icon: Shield,
    title: 'Phishing Awareness',
    desc: 'Understand common phishing patterns and warning signs to protect yourself.',
    href: '/cyber-safety/phishing-awareness',
  },
  {
    icon: Lock,
    title: 'Browser Security',
    desc: 'Improve your browser\'s security and privacy settings for safer sessions.',
    href: '/cyber-safety/browser-security',
  },
  {
    icon: EyeOff,
    title: 'Online Privacy',
    desc: 'Learn practical ways to protect personal information online.',
    href: '/cyber-safety/online-privacy',
  },
]

export function CyberSafetySection() {
  return (
    <section className="py-20 md:py-28 bg-white border-t border-slate-100" id="cyber-safety">
      <Container>
        <div className="text-center mb-14 max-w-xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-6">
            Cyber Safety Center
          </div>
          <h2 className="text-3xl md:text-4xl font-bold text-slate-900 leading-tight mb-4">
            Stay Safer on the Web
          </h2>
          <p className="text-base text-slate-500 leading-relaxed">
            Practical security guidance, protection checks, and actionable recommendations to reduce everyday cyber risk.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-10">
          {topics.map((t, i) => (
            <Link
              key={i}
              to={t.href}
              className="group bg-slate-50 rounded-xl border border-slate-100 p-6 hover:bg-white hover:border-blue-100 hover:shadow-md transition-all duration-200 flex flex-col gap-4"
            >
              <div className="bg-white w-11 h-11 rounded-lg flex items-center justify-center border border-slate-200 group-hover:border-blue-200 transition-colors shrink-0">
                <t.icon className="w-5 h-5 text-blue-600" />
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-slate-900 mb-1.5 group-hover:text-blue-700 transition-colors">{t.title}</h3>
                <p className="text-[13px] text-slate-500 leading-relaxed">{t.desc}</p>
              </div>
            </Link>
          ))}
        </div>

        <div className="text-center">
          <Link
            to="/cyber-safety"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-sm transition-all shadow-sm shadow-blue-500/20"
          >
            <span>Explore Cyber Safety Center</span>
          </Link>
        </div>
      </Container>
    </section>
  )
}
