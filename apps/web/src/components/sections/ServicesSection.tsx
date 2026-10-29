import { Container } from '../ui/Container'
import { Globe, ShieldAlert, Terminal, FileSearch, Puzzle } from 'lucide-react'

const services = [
  {
    icon: Globe,
    name: 'URL & Phishing Mega Scanner',
    desc: 'Unified security intelligence for URLs, domains, redirects, page structure, and phishing indicators.',
  },
  {
    icon: ShieldAlert,
    name: 'Website Security Scanner',
    desc: 'Review public web security configurations, HTTP headers, cookies, scripts, and TLS parameters.',
  },
  {
    icon: Terminal,
    name: 'API Security Scanner',
    desc: 'Audit API endpoints for CORS misconfigurations, exposed backend info, headers, and access controls.',
  },
  {
    icon: FileSearch,
    name: 'File Security Scanner',
    desc: 'Analyze downloadable assets for high-risk executable extensions, MIME mismatches, and format anomalies.',
  },
  {
    icon: Puzzle,
    name: 'Browser Extension Scanner',
    desc: 'Audit browser extensions and Manifest V3 metadata for high-risk permissions and scope combinations.',
  },
];

export function ServicesSection() {
  return (
    <section className="py-20 md:py-28 bg-slate-50/60 border-t border-slate-100" id="services">
      <Container>
        <div className="text-center mb-14 max-w-2xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-xs font-semibold mb-6">
            Security Services
          </div>
          <h2 className="text-3xl md:text-4xl font-bold text-slate-900 leading-tight mb-4">
            Security Services Built for the Modern Web
          </h2>
          <p className="text-lg text-slate-500 leading-relaxed">
            Analyze web destinations across multiple security layers from one platform.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {services.map((s, i) => (
            <div
              key={i}
              className="bg-white rounded-xl border border-slate-100 p-6 shadow-sm hover:shadow-md hover:border-blue-100 transition-all duration-200 flex flex-col gap-4"
            >
              <div className="bg-blue-50 w-11 h-11 rounded-lg flex items-center justify-center border border-blue-100/60 shrink-0">
                <s.icon className="w-5 h-5 text-blue-600" />
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-slate-900 mb-1.5">{s.name}</h3>
                <p className="text-[13px] text-slate-500 leading-relaxed">{s.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </Container>
    </section>
  )
}
