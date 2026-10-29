import { Container } from '../ui/Container'
import { Button } from '../ui/Button'
import { HeroVisual } from './HeroVisual'
import { ShieldCheck, ArrowRight, Shield, Activity, Lock, Globe, Search, Database, Fingerprint } from 'lucide-react'

export function HeroSection() {
  return (
    <div className="relative bg-[#fcfdff] overflow-hidden">
      {/* Background Graphic / Glows */}
      <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden flex justify-center">
        <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-blue-100/40 blur-[120px]" />
        <div className="absolute top-[20%] right-[-5%] w-[40%] h-[60%] rounded-full bg-blue-50/60 blur-[100px]" />
        
        {/* Subtle geometric grid / pattern could go here if needed */}
        <div className="absolute inset-0 bg-[url('/noise.png')] opacity-[0.01] mix-blend-overlay"></div>
      </div>

      <section className="pt-[100px] pb-14 md:pt-[118px] md:pb-16 relative z-10">
        <Container>
          <div className="flex flex-col lg:flex-row gap-12 lg:gap-8 items-center min-h-[520px] xl:min-h-[560px]">
            
            {/* Left Column - Content (55%) */}
            <div className="w-full lg:w-[55%] max-w-2xl lg:pr-8 xl:pr-12">
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-50 border border-blue-100 text-blue-700 text-sm font-semibold mb-8 shadow-sm">
                <ShieldCheck className="w-4 h-4" />
                <span>Unified Web & Browser Threat Detection</span>
              </div>
              
              <h1 className="text-[44px] md:text-6xl lg:text-[64px] font-[800] text-slate-900 tracking-tight leading-[1.08] mb-8">
                Know the Risk <span className="text-blue-600 block mt-2">Before</span> You Trust the Web.
              </h1>
              
              <p className="text-lg md:text-[19px] text-slate-600 mb-10 leading-[1.6] max-w-[560px]">
                CyberWatch analyzes URLs, websites, domains, browser activity, and files to help identify potential security risks and explain why a target may be considered safe, suspicious, or dangerous.
              </p>
              
              <div className="flex flex-col sm:flex-row gap-4">
                <Button size="lg" className="h-[52px] px-7 text-base rounded-lg group shadow-blue-600/20 shadow-lg w-full sm:w-auto">
                  <Search className="w-5 h-5 mr-2 opacity-90" />
                  Scan a URL
                  <ArrowRight className="w-4 h-4 ml-2 opacity-70 group-hover:translate-x-1 transition-transform" />
                </Button>
                <Button size="lg" variant="outline" className="h-[52px] px-7 text-base rounded-lg w-full sm:w-auto hover:bg-slate-50 border-slate-200">
                  Explore Security Services
                  <ArrowRight className="w-4 h-4 ml-2 opacity-70" />
                </Button>
              </div>
            </div>
            
            {/* Right Column - Visual (45%) */}
            <div className="w-full lg:w-[45%] relative">
              <HeroVisual />
            </div>
            
          </div>
        </Container>
      </section>

      {/* Hero Lower Benefits (Compact Strip) */}
      <section className="relative z-10 border-t border-slate-100 bg-white/50 backdrop-blur-md">
        <Container>
          <div className="py-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 lg:gap-0 lg:divide-x lg:divide-slate-100">
            {[
              { icon: Activity, title: 'Detect Threats', desc: 'Identify suspicious patterns and risks' },
              { icon: Search, title: 'Analyze Risks', desc: 'Check across multiple security layers' },
              { icon: Lock, title: 'Protect Your Data', desc: 'Keep your information safe and secure' },
              { icon: Globe, title: 'Safer Internet', desc: 'Build a more secure web for everyone' }
            ].map((item, i) => (
              <div key={i} className="flex items-start gap-4 lg:px-8 first:lg:pl-0 last:lg:pr-0">
                <div className="bg-blue-50 p-2.5 rounded-lg shrink-0 mt-1">
                  <item.icon className="w-5 h-5 text-blue-600" />
                </div>
                <div>
                  <h3 className="text-[15px] font-semibold text-slate-900 mb-1">{item.title}</h3>
                  <p className="text-[13px] text-slate-500 leading-snug">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </Container>
      </section>

      {/* Secondary Capability Band */}
      <section className="py-16 md:py-24 bg-slate-50/50 border-t border-slate-100 relative z-10">
        <Container>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
            {[
              { icon: Shield, title: 'Multi-Layer Scanning', desc: 'Comprehensive threat detection across multiple layers' },
              { icon: Database, title: 'Advanced Analysis', desc: 'AI-powered insights and risk assessment' },
              { icon: Activity, title: 'Real-time Protection', desc: 'Stay ahead of evolving threats' },
              { icon: Fingerprint, title: 'Secure by Design', desc: 'Built with privacy and security in mind' }
            ].map((item, i) => (
              <div key={i} className="bg-white p-6 rounded-2xl border border-slate-100 shadow-sm hover:shadow-md transition-shadow">
                <div className="bg-slate-50 w-12 h-12 rounded-xl flex items-center justify-center mb-5 border border-slate-100">
                  <item.icon className="w-6 h-6 text-slate-700" />
                </div>
                <h3 className="text-lg font-semibold text-slate-900 mb-2">{item.title}</h3>
                <p className="text-sm text-slate-600 leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </Container>
      </section>
    </div>
  )
}
