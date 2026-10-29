import { HeroSection } from '../components/hero/HeroSection'
import { AboutSection } from '../components/sections/AboutSection'
import { ServicesSection } from '../components/sections/ServicesSection'
import { HowItWorksSection } from '../components/sections/HowItWorksSection'
import { WhyCyberWatchSection } from '../components/sections/WhyCyberWatchSection'
import { CyberSafetySection } from '../components/sections/CyberSafetySection'
import { SecurityPrinciplesSection } from '../components/sections/SecurityPrinciplesSection'

export function Home() {

  return (
    <div className="w-full">
      {/* Hero + Feature Strip + Capability Band */}
      <HeroSection />

      {/* About CyberWatch */}
      <AboutSection />

      {/* Security Services */}
      <ServicesSection />

      {/* How CyberWatch Works */}
      <HowItWorksSection />

      {/* Why CyberWatch */}
      <WhyCyberWatchSection />

      {/* Security Education */}
      <CyberSafetySection />

      {/* Security Principles */}
      <SecurityPrinciplesSection />
    </div>
  )
}

