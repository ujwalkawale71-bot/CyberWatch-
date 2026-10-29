import { Container } from '../components/ui/Container'
import { Settings } from 'lucide-react'

export function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="pt-32 pb-16 min-h-[60vh] flex items-center">
      <Container>
        <div className="flex flex-col items-center justify-center text-center max-w-2xl mx-auto space-y-6">
          <div className="w-16 h-16 bg-blue-50 rounded-2xl flex items-center justify-center text-blue-600 mb-2">
            <Settings className="w-8 h-8" />
          </div>
          <h1 className="text-3xl font-bold text-slate-900">{title}</h1>
          <p className="text-lg text-slate-500">
            This section is currently being prepared for Phase 3 implementation. 
            The required routing structure is established.
          </p>
        </div>
      </Container>
    </div>
  )
}
