import { Shield, Lock, Globe, Activity, Search } from 'lucide-react';

export function HeroVisual() {
  return (
    <div className="relative w-full max-w-lg mx-auto lg:max-w-none h-[450px] lg:h-[550px] flex items-center justify-center perspective-[2000px]">
      
      {/* Background glow/rings */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[300px] h-[300px] bg-blue-400/20 rounded-full blur-[80px] z-0"></div>
      
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[320px] h-[320px] rounded-full border border-blue-500/10 shadow-[0_0_40px_rgba(59,130,246,0.1)] z-0 animate-[spin_20s_linear_infinite]"></div>
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[440px] h-[440px] rounded-full border border-blue-400/20 border-dashed z-0 animate-[spin_30s_linear_infinite_reverse]"></div>
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[580px] h-[580px] rounded-full border border-blue-200/40 z-0"></div>

      {/* Dimensional Laptop/Browser */}
      <div className="relative z-10 w-full max-w-[480px] mx-auto group">
        
        {/* Shadow under laptop */}
        <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 w-4/5 h-16 bg-slate-900/10 blur-xl rounded-[100%]"></div>
        
        {/* Laptop Screen Container */}
        <div className="relative bg-[#f8fafc] rounded-2xl shadow-2xl border border-slate-200/80 overflow-hidden transform transition-transform duration-700 hover:-translate-y-2 hover:shadow-blue-900/10 hover:shadow-3xl bg-clip-padding backdrop-filter backdrop-blur-xl bg-opacity-90">
          
          {/* Browser Top Bar */}
          <div className="bg-slate-50/90 px-4 py-3 flex items-center gap-4 border-b border-slate-200/60">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff5f56] shadow-sm"></div>
              <div className="w-3 h-3 rounded-full bg-[#ffbd2e] shadow-sm"></div>
              <div className="w-3 h-3 rounded-full bg-[#27c93f] shadow-sm"></div>
            </div>
            <div className="flex-1 bg-white rounded-md flex items-center px-3 py-1.5 shadow-sm border border-slate-200/60 justify-center relative">
              <Lock className="w-3 h-3 text-emerald-500 absolute left-3" />
              <div className="h-2 w-32 bg-slate-100 rounded-full mx-auto"></div>
            </div>
          </div>
          
          {/* Browser Content */}
          <div className="p-8 flex flex-col items-center justify-center min-h-[260px] bg-gradient-to-b from-white to-slate-50/50 relative overflow-hidden">
            
            {/* Grid background in browser */}
            <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px]"></div>
            
            {/* Shield Focus */}
            <div className="relative z-20 mb-6">
              <div className="absolute inset-0 bg-blue-500 blur-2xl opacity-30 rounded-full animate-pulse"></div>
              <div className="relative bg-gradient-to-br from-blue-600 to-blue-800 p-5 rounded-2xl shadow-xl shadow-blue-900/20 border border-blue-400/30 transform transition-transform duration-500 group-hover:scale-105 group-hover:rotate-3 group-hover:shadow-blue-500/30">
                <Shield className="w-16 h-16 text-white stroke-[1.5]" />
              </div>
            </div>
            
            {/* Fake Content Lines */}
            <div className="h-2.5 w-48 bg-slate-200/80 rounded-full mb-4 z-10 shadow-inner"></div>
            <div className="flex gap-2 z-10">
              <div className="h-2 w-16 bg-slate-200/60 rounded-full"></div>
              <div className="h-2 w-24 bg-slate-200/60 rounded-full"></div>
            </div>
          </div>
        </div>
      </div>

      {/* Floating Elements (4 Callouts) */}
      
      {/* Top Left */}
      <div className="absolute top-4 lg:top-12 -left-4 lg:-left-12 bg-white/90 backdrop-blur-md px-4 py-3 rounded-xl shadow-lg shadow-slate-200/50 border border-slate-100 flex items-center gap-3 z-20 animate-[bounce_6s_infinite] transition-transform hover:scale-105">
        <div className="bg-blue-50 p-2 rounded-lg border border-blue-100/50">
          <Search className="w-4 h-4 text-blue-600" />
        </div>
        <div>
          <div className="text-[13px] font-semibold text-slate-900">Detect Threats</div>
          <div className="text-[11px] text-slate-500 font-medium">Scan & Identify</div>
        </div>
      </div>

      {/* Top Right */}
      <div className="absolute top-20 lg:top-24 -right-4 lg:-right-8 bg-white/90 backdrop-blur-md px-4 py-3 rounded-xl shadow-lg shadow-slate-200/50 border border-slate-100 flex items-center gap-3 z-20 animate-[bounce_5s_infinite_0.5s] transition-transform hover:scale-105">
        <div className="bg-indigo-50 p-2 rounded-lg border border-indigo-100/50">
          <Activity className="w-4 h-4 text-indigo-600" />
        </div>
        <div>
          <div className="text-[13px] font-semibold text-slate-900">Analyze Risks</div>
          <div className="text-[11px] text-slate-500 font-medium">Deep Inspection</div>
        </div>
      </div>

      {/* Bottom Left */}
      <div className="absolute bottom-24 lg:bottom-28 -left-2 lg:-left-6 bg-white/90 backdrop-blur-md px-4 py-3 rounded-xl shadow-lg shadow-slate-200/50 border border-slate-100 flex items-center gap-3 z-20 animate-[bounce_7s_infinite_1s] transition-transform hover:scale-105">
        <div className="bg-emerald-50 p-2 rounded-lg border border-emerald-100/50">
          <Lock className="w-4 h-4 text-emerald-600" />
        </div>
        <div>
          <div className="text-[13px] font-semibold text-slate-900">Protect Your Data</div>
          <div className="text-[11px] text-slate-500 font-medium">Keep It Safe</div>
        </div>
      </div>

      {/* Bottom Right */}
      <div className="absolute bottom-8 lg:bottom-12 -right-2 lg:-right-12 bg-white/90 backdrop-blur-md px-4 py-3 rounded-xl shadow-lg shadow-slate-200/50 border border-slate-100 flex items-center gap-3 z-20 animate-[bounce_6s_infinite_1.5s] transition-transform hover:scale-105">
        <div className="bg-sky-50 p-2 rounded-lg border border-sky-100/50">
          <Globe className="w-4 h-4 text-sky-600" />
        </div>
        <div>
          <div className="text-[13px] font-semibold text-slate-900">Safer Internet</div>
          <div className="text-[11px] text-slate-500 font-medium">For a Better Tomorrow</div>
        </div>
      </div>

    </div>
  )
}
