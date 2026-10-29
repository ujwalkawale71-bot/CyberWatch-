import { Headphones, MessageSquare, ShieldAlert, BookOpen, Bot, ArrowRight } from 'lucide-react';

interface SupportOptionsProps {
  onSelectOption: (option: 'ticket' | 'chat' | 'security' | 'faq' | 'ai') => void;
  activeTab?: string;
  hasActiveChat?: boolean;
}

export function SupportOptions({ onSelectOption, activeTab }: SupportOptionsProps) {

  const options = [
    {
      id: 'ticket' as const,
      title: 'Support Request',
      description: 'Create, manage, and track technical assistance tickets with full audit trails.',
      icon: Headphones,
      actionText: 'Open Ticket',
      badge: 'Ticketing Desk',
      theme: 'cyan',
    },
    {
      id: 'chat' as const,
      title: 'Live Chat',
      description: 'Connect with a live CyberWatch technical operator in a real-time secure queue.',
      icon: MessageSquare,
      actionText: 'Start Chat',
      badge: 'Real-Time Desk',
      theme: 'emerald',
    },
    {
      id: 'ai' as const,
      title: 'AI Support',
      description: 'Grounded AI assistant to diagnose scan findings, explain risk scores, and guide fixes.',
      icon: Bot,
      actionText: 'Ask AI Assistant',
      badge: 'Instant AI',
      theme: 'indigo',
    },
    {
      id: 'security' as const,
      title: 'Security Report',
      description: 'Submit confidential vulnerability disclosures directly to our security engineering team.',
      icon: ShieldAlert,
      actionText: 'Report Issue',
      badge: 'Responsible Disclosure',
      theme: 'rose',
    },
    {
      id: 'faq' as const,
      title: 'Help Center',
      description: 'Explore scanner guides, threat intelligence definitions, and troubleshooting FAQs.',
      icon: BookOpen,
      actionText: 'View Knowledge Base',
      badge: 'Knowledge Hub',
      theme: 'slate',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 sm:gap-4">
      {options.map((opt) => {
        const Icon = opt.icon;
        const isActive = activeTab === opt.id;

        return (
          <div
            key={opt.id}
            onClick={() => onSelectOption(opt.id)}
            className={`flex flex-col justify-between bg-white rounded-2xl p-5 border transition-all duration-150 cursor-pointer text-left ${
              isActive
                ? 'border-cyan-500 shadow-md ring-1 ring-cyan-500/20'
                : 'border-slate-200/90 shadow-2xs hover:shadow-sm hover:border-slate-300'
            }`}
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <div
                  className={`w-9 h-9 rounded-xl flex items-center justify-center ${
                    opt.theme === 'cyan'
                      ? 'bg-cyan-50 text-cyan-700'
                      : opt.theme === 'emerald'
                      ? 'bg-emerald-50 text-emerald-700'
                      : opt.theme === 'indigo'
                      ? 'bg-indigo-50 text-indigo-700'
                      : opt.theme === 'rose'
                      ? 'bg-rose-50 text-rose-700'
                      : 'bg-slate-100 text-slate-700'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
                <span className="text-[10px] font-semibold tracking-wide uppercase px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">
                  {opt.badge}
                </span>
              </div>

              <h3 className="text-sm font-bold text-slate-900 mb-1">{opt.title}</h3>
              <p className="text-xs text-slate-600 leading-relaxed mb-3 line-clamp-3">
                {opt.description}
              </p>
            </div>

            <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs font-semibold text-cyan-700 group">
              <span>{opt.actionText}</span>
              <ArrowRight className="w-3.5 h-3.5 transition-transform duration-150 group-hover:translate-x-0.5" />
            </div>
          </div>
        );
      })}
    </div>
  );
}
