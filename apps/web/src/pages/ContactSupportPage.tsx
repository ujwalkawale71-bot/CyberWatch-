import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Container } from '../components/ui/Container';
import { SupportHero } from '../components/support/SupportHero';
import { SupportOptions } from '../components/support/SupportOptions';
import { SupportContactCards } from '../components/support/SupportContactCards';
import { SupportTicketForm } from '../components/support/SupportTicketForm';
import { SupportTicketList } from '../components/support/SupportTicketList';
import { SecurityReportForm } from '../components/support/SecurityReportForm';
import { LiveChatPanel } from '../components/support/LiveChatPanel';
import { SupportOperatorDesk } from '../components/support/SupportOperatorDesk';
import { AISupportAssistant } from '../components/support/AISupportAssistant';
import { supportService, DEFAULT_SUPPORT_CONFIG } from '../services/support.service';
import type { SupportPublicConfig, SupportCategory } from '../types';
import {
  PlusCircle,
  ListOrdered,
  ShieldAlert,
  ShieldCheck,
  MessageSquare,
  Shield,
  Bot,
} from 'lucide-react';
import { cn } from '../lib/utils';
import { useAuth } from '../context/AuthContext';

export function ContactSupportPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user, isAuthenticated } = useAuth();

  const tabParam = searchParams.get('tab');
  const [activeTab, setActiveTab] = useState<'create' | 'tickets' | 'security' | 'chat' | 'operator' | 'ai'>(
    tabParam === 'tickets'
      ? 'tickets'
      : tabParam === 'security'
      ? 'security'
      : tabParam === 'chat'
      ? 'chat'
      : tabParam === 'operator'
      ? 'operator'
      : tabParam === 'ai'
      ? 'ai'
      : 'create'
  );

  const [config, setConfig] = useState<SupportPublicConfig>(DEFAULT_SUPPORT_CONFIG);

  // Read URL prefill parameters
  const scanIdParam = searchParams.get('scanId') || '';
  const reportIdParam = searchParams.get('reportId') || '';
  const targetParam = searchParams.get('target') || '';
  const categoryParam = (searchParams.get('category') as SupportCategory) || 'TECHNICAL_ISSUE';

  useEffect(() => {
    async function fetchConfig() {
      const data = await supportService.getConfig();
      setConfig(data);
    }
    fetchConfig();
  }, []);

  function handleTabChange(tab: 'create' | 'tickets' | 'security' | 'chat' | 'operator' | 'ai') {
    setActiveTab(tab);
    setSearchParams((prev) => {
      prev.set('tab', tab);
      return prev;
    });
  }

  function handleSupportOptionSelect(option: 'ticket' | 'chat' | 'security' | 'faq' | 'ai') {
    if (option === 'ticket') handleTabChange('create');
    else if (option === 'chat') handleTabChange('chat');
    else if (option === 'ai') handleTabChange('ai');
    else if (option === 'security') handleTabChange('security');
    else if (option === 'faq') navigate('/help');
  }

  return (
    <div className="min-h-screen bg-slate-50/50 pb-20 pt-24 sm:pt-28">
      <Container>
        <div className="space-y-8 sm:space-y-10">
          {/* 1. Hero Section */}
          <SupportHero
            config={config}
            onStartTicketClick={() => handleTabChange('create')}
            onLiveChatClick={() => handleTabChange('chat')}
            onSecurityReportClick={() => handleTabChange('security')}
          />

          {/* 2. Five Support Option Cards */}
          <SupportOptions
            onSelectOption={handleSupportOptionSelect}
            activeTab={
              activeTab === 'create'
                ? 'ticket'
                : activeTab === 'chat'
                ? 'chat'
                : activeTab === 'ai'
                ? 'ai'
                : activeTab === 'security'
                ? 'security'
                : undefined
            }
          />

          {/* 3. Main Workspace Navigation Tabs */}
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-2">
              <div className="flex items-center gap-2 overflow-x-auto scrollbar-none">
                <button
                  type="button"
                  onClick={() => handleTabChange('create')}
                  className={cn(
                    'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer',
                    activeTab === 'create'
                      ? 'bg-cyan-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 bg-white border border-slate-200/90'
                  )}
                >
                  <PlusCircle className="w-4 h-4" />
                  <span>Start Support Request</span>
                </button>

                {isAuthenticated && (
                  <button
                    type="button"
                    onClick={() => handleTabChange('tickets')}
                    className={cn(
                      'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer',
                      activeTab === 'tickets'
                        ? 'bg-cyan-600 text-white shadow-xs'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 bg-white border border-slate-200/90'
                    )}
                  >
                    <ListOrdered className="w-4 h-4" />
                    <span>My Support Requests</span>
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => handleTabChange('chat')}
                  className={cn(
                    'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer',
                    activeTab === 'chat'
                      ? 'bg-cyan-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 bg-white border border-slate-200/90'
                  )}
                >
                  <MessageSquare className="w-4 h-4" />
                  <span>Live Support Chat</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleTabChange('ai')}
                  className={cn(
                    'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer',
                    activeTab === 'ai'
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 bg-white border border-slate-200/90'
                  )}
                >
                  <Bot className="w-4 h-4 text-indigo-500" />
                  <span>AI Support Assistant</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleTabChange('security')}
                  className={cn(
                    'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer',
                    activeTab === 'security'
                      ? 'bg-rose-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 bg-white border border-slate-200/90'
                  )}
                >
                  <ShieldAlert className="w-4 h-4 text-rose-500" />
                  <span>Security Vulnerability Reporting</span>
                </button>

                {/* Operator Console Tab (Available to Staff or demo toggle) */}
                <button
                  type="button"
                  onClick={() => handleTabChange('operator')}
                  className={cn(
                    'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer',
                    activeTab === 'operator'
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'text-indigo-700 hover:text-indigo-900 hover:bg-indigo-50 bg-indigo-50/50 border border-indigo-200/70'
                  )}
                  title="Real support agent queue and live response operator desk"
                >
                  <Shield className="w-4 h-4 text-indigo-600" />
                  <span>Operator Desk</span>
                </button>
              </div>

              {/* Status Indicator */}
              <div className="hidden lg:flex items-center gap-2 text-xs font-semibold text-slate-500 bg-white px-3 py-1.5 rounded-xl border border-slate-200">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span>Strict Ownership &amp; Data Isolation Active</span>
              </div>
            </div>

            {/* Tab Views */}
            <div className="pt-2">
              {activeTab === 'create' && (
                <div className="max-w-4xl mx-auto">
                  <SupportTicketForm
                    initialCategory={categoryParam}
                    initialScanId={scanIdParam}
                    initialReportId={reportIdParam}
                    initialTargetUrl={targetParam}
                    onSuccess={() => {
                      if (isAuthenticated) {
                        handleTabChange('tickets');
                      }
                    }}
                  />
                </div>
              )}

              {activeTab === 'tickets' && (
                <div className="max-w-4xl mx-auto">
                  <SupportTicketList onCreateClick={() => handleTabChange('create')} />
                </div>
              )}

              {activeTab === 'chat' && (
                <div className="max-w-4xl mx-auto">
                  <LiveChatPanel
                    config={config}
                    user={user}
                    onTicketConverted={() => {
                      if (isAuthenticated) {
                        handleTabChange('tickets');
                      }
                    }}
                  />
                </div>
              )}

              {activeTab === 'ai' && (
                <div className="max-w-4xl mx-auto">
                  <AISupportAssistant
                    prefillScanId={scanIdParam}
                    onEscalateToHuman={(ctx) => {
                      if (ctx?.scanId) {
                        handleTabChange('create');
                      } else {
                        handleTabChange('chat');
                      }
                    }}
                  />
                </div>
              )}

              {activeTab === 'operator' && (
                <div className="max-w-5xl mx-auto">
                  <SupportOperatorDesk operatorUser={user} />
                </div>
              )}

              {activeTab === 'security' && (
                <div className="max-w-4xl mx-auto">
                  <SecurityReportForm config={config} defaultEmail={user?.email} />
                </div>
              )}
            </div>
          </div>

          {/* 4. Quick Contact Cards Section */}
          <div className="pt-8 border-t border-slate-200">
            <div className="mb-4">
              <h2 className="text-base font-bold text-slate-900">Direct Contact &amp; Availability</h2>
              <p className="text-xs text-slate-500">
                Official verified communication channels for emergency escalation and inquiries.
              </p>
            </div>
            <SupportContactCards
              config={config}
              onStartChatClick={() => handleTabChange('chat')}
              onSecurityReportClick={() => handleTabChange('security')}
              onStartTicketClick={() => handleTabChange('create')}
            />
          </div>
        </div>
      </Container>
    </div>
  );
}
