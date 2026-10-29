import React, { useState, useEffect, useRef } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  Headphones,
  CheckCircle2,
  Shield,
  Activity,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import {
  aiSupportService,
  type UserScanOption,
} from '../../services/ai-support.service';
import type {
  AISupportMessage,
  AISupportQuickAction,
} from '../../types';
import { useAuth } from '../../context/AuthContext';
import { cn } from '../../lib/utils';

interface AISupportAssistantProps {
  onEscalateToHuman?: (initialContext?: { scanId?: string; topic?: string }) => void;
  prefillScanId?: string;
}

export function AISupportAssistant({
  onEscalateToHuman,
  prefillScanId,
}: AISupportAssistantProps) {
  const { isAuthenticated } = useAuth();
  const [messages, setMessages] = useState<AISupportMessage[]>([]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [quickActions, setQuickActions] = useState<AISupportQuickAction[]>([]);
  const [userScans, setUserScans] = useState<UserScanOption[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>(prefillScanId || '');
  const [providerBadge, setProviderBadge] = useState<string>('CyberWatch Grounded AI');

  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const isUserScrolledUpRef = useRef(false);

  // Container-scoped auto-scroll to bottom without displacing outer page scroll
  const scrollToBottom = (force = false) => {
    if (!messagesContainerRef.current) return;
    if (force || !isUserScrolledUpRef.current) {
      messagesContainerRef.current.scrollTo({
        top: messagesContainerRef.current.scrollHeight,
        behavior: 'smooth',
      });
    }
  };

  const handleContainerScroll = () => {
    if (!messagesContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = messagesContainerRef.current;
    isUserScrolledUpRef.current = scrollHeight - scrollTop - clientHeight > 80;
  };

  // Initial welcome message and loading quick actions & scans
  useEffect(() => {
    async function loadData() {
      const actions = await aiSupportService.getQuickActions();
      setQuickActions(actions);

      if (isAuthenticated) {
        const scans = await aiSupportService.getUserScans();
        setUserScans(scans);
        if (prefillScanId && scans.some((s) => s.id === prefillScanId)) {
          setSelectedScanId(prefillScanId);
        }
      }

      setMessages([
        {
          id: 'welcome-msg',
          role: 'assistant',
          content:
            'Welcome to the **CyberWatch AI Security Assistant**.\n\n' +
            'I provide grounded technical guidance on scanner findings, risk scoring breakdowns, security headers, threat intelligence, and remediation steps.\n\n' +
            (isAuthenticated
              ? '💡 *Tip: Select one of your recent scans from the dropdown above to analyze specific vulnerabilities.*'
              : 'Feel free to ask any question regarding CyberWatch scanners or security best practices.'),
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          suggestedActions: [
            'Explain My Scan',
            'Why Is My Risk Score High?',
            'Scanner Troubleshooting',
            'Talk to Human Support',
          ],
          sources: ['CyberWatch Security Knowledge Base', 'OWASP Top 10 Standards'],
        },
      ]);
    }

    loadData();
  }, [isAuthenticated, prefillScanId]);

  // Scroll to bottom on new message
  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  async function handleSendMessage(overrideText?: string, overrideScanId?: string) {
    const text = (overrideText || inputText).trim();
    if (!text || isLoading) return;

    const scanToUse = overrideScanId !== undefined ? overrideScanId : selectedScanId;

    const userMessage: AISupportMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputText('');
    setIsLoading(true);

    try {
      // Build conversation history for context
      const history = messages
        .filter((m) => m.role === 'user' || m.role === 'assistant')
        .slice(-6)
        .map((m) => ({
          role: m.role as 'user' | 'assistant',
          content: m.content,
        }));

      const res = await aiSupportService.sendMessage({
        message: text,
        conversationHistory: history,
        scanId: scanToUse || undefined,
      });

      if (res.provider) {
        setProviderBadge(res.provider);
      }

      const assistantMessage: AISupportMessage = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: res.reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestedActions: res.suggestedActions,
        sources: res.sources,
        scanContext: res.scanContext,
        escalateToHuman: res.escalateToHuman,
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err: any) {
      const errorMessage: AISupportMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content: `⚠️ **Error:** ${err.message || 'Unable to generate response. Please verify your connection or try again.'}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        escalateToHuman: true,
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  }

  function handleActionClick(actionPrompt: string) {
    if (actionPrompt === 'Talk to Human Support' || actionPrompt.toLowerCase().includes('human')) {
      if (onEscalateToHuman) {
        onEscalateToHuman({ scanId: selectedScanId });
        return;
      }
    }
    handleSendMessage(actionPrompt);
  }

  function renderFormattedContent(content: string) {
    // Simple markdown-style rendering for headers, bold, bullet points, and code
    const lines = content.split('\n');
    return (
      <div className="space-y-2 text-xs sm:text-sm text-slate-800 leading-relaxed break-words">
        {lines.map((line, idx) => {
          if (line.startsWith('### ')) {
            return (
              <h4 key={idx} className="text-sm font-bold text-slate-900 mt-2 mb-1 border-b border-slate-100 pb-1">
                {line.replace('### ', '')}
              </h4>
            );
          }
          if (line.startsWith('#### ')) {
            return (
              <h5 key={idx} className="text-xs font-bold text-slate-800 mt-2 mb-0.5 uppercase tracking-wide">
                {line.replace('#### ', '')}
              </h5>
            );
          }
          if (line.startsWith('- ') || line.startsWith('* ')) {
            const parsed = line.replace(/^[-*]\s+/, '');
            return (
              <div key={idx} className="flex items-start gap-2 pl-2">
                <span className="text-cyan-600 font-bold shrink-0">•</span>
                <span dangerouslySetInnerHTML={{ __html: formatInlineMarkdown(parsed) }} />
              </div>
            );
          }
          if (/^\d+\.\s/.test(line)) {
            return (
              <div key={idx} className="flex items-start gap-2 pl-2">
                <span className="text-cyan-700 font-semibold shrink-0">{line.match(/^\d+\./)?.[0]}</span>
                <span dangerouslySetInnerHTML={{ __html: formatInlineMarkdown(line.replace(/^\d+\.\s+/, '')) }} />
              </div>
            );
          }
          if (!line.trim()) {
            return <div key={idx} className="h-1" />;
          }
          return (
            <p
              key={idx}
              dangerouslySetInnerHTML={{ __html: formatInlineMarkdown(line) }}
            />
          );
        })}
      </div>
    );
  }

  function formatInlineMarkdown(text: string): string {
    // Bold: **text**
    let formatted = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    // Italic: *text*
    formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
    // Inline code: `code`
    formatted = formatted.replace(
      /`([^`]+)`/g,
      '<code class="px-1.5 py-0.5 rounded bg-slate-100 text-cyan-800 font-mono text-[11px] border border-slate-200">$1</code>'
    );
    return formatted;
  }

  return (
    <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm overflow-hidden flex flex-col h-[740px] max-h-[85vh]">
      {/* 1. Header with Scan Selector & Engine Status */}
      <div className="p-4 sm:p-5 border-b border-slate-100 bg-slate-50/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-600 text-white flex items-center justify-center shrink-0 shadow-xs shadow-cyan-600/20">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-900">CyberWatch AI Security Assistant</h3>
              <span className="inline-flex items-center gap-1 text-[10px] font-semibold bg-cyan-50 text-cyan-700 border border-cyan-200/70 px-2 py-0.5 rounded-full">
                <Sparkles className="w-3 h-3 text-cyan-600" />
                <span>{providerBadge}</span>
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Grounded in CyberWatch scanners, CVSS metrics, and threat intelligence.
            </p>
          </div>
        </div>

        {/* Scan Context Dropdown */}
        {isAuthenticated && userScans.length > 0 && (
          <div className="flex items-center gap-2 bg-white px-3 py-1.5 rounded-xl border border-slate-200 shadow-xs">
            <Activity className="w-4 h-4 text-cyan-600 shrink-0" />
            <div className="text-[11px] text-slate-500 font-medium shrink-0">Scan Context:</div>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="text-xs font-semibold text-slate-800 bg-transparent focus:outline-none cursor-pointer max-w-[180px] truncate"
            >
              <option value="">General (No specific scan)</option>
              {userScans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target} ({s.targetType} • {s.riskScore}/100)
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* 2. Chat Timeline */}
      <div
        ref={messagesContainerRef}
        onScroll={handleContainerScroll}
        className="flex-1 min-h-0 overflow-y-auto p-4 sm:p-6 space-y-5 bg-slate-50/30"
      >
        {messages.map((msg) => {
          const isUser = msg.role === 'user';

          return (
            <div
              key={msg.id}
              className={cn(
                'flex items-start gap-3 max-w-[88%]',
                isUser ? 'ml-auto flex-row-reverse' : 'mr-auto'
              )}
            >
              {/* Avatar */}
              <div
                className={cn(
                  'w-8 h-8 rounded-xl flex items-center justify-center shrink-0 mt-1 shadow-xs',
                  isUser
                    ? 'bg-slate-800 text-white'
                    : 'bg-cyan-600 text-white shadow-cyan-600/20'
                )}
              >
                {isUser ? <Shield className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Bubble */}
              <div className="space-y-2 flex-1 min-w-0">
                <div
                  className={cn(
                    'p-4 rounded-2xl shadow-xs border',
                    isUser
                      ? 'bg-slate-900 text-white border-slate-800 rounded-tr-xs'
                      : 'bg-white text-slate-800 border-slate-200/90 rounded-tl-xs'
                  )}
                >
                  {isUser ? (
                    <p className="text-xs sm:text-sm leading-relaxed whitespace-pre-wrap">
                      {msg.content}
                    </p>
                  ) : (
                    renderFormattedContent(msg.content)
                  )}

                  {/* Scan Context Badge if available */}
                  {msg.scanContext && !isUser && (
                    <div className="mt-3 pt-2.5 border-t border-slate-100 flex flex-wrap items-center gap-2 text-[11px]">
                      <span className="font-semibold text-slate-500">Grounded On:</span>
                      <span className="bg-slate-100 text-slate-700 font-mono px-2 py-0.5 rounded border border-slate-200">
                        {msg.scanContext.target}
                      </span>
                      <span
                        className={cn(
                          'px-2 py-0.5 rounded font-bold',
                          msg.scanContext.riskScore >= 70
                            ? 'bg-rose-50 text-rose-700 border border-rose-200'
                            : msg.scanContext.riskScore >= 40
                            ? 'bg-amber-50 text-amber-700 border border-amber-200'
                            : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        )}
                      >
                        {msg.scanContext.riskScore}/100 • {msg.scanContext.riskLevel}
                      </span>
                    </div>
                  )}

                  {/* Verified Sources if provided */}
                  {msg.sources && msg.sources.length > 0 && !isUser && (
                    <div className="mt-3 pt-2 border-t border-slate-100 flex flex-wrap items-center gap-1.5 text-[10px] text-slate-400">
                      <span className="font-bold uppercase tracking-wider text-slate-400">Sources:</span>
                      {msg.sources.map((src, i) => (
                        <span
                          key={i}
                          className="inline-flex items-center gap-1 bg-slate-50 text-slate-600 px-2 py-0.5 rounded border border-slate-200/80"
                        >
                          <CheckCircle2 className="w-2.5 h-2.5 text-cyan-600" />
                          <span>{src}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Suggested Action Chips below AI messages */}
                {msg.suggestedActions && msg.suggestedActions.length > 0 && !isUser && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {msg.suggestedActions.map((action, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => handleActionClick(action)}
                        disabled={isLoading}
                        className="inline-flex items-center gap-1 text-[11px] font-semibold text-cyan-700 hover:text-cyan-800 bg-white hover:bg-cyan-50 border border-cyan-200/80 px-2.5 py-1 rounded-lg transition-colors cursor-pointer shadow-2xs"
                      >
                        <span>{action}</span>
                        <ArrowRight className="w-3 h-3 text-cyan-600" />
                      </button>
                    ))}
                  </div>
                )}

                {/* Human Escalation Action Card */}
                {msg.escalateToHuman && !isUser && (
                  <div className="bg-cyan-50/80 border border-cyan-200 rounded-xl p-3 flex items-center justify-between gap-3 shadow-2xs">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-cyan-600 text-white flex items-center justify-center shrink-0">
                        <Headphones className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-bold text-cyan-950">Connect with Human Support Desk</div>
                        <div className="text-[11px] text-cyan-700">
                          Transfer your scan findings to a live operator or create a ticket.
                        </div>
                      </div>
                    </div>
                    {onEscalateToHuman && (
                      <button
                        type="button"
                        onClick={() => onEscalateToHuman({ scanId: selectedScanId })}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-xs font-bold transition-all shadow-xs cursor-pointer shrink-0"
                      >
                        <span>Talk to Agent</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                )}

                <div className={cn('text-[10px] text-slate-400 px-1', isUser && 'text-right')}>
                  {msg.timestamp}
                </div>
              </div>
            </div>
          );
        })}

        {/* Loading Indicator */}
        {isLoading && (
          <div className="flex items-center gap-3 mr-auto max-w-[80%]">
            <div className="w-8 h-8 rounded-xl bg-cyan-600 text-white flex items-center justify-center shrink-0 animate-pulse">
              <Bot className="w-4 h-4" />
            </div>
            <div className="bg-white border border-slate-200/90 rounded-2xl rounded-tl-xs px-4 py-3 shadow-xs flex items-center gap-2 text-xs font-medium text-slate-600">
              <RefreshCw className="w-3.5 h-3.5 text-cyan-600 animate-spin" />
              <span>Analyzing security knowledge base &amp; scan telemetry...</span>
            </div>
          </div>
        )}
      </div>

      {/* 3. Quick Action Bar */}
      <div className="px-4 py-2 bg-slate-50/70 border-t border-slate-100 flex items-center gap-2 overflow-x-auto scrollbar-none shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 shrink-0">
          Quick Prompts:
        </span>
        {quickActions.map((qa) => (
          <button
            key={qa.id}
            type="button"
            onClick={() => handleSendMessage(qa.prompt)}
            disabled={isLoading}
            className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-600 hover:text-cyan-700 hover:bg-white bg-slate-100 px-2.5 py-1 rounded-lg border border-slate-200/80 transition-colors whitespace-nowrap cursor-pointer shrink-0"
          >
            <span>{qa.title}</span>
          </button>
        ))}
      </div>

      {/* 4. Message Input Composer */}
      <div className="p-3 sm:p-4 bg-white border-t border-slate-200 shrink-0">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-end gap-2"
        >
          <div className="flex-1 relative">
            <textarea
              ref={inputRef}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about scan findings, risk scores, headers, CORS, or troubleshooting... (Press Enter to send)"
              rows={1}
              className="w-full resize-none pl-3.5 pr-10 py-2.5 text-xs sm:text-sm bg-slate-50 hover:bg-slate-100/60 focus:bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-cyan-500/20 focus:border-cyan-500 transition-all placeholder:text-slate-400"
            />
          </div>

          <button
            type="submit"
            disabled={!inputText.trim() || isLoading}
            className={cn(
              'p-2.5 rounded-xl font-bold transition-all shrink-0 cursor-pointer',
              inputText.trim() && !isLoading
                ? 'bg-cyan-600 text-white hover:bg-cyan-700 shadow-xs shadow-cyan-600/25'
                : 'bg-slate-100 text-slate-400 cursor-not-allowed'
            )}
            aria-label="Send message to AI assistant"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
