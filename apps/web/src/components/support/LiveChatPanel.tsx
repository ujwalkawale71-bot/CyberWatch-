import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Bot,
  Send,
  Sparkles,
  AlertCircle,
  RotateCcw,
  Trash2,
  Ticket,
  Headphones,
  CheckCircle2,
  Activity,
  ArrowRight,
  RefreshCw,
  X,
  FileText,
  LogOut,
  User,
} from 'lucide-react';
import type {
  SupportChatMessage,
  SupportChatSession,
  SupportPublicConfig,
  AISupportMessage,
  AISupportQuickAction,
} from '../../types';
import { supportService } from '../../services/support.service';
import {
  aiSupportService,
  type UserScanOption,
} from '../../services/ai-support.service';
import {
  liveChatSocketService,
  type ChatConnectionState,
  type ChatMessageEvent,
  type ChatTypingEvent,
  type ChatAssignedEvent,
  type ChatClosedEvent,
} from '../../services/live-chat.service';
import { cn } from '../../lib/utils';

interface LiveChatPanelProps {
  config: SupportPublicConfig;
  user?: { name?: string; email?: string; userId?: string } | null;
  onTicketConverted?: (ticketId: string) => void;
  initialScanContext?: any;
}

export function LiveChatPanel({
  config,
  user,
  onTicketConverted,
  initialScanContext,
}: LiveChatPanelProps) {
  const [searchParams] = useSearchParams();
  const scanIdFromUrl = searchParams.get('scanId') || '';

  // Mode: 'ai' (default CyberWatch AI Security Assistant) or 'operator' (Human Live Operator desk)
  const [chatMode, setChatMode] = useState<'ai' | 'operator'>('ai');

  // ─── AI Chat State ──────────────────────────────────────────────────────────
  const [aiMessages, setAiMessages] = useState<AISupportMessage[]>([]);
  const [aiInputText, setAiInputText] = useState('');
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [lastFailedMessage, setLastFailedMessage] = useState<string | null>(null);
  const [quickActions, setQuickActions] = useState<AISupportQuickAction[]>([]);
  const [userScans, setUserScans] = useState<UserScanOption[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>(scanIdFromUrl || '');
  const [providerBadge, setProviderBadge] = useState<string>('Evidence Grounded AI');
  const [conversationId, setConversationId] = useState<string>(() => `chat_${Date.now()}`);

  // ─── Operator Live Chat State (Preserved) ───────────────────────────────────
  const [humanSession, setHumanSession] = useState<SupportChatSession | null>(null);
  const [humanMessages, setHumanMessages] = useState<SupportChatMessage[]>([]);
  const [humanInput, setHumanInput] = useState('');
  const [isHumanStarting, setIsHumanStarting] = useState(false);
  const [isHumanSending, setIsHumanSending] = useState(false);
  const [isConverting, setIsConverting] = useState(false);
  const [humanError, setHumanError] = useState<string | null>(null);
  const [connectionState, setConnectionState] = useState<ChatConnectionState>('DISCONNECTED');
  const [isPeerTyping, setIsPeerTyping] = useState(false);
  const [peerTypingName, setPeerTypingName] = useState('');
  const [guestName, setGuestName] = useState(user?.name || '');
  const [guestEmail, setGuestEmail] = useState(user?.email || '');

  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const aiInputRef = useRef<HTMLTextAreaElement>(null);
  const humanTypingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
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
    // If user is more than 80px from bottom, they have scrolled up intentionally
    isUserScrolledUpRef.current = scrollHeight - scrollTop - clientHeight > 80;
  };

  useEffect(() => {
    scrollToBottom();
  }, [aiMessages, humanMessages, isAiLoading, isPeerTyping, chatMode]);

  // Initial Load for AI Assistant
  useEffect(() => {
    async function initAI() {
      const actions = await aiSupportService.getQuickActions();
      setQuickActions(actions);

      if (user?.userId) {
        const scans = await aiSupportService.getUserScans();
        setUserScans(scans);
        if (scanIdFromUrl && scans.some((s) => s.id === scanIdFromUrl)) {
          setSelectedScanId(scanIdFromUrl);
        }
      }

      // Initial welcome message
      setAiMessages([
        {
          id: 'welcome-init',
          role: 'assistant',
          content:
            '### CyberWatch AI Security Assistant\n\n' +
            'I am your dedicated AI security assistant. I provide evidence-grounded explanations for CyberWatch scanner findings, risk scores (0–100), HTTP security headers, TLS posture, and threat intelligence telemetry.\n\n' +
            (user?.userId
              ? '💡 **Tip:** Select an active scan from the dropdown above to analyze specific vulnerabilities and remediation steps.'
              : 'Feel free to ask any question about CyberWatch scanners, risk scores, or security remediation.'),
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          suggestedActions: [
            'Explain My Scan',
            'Why Is My Risk Score High?',
            'Threat Intelligence Help',
            'Talk to Human Support',
          ],
          sources: ['CyberWatch Security Knowledge Base', 'OWASP Top 10 Standards'],
        },
      ]);
    }

    initAI();
  }, [user?.userId, scanIdFromUrl]);

  // Socket IO Listeners for Human Operator Mode
  useEffect(() => {
    if (chatMode !== 'operator') return;

    liveChatSocketService.connect();

    const unsubConnection = liveChatSocketService.onConnectionStateChange((state) => {
      setConnectionState(state);
    });

    const unsubMessage = liveChatSocketService.onMessage((event: ChatMessageEvent) => {
      if (humanSession && event.sessionId === humanSession.sessionId) {
        setHumanMessages((prev) => {
          if (prev.some((m) => m.id === event.message.id)) return prev;
          return [...prev, event.message];
        });
        if (event.sessionStatus && humanSession) {
          setHumanSession((prev) => (prev ? { ...prev, status: event.sessionStatus as any } : null));
        }
      }
    });

    const unsubTyping = liveChatSocketService.onTyping((event: ChatTypingEvent) => {
      if (humanSession && event.sessionId === humanSession.sessionId) {
        setIsPeerTyping(event.isTyping);
        setPeerTypingName(event.userName || 'Support Agent');
      }
    });

    const unsubAssigned = liveChatSocketService.onAssigned((event: ChatAssignedEvent) => {
      if (humanSession && event.sessionId === humanSession.sessionId) {
        setHumanSession((prev) =>
          prev
            ? {
                ...prev,
                status: 'ACTIVE',
                agentName: event.agentName,
                assignedAgentName: event.agentName,
              }
            : null
        );
      }
    });

    const unsubClosed = liveChatSocketService.onClosed((event: ChatClosedEvent) => {
      if (humanSession && event.sessionId === humanSession.sessionId) {
        setHumanSession((prev) => (prev ? { ...prev, status: 'CLOSED', closedAt: event.closedAt } : null));
      }
    });

    const unsubError = liveChatSocketService.onError((err) => {
      setHumanError(err);
    });

    return () => {
      unsubConnection();
      unsubMessage();
      unsubTyping();
      unsubAssigned();
      unsubClosed();
      unsubError();
    };
  }, [chatMode, humanSession?.sessionId]);

  // ─── AI Chat Actions ────────────────────────────────────────────────────────

  const handleSendAiMessage = async (overrideText?: string) => {
    const text = (overrideText || aiInputText).trim();
    if (!text || isAiLoading) return;

    setAiError(null);
    setLastFailedMessage(null);

    const userMsg: AISupportMessage = {
      id: `usr_${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setAiMessages((prev) => [...prev, userMsg]);
    setAiInputText('');
    setIsAiLoading(true);

    try {
      const history = aiMessages
        .filter((m) => m.role === 'user' || m.role === 'assistant')
        .slice(-6)
        .map((m) => ({
          role: m.role as 'user' | 'assistant',
          content: m.content,
        }));

      const res = await aiSupportService.sendMessage({
        message: text,
        conversationId,
        conversationHistory: history,
        scanId: selectedScanId || undefined,
        scanContext: initialScanContext || undefined,
      });

      if (res.conversationId) {
        setConversationId(res.conversationId);
      }
      if (res.provider) {
        setProviderBadge(res.provider);
      }

      const aiReply: AISupportMessage = {
        id: `ai_${Date.now()}`,
        role: 'assistant',
        content: res.reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestedActions: res.suggestedActions,
        sources: res.sources,
        scanContext: res.scanContext,
        escalateToHuman: res.escalateToHuman,
      };

      setAiMessages((prev) => [...prev, aiReply]);
    } catch (err: any) {
      setLastFailedMessage(text);
      const friendlyError =
        err?.message || 'CyberWatch AI is temporarily unavailable. Please try again.';
      setAiError(friendlyError);
    } finally {
      setIsAiLoading(false);
      setTimeout(() => aiInputRef.current?.focus(), 50);
    }
  };

  const handleRetryAi = () => {
    if (lastFailedMessage) {
      handleSendAiMessage(lastFailedMessage);
    }
  };

  const handleClearAiConversation = () => {
    setAiMessages([
      {
        id: `welcome_${Date.now()}`,
        role: 'assistant',
        content:
          '### CyberWatch AI Security Assistant\n\n' +
          'Conversation cleared. How can I assist your security audit today?',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestedActions: [
          'Explain My Scan',
          'Why Is My Risk Score High?',
          'Threat Intelligence Help',
          'Talk to Human Support',
        ],
        sources: ['CyberWatch Security Knowledge Base'],
      },
    ]);
    setAiError(null);
    setLastFailedMessage(null);
    setConversationId(`chat_${Date.now()}`);
  };

  const handleAiKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendAiMessage();
    }
  };

  const handleAiActionClick = (prompt: string) => {
    if (
      prompt === 'Talk to Human Support' ||
      prompt.toLowerCase().includes('human') ||
      prompt.toLowerCase().includes('operator')
    ) {
      setChatMode('operator');
      return;
    }
    handleSendAiMessage(prompt);
  };

  // ─── Human Operator Actions ─────────────────────────────────────────────────

  const handleStartHumanChat = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = user?.name || guestName.trim();
    const email = user?.email || guestEmail.trim();

    if (!name || name.length < 2) {
      setHumanError('Please enter your full name.');
      return;
    }
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      setHumanError('Please enter a valid email address.');
      return;
    }

    try {
      setIsHumanStarting(true);
      setHumanError(null);
      const newSession = await supportService.startChatSession({
        userName: name,
        userEmail: email,
        initialMessage: 'Escalated from CyberWatch AI Live Chat',
      });

      setHumanSession(newSession);
      setHumanMessages(newSession.messages || []);
      liveChatSocketService.joinSession(newSession.sessionId);
    } catch (err: any) {
      setHumanError(err?.response?.data?.message || 'Failed to connect to human operator desk.');
    } finally {
      setIsHumanStarting(false);
    }
  };

  const handleSendHumanMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!humanInput.trim() || !humanSession || isHumanSending) return;

    const textToSend = humanInput.trim();
    setHumanInput('');

    if (humanTypingTimeoutRef.current) clearTimeout(humanTypingTimeoutRef.current);
    liveChatSocketService.sendTyping(humanSession.sessionId, false, user?.name || guestName);

    try {
      setIsHumanSending(true);
      setHumanError(null);
      liveChatSocketService.sendMessage(humanSession.sessionId, textToSend, user?.name || guestName);
    } catch {
      try {
        const updated = await supportService.sendChatMessage(
          humanSession.sessionId,
          textToSend,
          user?.name || guestName
        );
        setHumanSession(updated);
        setHumanMessages(updated.messages || []);
      } catch (restErr: any) {
        setHumanError(restErr?.response?.data?.message || 'Failed to deliver message to operator.');
      }
    } finally {
      setIsHumanSending(false);
    }
  };

  const handleEndHumanSession = async () => {
    if (!humanSession) return;
    if (!window.confirm('Are you sure you want to end this live operator session?')) return;

    try {
      liveChatSocketService.closeSession(humanSession.sessionId);
      const ended = await supportService.endChatSession(humanSession.sessionId);
      setHumanSession(ended);
      setHumanMessages(ended.messages || []);
    } catch (err: any) {
      setHumanError(err?.response?.data?.message || 'Failed to end session.');
    }
  };

  const handleConvertToTicket = async () => {
    if (!humanSession) return;
    try {
      setIsConverting(true);
      setHumanError(null);
      const ticket = await supportService.convertChatToTicket(humanSession.sessionId);
      setHumanSession((prev) => (prev ? { ...prev, convertedTicketNumber: ticket.ticketNumber } : null));
      if (onTicketConverted) {
        onTicketConverted(ticket.ticketNumber);
      }
    } catch (err: any) {
      setHumanError(err?.response?.data?.message || 'Failed to convert chat into a ticket.');
    } finally {
      setIsConverting(false);
    }
  };

  // ─── Markdown Rendering Helper ──────────────────────────────────────────────

  function renderFormattedMarkdown(text: string) {
    const lines = text.split('\n');
    return (
      <div className="space-y-2 text-xs sm:text-sm text-slate-800 leading-relaxed break-words">
        {lines.map((line, idx) => {
          if (line.startsWith('### ')) {
            return (
              <h4
                key={idx}
                className="text-sm font-bold text-slate-900 mt-2 mb-1 border-b border-slate-100 pb-1"
              >
                {line.replace('### ', '')}
              </h4>
            );
          }
          if (line.startsWith('#### ')) {
            return (
              <h5
                key={idx}
                className="text-xs font-bold text-slate-800 mt-2 mb-0.5 uppercase tracking-wide"
              >
                {line.replace('#### ', '')}
              </h5>
            );
          }
          if (line.startsWith('- ') || line.startsWith('* ')) {
            const parsed = line.replace(/^[-*]\s+/, '');
            return (
              <div key={idx} className="flex items-start gap-2 pl-1.5">
                <span className="text-cyan-600 font-bold shrink-0">•</span>
                <span dangerouslySetInnerHTML={{ __html: formatInline(parsed) }} />
              </div>
            );
          }
          if (/^\d+\.\s/.test(line)) {
            return (
              <div key={idx} className="flex items-start gap-2 pl-1.5">
                <span className="text-cyan-700 font-semibold shrink-0">
                  {line.match(/^\d+\./)?.[0]}
                </span>
                <span
                  dangerouslySetInnerHTML={{
                    __html: formatInline(line.replace(/^\d+\.\s+/, '')),
                  }}
                />
              </div>
            );
          }
          if (!line.trim()) {
            return <div key={idx} className="h-1" />;
          }
          return (
            <p
              key={idx}
              dangerouslySetInnerHTML={{ __html: formatInline(line) }}
            />
          );
        })}
      </div>
    );
  }

  function formatInline(str: string): string {
    let out = str.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    out = out.replace(/\*(.*?)\*/g, '<em>$1</em>');
    out = out.replace(
      /`([^`]+)`/g,
      '<code class="px-1.5 py-0.5 rounded bg-slate-100 text-cyan-800 font-mono text-[11px] border border-slate-200">$1</code>'
    );
    return out;
  }

  // ─── Render: Human Operator Mode ───────────────────────────────────────────
  if (chatMode === 'operator') {
    return (
      <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm overflow-hidden flex flex-col h-[650px] max-w-4xl mx-auto">
        {/* Header */}
        <div className="bg-slate-50/90 border-b border-slate-200 px-5 py-3.5 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-50 border border-cyan-100 flex items-center justify-center text-cyan-700">
              <Headphones className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-slate-900">CyberWatch Human Support Desk</h3>
                {humanSession && (
                  <span className="text-[11px] font-mono text-slate-500">
                    #{humanSession.sessionId}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500">
                Live consultation with cybersecurity support engineers. (Status: {connectionState})
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setChatMode('ai')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-50 text-cyan-700 border border-cyan-200 hover:bg-cyan-100 text-xs font-bold transition-all cursor-pointer"
            >
              <Bot className="w-3.5 h-3.5" />
              <span>Back to CyberWatch AI</span>
            </button>

            {humanSession?.convertedTicketNumber ? (
              <span className="text-xs font-semibold px-2.5 py-1 rounded-lg bg-cyan-50 border border-cyan-200 text-cyan-800 flex items-center gap-1">
                <Ticket className="w-3.5 h-3.5" />
                Ticket #{humanSession.convertedTicketNumber}
              </span>
            ) : humanSession ? (
              <button
                type="button"
                onClick={handleConvertToTicket}
                disabled={isConverting}
                className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Ticket className="w-3.5 h-3.5 text-cyan-600" />
                <span>Convert to Ticket</span>
              </button>
            ) : null}

            {humanSession &&
              humanSession.status !== 'CLOSED' &&
              humanSession.status !== 'ENDED' && (
                <button
                  type="button"
                  onClick={handleEndHumanSession}
                  className="text-xs font-semibold px-2.5 py-1.5 rounded-lg bg-slate-100 hover:bg-rose-50 hover:text-rose-700 text-slate-600 flex items-center gap-1 transition-colors cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>End Chat</span>
                </button>
              )}
          </div>
        </div>

        {/* Start Screen for Human Desk if no session */}
        {!humanSession ? (
          <div className="flex-1 min-h-0 overflow-y-auto p-6 flex flex-col justify-center max-w-lg mx-auto w-full">
            <div className="text-center mb-6">
              <div className="w-12 h-12 rounded-2xl bg-cyan-50 border border-cyan-100 flex items-center justify-center text-cyan-600 mx-auto mb-3">
                <Headphones className="w-6 h-6" />
              </div>
              <h2 className="text-lg font-bold text-slate-900">Connect with Human Support Desk</h2>
              <p className="text-xs sm:text-sm text-slate-500 mt-1">
                Our support team is available {config.supportHours || '24/7'} for technical escalations and inquiries.
              </p>
            </div>

            {humanError && (
              <div className="mb-4 p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{humanError}</span>
              </div>
            )}

            <form onSubmit={handleStartHumanChat} className="space-y-4">
              {!user && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      Your Full Name
                    </label>
                    <input
                      type="text"
                      value={guestName}
                      onChange={(e) => setGuestName(e.target.value)}
                      placeholder="e.g. Alex Rivera"
                      className="w-full text-sm px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 text-slate-900"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      Email Address
                    </label>
                    <input
                      type="email"
                      value={guestEmail}
                      onChange={(e) => setGuestEmail(e.target.value)}
                      placeholder="e.g. security@company.com"
                      className="w-full text-sm px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 text-slate-900"
                      required
                    />
                  </div>
                </>
              )}

              <button
                type="submit"
                disabled={isHumanStarting}
                className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-cyan-600 hover:bg-cyan-700 active:bg-cyan-800 text-white text-sm font-bold rounded-xl shadow-sm transition-all disabled:opacity-60 cursor-pointer"
              >
                {isHumanStarting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Connecting to Queue...</span>
                  </>
                ) : (
                  <>
                    <Headphones className="w-4 h-4" />
                    <span>Join Operator Queue</span>
                  </>
                )}
              </button>
            </form>
          </div>
        ) : (
          <>
            {/* Messages Area */}
            <div
              ref={messagesContainerRef}
              onScroll={handleContainerScroll}
              className="flex-1 min-h-0 overflow-y-auto p-4 sm:p-6 space-y-3.5 bg-slate-50/50"
            >
              {humanMessages.map((msg, index) => {
                const isUser = msg.senderType === 'USER';
                const isSystem = msg.senderType === 'SYSTEM';

                if (isSystem) {
                  return (
                    <div key={msg.id || index} className="flex justify-center my-2">
                      <span className="text-[11px] font-medium text-slate-500 bg-white border border-slate-200/80 px-3 py-1 rounded-full">
                        {msg.message}
                      </span>
                    </div>
                  );
                }

                return (
                  <div
                    key={msg.id || index}
                    className={`flex flex-col ${isUser ? 'items-end' : 'items-start'}`}
                  >
                    <div className="flex items-center gap-1.5 mb-1 px-1 text-[11px] text-slate-500">
                      <span className="font-semibold text-slate-700">{msg.senderName}</span>
                      <span>•</span>
                      <span>
                        {new Date(msg.createdAt).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>
                    </div>

                    <div
                      className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm shadow-2xs ${
                        isUser
                          ? 'bg-cyan-600 text-white rounded-tr-xs'
                          : 'bg-white text-slate-900 border border-slate-200/90 rounded-tl-xs'
                      }`}
                    >
                      <p className="whitespace-pre-wrap leading-relaxed">{msg.message}</p>
                      {msg.attachments && msg.attachments.length > 0 && (
                        <div className="mt-2 pt-2 border-t border-white/20 space-y-1">
                          {msg.attachments.map((att, attIdx) => (
                            <a
                              key={att.id || attIdx}
                              href={att.downloadUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1.5 text-xs font-semibold underline text-white"
                            >
                              <FileText className="w-3.5 h-3.5" />
                              <span>{att.originalName}</span>
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}

              {isPeerTyping && (
                <div className="flex items-center gap-2 text-xs text-slate-500 bg-white border border-slate-200/80 px-3 py-1.5 rounded-2xl w-fit shadow-2xs animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-600" />
                  <span>{peerTypingName || 'Support Agent'} is typing...</span>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="bg-white border-t border-slate-200 p-3 sm:p-4 shrink-0">
              {humanError && (
                <div className="mb-2 p-2 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center justify-between">
                  <span>{humanError}</span>
                  <button
                    type="button"
                    onClick={() => setHumanError(null)}
                    className="text-rose-500 hover:text-rose-700"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}

              <form onSubmit={handleSendHumanMessage} className="flex items-center gap-2">
                <input
                  type="text"
                  value={humanInput}
                  onChange={(e) => {
                    setHumanInput(e.target.value);
                    if (humanSession) {
                      liveChatSocketService.sendTyping(
                        humanSession.sessionId,
                        true,
                        user?.name || guestName
                      );
                    }
                  }}
                  placeholder="Type your message to the support engineer..."
                  className="flex-1 text-sm px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 text-slate-900"
                />
                <button
                  type="submit"
                  disabled={!humanInput.trim() || isHumanSending}
                  className="p-2.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-xl shadow-xs disabled:opacity-50 cursor-pointer"
                >
                  <Send className="w-4 h-4" />
                </button>
              </form>
            </div>
          </>
        )}
      </div>
    );
  }

  // ─── Render: CyberWatch AI Security Assistant (Default) ─────────────────────
  return (
    <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm overflow-hidden flex flex-col h-[650px] max-h-[85vh] max-w-4xl mx-auto">
      {/* 1. Header */}
      <div className="bg-slate-50/90 border-b border-slate-200 px-4 sm:px-6 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-600 text-white flex items-center justify-center shrink-0 shadow-xs shadow-cyan-600/20">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm sm:text-base font-bold text-slate-900">CyberWatch AI</h3>
              <span className="text-xs font-semibold text-cyan-700 bg-cyan-50 border border-cyan-200/70 px-2 py-0.5 rounded-full inline-flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-cyan-600" />
                <span>Security Assistant</span>
              </span>
              <span className="hidden md:inline-block text-[10px] text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full font-mono">
                {providerBadge}
              </span>
            </div>
            <p className="text-[11px] sm:text-xs text-slate-500">
              Evidence-based analysis grounded in CyberWatch security scanners &amp; threat telemetry.
            </p>
          </div>
        </div>

        {/* Action Controls & Scan Selector */}
        <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap justify-end">
          {/* Scan Context Dropdown */}
          {userScans.length > 0 && (
            <div className="flex items-center gap-1.5 bg-white px-2.5 py-1.5 rounded-xl border border-slate-200 shadow-2xs">
              <Activity className="w-3.5 h-3.5 text-cyan-600 shrink-0" />
              <select
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
                className="text-xs font-semibold text-slate-800 bg-transparent focus:outline-none cursor-pointer max-w-[150px] sm:max-w-[190px] truncate"
                title="Select active scan context"
              >
                <option value="">No Scan Context</option>
                {userScans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target} ({s.riskScore}/100 • {s.riskLevel})
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Clear Conversation */}
          <button
            type="button"
            onClick={handleClearAiConversation}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-100 text-slate-600 hover:text-slate-900 text-xs font-semibold transition-colors cursor-pointer"
            title="Clear current conversation"
          >
            <Trash2 className="w-3.5 h-3.5 text-slate-500" />
            <span className="hidden sm:inline">Clear</span>
          </button>

          {/* Switch to Human Operator Desk */}
          <button
            type="button"
            onClick={() => setChatMode('operator')}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-100 hover:bg-cyan-50 hover:text-cyan-800 text-slate-700 text-xs font-semibold transition-colors cursor-pointer border border-slate-200"
            title="Connect with a human security engineer"
          >
            <Headphones className="w-3.5 h-3.5 text-cyan-600" />
            <span>Human Desk</span>
          </button>
        </div>
      </div>

      {/* 2. Messages Scroll Area */}
      <div
        ref={messagesContainerRef}
        onScroll={handleContainerScroll}
        className="flex-1 min-h-0 overflow-y-auto p-4 sm:p-6 space-y-4 bg-slate-50/40"
      >
        {aiMessages.map((msg) => {
          const isUser = msg.role === 'user';

          return (
            <div
              key={msg.id}
              className={cn(
                'flex items-start gap-3 max-w-[92%] sm:max-w-[85%]',
                isUser ? 'ml-auto flex-row-reverse' : 'mr-auto'
              )}
            >
              {/* Avatar */}
              <div
                className={cn(
                  'w-8 h-8 rounded-xl flex items-center justify-center shrink-0 mt-0.5 shadow-2xs',
                  isUser ? 'bg-slate-800 text-white' : 'bg-cyan-600 text-white shadow-cyan-600/20'
                )}
              >
                {isUser ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Bubble */}
              <div className="space-y-2 flex-1 min-w-0">
                <div
                  className={cn(
                    'p-4 rounded-2xl shadow-2xs border',
                    isUser
                      ? 'bg-slate-900 text-white border-slate-800 rounded-tr-xs'
                      : 'bg-white text-slate-900 border-slate-200/90 rounded-tl-xs'
                  )}
                >
                  {isUser ? (
                    <p className="text-xs sm:text-sm leading-relaxed whitespace-pre-wrap">
                      {msg.content}
                    </p>
                  ) : (
                    renderFormattedMarkdown(msg.content)
                  )}

                  {/* Scan Context Grounding Tag if available */}
                  {msg.scanContext && !isUser && (
                    <div className="mt-3 pt-2.5 border-t border-slate-100 flex flex-wrap items-center gap-2 text-[11px]">
                      <span className="font-bold text-slate-500">Grounded On:</span>
                      <span className="bg-slate-100 text-slate-800 font-mono px-2 py-0.5 rounded border border-slate-200">
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

                  {/* Verified Sources */}
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

                {/* Suggested Action Chips */}
                {msg.suggestedActions && msg.suggestedActions.length > 0 && !isUser && (
                  <div className="flex flex-wrap gap-1.5 pt-0.5">
                    {msg.suggestedActions.map((action, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => handleAiActionClick(action)}
                        disabled={isAiLoading}
                        className="inline-flex items-center gap-1 text-[11px] font-semibold text-cyan-700 hover:text-cyan-800 bg-white hover:bg-cyan-50 border border-cyan-200/80 px-2.5 py-1 rounded-lg transition-colors cursor-pointer shadow-2xs"
                      >
                        <span>{action}</span>
                        <ArrowRight className="w-3 h-3 text-cyan-600" />
                      </button>
                    ))}
                  </div>
                )}

                {/* Escalation Card if Human Requested */}
                {msg.escalateToHuman && !isUser && (
                  <div className="bg-cyan-50 border border-cyan-200 rounded-xl p-3 flex items-center justify-between gap-3 shadow-2xs">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-cyan-600 text-white flex items-center justify-center shrink-0">
                        <Headphones className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-bold text-cyan-950">Connect with Human Support</div>
                        <div className="text-[11px] text-cyan-700">
                          Transfer to our live operator desk or convert this chat to a ticket.
                        </div>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setChatMode('operator')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-xs font-bold transition-all shadow-xs cursor-pointer shrink-0"
                    >
                      <span>Join Queue</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}

                <div className={cn('text-[10px] text-slate-400 px-1', isUser && 'text-right')}>
                  {msg.timestamp}
                </div>
              </div>
            </div>
          );
        })}

        {/* Loading / Typing State */}
        {isAiLoading && (
          <div className="flex items-center gap-3 mr-auto max-w-[85%]">
            <div className="w-8 h-8 rounded-xl bg-cyan-600 text-white flex items-center justify-center shrink-0 animate-pulse">
              <Bot className="w-4 h-4" />
            </div>
            <div className="bg-white border border-slate-200/90 rounded-2xl rounded-tl-xs px-4 py-3 shadow-2xs flex items-center gap-2 text-xs font-medium text-slate-600">
              <RefreshCw className="w-3.5 h-3.5 text-cyan-600 animate-spin" />
              <span>CyberWatch AI is analyzing security findings &amp; telemetry...</span>
            </div>
          </div>
        )}

        {/* Error State with Retry Button */}
        {aiError && (
          <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center justify-between gap-3 max-w-[85%]">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{aiError}</span>
            </div>
            {lastFailedMessage && (
              <button
                type="button"
                onClick={handleRetryAi}
                className="inline-flex items-center gap-1 px-2.5 py-1 bg-rose-600 hover:bg-rose-700 text-white font-bold rounded-lg text-xs shrink-0 cursor-pointer shadow-2xs"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Retry</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* 3. Quick Prompts Bar */}
      <div className="px-4 py-2 bg-slate-50/70 border-t border-slate-100 flex items-center gap-2 overflow-x-auto scrollbar-none shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 shrink-0">
          Quick Prompts:
        </span>
        {quickActions.map((qa) => (
          <button
            key={qa.id}
            type="button"
            onClick={() => handleSendAiMessage(qa.prompt)}
            disabled={isAiLoading}
            className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-600 hover:text-cyan-700 hover:bg-white bg-slate-100 px-2.5 py-1 rounded-lg border border-slate-200/80 transition-colors whitespace-nowrap cursor-pointer shrink-0"
          >
            <span>{qa.title}</span>
          </button>
        ))}
      </div>

      {/* 4. Input Composer */}
      <div className="p-3 sm:p-4 bg-white border-t border-slate-200 shrink-0">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendAiMessage();
          }}
          className="flex items-end gap-2"
        >
          <div className="flex-1 relative">
            <textarea
              ref={aiInputRef}
              value={aiInputText}
              onChange={(e) => setAiInputText(e.target.value)}
              onKeyDown={handleAiKeyDown}
              placeholder="Ask about scan findings, risk scores, headers, CORS, or troubleshooting... (Enter to send, Shift+Enter for newline)"
              rows={1}
              className="w-full resize-none pl-3.5 pr-10 py-2.5 text-xs sm:text-sm bg-slate-50 hover:bg-slate-100/60 focus:bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-cyan-500/20 focus:border-cyan-500 transition-all placeholder:text-slate-400 max-h-32 text-slate-900"
            />
          </div>

          <button
            type="submit"
            disabled={!aiInputText.trim() || isAiLoading}
            className={cn(
              'p-2.5 rounded-xl font-bold transition-all shrink-0 cursor-pointer',
              aiInputText.trim() && !isAiLoading
                ? 'bg-cyan-600 text-white hover:bg-cyan-700 shadow-xs shadow-cyan-600/25'
                : 'bg-slate-100 text-slate-400 cursor-not-allowed'
            )}
            aria-label="Send message"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
