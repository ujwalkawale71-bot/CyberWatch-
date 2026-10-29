import { useState, useEffect, useRef } from 'react';
import {
  Shield,
  MessageSquare,
  Send,
  LogOut,
  RefreshCw,
  Search,
  Check,
} from 'lucide-react';
import type { SupportChatSession, SupportChatMessage } from '../../types';
import { supportService } from '../../services/support.service';
import {
  liveChatSocketService,
  type ChatMessageEvent,
  type ChatTypingEvent,
} from '../../services/live-chat.service';

interface SupportOperatorDeskProps {
  operatorUser?: { name?: string; email?: string; userId?: string } | null;
}

export function SupportOperatorDesk({ operatorUser }: SupportOperatorDeskProps) {
  const [queue, setQueue] = useState<SupportChatSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<SupportChatSession | null>(null);
  const [messages, setMessages] = useState<SupportChatMessage[]>([]);
  const [replyInput, setReplyInput] = useState('');
  const [isLoadingQueue, setIsLoadingQueue] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'WAITING' | 'ACTIVE' | 'CLOSED'>('WAITING');
  const [searchQuery, setSearchQuery] = useState('');
  const [userTyping, setUserTyping] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Fetch Queue from backend
  const fetchQueue = async () => {
    try {
      setIsLoadingQueue(true);
      const data = await supportService.getOperatorQueue(statusFilter);
      setQueue(data);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.message || 'Failed to load operator chat queue.');
    } finally {
      setIsLoadingQueue(false);
    }
  };

  useEffect(() => {
    fetchQueue();
    const interval = setInterval(fetchQueue, 8000);
    return () => clearInterval(interval);
  }, [statusFilter]);

  // Connect socket and listen for live events
  useEffect(() => {
    liveChatSocketService.connect();

    const unsubQueue = liveChatSocketService.onQueueUpdated(() => {
      fetchQueue();
    });

    const unsubMessage = liveChatSocketService.onMessage((event: ChatMessageEvent) => {
      if (selectedSession && event.sessionId === selectedSession.sessionId) {
        setMessages((prev) => {
          if (prev.some((m) => m.id === event.message.id)) return prev;
          return [...prev, event.message];
        });
      }
      fetchQueue();
    });

    const unsubTyping = liveChatSocketService.onTyping((event: ChatTypingEvent) => {
      if (selectedSession && event.sessionId === selectedSession.sessionId) {
        setUserTyping(event.isTyping);
      }
    });

    return () => {
      unsubQueue();
      unsubMessage();
      unsubTyping();
    };
  }, [selectedSession?.sessionId]);

  // Select a session to view/chat
  const handleSelectSession = async (session: SupportChatSession) => {
    setSelectedSession(session);
    setMessages(session.messages || []);
    liveChatSocketService.joinSession(session.sessionId);
    liveChatSocketService.markAsRead(session.sessionId);
  };

  // Claim a waiting chat session
  const handleClaimSession = async (sessionId: string) => {
    try {
      setErrorMsg(null);
      liveChatSocketService.claimSession(sessionId);
      const updated = await supportService.claimChatSession(sessionId);
      setSelectedSession(updated);
      setMessages(updated.messages || []);
      fetchQueue();
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.message || 'Failed to claim session.');
    }
  };

  // Send Operator Reply
  const handleSendReply = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!replyInput.trim() || !selectedSession || isSending) return;

    const textToSend = replyInput.trim();
    setReplyInput('');

    try {
      setIsSending(true);
      setErrorMsg(null);

      liveChatSocketService.sendMessage(
        selectedSession.sessionId,
        textToSend,
        operatorUser?.name || 'Support Agent'
      );
    } catch (err: any) {
      try {
        const updated = await supportService.sendOperatorMessage(
          selectedSession.sessionId,
          textToSend,
          operatorUser?.name || 'Support Agent'
        );
        setSelectedSession(updated);
        setMessages(updated.messages || []);
      } catch (restErr: any) {
        setErrorMsg(restErr?.response?.data?.message || 'Failed to send reply.');
      }
    } finally {
      setIsSending(false);
    }
  };

  // Close Session
  const handleCloseSession = async () => {
    if (!selectedSession) return;
    if (!window.confirm('Are you sure you want to close this customer conversation?')) return;

    try {
      liveChatSocketService.closeSession(selectedSession.sessionId);
      const updated = await supportService.closeOperatorChat(selectedSession.sessionId);
      setSelectedSession(updated);
      setMessages(updated.messages || []);
      fetchQueue();
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.message || 'Failed to close session.');
    }
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, userTyping]);

  const filteredQueue = queue.filter((s) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      s.sessionId.toLowerCase().includes(query) ||
      s.userName.toLowerCase().includes(query) ||
      s.userEmail.toLowerCase().includes(query)
    );
  });

  return (
    <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm overflow-hidden flex flex-col lg:flex-row h-[650px]">
      {/* Left Column: Operator Queue */}
      <div className="w-full lg:w-80 border-r border-slate-200 flex flex-col bg-slate-50/50">
        {/* Queue Header */}
        <div className="p-4 border-b border-slate-200 bg-white">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-600" />
              <h3 className="text-sm font-bold text-slate-900">Live Support Queue</h3>
            </div>
            <button
              type="button"
              onClick={fetchQueue}
              className="text-slate-400 hover:text-slate-600 p-1 rounded-lg transition-colors cursor-pointer"
              title="Refresh queue"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingQueue ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {/* Search bar */}
          <div className="relative mb-2.5">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search user or session ID..."
              className="w-full text-xs pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg focus:bg-white focus:outline-none focus:ring-1 focus:ring-cyan-500 text-slate-900"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex gap-1">
            {(['WAITING', 'ACTIVE', 'ALL'] as const).map((filter) => (
              <button
                key={filter}
                type="button"
                onClick={() => setStatusFilter(filter)}
                className={`flex-1 text-[11px] font-semibold py-1 rounded-md transition-colors cursor-pointer ${
                  statusFilter === filter
                    ? 'bg-cyan-600 text-white shadow-2xs'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {filter === 'WAITING' ? 'Waiting' : filter === 'ACTIVE' ? 'Active' : 'All'}
              </button>
            ))}
          </div>
        </div>

        {/* Queue Item List */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
          {filteredQueue.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">
              {isLoadingQueue ? 'Loading queue...' : 'No conversations in this queue.'}
            </div>
          ) : (
            filteredQueue.map((s) => {
              const isSelected = selectedSession?.sessionId === s.sessionId;
              const isWaiting = s.status === 'WAITING_FOR_AGENT' || s.status === 'WAITING';
              const lastMsg = s.messages && s.messages.length > 0 ? s.messages[s.messages.length - 1] : null;

              return (
                <div
                  key={s.sessionId}
                  onClick={() => handleSelectSession(s)}
                  className={`p-3.5 cursor-pointer transition-colors text-left ${
                    isSelected ? 'bg-cyan-50/70 border-l-4 border-l-cyan-600' : 'hover:bg-white'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold text-slate-900 truncate max-w-[140px]">
                      {s.userName}
                    </span>
                    <span
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                        isWaiting
                          ? 'bg-amber-100 text-amber-800'
                          : s.status === 'ACTIVE'
                          ? 'bg-emerald-100 text-emerald-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {isWaiting ? 'Waiting' : s.status}
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-500 truncate mb-1">
                    {lastMsg ? lastMsg.message : 'Session started'}
                  </p>

                  <div className="flex items-center justify-between text-[10px] text-slate-400">
                    <span>#{s.sessionId}</span>
                    <span>
                      {new Date(s.updatedAt || s.createdAt).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Right Column: Selected Conversation Workspace */}
      <div className="flex-1 flex flex-col bg-white">
        {selectedSession ? (
          <>
            {/* Conversation Header */}
            <div className="p-4 border-b border-slate-200 bg-slate-50/70 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-bold text-slate-900">{selectedSession.userName}</h4>
                  <span className="text-xs text-slate-500">({selectedSession.userEmail})</span>
                  <span className="text-[11px] font-mono text-slate-400">#{selectedSession.sessionId}</span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-600 mt-0.5">
                  <span>Status: <strong className="text-slate-800">{selectedSession.status}</strong></span>
                  {selectedSession.assignedAgentName && (
                    <span>• Assigned: <strong>{selectedSession.assignedAgentName}</strong></span>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2">
                {(selectedSession.status === 'WAITING_FOR_AGENT' || selectedSession.status === 'WAITING') && (
                  <button
                    type="button"
                    onClick={() => handleClaimSession(selectedSession.sessionId)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white text-xs font-bold rounded-lg shadow-2xs transition-colors cursor-pointer"
                  >
                    <Check className="w-3.5 h-3.5" />
                    <span>Accept Chat</span>
                  </button>
                )}

                {selectedSession.status !== 'CLOSED' && selectedSession.status !== 'ENDED' && (
                  <button
                    type="button"
                    onClick={handleCloseSession}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-rose-50 hover:text-rose-700 text-slate-700 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Close</span>
                  </button>
                )}
              </div>
            </div>

            {/* Message Stream */}
            <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-3.5 bg-slate-50/30">
              {messages.map((msg, idx) => {
                const isOperator = msg.senderType === 'SUPPORT';
                const isSystem = msg.senderType === 'SYSTEM';

                if (isSystem) {
                  return (
                    <div key={msg.id || idx} className="flex justify-center my-2">
                      <span className="text-[11px] font-medium text-slate-500 bg-white border border-slate-200 px-3 py-1 rounded-full">
                        {msg.message}
                      </span>
                    </div>
                  );
                }

                return (
                  <div
                    key={msg.id || idx}
                    className={`flex flex-col ${isOperator ? 'items-end' : 'items-start'}`}
                  >
                    <div className="flex items-center gap-1.5 mb-1 text-[11px] text-slate-500 px-1">
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
                      className={`max-w-[75%] rounded-2xl px-4 py-2.5 text-sm ${
                        isOperator
                          ? 'bg-cyan-600 text-white rounded-tr-xs'
                          : 'bg-white text-slate-900 border border-slate-200 rounded-tl-xs shadow-2xs'
                      }`}
                    >
                      <p className="whitespace-pre-wrap">{msg.message}</p>
                    </div>
                  </div>
                );
              })}

              {userTyping && (
                <div className="flex items-center gap-2 text-xs text-slate-500 bg-white border border-slate-200 px-3 py-1.5 rounded-2xl w-fit animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-600" />
                  <span>User is typing a response...</span>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Operator Reply Composer */}
            <div className="p-3 sm:p-4 border-t border-slate-200 bg-white">
              {errorMsg && (
                <div className="mb-2 p-2 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 text-xs">
                  {errorMsg}
                </div>
              )}

              {selectedSession.status === 'CLOSED' || selectedSession.status === 'ENDED' ? (
                <div className="text-center py-2 text-xs text-slate-500 bg-slate-50 rounded-xl">
                  This conversation has ended and is read-only.
                </div>
              ) : (
                <form onSubmit={handleSendReply} className="flex items-center gap-2">
                  <input
                    type="text"
                    value={replyInput}
                    onChange={(e) => setReplyInput(e.target.value)}
                    placeholder="Type an official support response to the client..."
                    className="flex-1 text-sm px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 text-slate-900"
                  />
                  <button
                    type="submit"
                    disabled={!replyInput.trim() || isSending}
                    className="p-2.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-xl shadow-xs transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </form>
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-500">
            <MessageSquare className="w-12 h-12 text-slate-300 mb-3" />
            <h4 className="text-base font-bold text-slate-800">No Chat Selected</h4>
            <p className="text-xs text-slate-500 max-w-sm mt-1">
              Select a waiting user from the left queue to claim the session and begin real-time consultation.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
