import type { SupportMessage } from '../../types';
import { Shield, User, Info, FileText, Download, Image as ImageIcon } from 'lucide-react';
import { cn } from '../../lib/utils';

interface SupportConversationProps {
  messages: SupportMessage[];
}

export function SupportConversation({ messages }: SupportConversationProps) {
  if (!messages || messages.length === 0) {
    return (
      <div className="p-8 text-center text-xs text-slate-400 bg-slate-50/50 rounded-2xl border border-slate-200/60">
        No conversation history yet.
      </div>
    );
  }

  function formatTime(dateStr: string) {
    return new Date(dateStr).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  return (
    <div className="space-y-6">
      {messages.map((msg, idx) => {
        if (msg.senderType === 'SYSTEM') {
          return (
            <div key={msg.id || idx} className="flex items-center justify-center my-4">
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-100 border border-slate-200/80 text-[11px] font-medium text-slate-600 shadow-2xs">
                <Info className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span>{msg.message}</span>
                <span className="text-slate-400 text-[10px]">• {formatTime(msg.createdAt)}</span>
              </div>
            </div>
          );
        }

        const isSupport = msg.senderType === 'SUPPORT';

        return (
          <div
            key={msg.id || idx}
            className={cn('flex items-start gap-3 max-w-2xl', isSupport ? 'mr-auto' : 'ml-auto flex-row-reverse')}
          >
            {/* Avatar */}
            <div
              className={cn(
                'w-8 h-8 rounded-full flex items-center justify-center shrink-0 shadow-xs border text-xs font-bold',
                isSupport
                  ? 'bg-cyan-600 text-white border-cyan-700'
                  : 'bg-slate-800 text-white border-slate-900'
              )}
            >
              {isSupport ? <Shield className="w-4 h-4" /> : <User className="w-4 h-4" />}
            </div>

            {/* Bubble */}
            <div className={cn('space-y-1.5 min-w-0 flex-1', !isSupport && 'text-right')}>
              <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-500 px-1">
                <span className={cn('text-slate-900', isSupport && 'text-cyan-700')}>
                  {isSupport ? `${msg.senderName} (CyberWatch Support)` : msg.senderName}
                </span>
                <span>•</span>
                <span className="font-normal">{formatTime(msg.createdAt)}</span>
              </div>

              <div
                className={cn(
                  'p-4 rounded-2xl text-xs leading-relaxed break-words whitespace-pre-wrap text-left shadow-2xs',
                  isSupport
                    ? 'bg-white border border-slate-200/90 text-slate-800'
                    : 'bg-cyan-600 text-white border border-cyan-600'
                )}
              >
                {msg.message}

                {/* Message Attachments */}
                {msg.attachments && msg.attachments.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-slate-100/30 space-y-1.5">
                    <p className={cn('text-[11px] font-bold uppercase tracking-wider', isSupport ? 'text-slate-400' : 'text-cyan-100')}>
                      Attachments ({msg.attachments.length})
                    </p>
                    <div className="space-y-1">
                      {msg.attachments.map((att, attIdx) => (
                        <a
                          key={att.id || attIdx}
                          href={att.downloadUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={cn(
                            'flex items-center justify-between p-2 rounded-xl text-xs font-medium transition-colors border',
                            isSupport
                              ? 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100'
                              : 'bg-cyan-700/60 border-cyan-500/50 text-white hover:bg-cyan-700'
                          )}
                        >
                          <div className="flex items-center gap-2 truncate">
                            {att.mimeType.startsWith('image/') ? (
                              <ImageIcon className="w-4 h-4 shrink-0" />
                            ) : (
                              <FileText className="w-4 h-4 shrink-0" />
                            )}
                            <span className="truncate">{att.originalName}</span>
                          </div>
                          <Download className="w-3.5 h-3.5 shrink-0 ml-2 opacity-80" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
