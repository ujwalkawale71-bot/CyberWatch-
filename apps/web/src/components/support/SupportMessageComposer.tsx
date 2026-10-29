import { useState } from 'react';
import { Send, Loader2, Paperclip, AlertCircle, RotateCcw } from 'lucide-react';
import { AttachmentUploader } from './AttachmentUploader';

interface SupportMessageComposerProps {
  onSendMessage: (message: string, files: File[]) => Promise<void>;
  onReopenTicket?: () => Promise<void>;
  isResolved?: boolean;
  disabled?: boolean;
}

export function SupportMessageComposer({
  onSendMessage,
  onReopenTicket,
  isResolved = false,
  disabled = false,
}: SupportMessageComposerProps) {
  const [message, setMessage] = useState('');
  const [files, setFiles] = useState<File[]>([]);
  const [showAttachments, setShowAttachments] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [isReopening, setIsReopening] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!message.trim() && files.length === 0) return;

    try {
      setIsSending(true);
      setError(null);
      await onSendMessage(message.trim(), files);
      setMessage('');
      setFiles([]);
      setShowAttachments(false);
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Failed to send reply.');
    } finally {
      setIsSending(false);
    }
  }

  async function handleReopen() {
    if (!onReopenTicket) return;
    try {
      setIsReopening(true);
      setError(null);
      await onReopenTicket();
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Failed to reopen ticket.');
    } finally {
      setIsReopening(false);
    }
  }

  if (isResolved) {
    return (
      <div className="bg-slate-50 border border-slate-200/90 rounded-2xl p-6 text-center space-y-3">
        <p className="text-xs font-semibold text-slate-700">
          This support request has been marked as <span className="font-bold text-emerald-700">Resolved</span>.
        </p>
        <p className="text-[11px] text-slate-500 max-w-md mx-auto">
          If you are still experiencing issues or have additional questions related to this request, you can reopen this ticket.
        </p>
        {error && (
          <div className="flex items-center justify-center gap-1.5 text-xs text-rose-600 bg-rose-50 p-2 rounded-lg max-w-sm mx-auto">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {onReopenTicket && (
          <button
            type="button"
            onClick={handleReopen}
            disabled={isReopening}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-bold text-cyan-700 bg-cyan-50 border border-cyan-200 hover:bg-cyan-100 rounded-xl transition-colors shadow-2xs cursor-pointer"
          >
            {isReopening ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />}
            <span>Reopen Ticket</span>
          </button>
        )}
      </div>
    );
  }

  return (
    <form onSubmit={handleSend} className="bg-white rounded-2xl border border-slate-200/90 p-4 shadow-xs space-y-3">
      {error && (
        <div className="flex items-center gap-2 p-2.5 rounded-xl bg-rose-50 border border-rose-100 text-xs text-rose-700">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div>
        <textarea
          rows={3}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Write your reply or additional details here..."
          disabled={disabled || isSending}
          className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 border border-slate-200 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 font-sans leading-relaxed text-slate-900"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              handleSend(e);
            }
          }}
        />
      </div>

      {showAttachments && (
        <div className="pt-1">
          <AttachmentUploader files={files} onChange={setFiles} maxFiles={3} disabled={isSending} />
        </div>
      )}

      <div className="flex items-center justify-between pt-1 border-t border-slate-100">
        <button
          type="button"
          onClick={() => setShowAttachments(!showAttachments)}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 px-2.5 py-1.5 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
        >
          <Paperclip className="w-4 h-4 text-slate-400" />
          <span>{showAttachments ? 'Hide Attachments' : 'Attach Files'}</span>
          {files.length > 0 && (
            <span className="bg-cyan-100 text-cyan-800 font-bold px-1.5 py-0.2 rounded-full text-[10px]">
              {files.length}
            </span>
          )}
        </button>

        <div className="flex items-center gap-3">
          <span className="hidden sm:inline text-[11px] text-slate-400">Ctrl + Enter to send</span>
          <button
            type="submit"
            disabled={(!message.trim() && files.length === 0) || isSending || disabled}
            className="inline-flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-700 active:bg-cyan-800 disabled:opacity-50 text-white text-xs font-bold px-4 py-2 rounded-xl shadow-xs transition-colors cursor-pointer"
          >
            {isSending ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Sending...</span>
              </>
            ) : (
              <>
                <Send className="w-3.5 h-3.5" />
                <span>Send Reply</span>
              </>
            )}
          </button>
        </div>
      </div>
    </form>
  );
}
