import { io, Socket } from 'socket.io-client';
import type { SupportChatMessage, SupportChatSession } from '../types';

export type ChatConnectionState = 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR';

export interface ChatTypingEvent {
  sessionId: string;
  isTyping: boolean;
  userName: string;
  isOperator: boolean;
}

export interface ChatMessageEvent {
  sessionId: string;
  message: SupportChatMessage;
  sessionStatus?: string;
}

export interface ChatAssignedEvent {
  sessionId: string;
  status: string;
  agentName: string;
  session?: SupportChatSession;
}

export interface ChatClosedEvent {
  sessionId: string;
  status: string;
  closedAt: string;
}

class LiveChatSocketService {
  private socket: Socket | null = null;
  private currentSessionId: string | null = null;
  private connectionListeners: Set<(state: ChatConnectionState) => void> = new Set();
  private messageListeners: Set<(event: ChatMessageEvent) => void> = new Set();
  private typingListeners: Set<(event: ChatTypingEvent) => void> = new Set();
  private assignedListeners: Set<(event: ChatAssignedEvent) => void> = new Set();
  private closedListeners: Set<(event: ChatClosedEvent) => void> = new Set();
  private queueListeners: Set<(data: any) => void> = new Set();
  private errorListeners: Set<(err: string) => void> = new Set();

  private getSocketUrl(): string {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000/api/v1';
    return apiUrl.replace(/\/api\/v1\/?$/, '');
  }

  public connect(): void {
    if (this.socket?.connected) return;

    const token = localStorage.getItem('token') || localStorage.getItem('auth_token');
    const socketUrl = this.getSocketUrl();

    this.notifyConnectionState('CONNECTING');

    this.socket = io(socketUrl, {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnectionAttempts: 10,
      reconnectionDelay: 2000,
    });

    this.socket.on('connect', () => {
      this.notifyConnectionState('CONNECTED');
      if (this.currentSessionId) {
        this.joinSession(this.currentSessionId);
      }
    });

    this.socket.on('disconnect', () => {
      this.notifyConnectionState('DISCONNECTED');
    });

    this.socket.on('connect_error', () => {
      this.notifyConnectionState('ERROR');
    });

    this.socket.on('chat:message', (event: ChatMessageEvent) => {
      this.messageListeners.forEach((listener) => listener(event));
    });

    this.socket.on('chat:typing', (event: ChatTypingEvent) => {
      this.typingListeners.forEach((listener) => listener(event));
    });

    this.socket.on('chat:assigned', (event: ChatAssignedEvent) => {
      this.assignedListeners.forEach((listener) => listener(event));
    });

    this.socket.on('chat:closed', (event: ChatClosedEvent) => {
      this.closedListeners.forEach((listener) => listener(event));
    });

    this.socket.on('queue:updated', (data: any) => {
      this.queueListeners.forEach((listener) => listener(data));
    });

    this.socket.on('error', (err: { message: string }) => {
      this.errorListeners.forEach((listener) => listener(err.message || 'Chat error occurred'));
    });
  }

  public joinSession(sessionId: string): void {
    this.currentSessionId = sessionId;
    if (this.socket && this.socket.connected) {
      this.socket.emit('join_chat', { sessionId });
    }
  }

  public leaveSession(sessionId?: string): void {
    const idToLeave = sessionId || this.currentSessionId;
    if (idToLeave && this.socket && this.socket.connected) {
      this.socket.emit('leave_chat', { sessionId: idToLeave });
    }
    if (!sessionId || sessionId === this.currentSessionId) {
      this.currentSessionId = null;
    }
  }

  public sendMessage(sessionId: string, message: string, senderName?: string): void {
    if (!this.socket || !this.socket.connected) {
      throw new Error('Chat is not connected to the real-time server.');
    }
    this.socket.emit('chat:message', {
      sessionId,
      message,
      senderName,
    });
  }

  public sendTyping(sessionId: string, isTyping: boolean, userName?: string): void {
    if (this.socket && this.socket.connected) {
      this.socket.emit('chat:typing', { sessionId, isTyping, userName });
    }
  }

  public claimSession(sessionId: string): void {
    if (this.socket && this.socket.connected) {
      this.socket.emit('chat:claim', { sessionId });
    }
  }

  public closeSession(sessionId: string): void {
    if (this.socket && this.socket.connected) {
      this.socket.emit('chat:close', { sessionId });
    }
  }

  public markAsRead(sessionId: string): void {
    if (this.socket && this.socket.connected) {
      this.socket.emit('chat:read', { sessionId });
    }
  }

  public disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.currentSessionId = null;
      this.notifyConnectionState('DISCONNECTED');
    }
  }

  // ─── Event Subscriptions ───────────────────────────────────────────────────

  public onConnectionStateChange(callback: (state: ChatConnectionState) => void): () => void {
    this.connectionListeners.add(callback);
    return () => this.connectionListeners.delete(callback);
  }

  public onMessage(callback: (event: ChatMessageEvent) => void): () => void {
    this.messageListeners.add(callback);
    return () => this.messageListeners.delete(callback);
  }

  public onTyping(callback: (event: ChatTypingEvent) => void): () => void {
    this.typingListeners.add(callback);
    return () => this.typingListeners.delete(callback);
  }

  public onAssigned(callback: (event: ChatAssignedEvent) => void): () => void {
    this.assignedListeners.add(callback);
    return () => this.assignedListeners.delete(callback);
  }

  public onClosed(callback: (event: ChatClosedEvent) => void): () => void {
    this.closedListeners.add(callback);
    return () => this.closedListeners.delete(callback);
  }

  public onQueueUpdated(callback: (data: any) => void): () => void {
    this.queueListeners.add(callback);
    return () => this.queueListeners.delete(callback);
  }

  public onError(callback: (err: string) => void): () => void {
    this.errorListeners.add(callback);
    return () => this.errorListeners.delete(callback);
  }

  private notifyConnectionState(state: ChatConnectionState): void {
    this.connectionListeners.forEach((listener) => listener(state));
  }
}

export const liveChatSocketService = new LiveChatSocketService();
