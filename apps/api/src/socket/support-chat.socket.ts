import { Server as HttpServer } from 'http';
import { Server as SocketIOServer, Socket } from 'socket.io';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import { supportService } from '../services/support.service';
import { SupportChatSession } from '../models/SupportChatSession';
import { User } from '../models/User';

interface AuthenticatedSocket extends Socket {
  user?: {
    userId: string;
    email: string;
    role: string;
    name?: string;
  };
}

let ioInstance: SocketIOServer | null = null;

export function getIO(): SocketIOServer | null {
  return ioInstance;
}

export function initializeSupportChatSocket(httpServer: HttpServer): SocketIOServer {
  const io = new SocketIOServer(httpServer, {
    cors: {
      origin: [
        env.FRONTEND_URL,
        'http://localhost:5173',
        'http://localhost:3000',
        'http://127.0.0.1:5173',
      ],
      credentials: true,
      methods: ['GET', 'POST'],
    },
    pingTimeout: 30000,
    pingInterval: 10000,
  });

  ioInstance = io;

  // Socket authentication middleware
  io.use(async (socket: AuthenticatedSocket, next) => {
    try {
      const token =
        socket.handshake.auth?.token ||
        socket.handshake.headers?.authorization?.replace('Bearer ', '');

      if (token) {
        try {
          const decoded = jwt.verify(token, env.JWT_SECRET) as {
            userId: string;
            email: string;
            role: string;
          };
          const userDoc = await User.findById(decoded.userId);
          socket.user = {
            userId: decoded.userId,
            email: decoded.email,
            role: decoded.role || (userDoc?.role as string) || 'USER',
            name: userDoc?.name,
          };
        } catch {
          // Token invalid — allow connection as anonymous/guest chat user
        }
      }
      next();
    } catch (err) {
      next(err as Error);
    }
  });

  io.on('connection', (socket: AuthenticatedSocket) => {
    const isOperator = socket.user?.role === 'ADMIN' || socket.user?.role === 'SUPPORT';

    // If authenticated user, join personal room for real-time notifications
    if (socket.user?.userId) {
      socket.join(`user:${socket.user.userId}`);
    }

    // If operator/admin, join operator room for real-time queue notifications
    if (isOperator) {
      socket.join('support_operators');
    }

    // ─── Join a Chat Session ───────────────────────────────────────────────
    socket.on('join_chat', async ({ sessionId }: { sessionId: string }) => {
      try {
        if (!sessionId) return;

        const session = await SupportChatSession.findOne({ sessionId });
        if (!session) {
          socket.emit('error', { message: 'Chat session not found' });
          return;
        }

        // Check ownership if not operator
        if (!isOperator && session.userId && socket.user?.userId) {
          if (session.userId.toString() !== socket.user.userId) {
            socket.emit('error', { message: 'Unauthorized chat session' });
            return;
          }
        }

        socket.join(`chat:${sessionId}`);
        socket.emit('chat:joined', { sessionId, status: session.status });
      } catch (err) {
        socket.emit('error', { message: 'Failed to join chat session' });
      }
    });

    // ─── Leave a Chat Session ──────────────────────────────────────────────
    socket.on('leave_chat', ({ sessionId }: { sessionId: string }) => {
      if (sessionId) {
        socket.leave(`chat:${sessionId}`);
      }
    });

    // ─── Send Message ──────────────────────────────────────────────────────
    socket.on(
      'chat:message',
      async (data: {
        sessionId: string;
        message: string;
        senderName?: string;
        attachments?: any[];
      }) => {
        try {
          const { sessionId, message, attachments } = data;
          if (!sessionId || !message?.trim()) return;

          let updatedSession;
          if (isOperator) {
            const operatorName = socket.user?.name || 'Support Agent';
            updatedSession = await supportService.sendOperatorMessage(
              sessionId,
              socket.user?.userId || '',
              operatorName,
              message,
              attachments
            );
          } else {
            const userName = socket.user?.name || data.senderName || 'Guest User';
            updatedSession = await supportService.sendChatMessage(
              sessionId,
              userName,
              message,
              socket.user?.userId,
              attachments
            );
          }

          const latestMessage =
            updatedSession.messages[updatedSession.messages.length - 1];

          // Broadcast to everyone in the chat room
          io.to(`chat:${sessionId}`).emit('chat:message', {
            sessionId,
            message: latestMessage,
            sessionStatus: updatedSession.status,
          });

          // Notify operators queue
          io.to('support_operators').emit('queue:updated', {
            sessionId,
            latestMessage,
            status: updatedSession.status,
          });
        } catch (err) {
          socket.emit('error', {
            message: (err as Error).message || 'Failed to send message',
          });
        }
      }
    );

    // ─── Typing Indicator ──────────────────────────────────────────────────
    socket.on(
      'chat:typing',
      ({
        sessionId,
        isTyping,
        userName,
      }: {
        sessionId: string;
        isTyping: boolean;
        userName?: string;
      }) => {
        if (!sessionId) return;
        socket.to(`chat:${sessionId}`).emit('chat:typing', {
          sessionId,
          isTyping,
          userName: socket.user?.name || userName || (isOperator ? 'Support Agent' : 'User'),
          isOperator,
        });
      }
    );

    // ─── Read Receipt ──────────────────────────────────────────────────────
    socket.on('chat:read', async ({ sessionId }: { sessionId: string }) => {
      try {
        if (!sessionId) return;
        await supportService.markMessagesAsRead(sessionId, isOperator ? 'SUPPORT' : 'USER');
        io.to(`chat:${sessionId}`).emit('chat:read_receipt', {
          sessionId,
          readBy: isOperator ? 'SUPPORT' : 'USER',
          readAt: new Date().toISOString(),
        });
      } catch {
        // Safe ignore
      }
    });

    // ─── Operator Claims Session ───────────────────────────────────────────
    socket.on('chat:claim', async ({ sessionId }: { sessionId: string }) => {
      try {
        if (!isOperator) {
          socket.emit('error', { message: 'Only support operators can claim chats' });
          return;
        }

        const operatorId = socket.user?.userId || '';
        const operatorName = socket.user?.name || 'Support Agent';

        const session = await supportService.claimChatSession(
          sessionId,
          operatorId,
          operatorName
        );

        // Notify user in the room that agent has connected
        io.to(`chat:${sessionId}`).emit('chat:assigned', {
          sessionId,
          status: 'ACTIVE',
          agentName: operatorName,
          session,
        });

        // Broadcast to all operators
        io.to('support_operators').emit('queue:updated', {
          sessionId,
          status: 'ACTIVE',
          assignedAgentName: operatorName,
        });
      } catch (err) {
        socket.emit('error', {
          message: (err as Error).message || 'Failed to claim chat session',
        });
      }
    });

    // ─── Close Chat Session ────────────────────────────────────────────────
    socket.on('chat:close', async ({ sessionId }: { sessionId: string }) => {
      try {
        if (!sessionId) return;

        const session = await supportService.endChatSession(
          sessionId,
          socket.user?.userId,
          socket.user?.role
        );

        io.to(`chat:${sessionId}`).emit('chat:closed', {
          sessionId,
          status: 'CLOSED',
          closedAt: session.closedAt || new Date().toISOString(),
        });

        io.to('support_operators').emit('queue:updated', {
          sessionId,
          status: 'CLOSED',
        });
      } catch (err) {
        socket.emit('error', {
          message: (err as Error).message || 'Failed to close chat session',
        });
      }
    });

    socket.on('disconnect', () => {
      // Disconnection handled gracefully
    });
  });

  return io;
}
