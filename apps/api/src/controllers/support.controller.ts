import type { Request, Response, NextFunction } from 'express';
import { supportService } from '../services/support.service';
import { supportAttachmentService } from '../services/support-attachment.service';
import { User } from '../models/User';
import { notificationService } from '../services/notification.service';

export const supportController = {
  /**
   * GET /api/v1/support/config
   * Public contact & help desk configuration.
   */
  async getConfig(_req: Request, res: Response): Promise<void> {
    const config = supportService.getPublicConfig();
    res.status(200).json({
      success: true,
      data: config,
    });
  },

  /**
   * POST /api/v1/support/tickets
   * Create a new support ticket.
   */
  async createTicket(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      // Fetch user profile from DB to get verified name and email
      const user = await User.findById(req.user.userId);
      const userName = req.body.name?.trim() || user?.name || 'User';
      const userEmail = req.body.email?.trim() || user?.email || '';

      const attachments = [
        ...(req.supportAttachments || []),
        ...(Array.isArray(req.body.attachments) ? req.body.attachments : []),
      ];

      const ticket = await supportService.createTicket(
        req.user.userId,
        req.user.role,
        {
          name: userName,
          email: userEmail,
          category: req.body.category,
          priority: req.body.priority || 'MEDIUM',
          subject: req.body.subject,
          description: req.body.description,
          scanId: req.body.scanId,
          reportId: req.body.reportId,
          targetUrl: req.body.targetUrl,
          browserEnvironment: req.body.browserEnvironment,
        },
        attachments
      );

      notificationService.createSupportNotification({
        userId: req.user.userId,
        ticketId: (ticket as any).id || (ticket as any)._id?.toString() || 'ticket',
        ticketNumber: ticket.ticketNumber,
        subject: ticket.subject,
        type: 'SUPPORT_TICKET_CREATED',
      }).catch((err) => {
        console.error('[NotificationService] Failed to emit ticket created notification:', err);
      });

      res.status(201).json({
        success: true,
        message: 'Support request submitted successfully.',
        data: ticket,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/v1/support/tickets
   * Get authenticated user's tickets.
   */
  async getUserTickets(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const { status, search, sortBy, page, limit } = req.query;

      const result = await supportService.getUserTickets(req.user.userId, {
        status: typeof status === 'string' ? status : undefined,
        search: typeof search === 'string' ? search : undefined,
        sortBy: sortBy === 'oldest' || sortBy === 'updated' ? sortBy : 'newest',
        page: page ? parseInt(page as string, 10) : 1,
        limit: limit ? parseInt(limit as string, 10) : 20,
      });

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/v1/support/tickets/:ticketId
   * Get ticket details and conversation thread.
   */
  async getTicketById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const ticketId = Array.isArray(req.params.ticketId) ? req.params.ticketId[0] : req.params.ticketId;
      const ticket = await supportService.getTicketById(
        ticketId as string,
        req.user.userId,
        req.user.role
      );

      res.status(200).json({
        success: true,
        data: ticket,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/tickets/:ticketId/messages
   * Reply to a ticket.
   */
  async addTicketMessage(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const user = await User.findById(req.user.userId);
      const userName = user?.name || 'User';

      const attachments = [
        ...(req.supportAttachments || []),
        ...(Array.isArray(req.body.attachments) ? req.body.attachments : []),
      ];

      const ticketId = Array.isArray(req.params.ticketId) ? req.params.ticketId[0] : req.params.ticketId;
      const ticket = await supportService.addTicketMessage(
        ticketId as string,
        req.user.userId,
        req.user.role,
        userName,
        req.body.message,
        attachments
      );

      // Notify ticket owner if reply is from an operator/admin
      if (((req.user.role as string) === 'ADMIN' || (req.user.role as string) === 'SUPPORT') && (ticket as any).userId) {
        notificationService.createSupportNotification({
          userId: (ticket as any).userId.toString(),
          ticketId: (ticket as any).id || (ticket as any)._id?.toString() || 'ticket',
          ticketNumber: ticket.ticketNumber,
          subject: ticket.subject,
          type: 'SUPPORT_RESPONSE_RECEIVED',
          responderName: userName,
        }).catch((err) => {
          console.error('[NotificationService] Failed to emit ticket response notification:', err);
        });
      }

      res.status(200).json({
        success: true,
        message: 'Message sent successfully.',
        data: ticket,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/tickets/:ticketId/reopen
   * Reopen a resolved ticket.
   */
  async reopenTicket(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const ticketId = Array.isArray(req.params.ticketId) ? req.params.ticketId[0] : req.params.ticketId;
      const ticket = await supportService.reopenTicket(
        ticketId as string,
        req.user.userId,
        req.user.role,
        req.body.reason
      );

      res.status(200).json({
        success: true,
        message: 'Support ticket has been reopened.',
        data: ticket,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/attachments/upload
   * Upload an attachment file for tickets or reports.
   */
  async uploadAttachment(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.supportAttachments || req.supportAttachments.length === 0) {
        res.status(400).json({
          success: false,
          message: 'No valid file was provided in the upload request.',
        });
        return;
      }

      res.status(201).json({
        success: true,
        message: 'Attachment uploaded successfully.',
        data: req.supportAttachments[0],
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/v1/support/attachments/:filename
   * Securely download or view authorized attachment.
   */
  async downloadAttachment(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const paramFilename = req.params.filename;
      const filename = Array.isArray(paramFilename) ? paramFilename[0] : paramFilename;
      const userId = req.user?.userId;
      const userRole = req.user?.role;

      const fileInfo = await supportAttachmentService.getAuthorizedAttachmentPath(
        filename as string,
        userId,
        userRole
      );

      if (!fileInfo) {
        res.status(404).json({
          success: false,
          message: 'Attachment not found or you do not have permission to download it.',
        });
        return;
      }

      res.setHeader('Content-Type', fileInfo.mimeType);
      res.setHeader(
        'Content-Disposition',
        `inline; filename="${encodeURIComponent(fileInfo.originalName)}"`
      );
      res.sendFile(fileInfo.filePath);
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/security-reports
   * Submit a confidential vulnerability report.
   */
  async createSecurityReport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const attachments = [
        ...(req.supportAttachments || []),
        ...(Array.isArray(req.body.attachments) ? req.body.attachments : []),
      ];

      const report = await supportService.createSecurityReport(
        req.user?.userId,
        {
          email: req.body.email,
          vulnerabilityType: req.body.vulnerabilityType,
          severity: req.body.severity || 'MEDIUM',
          affectedComponent: req.body.affectedComponent,
          affectedUrl: req.body.affectedUrl,
          description: req.body.description,
          stepsToReproduce: req.body.stepsToReproduce,
          impact: req.body.impact,
          suggestedFix: req.body.suggestedFix,
        },
        attachments
      );

      res.status(201).json({
        success: true,
        message: 'Confidential security vulnerability report received. Thank you for responsible disclosure.',
        data: report,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/v1/support/security-reports
   * Get user's submitted security reports.
   */
  async getUserSecurityReports(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const reports = await supportService.getUserSecurityReports(req.user.userId);
      res.status(200).json({
        success: true,
        data: reports,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/v1/support/security-reports/:reportId
   * Get confidential security report by ID.
   */
  async getSecurityReportById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const paramReportId = req.params.reportId;
      const reportId = Array.isArray(paramReportId) ? paramReportId[0] : paramReportId;

      const report = await supportService.getSecurityReportById(
        reportId as string,
        req.user.userId,
        req.user.role
      );

      res.status(200).json({
        success: true,
        data: report,
      });
    } catch (err) {
      next(err);
    }
  },

  // ─── Live Chat Controller Endpoints ─────────────────────────────────────────

  /**
   * POST /api/v1/support/chat/session
   * Start support chat session.
   */
  async startChatSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      let userName = req.body.userName;
      let userEmail = req.body.userEmail;

      if (req.user) {
        const user = await User.findById(req.user.userId);
        if (user) {
          userName = userName || user.name;
          userEmail = userEmail || user.email;
        }
      }

      const session = await supportService.startChatSession({
        userId: req.user?.userId,
        userName,
        userEmail,
        initialMessage: req.body.initialMessage,
      });

      res.status(201).json({
        success: true,
        data: session,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/v1/support/chat/session/:sessionId
   * Retrieve chat session conversation.
   */
  async getChatSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const paramSessionId = req.params.sessionId;
      const sessionId = Array.isArray(paramSessionId) ? paramSessionId[0] : paramSessionId;

      const session = await supportService.getChatSession(
        sessionId as string,
        req.user?.userId
      );

      res.status(200).json({
        success: true,
        data: session,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/chat/session/:sessionId/messages
   * Send a chat message.
   */
  async sendChatMessage(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      let senderName = req.body.senderName;
      if (req.user) {
        const user = await User.findById(req.user.userId);
        if (user) senderName = user.name;
      }

      const paramSessionId = req.params.sessionId;
      const sessionId = Array.isArray(paramSessionId) ? paramSessionId[0] : paramSessionId;

      const session = await supportService.sendChatMessage(
        sessionId as string,
        senderName,
        req.body.message,
        req.user?.userId
      );

      res.status(200).json({
        success: true,
        data: session,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/chat/session/:sessionId/end
   * End a chat session.
   */
  async endChatSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const paramSessionId = req.params.sessionId;
      const sessionId = Array.isArray(paramSessionId) ? paramSessionId[0] : paramSessionId;

      const session = await supportService.endChatSession(
        sessionId as string,
        req.user?.userId,
        req.user?.role
      );

      res.status(200).json({
        success: true,
        message: 'Chat session closed.',
        data: session,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/v1/support/chat/sessions
   * Get user's past and current chat sessions.
   */
  async getUserChatSessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const sessions = await supportService.getUserChatSessions(req.user.userId);
      res.status(200).json({
        success: true,
        data: sessions,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/chat/session/:sessionId/convert-to-ticket
   * Convert live chat conversation to support ticket.
   */
  async convertChatToTicket(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const paramSessionId = req.params.sessionId;
      const sessionId = Array.isArray(paramSessionId) ? paramSessionId[0] : paramSessionId;

      const ticket = await supportService.convertChatToTicket(
        sessionId as string,
        req.user.userId,
        req.user.role
      );

      notificationService.createSupportNotification({
        userId: req.user.userId,
        ticketId: (ticket as any).id || (ticket as any)._id?.toString() || 'ticket',
        ticketNumber: ticket.ticketNumber,
        subject: ticket.subject,
        type: 'SUPPORT_TICKET_CREATED',
      }).catch((err) => {
        console.error('[NotificationService] Failed to emit ticket created notification:', err);
      });

      res.status(201).json({
        success: true,
        message: 'Chat session converted to support ticket.',
        data: ticket,
      });
    } catch (err) {
      next(err);
    }
  },

  // ─── Operator & Admin Chat Endpoints ────────────────────────────────────────

  /**
   * GET /api/v1/support/admin/chats
   * Get all chat sessions in operator queue.
   */
  async getOperatorQueue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const statusFilter = req.query.status as string | undefined;
      const sessions = await supportService.getOperatorChatQueue(statusFilter);

      res.status(200).json({
        success: true,
        data: sessions,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/admin/chats/:sessionId/claim
   * Operator claims a waiting chat session.
   */
  async claimChatSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const paramSessionId = req.params.sessionId;
      const sessionId = Array.isArray(paramSessionId) ? paramSessionId[0] : paramSessionId;

      let operatorName = 'Support Agent';
      const user = await User.findById(req.user.userId);
      if (user?.name) operatorName = user.name;

      const session = await supportService.claimChatSession(
        sessionId as string,
        req.user.userId,
        operatorName
      );

      res.status(200).json({
        success: true,
        message: 'Chat session claimed by operator.',
        data: session,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/admin/chats/:sessionId/messages
   * Operator sends a message to chat session.
   */
  async sendOperatorMessage(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const paramSessionId = req.params.sessionId;
      const sessionId = Array.isArray(paramSessionId) ? paramSessionId[0] : paramSessionId;

      let operatorName = req.body.operatorName || 'Support Agent';
      const user = await User.findById(req.user.userId);
      if (user?.name) operatorName = user.name;

      const session = await supportService.sendOperatorMessage(
        sessionId as string,
        req.user.userId,
        operatorName,
        req.body.message
      );

      res.status(200).json({
        success: true,
        data: session,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/v1/support/admin/chats/:sessionId/close
   * Operator closes chat session.
   */
  async closeOperatorChatSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required.' });
        return;
      }

      const paramSessionId = req.params.sessionId;
      const sessionId = Array.isArray(paramSessionId) ? paramSessionId[0] : paramSessionId;

      const session = await supportService.endChatSession(
        sessionId as string,
        req.user.userId,
        req.user.role
      );

      res.status(200).json({
        success: true,
        message: 'Chat session closed by operator.',
        data: session,
      });
    } catch (err) {
      next(err);
    }
  },
};
