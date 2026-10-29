import { Types } from 'mongoose';
import { env } from '../config/env';
import { AppError } from '../middleware/error.middleware';
import {
  SupportTicket,
  toSafeSupportTicket,
  SUPPORT_CATEGORIES,
  SUPPORT_PRIORITIES,
  type ISupportTicket,
  type ISupportAttachment,
} from '../models/SupportTicket';
import {
  SecurityReport,
  toSafeSecurityReport,
  SECURITY_VULNERABILITY_TYPES,
  SECURITY_REPORT_SEVERITIES,
  type ISecurityReport,
} from '../models/SecurityReport';
import {
  SupportChatSession,
  toSafeChatSession,
} from '../models/SupportChatSession';
import { Scan } from '../models/Scan';
import { emailNotificationService } from './email-notification.service';
import {
  ALLOWED_EXTENSIONS,
  ALLOWED_MIME_TYPES,
} from './support-attachment.service';
import type {
  SupportCategory,
  SupportPriority,
  SupportStatus,
  SecurityVulnerabilityType,
  SecurityReportSeverity,
  SupportPublicConfig,
  CreateSupportTicketInput,
  CreateSecurityReportInput,
} from '@cyberwatch/shared';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getCurrentYear(): number {
  return new Date().getFullYear();
}

/**
 * Generate human-friendly ticket number: e.g. CW-2026-000123
 */
export async function generateTicketNumber(): Promise<string> {
  const year = getCurrentYear();
  const count = await SupportTicket.countDocuments();
  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const sequentialPadded = String(count + 1).padStart(4, '0');
  return `CW-${year}-${sequentialPadded}${randomSuffix.toString().slice(-2)}`;
}

/**
 * Generate human-friendly security report number: e.g. SEC-2026-000123
 */
export async function generateSecurityReportNumber(): Promise<string> {
  const year = getCurrentYear();
  const count = await SecurityReport.countDocuments();
  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const sequentialPadded = String(count + 1).padStart(4, '0');
  return `SEC-${year}-${sequentialPadded}${randomSuffix.toString().slice(-2)}`;
}

/**
 * Generate unique chat session ID: e.g. CHAT-2026-XXXXXX
 */
export function generateChatSessionId(): string {
  const year = getCurrentYear();
  const randomHex = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `CHAT-${year}-${randomHex}`;
}

export const supportService = {
  /**
   * Get public support and contact configuration.
   */
  getPublicConfig(): SupportPublicConfig {
    return {
      supportEmail: env.SUPPORT_EMAIL,
      securityEmail: env.SECURITY_EMAIL,
      supportPhone: env.SUPPORT_PHONE,
      supportWhatsapp: env.SUPPORT_WHATSAPP,
      liveChatEnabled: env.SUPPORT_LIVE_CHAT_ENABLED,
      supportHours: env.SUPPORT_HOURS,
      maxAttachmentSizeMb: env.SUPPORT_ATTACHMENT_MAX_SIZE_MB,
      allowedAttachmentExtensions: [...ALLOWED_EXTENSIONS],
      allowedAttachmentMimeTypes: [...ALLOWED_MIME_TYPES],
    };
  },

  /**
   * Create a new support ticket.
   */
  async createTicket(
    userId: string,
    userRole: string,
    input: CreateSupportTicketInput,
    attachments: ISupportAttachment[] = []
  ) {
    // 1. Validate Category
    if (!SUPPORT_CATEGORIES.includes(input.category)) {
      throw new AppError(`Invalid support category '${input.category}'.`, 400);
    }

    // 2. Validate Priority
    if (!SUPPORT_PRIORITIES.includes(input.priority)) {
      throw new AppError(`Invalid support priority '${input.priority}'.`, 400);
    }

    // Server-side validation: ordinary users shouldn't create frivolous URGENT tickets unless security/production issue
    if (input.priority === 'URGENT' && input.category !== 'SECURITY_VULNERABILITY' && input.category !== 'SCANNER_ISSUE') {
      // Demote or enforce high unless critical
    }

    // 3. Validate Inputs
    if (!input.name || input.name.trim().length < 2 || input.name.trim().length > 100) {
      throw new AppError('Name must be between 2 and 100 characters.', 400);
    }

    if (!input.email || !/^\S+@\S+\.\S+$/.test(input.email.trim())) {
      throw new AppError('Please provide a valid email address.', 400);
    }

    if (!input.subject || input.subject.trim().length < 5 || input.subject.trim().length > 200) {
      throw new AppError('Subject must be between 5 and 200 characters.', 400);
    }

    if (!input.description || input.description.trim().length < 10 || input.description.trim().length > 10000) {
      throw new AppError('Description must be between 10 and 10,000 characters.', 400);
    }

    // 4. Optional Context Validation
    let validatedScanId: string | undefined;
    if (input.scanId && input.scanId.trim()) {
      const trimmedScanId = input.scanId.trim();
      if (Types.ObjectId.isValid(trimmedScanId)) {
        const scan = await Scan.findById(trimmedScanId);
        if (scan) {
          // If scan exists, ensure it belongs to the user or allow reference
          if ((scan.userId && scan.userId.toString() === userId) || userRole === 'ADMIN' || userRole === 'ANALYST') {
            validatedScanId = trimmedScanId;
          }
        }
      } else {
        validatedScanId = trimmedScanId;
      }
    }

    // 5. Generate human-friendly ticket number
    const ticketNumber = await generateTicketNumber();

    // 6. Create initial user message in conversation timeline
    const initialMessage = {
      senderType: 'USER' as const,
      senderUserId: new Types.ObjectId(userId),
      senderName: input.name.trim(),
      message: input.description.trim(),
      attachments,
      createdAt: new Date(),
    };

    // 7. Save ticket
    const ticket = await SupportTicket.create({
      ticketNumber,
      userId: new Types.ObjectId(userId),
      name: input.name.trim(),
      email: input.email.trim().toLowerCase(),
      category: input.category,
      priority: input.priority,
      subject: input.subject.trim(),
      description: input.description.trim(),
      scanId: validatedScanId || (input.scanId ? input.scanId.trim() : undefined),
      reportId: input.reportId ? input.reportId.trim() : undefined,
      targetUrl: input.targetUrl ? input.targetUrl.trim() : undefined,
      browserEnvironment: input.browserEnvironment ? input.browserEnvironment.trim() : undefined,
      status: 'OPEN',
      messages: [initialMessage],
      attachments,
      isSecurityReport: input.category === 'SECURITY_VULNERABILITY',
    });

    // 8. Trigger Email Acknowledgement (safe async background notification)
    emailNotificationService
      .sendTicketCreatedNotification({
        ticketNumber: ticket.ticketNumber,
        recipientEmail: ticket.email,
        recipientName: ticket.name,
        subject: ticket.subject,
        category: ticket.category,
        priority: ticket.priority,
      })
      .catch((err) => {
        console.warn(`[SupportService] Notification skipped: ${err?.message}`);
      });

    return toSafeSupportTicket(ticket);
  },

  /**
   * Get authenticated user's tickets with search, filtering, and pagination.
   */
  async getUserTickets(
    userId: string,
    options: {
      status?: string;
      search?: string;
      sortBy?: 'newest' | 'oldest' | 'updated';
      page?: number;
      limit?: number;
    } = {}
  ) {
    const page = Math.max(1, options.page || 1);
    const limit = Math.min(50, Math.max(1, options.limit || 20));
    const skip = (page - 1) * limit;

    const query: Record<string, any> = {
      userId: new Types.ObjectId(userId),
    };

    if (options.status && options.status !== 'ALL') {
      query.status = options.status;
    }

    if (options.search && options.search.trim()) {
      const searchRegex = new RegExp(options.search.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      query.$or = [{ ticketNumber: searchRegex }, { subject: searchRegex }, { targetUrl: searchRegex }];
    }

    let sortOption: Record<string, 1 | -1> = { createdAt: -1 };
    if (options.sortBy === 'oldest') {
      sortOption = { createdAt: 1 };
    } else if (options.sortBy === 'updated') {
      sortOption = { updatedAt: -1 };
    }

    const [tickets, totalCount] = await Promise.all([
      SupportTicket.find(query).sort(sortOption).skip(skip).limit(limit),
      SupportTicket.countDocuments(query),
    ]);

    return {
      tickets: tickets.map(toSafeSupportTicket),
      pagination: {
        total: totalCount,
        page,
        limit,
        totalPages: Math.ceil(totalCount / limit) || 1,
      },
    };
  },

  /**
   * Get single ticket by ID or ticketNumber with strict ownership check (IDOR protection).
   */
  async getTicketById(ticketIdOrNumber: string, userId: string, userRole: string) {
    let ticket: ISupportTicket | null = null;

    if (Types.ObjectId.isValid(ticketIdOrNumber)) {
      ticket = await SupportTicket.findById(ticketIdOrNumber);
    }

    if (!ticket) {
      ticket = await SupportTicket.findOne({ ticketNumber: ticketIdOrNumber.trim().toUpperCase() });
    }

    if (!ticket) {
      throw new AppError('Support ticket not found.', 404);
    }

    // Enforce ownership
    const isOwner = ticket.userId.toString() === userId;
    const isStaff = userRole === 'ADMIN' || userRole === 'ANALYST';

    if (!isOwner && !isStaff) {
      throw new AppError('You do not have permission to view this ticket.', 400);
    }

    return toSafeSupportTicket(ticket);
  },

  /**
   * Add a reply message to a support ticket.
   */
  async addTicketMessage(
    ticketIdOrNumber: string,
    userId: string,
    userRole: string,
    userName: string,
    messageText: string,
    attachments: ISupportAttachment[] = []
  ) {
    if (!messageText || messageText.trim().length === 0) {
      throw new AppError('Message cannot be empty.', 400);
    }

    if (messageText.trim().length > 10000) {
      throw new AppError('Message exceeds 10,000 characters limit.', 400);
    }

    let ticket: ISupportTicket | null = null;
    if (Types.ObjectId.isValid(ticketIdOrNumber)) {
      ticket = await SupportTicket.findById(ticketIdOrNumber);
    }
    if (!ticket) {
      ticket = await SupportTicket.findOne({ ticketNumber: ticketIdOrNumber.trim().toUpperCase() });
    }

    if (!ticket) {
      throw new AppError('Support ticket not found.', 404);
    }

    const isOwner = ticket.userId.toString() === userId;
    const isStaff = userRole === 'ADMIN' || userRole === 'ANALYST';

    if (!isOwner && !isStaff) {
      throw new AppError('You do not have permission to reply to this ticket.', 400);
    }

    // Determine sender type authoritatively on the backend — NEVER trust client-supplied senderType
    const senderType = isStaff ? 'SUPPORT' : 'USER';

    const newMessage = {
      senderType,
      senderUserId: new Types.ObjectId(userId),
      senderName: isStaff ? (ticket.assignedAgentName || 'CyberWatch Support') : userName,
      message: messageText.trim(),
      attachments,
      createdAt: new Date(),
    };

    ticket.messages.push(newMessage as any);

    // If ticket was waiting for user and user responded, shift back to INVESTIGATING
    if (!isStaff && ticket.status === 'WAITING_FOR_USER') {
      ticket.status = 'INVESTIGATING';
    }

    ticket.updatedAt = new Date();
    await ticket.save();

    return toSafeSupportTicket(ticket);
  },

  /**
   * Reopen a resolved or closed ticket.
   */
  async reopenTicket(ticketIdOrNumber: string, userId: string, userRole: string, reason?: string) {
    let ticket: ISupportTicket | null = null;
    if (Types.ObjectId.isValid(ticketIdOrNumber)) {
      ticket = await SupportTicket.findById(ticketIdOrNumber);
    }
    if (!ticket) {
      ticket = await SupportTicket.findOne({ ticketNumber: ticketIdOrNumber.trim().toUpperCase() });
    }

    if (!ticket) {
      throw new AppError('Support ticket not found.', 404);
    }

    const isOwner = ticket.userId.toString() === userId;
    const isStaff = userRole === 'ADMIN' || userRole === 'ANALYST';

    if (!isOwner && !isStaff) {
      throw new AppError('You do not have permission to reopen this ticket.', 400);
    }

    ticket.status = 'OPEN';
    ticket.resolvedAt = undefined;
    ticket.closedAt = undefined;

    // Add SYSTEM timeline entry
    const systemNotice = {
      senderType: 'SYSTEM' as const,
      senderName: 'System',
      message: `Ticket was reopened by ${isStaff ? 'support team' : 'the requester'}.${reason ? ` Reason: ${reason}` : ''}`,
      attachments: [],
      createdAt: new Date(),
    };

    ticket.messages.push(systemNotice as any);
    ticket.updatedAt = new Date();
    await ticket.save();

    return toSafeSupportTicket(ticket);
  },

  /**
   * Submit a Confidential Security Vulnerability Report.
   */
  async createSecurityReport(
    userId: string | undefined,
    input: CreateSecurityReportInput,
    attachments: ISupportAttachment[] = []
  ) {
    if (!SECURITY_VULNERABILITY_TYPES.includes(input.vulnerabilityType)) {
      throw new AppError(`Invalid vulnerability type '${input.vulnerabilityType}'.`, 400);
    }

    if (!SECURITY_REPORT_SEVERITIES.includes(input.severity)) {
      throw new AppError(`Invalid severity rating '${input.severity}'.`, 400);
    }

    if (!input.email || !/^\S+@\S+\.\S+$/.test(input.email.trim())) {
      throw new AppError('Please provide a valid security contact email address.', 400);
    }

    if (!input.affectedComponent || input.affectedComponent.trim().length < 2) {
      throw new AppError('Affected component is required.', 400);
    }

    if (!input.description || input.description.trim().length < 20) {
      throw new AppError('Vulnerability description must be at least 20 characters.', 400);
    }

    if (!input.stepsToReproduce || input.stepsToReproduce.trim().length < 20) {
      throw new AppError('Steps to reproduce must be at least 20 characters.', 400);
    }

    if (!input.impact || input.impact.trim().length < 10) {
      throw new AppError('Security impact assessment must be at least 10 characters.', 400);
    }

    const reportNumber = await generateSecurityReportNumber();

    const report = await SecurityReport.create({
      reportNumber,
      userId: userId ? new Types.ObjectId(userId) : undefined,
      email: input.email.trim().toLowerCase(),
      vulnerabilityType: input.vulnerabilityType,
      severity: input.severity,
      affectedComponent: input.affectedComponent.trim(),
      affectedUrl: input.affectedUrl ? input.affectedUrl.trim() : undefined,
      description: input.description.trim(),
      stepsToReproduce: input.stepsToReproduce.trim(),
      impact: input.impact.trim(),
      suggestedFix: input.suggestedFix ? input.suggestedFix.trim() : undefined,
      attachments,
      status: 'SUBMITTED',
    });

    // Notify Security Response Team
    emailNotificationService
      .sendSecurityReportNotification({
        reportNumber: report.reportNumber,
        reporterEmail: report.email,
        vulnerabilityType: report.vulnerabilityType,
        severity: report.severity,
        affectedComponent: report.affectedComponent,
      })
      .catch((err) => {
        console.warn(`[SupportService] Security notification skipped: ${err?.message}`);
      });

    return toSafeSecurityReport(report);
  },

  /**
   * Get user's submitted security reports.
   */
  async getUserSecurityReports(userId: string) {
    const reports = await SecurityReport.find({ userId: new Types.ObjectId(userId) }).sort({ createdAt: -1 });
    return reports.map(toSafeSecurityReport);
  },

  /**
   * Get security report details with ownership verification.
   */
  async getSecurityReportById(reportIdOrNumber: string, userId: string, userRole: string) {
    let report: ISecurityReport | null = null;
    if (Types.ObjectId.isValid(reportIdOrNumber)) {
      report = await SecurityReport.findById(reportIdOrNumber);
    }
    if (!report) {
      report = await SecurityReport.findOne({ reportNumber: reportIdOrNumber.trim().toUpperCase() });
    }

    if (!report) {
      throw new AppError('Security report not found.', 404);
    }

    const isOwner = report.userId && report.userId.toString() === userId;
    const isStaff = userRole === 'ADMIN' || userRole === 'ANALYST';

    if (!isOwner && !isStaff) {
      throw new AppError('You do not have permission to view this confidential security report.', 400);
    }

    return toSafeSecurityReport(report);
  },

  // ─── Live Chat Operations ───────────────────────────────────────────────────

  /**
   * Start or resume a support chat session.
   * Adheres strictly to the REAL data rule: Shows real queue status WAITING_FOR_AGENT.
   */
  async startChatSession(params: {
    userId?: string;
    userName: string;
    userEmail: string;
    priority?: SupportPriority;
    initialMessage?: string;
  }) {
    if (!params.userName || params.userName.trim().length < 2) {
      throw new AppError('Please provide your name to start live chat.', 400);
    }
    if (!params.userEmail || !/^\S+@\S+\.\S+$/.test(params.userEmail.trim())) {
      throw new AppError('Please provide a valid email address.', 400);
    }

    // Check for active session for this user
    if (params.userId) {
      const existingActive: any = await SupportChatSession.findOne({
        userId: new Types.ObjectId(params.userId),
        status: { $in: ['CONNECTING', 'WAITING_FOR_AGENT', 'WAITING', 'ACTIVE'] as any },
      }).sort({ createdAt: -1 });

      if (existingActive) {
        if (params.initialMessage && params.initialMessage.trim()) {
          existingActive.messages.push({
            senderType: 'USER',
            senderUserId: new Types.ObjectId(params.userId),
            senderName: params.userName.trim(),
            message: params.initialMessage.trim(),
            createdAt: new Date(),
          });
          await existingActive.save();
        }
        return toSafeChatSession(existingActive);
      }
    }

    const sessionId = generateChatSessionId();
    const messages = [];

    // Initial user inquiry if provided
    if (params.initialMessage && params.initialMessage.trim()) {
      messages.push({
        senderType: 'USER' as const,
        senderUserId: params.userId ? new Types.ObjectId(params.userId) : undefined,
        senderName: params.userName.trim(),
        message: params.initialMessage.trim(),
        createdAt: new Date(),
      });
    }

    // System queue notice
    messages.push({
      senderType: 'SYSTEM' as const,
      senderName: 'CyberWatch Desk',
      message: "You're in the queue. A support agent will respond as soon as possible.",
      createdAt: new Date(),
    });

    const session = await SupportChatSession.create({
      sessionId,
      userId: params.userId ? new Types.ObjectId(params.userId) : undefined,
      userName: params.userName.trim(),
      userEmail: params.userEmail.trim().toLowerCase(),
      priority: params.priority || 'MEDIUM',
      status: 'WAITING_FOR_AGENT',
      messages,
    });

    return toSafeChatSession(session);
  },

  /**
   * Get chat session and conversation history.
   */
  async getChatSession(sessionId: string, userId?: string, userRole?: string) {
    const session = await SupportChatSession.findOne({ sessionId: sessionId.trim().toUpperCase() });
    if (!session) {
      throw new AppError('Chat session not found.', 404);
    }

    const isStaff = userRole === 'ADMIN' || userRole === 'SUPPORT' || userRole === 'ANALYST';
    if (session.userId && userId && session.userId.toString() !== userId && !isStaff) {
      throw new AppError('You do not have access to this chat session.', 403);
    }

    return toSafeChatSession(session);
  },

  /**
   * Send a message within a chat session from a user.
   */
  async sendChatMessage(
    sessionId: string,
    senderName: string,
    message: string,
    userId?: string,
    attachments: ISupportAttachment[] = []
  ) {
    if (!message || message.trim().length === 0) {
      throw new AppError('Message cannot be empty.', 400);
    }

    const session = await SupportChatSession.findOne({ sessionId: sessionId.trim().toUpperCase() });
    if (!session) {
      throw new AppError('Chat session not found.', 404);
    }

    if (session.status === 'CLOSED' || session.status === 'ENDED') {
      throw new AppError('This chat session has closed. Please start a new conversation.', 400);
    }

    if (session.userId && userId && session.userId.toString() !== userId) {
      throw new AppError('You do not have access to this chat session.', 403);
    }

    session.messages.push({
      senderType: 'USER',
      senderUserId: userId ? new Types.ObjectId(userId) : undefined,
      senderName: senderName || session.userName,
      message: message.trim(),
      attachments,
      createdAt: new Date(),
    } as any);

    session.updatedAt = new Date();
    await session.save();

    return toSafeChatSession(session);
  },

  /**
   * Send a message from a support operator.
   */
  async sendOperatorMessage(
    sessionId: string,
    operatorId: string,
    operatorName: string,
    message: string,
    attachments: ISupportAttachment[] = []
  ) {
    if (!message || message.trim().length === 0) {
      throw new AppError('Message cannot be empty.', 400);
    }

    const session = await SupportChatSession.findOne({ sessionId: sessionId.trim().toUpperCase() });
    if (!session) {
      throw new AppError('Chat session not found.', 404);
    }

    if (session.status === 'CLOSED' || session.status === 'ENDED') {
      throw new AppError('This chat session has closed.', 400);
    }

    session.messages.push({
      senderType: 'SUPPORT',
      senderUserId: Types.ObjectId.isValid(operatorId) ? new Types.ObjectId(operatorId) : undefined,
      senderName: operatorName || session.assignedAgentName || 'CyberWatch Support',
      message: message.trim(),
      attachments,
      createdAt: new Date(),
    } as any);

    // If session was waiting, mark it as active
    if (session.status === 'WAITING_FOR_AGENT' || session.status === 'WAITING') {
      session.status = 'ACTIVE';
      if (!session.assignedAgentName) {
        session.assignedAgentName = operatorName;
      }
    }

    session.updatedAt = new Date();
    await session.save();

    return toSafeChatSession(session);
  },

  /**
   * Support operator claims a waiting chat session.
   */
  async claimChatSession(sessionId: string, operatorId: string, operatorName: string) {
    const session = await SupportChatSession.findOne({ sessionId: sessionId.trim().toUpperCase() });
    if (!session) {
      throw new AppError('Chat session not found.', 404);
    }

    session.status = 'ACTIVE';
    session.assignedAgentId = Types.ObjectId.isValid(operatorId) ? new Types.ObjectId(operatorId) : undefined;
    session.assignedAgentName = operatorName || 'Support Agent';
    session.agentName = operatorName || 'Support Agent';

    session.messages.push({
      senderType: 'SYSTEM',
      senderName: 'System',
      message: `Support Agent ${session.assignedAgentName} has joined the conversation.`,
      createdAt: new Date(),
    } as any);

    session.updatedAt = new Date();
    await session.save();

    return toSafeChatSession(session);
  },

  /**
   * Mark messages as read by recipient.
   */
  async markMessagesAsRead(sessionId: string, readBy: 'USER' | 'SUPPORT') {
    const session = await SupportChatSession.findOne({ sessionId: sessionId.trim().toUpperCase() });
    if (!session) return null;

    let modified = false;
    session.messages.forEach((msg) => {
      if (!msg.readAt) {
        if (readBy === 'SUPPORT' && msg.senderType === 'USER') {
          msg.readAt = new Date();
          modified = true;
        } else if (readBy === 'USER' && msg.senderType === 'SUPPORT') {
          msg.readAt = new Date();
          modified = true;
        }
      }
    });

    if (modified) {
      await session.save();
    }
    return toSafeChatSession(session);
  },

  /**
   * End or close a chat session.
   */
  async endChatSession(sessionId: string, userId?: string, userRole?: string) {
    const session = await SupportChatSession.findOne({ sessionId: sessionId.trim().toUpperCase() });
    if (!session) {
      throw new AppError('Chat session not found.', 404);
    }

    const isStaff = userRole === 'ADMIN' || userRole === 'SUPPORT' || userRole === 'ANALYST';
    if (session.userId && userId && session.userId.toString() !== userId && !isStaff) {
      throw new AppError('You do not have permission to close this chat.', 403);
    }

    session.status = 'CLOSED';
    session.endedAt = new Date();
    session.closedAt = new Date();
    session.messages.push({
      senderType: 'SYSTEM',
      senderName: 'System',
      message: 'This conversation has ended. Thank you for contacting CyberWatch Support.',
      createdAt: new Date(),
    } as any);

    await session.save();
    return toSafeChatSession(session);
  },

  /**
   * Get all chat sessions in the operator queue.
   */
  async getOperatorChatQueue(statusFilter?: string) {
    const query: any = {};
    if (statusFilter && statusFilter !== 'ALL') {
      if (statusFilter === 'WAITING') {
        query.status = { $in: ['WAITING', 'WAITING_FOR_AGENT', 'CONNECTING'] };
      } else {
        query.status = statusFilter;
      }
    } else {
      query.status = { $in: ['WAITING', 'WAITING_FOR_AGENT', 'CONNECTING', 'ACTIVE'] };
    }

    const sessions = await SupportChatSession.find(query).sort({ updatedAt: -1, createdAt: -1 });
    return sessions.map(toSafeChatSession);
  },

  /**
   * Get user's past and current chat sessions.
   */
  async getUserChatSessions(userId: string) {
    const sessions = await SupportChatSession.find({
      userId: new Types.ObjectId(userId),
    }).sort({ createdAt: -1 });
    return sessions.map(toSafeChatSession);
  },

  /**
   * Convert a Live Chat conversation into a formal Support Ticket.
   */
  async convertChatToTicket(sessionId: string, userId: string, userRole?: string) {
    const session = await SupportChatSession.findOne({ sessionId: sessionId.trim().toUpperCase() });
    if (!session) {
      throw new AppError('Chat session not found.', 404);
    }

    if (session.convertedTicketNumber) {
      throw new AppError(
        `This chat has already been converted to ticket #${session.convertedTicketNumber}.`,
        400
      );
    }

    const isStaff = userRole === 'ADMIN' || userRole === 'SUPPORT' || userRole === 'ANALYST';
    if (session.userId && session.userId.toString() !== userId && !isStaff) {
      throw new AppError('You do not have permission to convert this chat.', 403);
    }

    const ticketNumber = await generateTicketNumber();
    const transcript = session.messages
      .map((m) => `[${m.senderType} - ${m.senderName}]: ${m.message}`)
      .join('\n\n');

    const ticket = await SupportTicket.create({
      ticketNumber,
      userId: session.userId || new Types.ObjectId(userId),
      name: session.userName,
      email: session.userEmail,
      category: 'TECHNICAL_ISSUE',
      priority: session.priority || 'MEDIUM',
      subject: `Live Chat Consultation — ${session.sessionId}`,
      description: `Support Ticket created from Live Chat conversation ${session.sessionId}:\n\n${transcript}`,
      status: 'OPEN',
      assignedTo: session.assignedAgentId,
      assignedAgentName: session.assignedAgentName,
      messages: [
        {
          senderType: 'SYSTEM',
          senderName: 'System',
          message: `Ticket converted from Live Chat session ${session.sessionId}.`,
          createdAt: new Date(),
        },
      ],
      metadata: {
        chatSessionId: session.sessionId,
      },
    });

    session.convertedTicketNumber = ticket.ticketNumber;
    await session.save();

    return toSafeSupportTicket(ticket);
  },
};
