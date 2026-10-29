import { apiClient } from '../lib/api';
import type {
  ApiResponse,
  SupportTicket,
  SecurityReport,
  SupportChatSession,
  SupportPublicConfig,
  CreateSupportTicketInput,
  CreateSecurityReportInput,
} from '../types';

// Safe configuration fallback when backend is loading or unconfigured
export const DEFAULT_SUPPORT_CONFIG: SupportPublicConfig = {
  supportEmail: '',
  securityEmail: '',
  supportPhone: '',
  supportWhatsapp: '',
  liveChatEnabled: false,
  supportHours: '',
  maxAttachmentSizeMb: 10,
  allowedAttachmentExtensions: ['.pdf', '.png', '.jpg', '.jpeg', '.txt', '.csv', '.json'],
  allowedAttachmentMimeTypes: [
    'application/pdf',
    'image/png',
    'image/jpeg',
    'image/jpg',
    'text/plain',
    'text/csv',
    'application/json',
  ],
};

/**
 * Generate a clean, properly formatted WhatsApp direct chat link.
 */
export function buildWhatsAppLink(phone: string, defaultMessage = 'Hello CyberWatch Support Team'): string {
  if (!phone) return '';
  const digitsOnly = phone.replace(/[^0-9]/g, '');
  if (!digitsOnly) return '';
  const encodedMsg = encodeURIComponent(defaultMessage);
  return `https://wa.me/${digitsOnly}?text=${encodedMsg}`;
}

export const supportService = {
  /**
   * Fetch public support configuration from backend.
   */
  async getConfig(): Promise<SupportPublicConfig> {
    try {
      const response = await apiClient.get<ApiResponse<SupportPublicConfig>>('/support/config');
      return response.data.data || DEFAULT_SUPPORT_CONFIG;
    } catch {
      return DEFAULT_SUPPORT_CONFIG;
    }
  },

  /**
   * Create a new support ticket (supports optional file attachments).
   */
  async createTicket(input: CreateSupportTicketInput, files: File[] = []): Promise<SupportTicket> {
    if (files.length > 0) {
      const formData = new FormData();
      formData.append('name', input.name);
      formData.append('email', input.email);
      formData.append('category', input.category);
      formData.append('priority', input.priority);
      formData.append('subject', input.subject);
      formData.append('description', input.description);
      if (input.scanId) formData.append('scanId', input.scanId);
      if (input.reportId) formData.append('reportId', input.reportId);
      if (input.targetUrl) formData.append('targetUrl', input.targetUrl);
      if (input.browserEnvironment) formData.append('browserEnvironment', input.browserEnvironment);

      formData.append('file', files[0]);

      const response = await apiClient.post<ApiResponse<SupportTicket>>('/support/tickets', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'x-filename': files[0].name,
        },
      });
      return response.data.data!;
    }

    const response = await apiClient.post<ApiResponse<SupportTicket>>('/support/tickets', input);
    return response.data.data!;
  },

  /**
   * Get user's tickets list with search and filtering.
   */
  async getUserTickets(params?: {
    status?: string;
    search?: string;
    sortBy?: 'newest' | 'oldest' | 'updated';
    page?: number;
    limit?: number;
  }): Promise<{ tickets: SupportTicket[]; pagination: { total: number; page: number; limit: number; totalPages: number } }> {
    const response = await apiClient.get<
      ApiResponse<{ tickets: SupportTicket[]; pagination: { total: number; page: number; limit: number; totalPages: number } }>
    >('/support/tickets', { params });
    return response.data.data || { tickets: [], pagination: { total: 0, page: 1, limit: 20, totalPages: 1 } };
  },

  /**
   * Get specific ticket and conversation timeline by ID or ticketNumber.
   */
  async getTicketById(ticketIdOrNumber: string): Promise<SupportTicket> {
    const response = await apiClient.get<ApiResponse<SupportTicket>>(`/support/tickets/${ticketIdOrNumber}`);
    return response.data.data!;
  },

  /**
   * Post a reply to an ongoing ticket.
   */
  async addTicketMessage(ticketIdOrNumber: string, message: string, files: File[] = []): Promise<SupportTicket> {
    if (files.length > 0) {
      const formData = new FormData();
      formData.append('message', message);
      formData.append('file', files[0]);

      const response = await apiClient.post<ApiResponse<SupportTicket>>(
        `/support/tickets/${ticketIdOrNumber}/messages`,
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
            'x-filename': files[0].name,
          },
        }
      );
      return response.data.data!;
    }

    const response = await apiClient.post<ApiResponse<SupportTicket>>(
      `/support/tickets/${ticketIdOrNumber}/messages`,
      { message }
    );
    return response.data.data!;
  },

  /**
   * Reopen a closed or resolved ticket.
   */
  async reopenTicket(ticketIdOrNumber: string, reason?: string): Promise<SupportTicket> {
    const response = await apiClient.post<ApiResponse<SupportTicket>>(
      `/support/tickets/${ticketIdOrNumber}/reopen`,
      { reason }
    );
    return response.data.data!;
  },

  /**
   * Submit a confidential security vulnerability report.
   */
  async createSecurityReport(input: CreateSecurityReportInput, files: File[] = []): Promise<SecurityReport> {
    if (files.length > 0) {
      const formData = new FormData();
      formData.append('email', input.email);
      formData.append('vulnerabilityType', input.vulnerabilityType);
      formData.append('severity', input.severity);
      formData.append('affectedComponent', input.affectedComponent);
      if (input.affectedUrl) formData.append('affectedUrl', input.affectedUrl);
      formData.append('description', input.description);
      formData.append('stepsToReproduce', input.stepsToReproduce);
      formData.append('impact', input.impact);
      if (input.suggestedFix) formData.append('suggestedFix', input.suggestedFix);

      formData.append('file', files[0]);

      const response = await apiClient.post<ApiResponse<SecurityReport>>('/support/security-reports', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'x-filename': files[0].name,
        },
      });
      return response.data.data!;
    }

    const response = await apiClient.post<ApiResponse<SecurityReport>>('/support/security-reports', input);
    return response.data.data!;
  },

  /**
   * Get user's security vulnerability reports.
   */
  async getUserSecurityReports(): Promise<SecurityReport[]> {
    const response = await apiClient.get<ApiResponse<SecurityReport[]>>('/support/security-reports');
    return response.data.data || [];
  },

  // ─── Live Chat Operations ───────────────────────────────────────────────────

  /**
   * Start or retrieve an active live chat session.
   */
  async startChatSession(params: {
    userName: string;
    userEmail: string;
    initialMessage?: string;
  }): Promise<SupportChatSession> {
    const response = await apiClient.post<ApiResponse<SupportChatSession>>('/support/chat/session', params);
    return response.data.data!;
  },

  /**
   * Fetch chat session conversation history.
   */
  async getChatSession(sessionId: string): Promise<SupportChatSession> {
    const response = await apiClient.get<ApiResponse<SupportChatSession>>(`/support/chat/session/${sessionId}`);
    return response.data.data!;
  },

  /**
   * Get user's past and current chat sessions.
   */
  async getUserChatSessions(): Promise<SupportChatSession[]> {
    const response = await apiClient.get<ApiResponse<SupportChatSession[]>>('/support/chat/sessions');
    return response.data.data || [];
  },

  /**
   * Send a message to the active chat session via REST.
   */
  async sendChatMessage(sessionId: string, message: string, senderName?: string): Promise<SupportChatSession> {
    const response = await apiClient.post<ApiResponse<SupportChatSession>>(
      `/support/chat/session/${sessionId}/messages`,
      { message, senderName }
    );
    return response.data.data!;
  },

  /**
   * Close or leave the chat session.
   */
  async endChatSession(sessionId: string): Promise<SupportChatSession> {
    const response = await apiClient.post<ApiResponse<SupportChatSession>>(
      `/support/chat/session/${sessionId}/end`
    );
    return response.data.data!;
  },

  /**
   * Convert a Live Chat session into a formal Support Ticket.
   */
  async convertChatToTicket(sessionId: string): Promise<SupportTicket> {
    const response = await apiClient.post<ApiResponse<SupportTicket>>(
      `/support/chat/session/${sessionId}/convert-to-ticket`
    );
    return response.data.data!;
  },

  // ─── Operator & Admin Endpoints ─────────────────────────────────────────────

  /**
   * Get all live chat sessions in operator queue.
   */
  async getOperatorQueue(statusFilter?: string): Promise<SupportChatSession[]> {
    const response = await apiClient.get<ApiResponse<SupportChatSession[]>>('/support/admin/chats', {
      params: { status: statusFilter },
    });
    return response.data.data || [];
  },

  /**
   * Operator claims a waiting chat session.
   */
  async claimChatSession(sessionId: string): Promise<SupportChatSession> {
    const response = await apiClient.post<ApiResponse<SupportChatSession>>(
      `/support/admin/chats/${sessionId}/claim`
    );
    return response.data.data!;
  },

  /**
   * Operator sends a message to chat session.
   */
  async sendOperatorMessage(sessionId: string, message: string, operatorName?: string): Promise<SupportChatSession> {
    const response = await apiClient.post<ApiResponse<SupportChatSession>>(
      `/support/admin/chats/${sessionId}/messages`,
      { message, operatorName }
    );
    return response.data.data!;
  },

  /**
   * Operator closes chat session.
   */
  async closeOperatorChat(sessionId: string): Promise<SupportChatSession> {
    const response = await apiClient.post<ApiResponse<SupportChatSession>>(
      `/support/admin/chats/${sessionId}/close`
    );
    return response.data.data!;
  },
};
