import { apiClient } from '../lib/api';
import type {
  AISupportChatRequest,
  AISupportChatResponse,
  AISupportQuickAction,
} from '../types';

export interface UserScanOption {
  id: string;
  target: string;
  targetType: string;
  riskScore: number;
  riskLevel: string;
  findingsCount: number;
  createdAt: string;
}

export const aiSupportService = {
  /**
   * Send message to CyberWatch AI Security Assistant.
   */
  async sendMessage(request: AISupportChatRequest): Promise<AISupportChatResponse> {
    try {
      const response = await apiClient.post<{
        success: boolean;
        message: string;
        data: AISupportChatResponse;
      }>('/live-chat/ai', request, {
        timeout: 25000,
      });

      if (!response.data || !response.data.data) {
        throw new Error('Malformed response received from CyberWatch AI.');
      }

      return response.data.data;
    } catch (primaryError: any) {
      // Fallback attempt to support/ai/chat if live-chat/ai is not available
      try {
        const fallbackRes = await apiClient.post<{
          success: boolean;
          message: string;
          data: AISupportChatResponse;
        }>('/support/ai/chat', request, {
          timeout: 25000,
        });

        if (fallbackRes.data && fallbackRes.data.data) {
          return fallbackRes.data.data;
        }
      } catch (fallbackError: any) {
        const status = primaryError.response?.status || fallbackError.response?.status;
        const msg =
          primaryError.response?.data?.message ||
          fallbackError.response?.data?.message;

        if (status === 400) {
          throw new Error(msg || 'Invalid request. Please verify your message.');
        }
        if (status === 401) {
          throw new Error(msg || 'Authentication required to analyze user scans.');
        }
        if (status === 403) {
          throw new Error(msg || 'You do not have permission to access this scan context.');
        }
        if (status === 429) {
          throw new Error(msg || 'Rate limit reached. Please wait a moment before sending another message.');
        }
        if (status >= 500) {
          throw new Error('CyberWatch AI service is temporarily experiencing high load. Please try again.');
        }
        if (primaryError.code === 'ECONNABORTED' || primaryError.message?.includes('timeout')) {
          throw new Error('AI response timed out. Please try again.');
        }
        throw new Error(msg || primaryError.message || 'CyberWatch AI is temporarily unavailable. Please try again.');
      }
      throw new Error(primaryError.response?.data?.message || 'CyberWatch AI is temporarily unavailable. Please try again.');
    }
  },

  /**
   * Get available quick action chips.
   */
  async getQuickActions(): Promise<AISupportQuickAction[]> {
    try {
      const response = await apiClient.get<{
        success: boolean;
        data: AISupportQuickAction[];
      }>('/live-chat/quick-actions');

      return response.data.data || [];
    } catch {
      try {
        const res = await apiClient.get<{
          success: boolean;
          data: AISupportQuickAction[];
        }>('/support/ai/quick-actions');
        return res.data.data || [];
      } catch {
        return [
          {
            id: 'explain-scan',
            title: 'Explain My Scan',
            description: 'Break down your latest security scan results and risk contributors.',
            prompt: 'Can you explain the security findings and risk score from my latest scan?',
            category: 'scans',
            icon: 'Activity',
          },
          {
            id: 'why-risk-high',
            title: 'Why Is My Risk Score High?',
            description: 'Understand the specific vulnerabilities driving up your risk score.',
            prompt: 'Why is my scan risk score high and what are the top findings I should fix first?',
            category: 'findings',
            icon: 'AlertTriangle',
          },
          {
            id: 'threat-intel',
            title: 'Threat Intelligence Help',
            description: 'Learn how IOC reputation and threat indicators affect your assets.',
            prompt: 'How does CyberWatch correlate threat intelligence and reputation feeds?',
            category: 'threat_intel',
            icon: 'Globe',
          },
          {
            id: 'troubleshoot',
            title: 'Scanner Troubleshooting',
            description: 'Get help with unreachable targets, timeouts, or policy blocks.',
            prompt: 'My scan failed or returned unreachable. How can I troubleshoot this?',
            category: 'troubleshooting',
            icon: 'HelpCircle',
          },
          {
            id: 'talk-human',
            title: 'Talk to Human Support',
            description: 'Connect with a live CyberWatch security engineer or open a ticket.',
            prompt: 'I need to speak with a human support specialist about my account or a critical issue.',
            category: 'escalation',
            icon: 'Headphones',
          },
        ];
      }
    }
  },

  /**
   * Fetch recent user scans to populate AI context selector.
   */
  async getUserScans(): Promise<UserScanOption[]> {
    try {
      const response = await apiClient.get<{
        success: boolean;
        data: UserScanOption[];
      }>('/live-chat/user-scans');

      return response.data.data || [];
    } catch {
      try {
        const response = await apiClient.get<{
          success: boolean;
          data: UserScanOption[];
        }>('/support/ai/user-scans');
        return response.data.data || [];
      } catch {
        return [];
      }
    }
  },
};
