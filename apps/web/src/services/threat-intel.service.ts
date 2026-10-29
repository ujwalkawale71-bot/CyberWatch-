import { apiClient } from '../lib/api';
import type {
  ApiResponse,
  NormalizedIndicator,
  ThreatIntelAnalysisReport,
} from '../types';

export interface ThreatIntelProviderMeta {
  id: string;
  name: string;
  configured: boolean;
  supportedTypes: string[];
}

export const threatIntelService = {
  /**
   * Analyze an indicator against configured Threat Intelligence feeds.
   */
  async analyzeIndicator(
    indicator: string,
    forceRefresh = false
  ): Promise<ThreatIntelAnalysisReport> {
    const response = await apiClient.post<ApiResponse<ThreatIntelAnalysisReport>>(
      '/threat-intelligence/analyze',
      {
        indicator,
        forceRefresh,
      },
      {
        timeout: 45000,
      }
    );

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Threat intelligence lookup failed.');
    }
    return response.data.data;
  },

  /**
   * Normalize an indicator without triggering external intelligence lookups.
   */
  async normalizeIndicator(indicator: string): Promise<NormalizedIndicator> {
    const response = await apiClient.post<ApiResponse<NormalizedIndicator>>(
      '/threat-intelligence/normalize',
      {
        indicator,
      }
    );

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Failed to normalize indicator.');
    }
    return response.data.data;
  },

  /**
   * Get metadata and configuration state for registered intelligence providers.
   */
  async getProviders(): Promise<ThreatIntelProviderMeta[]> {
    const response = await apiClient.get<ApiResponse<ThreatIntelProviderMeta[]>>(
      '/threat-intelligence/providers'
    );

    if (!response.data.success || !response.data.data) {
      return [];
    }
    return response.data.data;
  },

  /**
   * Get historical threat intelligence analysis report by analysis ID.
   */
  async getAnalysisById(analysisId: string): Promise<ThreatIntelAnalysisReport> {
    const response = await apiClient.get<ApiResponse<ThreatIntelAnalysisReport>>(
      `/threat-intelligence/${encodeURIComponent(analysisId)}`
    );

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Threat intelligence report not found.');
    }
    return response.data.data;
  },

  /**
   * List analyzed threat indicators from database with optional filters.
   */
  async listIndicators(params: {
    type?: string;
    status?: string;
    provider?: string;
    search?: string;
    page?: number;
    limit?: number;
  } = {}) {
    const response = await apiClient.get<ApiResponse<{ items: any[]; total: number; page: number; limit: number }>>(
      '/threat-intelligence/indicators',
      { params }
    );

    if (!response.data.success || !response.data.data) {
      return { items: [], total: 0, page: 1, limit: 20 };
    }
    return response.data.data;
  },

  /**
   * Get security advisories configuration and list.
   */
  async getAdvisories() {
    const response = await apiClient.get<ApiResponse<{
      configured: boolean;
      provider: string;
      advisories: any[];
      notice: string;
    }>>('/threat-intelligence/advisories');

    if (!response.data.success || !response.data.data) {
      return {
        configured: false,
        provider: 'None Configured',
        advisories: [],
        notice: 'Security advisory provider is not configured.',
      };
    }
    return response.data.data;
  },

  /**
   * Get threat intelligence feeds and their synchronization status.
   */
  async getFeeds() {
    const response = await apiClient.get<ApiResponse<Array<{
      id: string;
      name: string;
      provider: string;
      providerId: string;
      type: string;
      status: string;
      configured: boolean;
      description: string;
      supportedIndicators: string[];
      frequency: string;
      sourceUrl: string;
    }>>>('/threat-intelligence/feeds');

    if (!response.data.success || !response.data.data) {
      return [];
    }
    return response.data.data;
  },

  /**
   * Test connection to a specific provider adapter.
   */
  async testProvider(providerId: string) {
    const response = await apiClient.post<ApiResponse<{
      providerId: string;
      providerName: string;
      status: 'ONLINE' | 'NOT_CONFIGURED' | 'ERROR';
      configured: boolean;
      latencyMs: number;
      message: string;
    }>>(`/threat-intelligence/providers/${encodeURIComponent(providerId)}/test`);

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Provider connection test failed.');
    }
    return response.data.data;
  },

  /**
   * Correlate scanner findings with threat intelligence.
   */
  async correlateScan(data: {
    scannerType: string;
    target: string;
    findings?: any[];
    scanResult?: any;
  }) {
    const response = await apiClient.post<ApiResponse<any>>(
      '/threat-intelligence/correlate',
      data
    );

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Threat intelligence correlation failed.');
    }
    return response.data.data;
  },
};


