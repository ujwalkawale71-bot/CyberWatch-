import { apiClient } from '../lib/api';
import type { ApiResponse, ScanRecord, ScanStats, ScanTargetType } from '../types';

export interface PaginatedScans {
  scans: ScanRecord[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

export const scanService = {
  /**
   * Initiate a new URL/Target security analysis.
   */
  async analyzeUrl(target: string, targetType: ScanTargetType = 'URL', forceRescan?: boolean): Promise<ScanRecord> {
    const response = await apiClient.post<ApiResponse<ScanRecord>>(
      '/scans',
      {
        target,
        targetType,
        forceRescan,
      },
      {
        timeout: 60000,
      }
    );
    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Scan failed.');
    }
    return response.data.data;
  },

  /**
   * Fetch recent scans for the authenticated user.
   */
  async getRecentScans(limit = 10, page = 1): Promise<PaginatedScans> {
    const response = await apiClient.get<ApiResponse<PaginatedScans>>('/scans', {
      params: { limit, page },
    });
    if (!response.data.success || !response.data.data) {
      return {
        scans: [],
        pagination: { total: 0, page: 1, limit, totalPages: 0 },
      };
    }
    return response.data.data;
  },

  /**
   * Fetch aggregate security metrics for dashboard.
   */
  async getScanStats(): Promise<ScanStats> {
    const response = await apiClient.get<ApiResponse<ScanStats>>('/scans/stats');
    if (!response.data.success || !response.data.data) {
      return {
        totalScans: 0,
        threatsDetected: 0,
        reportsCount: 0,
        activeMonitoring: 'Active',
        lastScannedAt: null,
      };
    }
    return response.data.data;
  },

  /**
   * Upload and statically analyze a file.
   */
  async uploadFile(file: File, onProgress?: (percent: number) => void): Promise<ScanRecord> {
    const formData = new FormData();
    formData.append('file', file, file.name);

    const response = await apiClient.post<ApiResponse<ScanRecord>>('/scans/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      timeout: 120000,
      onUploadProgress: (progressEvent) => {
        if (progressEvent.total && onProgress) {
          const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(percent);
        }
      },
    });

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'File scan failed.');
    }
    return response.data.data;
  },

  /**
   * Look up an existing file scan report by SHA-256 hash.
   */
  async getScanBySha256(sha256: string): Promise<ScanRecord | null> {
    const response = await apiClient.get<ApiResponse<ScanRecord>>(`/scans/by-hash/${encodeURIComponent(sha256)}`);
    if (!response.data.success || !response.data.data) {
      return null;
    }
    return response.data.data;
  },

  /**
   * Fetch detailed report by Scan ID.
   */
  async getScanById(id: string): Promise<ScanRecord> {
    const response = await apiClient.get<ApiResponse<ScanRecord>>(`/scans/${id}`);
    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Report not found.');
    }
    return response.data.data;
  },
};
