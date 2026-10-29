import { apiClient } from '../lib/api';
import type {
  ApiResponse,
  ReportOverviewStats,
  EnrichedFinding,
  NormalizedScanReportDTO,
  ScanComparisonResult,
  FindingsFilterParams,
  HistoryFilterParams,
  ScanRecord,
} from '../types';

export const reportService = {
  /**
   * Fetch executive report dashboard overview metrics.
   */
  async getOverview(): Promise<ReportOverviewStats> {
    const response = await apiClient.get<ApiResponse<ReportOverviewStats>>('/reports/overview');
    if (!response.data.success || !response.data.data) {
      return {
        totalScans: 0,
        completedScans: 0,
        partialScans: 0,
        failedScans: 0,
        safeScans: 0,
        findingsSeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        scannerBreakdown: { URL: 0, Website: 0, API: 0, Phishing: 0, File: 0, Extension: 0 },
        scannerTelemetry: {},
        recentScans: [],
        recentFindings: [],
        hasData: false,
      };
    }
    return response.data.data;
  },

  /**
   * Fetch centralized security findings with filters and pagination.
   */
  async getFindings(params?: FindingsFilterParams): Promise<{
    findings: EnrichedFinding[];
    pagination: { total: number; page: number; limit: number; totalPages: number };
  }> {
    const response = await apiClient.get<ApiResponse<{
      findings: EnrichedFinding[];
      pagination: { total: number; page: number; limit: number; totalPages: number };
    }>>('/reports/findings', { params });

    if (!response.data.success || !response.data.data) {
      return {
        findings: [],
        pagination: { total: 0, page: 1, limit: 20, totalPages: 0 },
      };
    }
    return response.data.data;
  },

  /**
   * Fetch single finding detail by ID with correlated threat intelligence.
   */
  async getFindingById(findingId: string): Promise<EnrichedFinding> {
    const response = await apiClient.get<ApiResponse<EnrichedFinding>>(`/reports/findings/${encodeURIComponent(findingId)}`);
    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Security finding not found.');
    }
    return response.data.data;
  },

  /**
   * Fetch scan history workspace records with filters and sorting.
   */
  async getHistory(params?: HistoryFilterParams): Promise<{
    scans: ScanRecord[];
    pagination: { total: number; page: number; limit: number; totalPages: number };
  }> {
    const response = await apiClient.get<ApiResponse<{
      scans: ScanRecord[];
      pagination: { total: number; page: number; limit: number; totalPages: number };
    }>>('/reports/history', { params });

    if (!response.data.success || !response.data.data) {
      return {
        scans: [],
        pagination: { total: 0, page: 1, limit: 10, totalPages: 0 },
      };
    }
    return response.data.data;
  },

  /**
   * Fetch normalized scan report DTO for a specific scan.
   */
  async getScanReport(scanId: string): Promise<NormalizedScanReportDTO> {
    try {
      const response = await apiClient.get<ApiResponse<NormalizedScanReportDTO>>(`/reports/scans/${encodeURIComponent(scanId)}`);
      if (response.data.success && response.data.data) {
        return response.data.data;
      }
    } catch {
      // Try fallback to /reports/scan-report/:id
      const fallbackResponse = await apiClient.get<ApiResponse<NormalizedScanReportDTO>>(`/reports/scan-report/${encodeURIComponent(scanId)}`);
      if (fallbackResponse.data.success && fallbackResponse.data.data) {
        return fallbackResponse.data.data;
      }
    }
    throw new Error('Scan report not found.');
  },

  /**
   * Compare two scans of the same target.
   */
  async compareScans(scan1: string, scan2: string): Promise<ScanComparisonResult> {
    const response = await apiClient.get<ApiResponse<ScanComparisonResult>>('/reports/compare', {
      params: { scan1, scan2 },
    });
    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Scan comparison failed.');
    }
    return response.data.data;
  },

  /**
   * Trigger direct report export download (PDF, JSON, CSV).
   */
  async downloadExport(
    type: 'scan' | 'findings' | 'history',
    format: 'pdf' | 'json' | 'csv',
    scanId?: string
  ): Promise<void> {
    const response = await apiClient.post(
      '/reports/export',
      { format, type, scanId },
      {
        responseType: format === 'json' ? 'json' : 'blob',
      }
    );

    let blob: Blob;
    let filename = `CyberWatch_${type}_export_${Date.now()}.${format}`;

    if (format === 'json') {
      const jsonString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data, null, 2);
      blob = new Blob([jsonString], { type: 'application/json' });
    } else if (format === 'csv') {
      blob = response.data instanceof Blob ? response.data : new Blob([response.data], { type: 'text/csv;charset=utf-8;' });
    } else {
      blob = response.data instanceof Blob ? response.data : new Blob([response.data], { type: 'application/pdf' });
      if (scanId) filename = `CyberWatch_Security_Report_${scanId}.pdf`;
    }

    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  },
};
