// API client for CyberWatch Extension
// Reuses verified backend routes directly:
// - POST /api/v1/scans
// - POST /api/v1/scans/upload
// - POST /api/v1/auth/login
// - GET /api/v1/health
// - GET /api/v1/scans/:id

import { storageService } from './storage.js';
import type { ApiResponse, ScanResultData, ScannerType, UserSession } from './types.js';

export class ApiClient {
  private normalizeBaseUrl(url: string): string {
    const trimmed = (url || '').trim().replace(/\/+$/, '');
    if (!trimmed) return 'http://localhost:5000/api/v1';
    // If user provided origin only without /api/v1, append /api/v1
    if (!trimmed.endsWith('/api/v1')) {
      return `${trimmed}/api/v1`;
    }
    return trimmed;
  }

  private async parseJsonSafe<T = any>(res: Response): Promise<ApiResponse<T> | null> {
    try {
      const text = await res.text();
      return text ? (JSON.parse(text) as ApiResponse<T>) : null;
    } catch {
      return null;
    }
  }

  private async getHeaders(isJson = true): Promise<Record<string, string>> {
    const headers: Record<string, string> = {};
    if (isJson) {
      headers['Content-Type'] = 'application/json';
    }
    const token = await storageService.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  }

  /**
   * Check if backend API is reachable and healthy.
   */
  async checkHealth(): Promise<{ ok: boolean; message: string; version?: string }> {
    const { apiBaseUrl } = await storageService.getConfig();
    const base = this.normalizeBaseUrl(apiBaseUrl);
    try {
      const res = await fetch(`${base}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(4000),
      });
      if (res.ok) {
        const data = await this.parseJsonSafe(res);
        return { ok: true, message: data?.message || 'API healthy' };
      }
      return { ok: false, message: `HTTP ${res.status} ${res.statusText}` };
    } catch (err: any) {
      return { ok: false, message: err.name === 'TimeoutError' ? 'Connection timed out' : 'Backend offline or unreachable' };
    }
  }

  /**
   * Authenticate against POST /api/v1/auth/login.
   * Stores received token in chrome.storage.session.
   * Never stores or prints the user password.
   */
  async login(email: string, password: string): Promise<UserSession> {
    const { apiBaseUrl } = await storageService.getConfig();
    const base = this.normalizeBaseUrl(apiBaseUrl);

    let res: Response;
    try {
      res = await fetch(`${base}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), password }),
      });
    } catch (networkErr: any) {
      throw new Error(`Unable to reach backend at ${base}. Please ensure the API is running.`);
    }

    const data = await this.parseJsonSafe<UserSession>(res);

    if (!res.ok || !data?.success || !data?.data) {
      throw new Error(data?.message || `Authentication failed (status ${res.status}).`);
    }

    await storageService.setToken(data.data.token);
    await storageService.setUser(data.data.user);
    return data.data;
  }

  /**
   * Initiate scan via POST /api/v1/scans.
   */
  async initiateScan(
    target: string,
    targetType: ScannerType,
    forceRescan = false
  ): Promise<ScanResultData> {
    const { apiBaseUrl } = await storageService.getConfig();
    const base = this.normalizeBaseUrl(apiBaseUrl);
    const headers = await this.getHeaders(true);

    let res: Response;
    try {
      res = await fetch(`${base}/scans`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          target: target.trim(),
          targetType,
          forceRescan,
        }),
        signal: AbortSignal.timeout(60000), // Scanning may take a few seconds
      });
    } catch (networkErr: any) {
      throw new Error(`Unable to connect to scanner service at ${base}.`);
    }

    if (res.status === 401) {
      await storageService.clearToken();
      throw new Error('Authentication required. Please sign in to run security scans.');
    }

    const data = await this.parseJsonSafe<ScanResultData>(res);

    if (!res.ok || !data?.success || !data?.data) {
      throw new Error(data?.message || `Scan failed with HTTP status ${res.status}`);
    }

    return data.data;
  }

  /**
   * Upload and scan file via POST /api/v1/scans/upload.
   */
  async uploadAndScanFile(file: File): Promise<ScanResultData> {
    const { apiBaseUrl } = await storageService.getConfig();
    const base = this.normalizeBaseUrl(apiBaseUrl);
    const headers = await this.getHeaders(false); // multipart boundary will be set by fetch

    const formData = new FormData();
    formData.append('file', file, file.name);

    let res: Response;
    try {
      res = await fetch(`${base}/scans/upload`, {
        method: 'POST',
        headers,
        body: formData,
        signal: AbortSignal.timeout(120000),
      });
    } catch (networkErr: any) {
      throw new Error(`Unable to upload file to scanner service at ${base}.`);
    }

    if (res.status === 401) {
      await storageService.clearToken();
      throw new Error('Authentication required. Please sign in to scan files.');
    }

    if (res.status === 413) {
      throw new Error('File exceeds the maximum allowed size (25 MB limit).');
    }

    const data = await this.parseJsonSafe<ScanResultData>(res);

    if (!res.ok || !data?.success || !data?.data) {
      throw new Error(data?.message || `File scan failed (HTTP status ${res.status})`);
    }

    return data.data;
  }

  /**
   * Retrieve report by ID from GET /api/v1/scans/:id.
   */
  async getScanById(scanId: string): Promise<ScanResultData> {
    const { apiBaseUrl } = await storageService.getConfig();
    const base = this.normalizeBaseUrl(apiBaseUrl);
    const headers = await this.getHeaders(true);

    let res: Response;
    try {
      res = await fetch(`${base}/scans/${encodeURIComponent(scanId)}`, {
        method: 'GET',
        headers,
      });
    } catch (networkErr: any) {
      throw new Error(`Unable to retrieve scan report from ${base}.`);
    }

    const data = await this.parseJsonSafe<ScanResultData>(res);
    if (!res.ok || !data?.success || !data?.data) {
      throw new Error(data?.message || 'Report not found.');
    }

    return data.data;
  }
}

export const api = new ApiClient();
