import { describe, it, expect, vi } from 'vitest';
import { scanService } from '../services/scan.service';

// Mock Mongoose model save to avoid needing a live Mongo daemon in unit tests
vi.mock('../models/Scan', async () => {
  const original = await vi.importActual('../models/Scan');
  function MockScan(this: any, data: any) {
    Object.assign(this, data);
    this._id = { toString: () => 'mock-scan-id-api-456' };
    this.createdAt = new Date();
    this.save = vi.fn().mockResolvedValue(this);
  }
  return {
    ...original as any,
    Scan: MockScan,
  };
});

describe('Real API Security Scanner Engine', () => {
  it('1. Scans https://httpbin.org/get and extracts API structure, CORS, and response metrics', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://httpbin.org/get',
      targetType: 'API',
    });

    expect(result).toBeDefined();
    expect(result.checks.apiAnalysis).toBeDefined();
    expect(result.checks.apiAnalysis?.endpointUrl).toBe('https://httpbin.org/get');
    expect(result.checks.apiAnalysis?.httpMethod).toBe('GET');
    expect(result.checks.httpAnalysis?.statusCode).toBe(200);
    expect(result.checks.httpAnalysis?.contentType).toContain('application/json');
    expect(result.checks.apiAnalysis?.responseStructure?.format).toBe('JSON');
    expect(result.checks.apiAnalysis?.responseStructure?.isStructured).toBe(true);
    expect(result.checks.apiAnalysis?.corsConfig).toBeDefined();
    expect(result.checks.apiAnalysis?.rateLimitIndicators).toBeDefined();
    expect(result.findings).toBeDefined();
  }, 20000);

  it('2. Detects HTTP 404 on https://httpbin.org/status/404 for API scan', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://httpbin.org/status/404',
      targetType: 'API',
    });

    expect(result).toBeDefined();
    expect(result.checks.httpAnalysis?.statusCode).toBe(404);
    expect(result.checks.apiAnalysis).toBeDefined();
  }, 20000);

  it('3. Scans https://postman-echo.com/get?test=123 preserving query and detecting JSON payload', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://postman-echo.com/get?test=123',
      targetType: 'API',
    });

    expect(result).toBeDefined();
    expect(result.checks.apiAnalysis).toBeDefined();
    expect(result.checks.httpAnalysis?.statusCode).toBe(200);
    expect(result.checks.apiAnalysis?.responseStructure?.format).toBe('JSON');
    expect(result.checks.apiAnalysis?.endpointUrl).toBe('https://postman-echo.com/get?test=123');
  }, 20000);

  it('4. Scans https://api.jsonplaceholder.dev/users/1 or handles reachability/timeout cleanly', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://api.jsonplaceholder.dev/users/1',
      targetType: 'API',
    });

    expect(result).toBeDefined();
    expect(result.checks.apiAnalysis).toBeDefined();
    if (result.checks.httpAnalysis?.status === 'failed' || !result.checks.httpAnalysis?.statusCode) {
      expect(result.checks.httpAnalysis?.details).toMatch(/timed out|ETIMEDOUT|ECONNREFUSED|failed|unreachable/i);
    } else {
      expect(result.checks.httpAnalysis.statusCode).toBeGreaterThanOrEqual(200);
    }
  }, 25000);

  it('5. Handles timeout / unreachable endpoint on https://api.jsonplaceholder.dev/posts honestly', async () => {
    const result = await scanService.analyzeAndSave({
      target: 'https://api.jsonplaceholder.dev/posts',
      targetType: 'API',
    });

    expect(result).toBeDefined();
    expect(result.checks.apiAnalysis).toBeDefined();
    // Must not produce fake "100% PASS" or fake headers
    if (result.checks.httpAnalysis?.status === 'failed' || !result.checks.httpAnalysis?.statusCode) {
      expect(result.checks.httpAnalysis?.details).toMatch(/timed out|ETIMEDOUT|ECONNREFUSED|failed|unreachable/i);
    }
  }, 25000);
});
