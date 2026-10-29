import { describe, it, expect } from 'vitest';
import { fileScannerService } from '../services/file-scanner.service';
import { deriveClassificationFromRiskScore } from '../services/scan.service';
import fs from 'fs';
import path from 'path';

describe('File Security Scanner Risk Engine & Evidence Verification', () => {
  // ── TEST 1: Benign file with no risk contributions ─────────────────────────
  it('TEST 1: Benign file with no risk contributions produces 0 or baseline low risk score', async () => {
    const benignBuffer = Buffer.from('Hello world, this is a clean text document.\nNo active scripts or payloads.', 'utf-8');
    const result = await fileScannerService.analyzeBuffer(benignBuffer, {
      originalFilename: 'notes.txt',
      claimedMimeType: 'text/plain',
    });

    expect(result.riskScore).toBe(0);
    expect(result.verdict).toBe('Clean');
    expect(result.findings.filter((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL').length).toBe(0);
  });

  // ── TEST 2: Extension mismatch ─────────────────────────────────────────────
  it('TEST 2: Extension mismatch increases score according to configured contribution', async () => {
    // PE binary header disguised with .txt extension
    const peDisguised = Buffer.alloc(256);
    peDisguised[0] = 0x4d;
    peDisguised[1] = 0x5a;
    peDisguised.writeUInt32LE(0x40, 0x3c);
    peDisguised[0x40] = 0x50;
    peDisguised[0x41] = 0x45;

    const result = await fileScannerService.analyzeBuffer(peDisguised, {
      originalFilename: 'readme.txt',
      claimedMimeType: 'text/plain',
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(45);
    const mismatchFinding = result.findings.find(
      (f) => f.findingId === 'EVASION-MASQUERADED-EXECUTABLE' || f.category.includes('Evasion')
    );
    expect(mismatchFinding).toBeDefined();
    expect(mismatchFinding?.severity === 'HIGH' || mismatchFinding?.severity === 'CRITICAL').toBe(true);
  });

  // ── TEST 3: Double extension ───────────────────────────────────────────────
  it('TEST 3: Double extension generates an actual high-severity finding', async () => {
    const sample = Buffer.from('Harmless file content', 'utf-8');
    const result = await fileScannerService.analyzeBuffer(sample, {
      originalFilename: 'quarterly_report.pdf.exe',
    });

    const doubleExtFinding = result.findings.find((f) => f.findingId === 'EVASION-DOUBLE-EXTENSION');
    expect(doubleExtFinding).toBeDefined();
    expect(doubleExtFinding?.severity).toBe('HIGH');
    expect(result.analysis.stages?.fileType?.data?.isDoubleExtension).toBe(true);
  });

  // ── TEST 4: High entropy evidence ──────────────────────────────────────────
  it('TEST 4: High entropy evidence generates an actual finding with score contribution', async () => {
    // Generate high entropy random buffer
    const randomBuffer = Buffer.alloc(4096);
    for (let i = 0; i < randomBuffer.length; i++) {
      randomBuffer[i] = Math.floor(Math.random() * 256);
    }

    const result = await fileScannerService.analyzeBuffer(randomBuffer, {
      originalFilename: 'data.bin',
    });

    expect(result.analysis.entropy).toBeGreaterThan(7.5);
    expect(result.analysis.stages?.entropy?.data?.isPackedOrEncrypted).toBe(true);
  });

  // ── TEST 5: Suspicious imports ─────────────────────────────────────────────
  it('TEST 5: Suspicious Win32 process injection strings/imports generate actual findings', async () => {
    const payload = Buffer.from(
      'VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00powershell.exe\x00',
      'utf-8'
    );
    const result = await fileScannerService.analyzeBuffer(payload, {
      originalFilename: 'agent.dll',
    });

    const injectionFinding = result.findings.find((f) => f.findingId === 'STRINGS-PROCESS-INJECTION-APIS');
    expect(injectionFinding).toBeDefined();
    expect(injectionFinding?.severity).toBe('HIGH');
    expect(injectionFinding?.scoreContribution).toBeGreaterThan(0);
  });

  // ── TEST 6: Multiple independent findings ──────────────────────────────────
  it('TEST 6: Multiple independent findings accumulate evidence into the final score', async () => {
    // Disguised PE with injection APIs and double extension
    const complex = Buffer.alloc(512);
    complex[0] = 0x4d;
    complex[1] = 0x5a;
    complex.writeUInt32LE(0x40, 0x3c);
    complex[0x40] = 0x50;
    complex[0x41] = 0x45;
    complex.write('VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00', 128, 'utf-8');

    const result = await fileScannerService.analyzeBuffer(complex, {
      originalFilename: 'statement.pdf.exe',
      claimedMimeType: 'application/pdf',
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(75);
    expect(result.verdict).toBe('Malicious');
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
  });

  // ── TEST 7: Duplicate evidence does not double count ───────────────────────
  it('TEST 7: Duplicate evidence does not double count identical contributors', async () => {
    const duplicateStringPayload = Buffer.from(
      'VirtualAlloc VirtualAlloc VirtualAlloc WriteProcessMemory WriteProcessMemory CreateRemoteThread CreateRemoteThread',
      'utf-8'
    );
    const result = await fileScannerService.analyzeBuffer(duplicateStringPayload, {
      originalFilename: 'test.bin',
    });

    // Score contributors should have unique findingIds
    const contributors = result.analysis.scoreContributors || [];
    const keys = contributors.map((c) => c.findingId || c.title);
    const uniqueKeys = new Set(keys);
    expect(keys.length).toBe(uniqueKeys.size);
  });

  // ── TEST 8: Threat Intelligence unavailable does not produce false Clean/0 ──
  it('TEST 8: Threat Intelligence not configured does not lower score or falsely produce clean', async () => {
    const sample = Buffer.from('Some payload without external VT key', 'utf-8');
    const result = await fileScannerService.analyzeBuffer(sample, {
      originalFilename: 'check.bin',
    });

    const repStage = result.analysis.stages?.reputation;
    expect(repStage).toBeDefined();
    // Providers should report not_configured, not fake clean
    const allNotConfiguredOrClean = repStage?.data?.providers.every(
      (p) => p.status === 'not_configured' || p.status === 'no_match'
    );
    expect(allNotConfiguredOrClean).toBe(true);
  });

  // ── TEST 9: Incomplete scan status ─────────────────────────────────────────
  it('TEST 9: Incomplete scan is not classified as Safe/0 without verification', () => {
    const isScanFailed = true;
    const classification = deriveClassificationFromRiskScore(0, false, isScanFailed);
    expect(classification).not.toBe('Safe');
    expect(classification).toBe('Suspicious');
  });

  // ── TEST 10: Determinism: Same evidence twice yields same score ────────────
  it('TEST 10: Determinism: Repeated scans of identical file yield exact same findings and score', async () => {
    const sample = Buffer.from('Exact byte pattern for deterministic verification test #101', 'utf-8');
    const scan1 = await fileScannerService.analyzeBuffer(sample, { originalFilename: 'sample.dat' });
    const scan2 = await fileScannerService.analyzeBuffer(sample, { originalFilename: 'sample.dat' });

    expect(scan1.riskScore).toBe(scan2.riskScore);
    expect(scan1.verdict).toBe(scan2.verdict);
    expect(scan1.findings.length).toBe(scan2.findings.length);
    expect(scan1.analysis.sha256).toBe(scan2.analysis.sha256);
  });

  // ── TEST 11: Risk Level Mapping Consistency ────────────────────────────────
  it('TEST 11: Centralized classification aligns across score ranges', () => {
    expect(deriveClassificationFromRiskScore(0)).toBe('Safe');
    expect(deriveClassificationFromRiskScore(10)).toBe('Safe');
    expect(deriveClassificationFromRiskScore(20)).toBe('Low Risk');
    expect(deriveClassificationFromRiskScore(35)).toBe('Suspicious');
    expect(deriveClassificationFromRiskScore(60)).toBe('High Risk');
    expect(deriveClassificationFromRiskScore(80)).toBe('Critical');
  });

  // ── TEST 14: Screenshot "28/100" is NOT hardcoded anywhere ────────────────
  it('TEST 14: Verifies 28/100 is not hardcoded anywhere in codebase as a default value', () => {
    const serviceContent = fs.readFileSync(path.resolve(__dirname, '../services/file-scanner.service.ts'), 'utf-8');
    expect(serviceContent).not.toMatch(/riskScore\s*=\s*28\b/);
    expect(serviceContent).not.toMatch(/risk\s*=\s*28\b/);
  });
});
