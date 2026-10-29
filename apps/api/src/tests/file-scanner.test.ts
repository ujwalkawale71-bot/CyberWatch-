import { describe, it, expect } from 'vitest';
import { fileScannerService } from '../services/file-scanner.service';

describe('CyberWatch File Security Scanner (Phases 1–6)', () => {
  // ── PHASE 1: Upload Handling & Security ───────────────────────────────────
  describe('Phase 1: Upload Handling, Isolation & Sanitization', () => {
    it('sanitizes malicious filenames with directory traversal, null-bytes, and control chars', () => {
      expect(fileScannerService.sanitizeFilename('../../../../etc/passwd')).toBe('passwd');
      expect(fileScannerService.sanitizeFilename('..\\..\\Windows\\System32\\calc.exe')).toBe('calc.exe');
      expect(fileScannerService.sanitizeFilename('invoice; rm -rf /; `calc`.pdf')).not.toContain(';');
      expect(fileScannerService.sanitizeFilename('invoice; rm -rf /; `calc`.pdf')).not.toContain('`');
      expect(fileScannerService.sanitizeFilename('document.pdf\0.exe')).toBe('document.pdf.exe');
      expect(fileScannerService.sanitizeFilename('   sample.pdf   ')).toBe('sample.pdf');
    });

    it('generates a secure isolated temporary storage path with random UUID', () => {
      const { storageFilename, storagePath } = fileScannerService.generateSafeStoragePath();
      expect(storageFilename).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.bin$/i);
      expect(storagePath).toContain('file-scan');
    });
  });

  // ── PHASE 2: Hashing & Identity ───────────────────────────────────────────
  describe('Phase 2: Hashing & Identity', () => {
    it('computes MD5, SHA1, SHA256, and ssdeep fuzzy hash from raw file bytes', async () => {
      const sample = Buffer.from('CyberWatch Real Static Analysis Sample Payload', 'utf-8');
      const result = await fileScannerService.analyzeBuffer(sample, {
        originalFilename: 'test.txt',
      });

      const hashingStage = result.analysis.stages?.hashing;
      expect(hashingStage?.status).toBe('done');
      expect(hashingStage?.data?.md5).toBe('37aeaeda3a96cfdfd635c53b1b5d3da4');
      expect(hashingStage?.data?.sha1).toBeDefined();
      expect(hashingStage?.data?.sha256).toBeDefined();
      expect(hashingStage?.data?.ssdeep).toBeDefined();
      expect(result.analysis.sha256).toBe(hashingStage?.data?.sha256);
      expect(result.analysis.fileSize).toBe(sample.length);
    });
  });

  // ── PHASE 3: File Type & Magic Bytes Detection ────────────────────────────
  describe('Phase 3: Magic Bytes & Format Identification', () => {
    it('identifies Windows PE executable from MZ + PE header bytes', () => {
      const pe = Buffer.alloc(128);
      pe[0] = 0x4d;
      pe[1] = 0x5a;
      pe.writeUInt32LE(0x40, 0x3c);
      pe[0x40] = 0x50;
      pe[0x41] = 0x45;

      const type = fileScannerService.detectMagicType(pe);
      expect(type.detectedFormat).toContain('Windows PE Executable');
      expect(type.isExecutableFormat).toBe(true);
      expect(type.detectedMime).toBe('application/x-dosexec');
    });

    it('identifies Linux ELF executable from magic bytes', () => {
      const elf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
      const type = fileScannerService.detectMagicType(elf);
      expect(type.detectedFormat).toContain('Linux ELF Executable');
      expect(type.isExecutableFormat).toBe(true);
      expect(type.detectedMime).toBe('application/x-executable');
    });

    it('identifies macOS Mach-O binary from magic bytes', () => {
      const macho = Buffer.from([0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00, 0x00, 0x00]);
      const type = fileScannerService.detectMagicType(macho);
      expect(type.detectedFormat).toContain('Mach-O Binary');
      expect(type.isExecutableFormat).toBe(true);
    });

    it('identifies PDF document from header bytes', () => {
      const pdf = Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF');
      const type = fileScannerService.detectMagicType(pdf);
      expect(type.detectedFormat).toBe('PDF Document');
      expect(type.isExecutableFormat).toBe(false);
      expect(type.detectedMime).toBe('application/pdf');
    });

    it('identifies Windows Shell Link (LNK) shortcut', () => {
      const lnk = Buffer.alloc(32);
      lnk[0] = 0x4c;
      lnk[4] = 0x01;
      lnk[5] = 0x14;
      lnk[6] = 0x02;
      const type = fileScannerService.detectMagicType(lnk);
      expect(type.detectedFormat).toContain('LNK Shortcut');
      expect(type.isExecutableFormat).toBe(true);
    });

    it('identifies Rich Text Format (RTF) document', () => {
      const rtf = Buffer.from('{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Courier;}} Hello}');
      const type = fileScannerService.detectMagicType(rtf);
      expect(type.detectedFormat).toContain('Rich Text Format');
      expect(type.detectedMime).toBe('application/rtf');
    });

    it('identifies 7-Zip, RAR, and GZIP archives', () => {
      const sevenZ = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
      expect(fileScannerService.detectMagicType(sevenZ).detectedFormat).toContain('7-Zip');

      const rar = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]);
      expect(fileScannerService.detectMagicType(rar).detectedFormat).toContain('RAR');

      const gz = Buffer.from([0x1f, 0x8b, 0x08, 0x00]);
      expect(fileScannerService.detectMagicType(gz).detectedFormat).toContain('GZIP');
    });

    it('identifies HTA application and HTML documents', () => {
      const hta = Buffer.from('<html><head><hta:application id="oHTA" applicationname="test"></head><body></body></html>');
      expect(fileScannerService.detectMagicType(hta).detectedFormat).toContain('HTML Application');

      const html = Buffer.from('<!DOCTYPE html><html><body><h1>Hello</h1></body></html>');
      expect(fileScannerService.detectMagicType(html).detectedFormat).toBe('HTML Document');
    });
  });

  // ── PHASE 4: File Type Mismatch & Name Analysis ───────────────────────────
  describe('Phase 4: File Type Mismatch & Name Analysis', () => {
    it('detects executable masquerading as a PDF document (Critical Finding)', async () => {
      const peHeader = Buffer.alloc(128);
      peHeader[0] = 0x4d; // 'M'
      peHeader[1] = 0x5a; // 'Z'
      peHeader.writeUInt32LE(0x40, 0x3c);
      peHeader[0x40] = 0x50; // 'P'
      peHeader[0x41] = 0x45; // 'E'

      const result = await fileScannerService.analyzeBuffer(peHeader, {
        originalFilename: 'invoice.pdf',
        claimedMimeType: 'application/pdf',
      });

      expect(result.analysis.stages?.fileType?.data?.isMasquerading).toBe(true);
      expect(result.analysis.stages?.fileType?.data?.isMismatch).toBe(true);

      const finding = result.findings.find((f) => f.findingId === 'EVASION-MASQUERADED-EXECUTABLE');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('CRITICAL');
      expect(result.riskScore).toBeGreaterThanOrEqual(50);
    });

    it('detects double extension evasion (.pdf.exe)', async () => {
      const sample = Buffer.from('binary payload data', 'utf-8');
      const result = await fileScannerService.analyzeBuffer(sample, {
        originalFilename: 'urgent_invoice.pdf.exe',
      });

      expect(result.analysis.stages?.fileType?.data?.isDoubleExtension).toBe(true);
      const finding = result.findings.find((f) => f.findingId === 'EVASION-DOUBLE-EXTENSION');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('HIGH');
    });

    it('detects Unicode Right-to-Left Override (RTLO) spoofing in filename', async () => {
      const rtloFilename = 'financial_report\u202Efdp.exe'; // reverses "fdp.exe" to look like "reportexe.pdf"
      const sample = Buffer.from('harmless payload', 'utf-8');

      const result = await fileScannerService.analyzeBuffer(sample, {
        originalFilename: rtloFilename,
      });

      const rtloFinding = result.findings.find((f) => f.findingId === 'EVASION-UNICODE-RTLO');
      expect(rtloFinding).toBeDefined();
      expect(rtloFinding?.severity).toBe('HIGH');
    });

    it('detects zero-byte file anomaly', async () => {
      const empty = Buffer.alloc(0);
      const result = await fileScannerService.analyzeBuffer(empty, {
        originalFilename: 'empty.bin',
      });

      expect(result.analysis.stages?.fileType?.data?.sizeAnomaly).toBe('Zero-byte empty file');
      expect(result.findings.some((f) => f.findingId === 'ANOMALY-ZERO-BYTE')).toBe(true);
    });
  });

  // ── PHASE 5: Shannon Entropy Analysis ─────────────────────────────────────
  describe('Phase 5: Shannon Entropy Analysis', () => {
    it('calculates low entropy for uniform text and high entropy for randomized/packed bytes', async () => {
      // 1. Uniform text -> very low entropy
      const textBuffer = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'utf-8');
      const lowResult = await fileScannerService.analyzeBuffer(textBuffer, { originalFilename: 'uniform.txt' });
      expect(lowResult.analysis.stages?.entropy?.data?.entropy).toBeLessThan(1.0);
      expect(lowResult.analysis.stages?.entropy?.data?.interpretation).toBe('low_entropy');

      // 2. Random bytes -> high entropy
      const randomBuffer = Buffer.alloc(2048);
      for (let i = 0; i < randomBuffer.length; i++) {
        randomBuffer[i] = Math.floor(Math.random() * 256);
      }
      const highResult = await fileScannerService.analyzeBuffer(randomBuffer, { originalFilename: 'packed.bin' });
      expect(highResult.analysis.stages?.entropy?.data?.entropy).toBeGreaterThan(7.0);
      expect(highResult.analysis.stages?.entropy?.data?.blockEntropy).toBeDefined();
    });
  });

  // ── PHASE 6: Strings Extraction & Indicator Categorization ────────────────
  describe('Phase 6: Safe Strings Extraction & Indicator Categorization', () => {
    it('extracts URLs, IPs, domains, emails, registry keys, file paths, and dangerous API triads', async () => {
      const payload = Buffer.from(
        'https://c2-update.xyz/agent.bin\n' +
          '198.51.100.45\n' +
          'attacker@malicious-domain.com\n' +
          'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n' +
          'C:\\Windows\\System32\\svchost.exe\n' +
          'VirtualAlloc\n' +
          'WriteProcessMemory\n' +
          'CreateRemoteThread\n' +
          'powershell.exe -EncodedCommand AAAAAA==\n' +
          '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n' +
          'all your files have been encrypted send bitcoin to unlock\n',
        'utf-8'
      );

      const result = await fileScannerService.analyzeBuffer(payload, { originalFilename: 'sample.dat' });
      const stringsStage = result.analysis.stages?.strings?.data;

      expect(stringsStage?.urls).toContain('https://c2-update.xyz/agent.bin');
      expect(stringsStage?.ips).toContain('198.51.100.45');
      expect(stringsStage?.emails).toContain('attacker@malicious-domain.com');
      expect(stringsStage?.registryKeys?.some((k) => k.includes('HKEY_LOCAL_MACHINE'))).toBe(true);
      expect(stringsStage?.filePaths?.some((p) => p.includes('System32'))).toBe(true);
      expect(stringsStage?.suspiciousApis).toContain('VirtualAlloc');
      expect(stringsStage?.suspiciousApis).toContain('WriteProcessMemory');
      expect(stringsStage?.suspiciousApis).toContain('CreateRemoteThread');
      expect(stringsStage?.cryptoWallets?.length).toBeGreaterThan(0);
      expect(stringsStage?.ransomwareIndicators?.length).toBeGreaterThan(0);

      const injectionFinding = result.findings.find((f) => f.findingId === 'STRINGS-PROCESS-INJECTION-APIS');
      expect(injectionFinding).toBeDefined();
    });

    it('extracts UTF-16LE wide character strings safely', async () => {
      const wideString = Buffer.from('powershell.exe\0VirtualAlloc\0https://example.org/test\0', 'utf16le');
      const result = await fileScannerService.analyzeBuffer(wideString, { originalFilename: 'wide.bin' });
      const stringsStage = result.analysis.stages?.strings?.data;

      expect(stringsStage?.suspiciousApis).toContain('VirtualAlloc');
      expect(stringsStage?.urls).toContain('https://example.org/test');
    });
  });
});
