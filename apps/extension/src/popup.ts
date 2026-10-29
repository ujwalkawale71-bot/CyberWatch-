// CyberWatch Popup Logic (Manifest V3)
// Strictly follows security standards: XSS-safe DOM text manipulation,
// ephemeral session storage, no password persistence, real backend integration.

import { api } from './api.js';
import { storageService } from './storage.js';
import type { ScannerType, ScanResultData, IScanFinding } from './types.js';

interface ScannerInfo {
  type: ScannerType;
  title: string;
  desc: string;
  placeholder: string;
  inputLabel: string;
}

const SCANNER_DETAILS: Record<ScannerType, ScannerInfo> = {
  URL: {
    type: 'URL',
    title: 'URL Security Scanner',
    desc: 'Analyzes destination structure, DNS resolution, TLS certificate, and redirect hops.',
    placeholder: 'https://example.com/login',
    inputLabel: 'Target URL',
  },
  Website: {
    type: 'Website',
    title: 'Website Security Scanner',
    desc: 'Assesses web security headers, cookie flags, TLS protocol, and server technologies.',
    placeholder: 'https://portal.company.com',
    inputLabel: 'Website Domain or URL',
  },
  API: {
    type: 'API',
    title: 'API Security Scanner',
    desc: 'Audits REST/HTTP API endpoints for CORS policies, auth schemes, and data disclosures.',
    placeholder: 'https://api.example.com/v1/users',
    inputLabel: 'API Endpoint Address',
  },
  Phishing: {
    type: 'Phishing',
    title: 'Phishing & Deception Scanner',
    desc: 'Identifies brand impersonation lures, credential harvesting keywords, and lookalike characters.',
    placeholder: 'https://account-security-update.com',
    inputLabel: 'Suspicious Link Address',
  },
  File: {
    type: 'File',
    title: 'File Security Scanner',
    desc: 'Performs static binary inspection, magic byte verification, and double-extension detection.',
    placeholder: 'https://example.com/assets/sample.zip or upload below',
    inputLabel: 'Downloadable File URL or Upload File',
  },
  Extension: {
    type: 'Extension',
    title: 'Browser Extension Scanner',
    desc: 'Evaluates extension packages, Manifest V3 compliance, broad host access, and permissions.',
    placeholder: 'https://chromewebstore.google.com/detail/... or 32-char ID',
    inputLabel: 'Extension Store URL, ID, or Manifest',
  },
};

// ── State ─────────────────────────────────────────────────────────────────────
let currentScanner: ScannerType = 'URL';
let activeTabUrl = '';
let selectedFile: File | null = null;
let lastScanResult: ScanResultData | null = null;

// ── DOM Elements ──────────────────────────────────────────────────────────────
const el = {
  // Navigation
  tabs: document.querySelectorAll<HTMLButtonElement>('.nav-tab'),
  openWebBtn: document.getElementById('open-web-btn') as HTMLButtonElement,
  authToggleBtn: document.getElementById('auth-toggle-btn') as HTMLButtonElement,
  authBadgeStatus: document.getElementById('auth-badge-status') as HTMLSpanElement,

  // Status & Active Tab
  statusBanner: document.getElementById('status-banner') as HTMLDivElement,
  statusBannerText: document.getElementById('status-banner-text') as HTMLSpanElement,
  activeTabCard: document.getElementById('active-tab-card') as HTMLDivElement,
  activeTabUrl: document.getElementById('active-tab-url') as HTMLSpanElement,
  useTabBtn: document.getElementById('use-tab-btn') as HTMLButtonElement,

  // Sections
  scannerFormSection: document.getElementById('scanner-form-section') as HTMLElement,
  scanningSection: document.getElementById('scanning-section') as HTMLElement,
  resultsSection: document.getElementById('results-section') as HTMLElement,
  errorSection: document.getElementById('error-section') as HTMLElement,

  // Form
  scannerTitle: document.getElementById('scanner-title') as HTMLHeadingElement,
  scannerDesc: document.getElementById('scanner-desc') as HTMLParagraphElement,
  targetInputGroup: document.getElementById('target-input-group') as HTMLDivElement,
  targetInputLabel: document.getElementById('target-input-label') as HTMLLabelElement,
  targetInput: document.getElementById('target-input') as HTMLInputElement,
  clearInputBtn: document.getElementById('clear-input-btn') as HTMLButtonElement,

  fileInputGroup: document.getElementById('file-input-group') as HTMLDivElement,
  fileDropZone: document.getElementById('file-drop-zone') as HTMLDivElement,
  fileInput: document.getElementById('file-input') as HTMLInputElement,
  fileLabelText: document.getElementById('file-label-text') as HTMLSpanElement,
  selectedFileBadge: document.getElementById('selected-file-badge') as HTMLDivElement,
  selectedFileName: document.getElementById('selected-file-name') as HTMLSpanElement,
  selectedFileSize: document.getElementById('selected-file-size') as HTMLSpanElement,
  removeFileBtn: document.getElementById('remove-file-btn') as HTMLButtonElement,

  extensionManifestGroup: document.getElementById('extension-manifest-group') as HTMLDivElement,
  manifestInput: document.getElementById('manifest-input') as HTMLTextAreaElement,

  forceRescanCheckbox: document.getElementById('force-rescan-checkbox') as HTMLInputElement,
  startScanBtn: document.getElementById('start-scan-btn') as HTMLButtonElement,
  scanBtnText: document.getElementById('scan-btn-text') as HTMLSpanElement,

  // Progress
  scanningStepTitle: document.getElementById('scanning-step-title') as HTMLHeadingElement,
  scanningStepDesc: document.getElementById('scanning-step-desc') as HTMLParagraphElement,

  // Results
  scanStatusAlert: document.getElementById('scan-status-alert') as HTMLDivElement,
  scanStatusTitle: document.getElementById('scan-status-title') as HTMLDivElement,
  scanStatusDesc: document.getElementById('scan-status-desc') as HTMLDivElement,
  evidenceContainer: document.getElementById('evidence-container') as HTMLDivElement,
  evidenceGrid: document.getElementById('evidence-grid') as HTMLDivElement,
  resultClassificationBadge: document.getElementById('result-classification-badge') as HTMLSpanElement,
  resultScoreVal: document.getElementById('result-score-val') as HTMLElement,
  resultTargetType: document.getElementById('result-target-type') as HTMLDivElement,
  resultTargetVal: document.getElementById('result-target-val') as HTMLDivElement,
  scoreMeterFill: document.getElementById('score-meter-fill') as HTMLDivElement,
  findingsCount: document.getElementById('findings-count') as HTMLSpanElement,
  findingsList: document.getElementById('findings-list') as HTMLDivElement,
  recommendationsList: document.getElementById('recommendations-list') as HTMLUListElement,
  viewFullReportBtn: document.getElementById('view-full-report-btn') as HTMLButtonElement,
  newScanBtn: document.getElementById('new-scan-btn') as HTMLButtonElement,

  // Errors
  errorTitle: document.getElementById('error-title') as HTMLHeadingElement,
  errorMessage: document.getElementById('error-message') as HTMLParagraphElement,
  errorRetryBtn: document.getElementById('error-retry-btn') as HTMLButtonElement,
  errorLoginBtn: document.getElementById('error-login-btn') as HTMLButtonElement,

  // Drawer
  authDrawer: document.getElementById('auth-drawer') as HTMLDivElement,
  drawerCloseBtn: document.getElementById('drawer-close-btn') as HTMLButtonElement,
  loggedInView: document.getElementById('logged-in-view') as HTMLDivElement,
  loggedOutView: document.getElementById('logged-out-view') as HTMLDivElement,
  userInitials: document.getElementById('user-initials') as HTMLDivElement,
  userName: document.getElementById('user-name') as HTMLSpanElement,
  userEmail: document.getElementById('user-email') as HTMLSpanElement,
  userRole: document.getElementById('user-role') as HTMLSpanElement,
  logoutBtn: document.getElementById('logout-btn') as HTMLButtonElement,

  loginForm: document.getElementById('login-form') as HTMLFormElement,
  loginEmail: document.getElementById('login-email') as HTMLInputElement,
  loginPassword: document.getElementById('login-password') as HTMLInputElement,
  loginError: document.getElementById('login-error') as HTMLDivElement,
  manualTokenInput: document.getElementById('manual-token-input') as HTMLInputElement,
  saveTokenBtn: document.getElementById('save-token-btn') as HTMLButtonElement,

  configApiUrl: document.getElementById('config-api-url') as HTMLInputElement,
  configWebUrl: document.getElementById('config-web-url') as HTMLInputElement,
  saveConfigBtn: document.getElementById('save-config-btn') as HTMLButtonElement,
};

// ── Initialization ────────────────────────────────────────────────────────────
async function init() {
  setupEventListeners();
  await loadConfigurations();
  await checkSessionState();
  await detectActiveTab();
  await checkBackendStatus();
  switchScanner('URL');
}

// ── Event Handlers Setup ──────────────────────────────────────────────────────
function setupEventListeners() {
  // Navigation tabs
  el.tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const type = tab.getAttribute('data-type') as ScannerType;
      if (type) switchScanner(type);
    });
  });

  // Active tab "Use" button
  el.useTabBtn.addEventListener('click', () => {
    if (activeTabUrl) {
      el.targetInput.value = activeTabUrl;
      el.clearInputBtn.style.display = 'block';
    }
  });

  // Target input interactions
  el.targetInput.addEventListener('input', () => {
    el.clearInputBtn.style.display = el.targetInput.value ? 'block' : 'none';
  });

  el.clearInputBtn.addEventListener('click', () => {
    el.targetInput.value = '';
    el.clearInputBtn.style.display = 'none';
    el.targetInput.focus();
  });

  // File picker interactions
  el.fileDropZone.addEventListener('click', () => {
    el.fileInput.click();
  });

  el.fileInput.addEventListener('change', (e) => {
    const target = e.target as HTMLInputElement;
    if (target.files && target.files.length > 0) {
      handleFileSelected(target.files[0]);
    }
  });

  // Drag and drop
  el.fileDropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    el.fileDropZone.classList.add('dragover');
  });

  el.fileDropZone.addEventListener('dragleave', () => {
    el.fileDropZone.classList.remove('dragover');
  });

  el.fileDropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    el.fileDropZone.classList.remove('dragover');
    if (e.dataTransfer && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  el.removeFileBtn.addEventListener('click', () => {
    selectedFile = null;
    el.fileInput.value = '';
    el.selectedFileBadge.classList.add('hidden');
    el.fileDropZone.classList.remove('hidden');
  });

  // Start scan button
  el.startScanBtn.addEventListener('click', executeScan);

  // New scan button
  el.newScanBtn.addEventListener('click', () => {
    showSection('scannerFormSection');
  });

  // View full report button
  el.viewFullReportBtn.addEventListener('click', openFullReport);

  // Open web app button
  el.openWebBtn.addEventListener('click', async () => {
    const { webBaseUrl } = await storageService.getConfig();
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: webBaseUrl });
    } else {
      window.open(webBaseUrl, '_blank');
    }
  });

  // Auth drawer toggle
  el.authToggleBtn.addEventListener('click', () => {
    el.authDrawer.classList.toggle('hidden');
  });

  el.drawerCloseBtn.addEventListener('click', () => {
    el.authDrawer.classList.add('hidden');
  });

  // Login form submit
  el.loginForm.addEventListener('submit', handleLogin);

  // Manual token save
  el.saveTokenBtn.addEventListener('click', async () => {
    const token = el.manualTokenInput.value.trim();
    if (token) {
      await storageService.setToken(token);
      await storageService.setUser({ name: 'Token User', email: 'authenticated via token', role: 'USER' });
      el.manualTokenInput.value = '';
      await checkSessionState();
      el.authDrawer.classList.add('hidden');
      showSection('scannerFormSection');
    }
  });

  // Logout button
  el.logoutBtn.addEventListener('click', async () => {
    await storageService.clearToken();
    await checkSessionState();
  });

  // Configuration save
  el.saveConfigBtn.addEventListener('click', async () => {
    const apiBaseUrl = el.configApiUrl.value.trim() || 'http://localhost:5000/api/v1';
    const webBaseUrl = el.configWebUrl.value.trim() || 'http://localhost:5173';
    await storageService.setConfig({ apiBaseUrl, webBaseUrl });
    await checkBackendStatus();
    alert('Configuration saved.');
  });

  // Error retry button
  el.errorRetryBtn.addEventListener('click', () => {
    showSection('scannerFormSection');
  });

  // Error login button
  el.errorLoginBtn.addEventListener('click', () => {
    showSection('scannerFormSection');
    el.authDrawer.classList.remove('hidden');
  });
}

// ── Scanner Switcher ──────────────────────────────────────────────────────────
function switchScanner(type: ScannerType) {
  currentScanner = type;

  // Update tabs
  el.tabs.forEach((tab) => {
    const tabType = tab.getAttribute('data-type');
    if (tabType === type) {
      tab.classList.add('active');
    } else {
      tab.classList.remove('active');
    }
  });

  const info = SCANNER_DETAILS[type];
  el.scannerTitle.textContent = info.title;
  el.scannerDesc.textContent = info.desc;
  el.targetInputLabel.textContent = info.inputLabel;
  el.targetInput.placeholder = info.placeholder;

  // Handle special scanner UI modes
  if (type === 'File') {
    el.fileInputGroup.classList.remove('hidden');
    el.extensionManifestGroup.classList.add('hidden');
    el.targetInputGroup.classList.remove('hidden');
    el.targetInputLabel.textContent = 'Or Enter Direct File URL';
  } else if (type === 'Extension') {
    el.fileInputGroup.classList.add('hidden');
    el.extensionManifestGroup.classList.remove('hidden');
    el.targetInputGroup.classList.remove('hidden');
    el.targetInputLabel.textContent = 'Chrome Web Store URL or Extension ID';
  } else {
    el.fileInputGroup.classList.add('hidden');
    el.extensionManifestGroup.classList.add('hidden');
    el.targetInputGroup.classList.remove('hidden');
  }

  showSection('scannerFormSection');
}

// ── Active Tab Detection ──────────────────────────────────────────────────────
async function detectActiveTab() {
  try {
    if (typeof chrome === 'undefined' || !chrome.tabs) {
      el.activeTabUrl.textContent = 'Active tab detection not available.';
      el.useTabBtn.disabled = true;
      return;
    }
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime && chrome.runtime.lastError) {
        el.activeTabUrl.textContent = 'Active page detection unavailable.';
        el.useTabBtn.disabled = true;
        return;
      }
      const tab = tabs && tabs[0];
      if (tab && tab.url) {
        activeTabUrl = tab.url;

        // Skip internal/chrome URLs gracefully
        if (
          activeTabUrl.startsWith('chrome://') ||
          activeTabUrl.startsWith('chrome-extension://') ||
          activeTabUrl.startsWith('edge://') ||
          activeTabUrl.startsWith('about:')
        ) {
          el.activeTabUrl.textContent = 'Internal browser tab (enter target below)';
          el.useTabBtn.disabled = true;
          el.useTabBtn.style.opacity = '0.5';
        } else {
          el.activeTabUrl.textContent = activeTabUrl;
          el.useTabBtn.disabled = false;
          el.useTabBtn.style.opacity = '1';

          // Pre-populate if currently empty and URL is standard web
          if (!el.targetInput.value && (activeTabUrl.startsWith('http://') || activeTabUrl.startsWith('https://'))) {
            el.targetInput.value = activeTabUrl;
            el.clearInputBtn.style.display = 'block';
          }
        }
      } else {
        el.activeTabUrl.textContent = 'No accessible active page.';
        el.useTabBtn.disabled = true;
      }
    });
  } catch {
    el.activeTabUrl.textContent = 'Page detection unavailable.';
    el.useTabBtn.disabled = true;
  }
}

// ── Backend Health Check ──────────────────────────────────────────────────────
async function checkBackendStatus() {
  const health = await api.checkHealth();
  if (health.ok) {
    el.statusBanner.classList.add('hidden');
  } else {
    el.statusBanner.classList.remove('hidden');
    el.statusBannerText.textContent = `Backend offline (${health.message}). Run 'npm run dev:api'.`;
  }
}

// ── Session & Auth State Management ───────────────────────────────────────────
async function checkSessionState() {
  const token = await storageService.getToken();
  const user = await storageService.getUser();

  if (token) {
    const effectiveUser = user || { name: 'Account', email: '', role: 'USER' };
    el.authBadgeStatus.textContent = effectiveUser.name || 'Account';
    el.loggedInView.classList.remove('hidden');
    el.loggedOutView.classList.add('hidden');

    el.userName.textContent = effectiveUser.name || 'CyberWatch User';
    el.userEmail.textContent = effectiveUser.email || '';
    el.userRole.textContent = effectiveUser.role || 'USER';

    const initials = (effectiveUser.name || 'CW')
      .split(' ')
      .map((p: string) => p[0])
      .slice(0, 2)
      .join('')
      .toUpperCase();
    el.userInitials.textContent = initials || 'CW';
  } else {
    el.authBadgeStatus.textContent = 'Sign In';
    el.loggedInView.classList.add('hidden');
    el.loggedOutView.classList.remove('hidden');
  }
}

async function handleLogin(e: Event) {
  e.preventDefault();
  el.loginError.classList.add('hidden');
  const email = el.loginEmail.value.trim();
  const password = el.loginPassword.value;

  if (!email || !password) return;

  const submitBtn = el.loginForm.querySelector('button[type="submit"]');
  try {
    if (submitBtn) submitBtn.textContent = 'Authenticating...';
    await api.login(email, password);
    el.loginPassword.value = '';
    await checkSessionState();
    el.authDrawer.classList.add('hidden');
    showSection('scannerFormSection');
  } catch (err: any) {
    el.loginError.textContent = err.message || 'Login failed.';
    el.loginError.classList.remove('hidden');
  } finally {
    if (submitBtn) submitBtn.textContent = 'Sign In';
  }
}

// ── File Selection ────────────────────────────────────────────────────────────
function handleFileSelected(file: File) {
  // Enforce 25 MB max limit
  const maxBytes = 25 * 1024 * 1024;
  if (file.size > maxBytes) {
    alert('File exceeds the 25 MB maximum upload limit.');
    return;
  }

  selectedFile = file;
  el.selectedFileName.textContent = file.name;
  el.selectedFileSize.textContent = formatBytes(file.size);
  el.fileDropZone.classList.add('hidden');
  el.selectedFileBadge.classList.remove('hidden');
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

// ── Configuration Loading ─────────────────────────────────────────────────────
async function loadConfigurations() {
  const config = await storageService.getConfig();
  el.configApiUrl.value = config.apiBaseUrl;
  el.configWebUrl.value = config.webBaseUrl;
}

// ── Section View Management ───────────────────────────────────────────────────
function showSection(name: 'scannerFormSection' | 'scanningSection' | 'resultsSection' | 'errorSection') {
  el.scannerFormSection.classList.add('hidden');
  el.scanningSection.classList.add('hidden');
  el.resultsSection.classList.add('hidden');
  el.errorSection.classList.add('hidden');

  el[name].classList.remove('hidden');
}

// ── Scan Execution ────────────────────────────────────────────────────────────
async function executeScan() {
  const forceRescan = el.forceRescanCheckbox.checked;

  let targetValue = el.targetInput.value.trim();
  const manifestValue = el.manifestInput.value.trim();

  // If Browser Extension scanner has a manifest pasted, use that
  if (currentScanner === 'Extension' && manifestValue) {
    targetValue = manifestValue;
  }

  // File scanner with selected file
  if (currentScanner === 'File' && selectedFile) {
    return runFileUploadScan(selectedFile);
  }

  // Validate presence
  if (!targetValue) {
    alert('Please enter a target address or select a file to scan.');
    el.targetInput.focus();
    return;
  }

  showSection('scanningSection');
  el.scanningStepTitle.textContent = `Scanning with ${SCANNER_DETAILS[currentScanner].title}...`;
  el.scanningStepDesc.textContent = 'Evaluating DNS, TLS, HTTP security headers, and risk signals.';

  try {
    const result = await api.initiateScan(targetValue, currentScanner, forceRescan);
    displayScanResult(result);
  } catch (err: any) {
    handleScanError(err);
  }
}

async function runFileUploadScan(file: File) {
  showSection('scanningSection');
  el.scanningStepTitle.textContent = 'Uploading & Inspecting File...';
  el.scanningStepDesc.textContent = 'Computing SHA-256 hash, evaluating magic bytes and binary indicators.';

  try {
    const result = await api.uploadAndScanFile(file);
    displayScanResult(result);
  } catch (err: any) {
    handleScanError(err);
  }
}

// ── Scan Error Handling ───────────────────────────────────────────────────────
function handleScanError(err: any) {
  showSection('errorSection');
  const message = err.message || 'An unexpected error occurred during security scanning.';
  el.errorMessage.textContent = message;

  if (message.includes('Authentication') || message.includes('log in')) {
    el.errorLoginBtn.classList.remove('hidden');
    el.errorTitle.textContent = 'Authentication Required';
  } else {
    el.errorLoginBtn.classList.add('hidden');
    el.errorTitle.textContent = 'Security Scan Failed';
  }
}

// ── Results Display ───────────────────────────────────────────────────────────
function displayScanResult(scan: ScanResultData) {
  lastScanResult = scan;
  showSection('resultsSection');

  // Classification & Score
  const classification = scan.result || (scan.status === 'failed' ? 'Failed' : 'Safe');
  const score = Math.min(100, Math.max(0, scan.riskScore || 0));

  el.resultClassificationBadge.textContent = classification;
  el.resultClassificationBadge.className = 'classification-badge';

  const classKey = classification.toLowerCase().replace(/\s+/g, '-');
  el.resultClassificationBadge.classList.add(classKey);

  el.resultScoreVal.textContent = String(score);

  // Meter color
  let meterColor = '#10b981'; // safe
  if (score >= 75) meterColor = '#ef4444'; // critical
  else if (score >= 50) meterColor = '#f97316'; // high risk
  else if (score >= 25) meterColor = '#f59e0b'; // suspicious
  else if (score >= 12) meterColor = '#3b82f6'; // low risk

  el.scoreMeterFill.style.width = `${score}%`;
  el.scoreMeterFill.style.backgroundColor = meterColor;

  // Scan Status Alert handling
  if (scan.status === 'failed' || scan.status === 'inconclusive' || scan.status === 'partial') {
    el.scanStatusAlert.classList.remove('hidden');
    el.scanStatusAlert.className = `scan-status-alert ${scan.status === 'failed' ? 'failed' : 'incomplete'}`;
    el.scanStatusTitle.textContent = scan.status === 'failed' ? 'Scan Incomplete / Connection Failed' : 'Scan Inconclusive / Partial';

    const failFinding = scan.findings?.find((f) =>
      f.title.toLowerCase().includes('failed') ||
      f.title.toLowerCase().includes('error') ||
      f.title.toLowerCase().includes('timed out') ||
      f.title.toLowerCase().includes('ssrf') ||
      f.title.toLowerCase().includes('unreachable')
    );
    el.scanStatusDesc.textContent =
      failFinding?.description ||
      'Target connection could not be fully completed. Some checks were skipped due to network/host errors.';
  } else {
    el.scanStatusAlert.classList.add('hidden');
  }

  // Target summary
  el.resultTargetType.textContent = `${scan.targetType} Security Scanner`;
  if (scan.target && scan.target.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(scan.target);
      el.resultTargetVal.textContent = `Manifest: ${parsed.name || 'Extension'} (v${parsed.version || '1.0'})`;
    } catch {
      el.resultTargetVal.textContent = scan.target;
    }
  } else {
    el.resultTargetVal.textContent = scan.target || '';
  }

  // Verified Technical Evidence Grid
  el.evidenceGrid.innerHTML = '';
  const evidenceItems: Array<{ label: string; value: string }> = [];
  const checks = scan.checks || {};
  const http = checks.httpAnalysis;
  const domain = checks.domainAnalysis;
  const ssl = checks.sslAnalysis;
  const redirect = checks.redirectAnalysis;
  const apiAnalysis = checks.apiAnalysis;
  const fileAnalysis = checks.fileAnalysis;
  const extensionAnalysis = checks.extensionAnalysis;

  if (scan.targetType === 'File' || fileAnalysis) {
    if (fileAnalysis?.sha256) {
      evidenceItems.push({ label: 'SHA-256 Hash', value: fileAnalysis.sha256.substring(0, 16) + '...' });
    }
    if (fileAnalysis?.detectedMimeType || fileAnalysis?.extension) {
      evidenceItems.push({ label: 'Detected Format', value: `${fileAnalysis.detectedMimeType || 'Binary'} (.${fileAnalysis.extension || 'bin'})` });
    }
    if (fileAnalysis?.magicBytesHex) {
      evidenceItems.push({ label: 'Magic Bytes', value: fileAnalysis.magicBytesHex });
    }
    if (fileAnalysis?.fileSizeBytes !== undefined) {
      evidenceItems.push({ label: 'Payload Size', value: formatBytes(fileAnalysis.fileSizeBytes) });
    }
  } else if (scan.targetType === 'Extension' || extensionAnalysis) {
    evidenceItems.push({ label: 'Manifest Version', value: `Manifest V${extensionAnalysis?.manifestVersion || 3}` });
    if (extensionAnalysis?.extensionId) {
      evidenceItems.push({ label: 'Extension ID', value: extensionAnalysis.extensionId });
    }
    evidenceItems.push({ label: 'Dangerous Perms', value: `${extensionAnalysis?.dangerousPermissions?.length || 0} flagged` });
    evidenceItems.push({ label: 'Host Access', value: `${extensionAnalysis?.hostPermissions?.length || 0} pattern(s)` });
  } else if (scan.targetType === 'API' || apiAnalysis) {
    if (http?.statusCode) {
      evidenceItems.push({ label: 'HTTP Status', value: `HTTP ${http.statusCode} (${http.responseTimeMs || 0}ms)` });
    } else {
      evidenceItems.push({ label: 'HTTP Status', value: 'Unreachable / Timed Out' });
    }
    evidenceItems.push({ label: 'Auth Scheme', value: apiAnalysis?.authIndicators?.scheme || (http?.statusCode === 401 ? 'HTTP 401' : 'None Enforced') });
    evidenceItems.push({ label: 'CORS Origin', value: apiAnalysis?.corsConfig?.isPermissive ? 'Wildcard (*)' : (apiAnalysis?.corsConfig?.allowOrigin || 'Restricted') });
    evidenceItems.push({ label: 'Rate Limiting', value: apiAnalysis?.rateLimitIndicators?.limit ? `Limit: ${apiAnalysis.rateLimitIndicators.limit}` : 'None Observed' });
  } else {
    // URL, Website, Phishing
    if (domain?.resolvedIps && domain.resolvedIps.length > 0) {
      evidenceItems.push({ label: 'Resolved IP', value: domain.resolvedIps[0] });
    } else if (domain?.dnsStatus) {
      evidenceItems.push({ label: 'DNS Status', value: domain.dnsStatus });
    }
    if (http?.statusCode) {
      evidenceItems.push({ label: 'HTTP Status', value: `HTTP ${http.statusCode} (${http.responseTimeMs || 0}ms)` });
    } else {
      evidenceItems.push({ label: 'HTTP Status', value: 'Unreachable' });
    }
    if (ssl?.protocol) {
      evidenceItems.push({ label: 'TLS Protocol', value: `${ssl.protocol} (${ssl.valid !== false ? 'Valid' : 'Untrusted'})` });
    } else {
      evidenceItems.push({ label: 'TLS Transport', value: ssl?.valid === false ? 'Untrusted' : 'None / HTTP' });
    }
    evidenceItems.push({ label: 'Redirect Chain', value: `${redirect?.redirectCount || 0} hop(s)` });
  }

  // Scan ID reference
  const realScanId = scan.id || scan._id;
  if (realScanId) {
    evidenceItems.push({ label: 'Backend Scan ID', value: String(realScanId).substring(0, 16) + '...' });
  }

  evidenceItems.forEach((item) => {
    const box = document.createElement('div');
    box.className = 'evidence-item';

    const lbl = document.createElement('span');
    lbl.className = 'evidence-label';
    lbl.textContent = item.label;

    const val = document.createElement('span');
    val.className = 'evidence-val';
    val.textContent = item.value;
    val.title = item.value;

    box.appendChild(lbl);
    box.appendChild(val);
    el.evidenceGrid.appendChild(box);
  });

  // Findings list
  const findings: IScanFinding[] = scan.findings || [];
  el.findingsCount.textContent = String(findings.length);
  el.findingsList.innerHTML = '';

  if (findings.length === 0) {
    const emptyEl = document.createElement('div');
    emptyEl.className = 'finding-item';
    emptyEl.textContent = 'No high-risk vulnerabilities or anomalous indicators detected.';
    el.findingsList.appendChild(emptyEl);
  } else {
    findings.slice(0, 10).forEach((f) => {
      const item = document.createElement('div');
      item.className = 'finding-item';

      const top = document.createElement('div');
      top.className = 'finding-top';

      const title = document.createElement('span');
      title.className = 'finding-title';
      title.textContent = f.title;

      const severity = document.createElement('span');
      severity.className = `severity-pill ${f.severity || 'INFO'}`;
      severity.textContent = f.severity || 'INFO';

      top.appendChild(title);
      top.appendChild(severity);

      item.appendChild(top);

      if (f.description) {
        const desc = document.createElement('span');
        desc.className = 'finding-desc';
        desc.textContent = f.description;
        item.appendChild(desc);
      }

      if (f.evidence) {
        const ev = document.createElement('div');
        ev.className = 'finding-evidence';
        ev.textContent = `Evidence: ${f.evidence}`;
        item.appendChild(ev);
      }

      el.findingsList.appendChild(item);
    });
  }

  // Recommendations
  const recommendations = scan.recommendations || [];
  el.recommendationsList.innerHTML = '';

  if (recommendations.length === 0) {
    const recEl = document.createElement('li');
    recEl.className = 'recommendation-item';
    recEl.textContent = 'Target demonstrates standard defensive security posture.';
    el.recommendationsList.appendChild(recEl);
  } else {
    recommendations.slice(0, 4).forEach((rec) => {
      const recEl = document.createElement('li');
      recEl.className = 'recommendation-item';
      recEl.textContent = rec;
      el.recommendationsList.appendChild(recEl);
    });
  }
}

// ── Open Full Report in CyberWatch ─────────────────────────────────────────────
async function openFullReport() {
  if (!lastScanResult) {
    alert('Please execute a scan first to view its full report.');
    return;
  }
  const scanId = lastScanResult.id || lastScanResult._id;
  if (!scanId) {
    alert('Unable to open full report: no scan ID was recorded for this assessment.');
    return;
  }

  const { webBaseUrl } = await storageService.getConfig();
  const targetUrl = `${webBaseUrl}/reports/scans/${scanId}`;

  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
    chrome.tabs.create({ url: targetUrl });
  } else {
    window.open(targetUrl, '_blank');
  }
}

// ── Launch ────────────────────────────────────────────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
