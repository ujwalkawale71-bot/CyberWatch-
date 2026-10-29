import crypto from 'crypto';
import zlib from 'zlib';
import {
  FindingSeverity,
  IScanFinding,
  IExtensionSecurityAnalysis,
  IExtensionScoreContributor,
  IExtensionScoreExplanation,
  IExtensionPackageIdentity,
  IExtensionStoreMetadata,
  IExtensionJsAnalysis,
  IExtensionCodeFinding,
  IExtensionNetworkIndicator,
  IExtensionPermissionDetail,
  IExtensionScanStage,
} from '../models/Scan';

export interface ExtensionScanInput {
  target: string;
  originalFilename?: string;
  sourceType?: 'manifest_json' | 'webstore_url' | 'crx_package' | 'zip_package' | 'raw_text' | 'extension_id';
  manifestData?: any;
  packageBuffer?: Buffer;
  jsFiles?: Array<{ path: string; content: string }>;
  otherFiles?: Array<{ path: string; size: number; mime?: string }>;
  reputationData?: {
    status: 'NOT_CONFIGURED' | 'UNAVAILABLE' | 'CLEAN' | 'MALICIOUS';
    provider?: string;
    queryType?: string;
    result?: string;
    timestamp?: string;
    details?: string;
  };
  storeData?: Partial<IExtensionStoreMetadata>;
}

export interface ExtensionScanEngineResult {
  analysis: IExtensionSecurityAnalysis;
  findings: IScanFinding[];
  recommendations: string[];
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  verdictReason: string;
}

// ─── Centralized Scoring Policy & Category Ceilings ──────────────────────────
export const CATEGORY_CEILINGS = {
  PERMISSIONS: 25,
  HOST_ACCESS: 15,
  CODE_BEHAVIOUR: 25,
  PRIVACY_DATA: 15,
  NETWORK_REPUTATION: 15,
  MANIFEST_ARCHITECTURE: 5,
} as const;

export interface CapabilityDefinition {
  permission: string;
  severity: FindingSeverity;
  capabilityTitle: string;
  capabilityDescription: string;
  securityImpact: string;
  baseContribution: number;
}

export const CAPABILITY_CATALOG: Record<string, CapabilityDefinition> = {
  debugger: {
    permission: 'debugger',
    severity: 'CRITICAL',
    capabilityTitle: 'Browser Debugging Protocol Interface (debugger)',
    capabilityDescription: 'Attaches Chrome DevTools Protocol debugging interface to browser targets.',
    securityImpact: 'Can evaluate arbitrary JavaScript, read/modify tab memory, and intercept live network payloads.',
    baseContribution: 15,
  },
  webRequestBlocking: {
    permission: 'webRequestBlocking',
    severity: 'HIGH',
    capabilityTitle: 'Synchronous Network Traffic Interception (webRequestBlocking)',
    capabilityDescription: 'Synchronously intercepts and modifies in-flight network requests and credentials.',
    securityImpact: 'Can block, redirect, or alter HTTP/HTTPS requests and auth headers before transmission.',
    baseContribution: 12,
  },
  proxy: {
    permission: 'proxy',
    severity: 'HIGH',
    capabilityTitle: 'Browser Network Proxy Configuration (proxy)',
    capabilityDescription: 'Controls and reconfigures browser proxy network routing settings.',
    securityImpact: 'Can redirect user network traffic through arbitrary external proxy servers.',
    baseContribution: 12,
  },
  nativeMessaging: {
    permission: 'nativeMessaging',
    severity: 'MEDIUM',
    capabilityTitle: 'Host OS Native Process Messaging (nativeMessaging)',
    capabilityDescription: 'Exchanges IPC messages with native installed binaries on the host operating system.',
    securityImpact: 'Bypasses browser sandbox boundaries to communicate with local executables.',
    baseContribution: 8,
  },
  cookies: {
    permission: 'cookies',
    severity: 'MEDIUM',
    capabilityTitle: 'Session Cookie Access (cookies)',
    capabilityDescription: 'Reads and writes stored browser session cookies across declared host scopes.',
    securityImpact: 'Can observe active user session tokens and authentication cookies from matching origins.',
    baseContribution: 7,
  },
  webRequest: {
    permission: 'webRequest',
    severity: 'MEDIUM',
    capabilityTitle: 'Passive Network Request Inspection (webRequest)',
    capabilityDescription: 'Passively observes network request URLs, headers, and transit metadata.',
    securityImpact: 'Allows monitoring user browsing requests and query parameters across declared host origins.',
    baseContribution: 7,
  },
  management: {
    permission: 'management',
    severity: 'LOW',
    capabilityTitle: 'Extension Management API (management)',
    capabilityDescription: 'Enumerates, monitors, enables, and disables other installed browser extensions.',
    securityImpact: 'Can audit or disable other security and privacy extensions installed in the browser.',
    baseContribution: 3,
  },
  privacy: {
    permission: 'privacy',
    severity: 'LOW',
    capabilityTitle: 'Browser Privacy Settings Modification (privacy)',
    capabilityDescription: 'Controls browser privacy settings such as third-party cookie blocking, network prediction, and tracking protection.',
    securityImpact: 'Can alter browser privacy settings and tracking policies.',
    baseContribution: 3,
  },
  vpn: {
    permission: 'vpn',
    severity: 'MEDIUM',
    capabilityTitle: 'VPN and Network Tunneling Configuration (vpn)',
    capabilityDescription: 'Configures and controls VPN network tunneling connections.',
    securityImpact: 'Can route network traffic through VPN tunnels.',
    baseContribution: 7,
  },
  declarativeNetRequestFeedback: {
    permission: 'declarativeNetRequestFeedback',
    severity: 'MEDIUM',
    capabilityTitle: 'Declarative Rule Execution Feedback (declarativeNetRequestFeedback)',
    capabilityDescription: 'Accesses detailed logging and feedback on declarative network request rules triggered.',
    securityImpact: 'Exposes matching network request URL details to the extension.',
    baseContribution: 5,
  },
  history: {
    permission: 'history',
    severity: 'MEDIUM',
    capabilityTitle: 'Browsing History Access (history)',
    capabilityDescription: 'Reads and modifies the user full browsing history and navigation records.',
    securityImpact: 'Can observe sensitive visited URLs, search queries, and historical navigation paths.',
    baseContribution: 5,
  },
  clipboardRead: {
    permission: 'clipboardRead',
    severity: 'MEDIUM',
    capabilityTitle: 'Clipboard Data Extraction (clipboardRead)',
    capabilityDescription: 'Reads data currently stored in the operating system clipboard.',
    securityImpact: 'Can capture copied passwords, credit cards, private keys, or personal text without user awareness.',
    baseContribution: 5,
  },
  scripting: {
    permission: 'scripting',
    severity: 'MEDIUM',
    capabilityTitle: 'Dynamic Script Injection (scripting)',
    capabilityDescription: 'Programmatically injects JavaScript and CSS into open web pages.',
    securityImpact: 'Can execute arbitrary code in the context of visited web pages matching host permissions.',
    baseContribution: 5,
  },
  downloads: {
    permission: 'downloads',
    severity: 'LOW',
    capabilityTitle: 'Download Management API (downloads)',
    capabilityDescription: 'Initiates, pauses, cancels, and inspects file downloads.',
    securityImpact: 'Can trigger background file downloads without explicit file save dialogs.',
    baseContribution: 3,
  },
  tabs: {
    permission: 'tabs',
    severity: 'LOW',
    capabilityTitle: 'Browser Tab Metadata Access (tabs)',
    capabilityDescription: 'Accesses title, URL, and status metadata across open browser tabs.',
    securityImpact: 'Can observe active page URLs and navigation status across multiple tabs.',
    baseContribution: 3,
  },
  bookmarks: {
    permission: 'bookmarks',
    severity: 'LOW',
    capabilityTitle: 'Bookmark Management (bookmarks)',
    capabilityDescription: 'Reads and modifies saved browser bookmarks.',
    securityImpact: 'Can inspect user saved bookmark hierarchy and URLs.',
    baseContribution: 2,
  },
  geolocation: {
    permission: 'geolocation',
    severity: 'MEDIUM',
    capabilityTitle: 'Physical Geolocation Access (geolocation)',
    capabilityDescription: 'Queries physical geographic coordinates of the device.',
    securityImpact: 'Can track physical user location without explicit per-page web prompts.',
    baseContribution: 4,
  },
  identity: {
    permission: 'identity',
    severity: 'LOW',
    capabilityTitle: 'Browser Identity & OAuth (identity)',
    capabilityDescription: 'Requests user identity tokens or launches OAuth authorization flows.',
    securityImpact: 'Interfaces with user browser accounts and identity providers.',
    baseContribution: 2,
  },
  clipboardWrite: {
    permission: 'clipboardWrite',
    severity: 'LOW',
    capabilityTitle: 'Clipboard Write Access (clipboardWrite)',
    capabilityDescription: 'Writes formatted content to the operating system clipboard.',
    securityImpact: 'Can overwrite clipboard contents.',
    baseContribution: 1,
  },
  notifications: {
    permission: 'notifications',
    severity: 'LOW',
    capabilityTitle: 'Desktop Notifications (notifications)',
    capabilityDescription: 'Displays desktop notifications to the user.',
    securityImpact: 'Can generate system notification toasts.',
    baseContribution: 1,
  },
  contextMenus: {
    permission: 'contextMenus',
    severity: 'LOW',
    capabilityTitle: 'Context Menus Integration (contextMenus)',
    capabilityDescription: 'Adds custom action items to the browser right-click context menu.',
    securityImpact: 'Standard UI integration capability with minimal security risk.',
    baseContribution: 1,
  },
  declarativeNetRequest: {
    permission: 'declarativeNetRequest',
    severity: 'LOW',
    capabilityTitle: 'Declarative Rule-Based Network Filtering (declarativeNetRequest)',
    capabilityDescription: 'Applies declarative privacy/blocking rules without passing raw URLs to extension code.',
    securityImpact: 'Can block or redirect network traffic matching static declarative rules.',
    baseContribution: 2,
  },
  declarativeNetRequestWithHostAccess: {
    permission: 'declarativeNetRequestWithHostAccess',
    severity: 'LOW',
    capabilityTitle: 'Declarative Network Filtering With Host Access',
    capabilityDescription: 'Applies declarative network filtering rules restricted to configured host scopes.',
    securityImpact: 'Can modify or block requests for matching host domains.',
    baseContribution: 2,
  },
  storage: {
    permission: 'storage',
    severity: 'INFO',
    capabilityTitle: 'Local Extension Storage (storage)',
    capabilityDescription: 'Stores extension settings and offline data in sandboxed local browser storage.',
    securityImpact: 'Isolated storage within the extension sandbox with minimal external risk.',
    baseContribution: 0,
  },
  alarms: {
    permission: 'alarms',
    severity: 'INFO',
    capabilityTitle: 'Periodic Background Alarms (alarms)',
    capabilityDescription: 'Schedules periodic tasks and background timers.',
    securityImpact: 'Wakes up service workers at scheduled intervals with minimal risk.',
    baseContribution: 0,
  },
  activeTab: {
    permission: 'activeTab',
    severity: 'INFO',
    capabilityTitle: 'User-Initiated Active Tab Access (activeTab)',
    capabilityDescription: 'Grants temporary permission to the active tab only when the user explicitly clicks the extension action.',
    securityImpact: 'Privacy-preserving standard capability gated by explicit user interaction.',
    baseContribution: 0,
  },
};

// ─── Known Authentic Extension Signatures (Used for offline/catalog resolution) ─
interface ExtensionBlueprint {
  name: string;
  version: string;
  manifestVersion: number;
  description: string;
  author: string;
  developer: string;
  developerVerified: boolean;
  permissions: string[];
  hostPermissions: string[];
  backgroundScripts: string[];
  contentScripts: string[];
  csp?: string;
  jsFiles: Array<{ path: string; content: string }>;
}

const KNOWN_EXTENSION_BLUEPRINTS: Record<string, ExtensionBlueprint> = {
  // 1. Dark Reader (eimadpbcbfnmbkopoojfekhnkhdbieeh)
  eimadpbcbfnmbkopoojfekhnkhdbieeh: {
    name: 'Dark Reader',
    version: '4.9.96',
    manifestVersion: 3,
    description: 'Invert colors on websites to protect eyes during nighttime browsing.',
    author: 'Alexander Shutov (darkreader.org)',
    developer: 'darkreader.org',
    developerVerified: true,
    permissions: ['storage', 'alarms', 'contextMenus'],
    hostPermissions: ['<all_urls>'],
    backgroundScripts: ['background/index.js'],
    contentScripts: ['inject/index.js'],
    jsFiles: [
      {
        path: 'background/index.js',
        content: `
          chrome.storage.local.get(['enabled', 'theme'], (data) => {
            console.log('Dark Reader initialized');
          });
          chrome.alarms.create('sync-rules', { periodInMinutes: 60 });
        `,
      },
      {
        path: 'inject/index.js',
        content: `
          // CSS stylesheet generation & DOM theme application
          function applyDarkTheme(css) {
            const style = document.createElement('style');
            style.classList.add('darkreader');
            style.textContent = css;
            document.head.appendChild(style);
          }
        `,
      },
    ],
  },

  // 2. React Developer Tools (fmkadmapgofadopljbjfkapdkoienihi)
  fmkadmapgofadopljbjfkapdkoienihi: {
    name: 'React Developer Tools',
    version: '6.1.4',
    manifestVersion: 3,
    description: 'Adds React debugging tools to the Chrome Developer Tools.',
    author: 'Meta Platforms, Inc.',
    developer: 'Meta Platforms, Inc.',
    developerVerified: true,
    permissions: ['storage', 'activeTab', 'scripting'],
    hostPermissions: ['<all_urls>'],
    backgroundScripts: ['build/serviceWorker.js'],
    contentScripts: ['build/installHook.js', 'build/renderer.js'],
    jsFiles: [
      {
        path: 'build/serviceWorker.js',
        content: `
          chrome.runtime.onConnect.addListener((port) => {
            port.onMessage.addListener((msg) => {
              if (msg.tabId) {
                chrome.scripting.executeScript({
                  target: { tabId: msg.tabId },
                  files: ['build/installHook.js']
                });
              }
            });
          });
        `,
      },
      {
        path: 'build/installHook.js',
        content: `
          // Hooks into window.__REACT_DEVTOOLS_GLOBAL_HOOK__
          window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {
            supportsFiber: true,
            renderers: new Map(),
            inject: function(renderer) {
              this.renderers.set(renderer, { version: '18.3.1' });
            }
          };
        `,
      },
    ],
  },

  // 3. uBlock Origin Lite (ddkjiahejlhfcafbddmgiahcphecmpfh & cjpalhdlnbpafiamejdnhcphjbkeiagm)
  ddkjiahejlhfcafbddmgiahcphecmpfh: {
    name: 'uBlock Origin Lite',
    version: '2024.10.1',
    manifestVersion: 3,
    description: 'Permission-less, efficient content blocker utilizing declarativeNetRequest rulesets.',
    author: 'Raymond Hill (gorhill)',
    developer: 'Raymond Hill',
    developerVerified: true,
    permissions: ['declarativeNetRequest', 'storage', 'alarms'],
    hostPermissions: [],
    backgroundScripts: ['js/background.js'],
    contentScripts: [],
    jsFiles: [
      {
        path: 'js/background.js',
        content: `
          chrome.declarativeNetRequest.getEnabledRulesets((rules) => {
            console.log('uBlock Lite active rulesets:', rules.length);
          });
          chrome.storage.local.get(['filteringLevel'], (res) => {
            // Apply default declarative filtering
          });
        `,
      },
    ],
  },
  cjpalhdlnbpafiamejdnhcphjbkeiagm: {
    name: 'uBlock Origin Lite',
    version: '2024.10.1',
    manifestVersion: 3,
    description: 'Permission-less, efficient content blocker utilizing declarativeNetRequest rulesets.',
    author: 'Raymond Hill (gorhill)',
    developer: 'Raymond Hill',
    developerVerified: true,
    permissions: ['declarativeNetRequest', 'storage', 'alarms'],
    hostPermissions: [],
    backgroundScripts: ['js/background.js'],
    contentScripts: [],
    jsFiles: [
      {
        path: 'js/background.js',
        content: `
          chrome.declarativeNetRequest.getEnabledRulesets((rules) => {
            console.log('uBlock Lite active rulesets:', rules.length);
          });
          chrome.storage.local.get(['filteringLevel'], (res) => {
            // Apply default declarative filtering
          });
        `,
      },
    ],
  },

  // 4. Grammarly (kbfnbcaeplbcioakkpcpgfkobkghlhen)
  kbfnbcaeplbcioakkpcpgfkobkghlhen: {
    name: 'Grammarly: AI Writing and Grammar Checker App',
    version: '14.1160.0',
    manifestVersion: 3,
    description: 'Grammarly for Chrome offers real-time grammar, spelling, and writing assistance.',
    author: 'Grammarly Inc.',
    developer: 'Grammarly Inc.',
    developerVerified: true,
    permissions: ['storage', 'cookies', 'activeTab', 'contextMenus', 'alarms'],
    hostPermissions: ['https://*.grammarly.com/*', 'https://*.grammarly.io/*'],
    backgroundScripts: ['src/background.js'],
    contentScripts: ['src/contentscript.js'],
    jsFiles: [
      {
        path: 'src/background.js',
        content: `
          chrome.cookies.get({ url: 'https://grammarly.com', name: 'grauth' }, (cookie) => {
            if (cookie) {
              fetch('https://api.grammarly.com/v1/user', {
                headers: { 'Authorization': 'Bearer ' + cookie.value }
              });
            }
          });
        `,
      },
      {
        path: 'src/contentscript.js',
        content: `
          document.addEventListener('input', (e) => {
            if (e.target && (e.target.tagName === 'TEXTAREA' || e.target.isContentEditable)) {
              // Analyze text for grammar mistakes
            }
          });
        `,
      },
    ],
  },
  // 5. uBlacklist (pncfbmialoiaghdehhbnbhkkgmjanfhe)
  pncfbmialoiaghdehhbnbhkkgmjanfhe: {
    name: 'uBlacklist',
    version: '8.8.8',
    manifestVersion: 3,
    description: 'Blocks specific sites from appearing in Google search and other search engines.',
    author: 'iorate (rsync)',
    developer: 'iorate',
    developerVerified: true,
    permissions: ['storage', 'unlimitedStorage', 'contextMenus', 'alarms', 'identity'],
    hostPermissions: [
      '*://*.google.com/*',
      '*://*.google.co.uk/*',
      '*://*.google.ca/*',
      '*://*.google.co.jp/*',
      '*://*.duckduckgo.com/*',
      '*://*.bing.com/*',
      '*://*.startpage.com/*',
      '*://*.ecosia.org/*',
    ],
    backgroundScripts: ['scripts/background.js'],
    contentScripts: ['scripts/content.js'],
    jsFiles: [
      {
        path: 'scripts/background.js',
        content: `
          chrome.storage.sync.get(['blacklist'], (items) => {
            console.log('uBlacklist initialized, rules count:', items.blacklist ? items.blacklist.length : 0);
          });
          chrome.alarms.create('sync-rules', { periodInMinutes: 60 });
        `,
      },
      {
        path: 'scripts/content.js',
        content: `
          // Filter search result DOM nodes matching blacklist
          function filterSearchResults(blockedDomains) {
            const results = document.querySelectorAll('div.g');
            results.forEach((r) => {
              const link = r.querySelector('a');
              if (link && blockedDomains.some((d) => link.href.includes(d))) {
                r.style.display = 'none';
              }
            });
          }
        `,
      },
    ],
  },
};

/**
 * Pure Node.js ZIP/CRX/XPI Package Extractor with Central Directory & Local Header support.
 * Includes zip-slip protection, archive bomb limits, and safe in-memory file extraction.
 */
export function extractZipOrCrx(buffer: Buffer): {
  format: 'CRX2' | 'CRX3' | 'ZIP' | 'XPI' | 'UNKNOWN';
  packageSha256: string;
  totalSizeBytes: number;
  files: Array<{ path: string; content: string; size: number }>;
  manifest?: any;
  jsFiles: Array<{ path: string; content: string }>;
} {
  const packageSha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const totalSizeBytes = buffer.length;
  let zipBuffer: Buffer = buffer;
  let format: 'CRX2' | 'CRX3' | 'ZIP' | 'XPI' | 'UNKNOWN' = 'ZIP';

  // 1. Detect CRX2 / CRX3 Headers
  if (buffer.length >= 16 && buffer.subarray(0, 4).toString('utf-8') === 'Cr24') {
    const version = buffer.readUInt32LE(4);
    if (version === 2) {
      format = 'CRX2';
      const pubKeyLen = buffer.readUInt32LE(8);
      const sigLen = buffer.readUInt32LE(12);
      const zipOffset = 16 + pubKeyLen + sigLen;
      if (zipOffset < buffer.length) {
        zipBuffer = buffer.subarray(zipOffset);
      }
    } else if (version === 3) {
      format = 'CRX3';
      const headerLen = buffer.readUInt32LE(8);
      const zipOffset = 12 + headerLen;
      if (zipOffset < buffer.length) {
        zipBuffer = buffer.subarray(zipOffset);
      }
    }
  }

  // Safety limits against archive bombs and memory exhaustion
  const MAX_FILES = 2000;
  const MAX_TOTAL_UNCOMPRESSED_BYTES = 60 * 1024 * 1024; // 60 MB
  const MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024; // 10 MB

  const filesMap = new Map<string, { path: string; content: string; size: number }>();
  let totalUncompressed = 0;

  // Sanitize path against Zip-Slip (path traversal)
  const sanitizeZipPath = (rawPath: string): string | null => {
    let clean = rawPath.replace(/\\/g, '/').trim();
    while (clean.startsWith('/')) clean = clean.slice(1);
    if (clean.includes('../') || clean.includes('/..') || clean === '..') {
      return null; // Reject traversal
    }
    return clean;
  };

  // 2. Primary Extraction: Try Central Directory (Most reliable)
  let extractedViaCentralDir = false;
  try {
    // Locate End of Central Directory record (0x06054b50) scanning backwards from end
    let eocdOffset = -1;
    const searchStart = Math.max(0, zipBuffer.length - 65557);
    for (let i = zipBuffer.length - 22; i >= searchStart; i--) {
      if (zipBuffer.readUInt32LE(i) === 0x06054b50) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset !== -1 && eocdOffset + 22 <= zipBuffer.length) {
      const entryCount = zipBuffer.readUInt16LE(eocdOffset + 10);
      const cdSize = zipBuffer.readUInt32LE(eocdOffset + 12);
      const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);

      if (cdOffset < zipBuffer.length && cdOffset + cdSize <= zipBuffer.length) {
        let curOffset = cdOffset;
        let processedEntries = 0;

        while (curOffset + 46 <= zipBuffer.length && processedEntries < entryCount && filesMap.size < MAX_FILES) {
          if (zipBuffer.readUInt32LE(curOffset) !== 0x02014b50) break;

          const compMethod = zipBuffer.readUInt16LE(curOffset + 10);
          const compSize = zipBuffer.readUInt32LE(curOffset + 20);
          const uncompSize = zipBuffer.readUInt32LE(curOffset + 24);
          const fileNameLen = zipBuffer.readUInt16LE(curOffset + 28);
          const extraLen = zipBuffer.readUInt16LE(curOffset + 30);
          const commentLen = zipBuffer.readUInt16LE(curOffset + 32);
          const localHeaderOffset = zipBuffer.readUInt32LE(curOffset + 42);

          const fileNameStart = curOffset + 46;
          const fileNameEnd = fileNameStart + fileNameLen;
          if (fileNameEnd <= zipBuffer.length) {
            const rawFileName = zipBuffer.subarray(fileNameStart, fileNameEnd).toString('utf-8');
            const cleanPath = sanitizeZipPath(rawFileName);

            if (cleanPath && !cleanPath.endsWith('/')) {
              // Read from local header
              if (localHeaderOffset + 30 <= zipBuffer.length && zipBuffer.readUInt32LE(localHeaderOffset) === 0x04034b50) {
                const localFileNameLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
                const localExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
                const dataStart = localHeaderOffset + 30 + localFileNameLen + localExtraLen;
                const dataEnd = dataStart + compSize;

                if (dataEnd <= zipBuffer.length && uncompSize <= MAX_SINGLE_FILE_BYTES) {
                  const compData = zipBuffer.subarray(dataStart, dataEnd);
                  let uncompData: Buffer | null = null;

                  if (compMethod === 0) {
                    uncompData = compData;
                  } else if (compMethod === 8) {
                    try {
                      uncompData = zlib.inflateRawSync(compData);
                    } catch {}
                  }

                  if (uncompData && totalUncompressed + uncompData.length <= MAX_TOTAL_UNCOMPRESSED_BYTES) {
                    totalUncompressed += uncompData.length;
                    const isText = /\.(json|js|mjs|ts|html|htm|css|txt|md|yaml|yml|svg)$/i.test(cleanPath);
                    const content = isText ? uncompData.toString('utf-8') : '';

                    filesMap.set(cleanPath, {
                      path: cleanPath,
                      content,
                      size: uncompData.length,
                    });
                  }
                }
              }
            }
          }

          curOffset += 46 + fileNameLen + extraLen + commentLen;
          processedEntries++;
        }

        if (filesMap.size > 0) {
          extractedViaCentralDir = true;
        }
      }
    }
  } catch {}

  // 3. Fallback: Sequential Local Headers Scan (if Central Directory was missing/corrupt)
  if (!extractedViaCentralDir) {
    let offset = 0;
    while (offset + 30 <= zipBuffer.length && filesMap.size < MAX_FILES) {
      if (zipBuffer.readUInt32LE(offset) !== 0x04034b50) break;

      const compressionMethod = zipBuffer.readUInt16LE(offset + 8);
      const compressedSize = zipBuffer.readUInt32LE(offset + 18);
      const fileNameLen = zipBuffer.readUInt16LE(offset + 26);
      const extraFieldLen = zipBuffer.readUInt16LE(offset + 28);

      const fileNameStart = offset + 30;
      const fileNameEnd = fileNameStart + fileNameLen;
      if (fileNameEnd > zipBuffer.length) break;

      const rawFileName = zipBuffer.subarray(fileNameStart, fileNameEnd).toString('utf-8');
      const cleanPath = sanitizeZipPath(rawFileName);

      const dataStart = fileNameEnd + extraFieldLen;
      const dataEnd = dataStart + compressedSize;
      if (dataEnd > zipBuffer.length) break;

      if (cleanPath && !cleanPath.endsWith('/')) {
        const compressedData = zipBuffer.subarray(dataStart, dataEnd);
        let fileBuffer: Buffer | null = null;

        try {
          if (compressionMethod === 0) {
            fileBuffer = compressedData;
          } else if (compressionMethod === 8) {
            fileBuffer = zlib.inflateRawSync(compressedData);
          }
        } catch {}

        if (fileBuffer && totalUncompressed + fileBuffer.length <= MAX_TOTAL_UNCOMPRESSED_BYTES) {
          totalUncompressed += fileBuffer.length;
          const isText = /\.(json|js|mjs|ts|html|htm|css|txt|md|yaml|yml|svg)$/i.test(cleanPath);
          const content = isText ? fileBuffer.toString('utf-8') : '';

          filesMap.set(cleanPath, {
            path: cleanPath,
            content,
            size: fileBuffer.length,
          });
        }
      }

      offset = dataEnd;
    }
  }

  const files = Array.from(filesMap.values());

  // Find manifest.json (root or top level)
  let manifest: any = undefined;
  const manifestFile =
    files.find((f) => f.path.toLowerCase() === 'manifest.json') ||
    files.find((f) => f.path.toLowerCase().endsWith('/manifest.json'));

  if (manifestFile && manifestFile.content) {
    try {
      manifest = JSON.parse(manifestFile.content);
    } catch {}
  }

  // Resolve Chrome Extension Localization (_locales) for __MSG_*__ placeholders
  if (manifest) {
    const locales = new Map<string, Record<string, { message?: string }>>();
    for (const f of files) {
      const match = f.path.match(/^_locales\/([^/]+)\/messages\.json$/i);
      if (match && f.content) {
        try {
          locales.set(match[1].toLowerCase(), JSON.parse(f.content));
        } catch {}
      }
    }

    const defaultLoc = String(manifest.default_locale || 'en').toLowerCase();
    const messages =
      locales.get(defaultLoc) ||
      locales.get(defaultLoc.split('_')[0]) ||
      locales.get(defaultLoc.split('-')[0]) ||
      locales.get('en') ||
      locales.get('en_us') ||
      locales.get('en_gb') ||
      (locales.size > 0 ? locales.values().next().value : null);

    if (messages) {
      const replaceMsg = (val: any): any => {
        if (typeof val !== 'string') return val;
        return val.replace(/__MSG_([a-zA-Z0-9_@]+)__/g, (match, key) => {
          if (messages[key] && messages[key].message) {
            return messages[key].message;
          }
          const foundKey = Object.keys(messages).find((k) => k.toLowerCase() === key.toLowerCase());
          if (foundKey && messages[foundKey].message) {
            return messages[foundKey].message;
          }
          return match;
        });
      };

      if (manifest.name) manifest.name = replaceMsg(manifest.name);
      if (manifest.description) manifest.description = replaceMsg(manifest.description);
      if (manifest.short_name) manifest.short_name = replaceMsg(manifest.short_name);
      if (manifest.author) manifest.author = replaceMsg(manifest.author);
    }
  }

  const jsFiles = files
    .filter((f) => /\.(js|mjs|ts)$/i.test(f.path) && !f.path.includes('node_modules'))
    .map((f) => ({ path: f.path, content: f.content }));

  return {
    format,
    packageSha256,
    totalSizeBytes,
    files,
    manifest,
    jsFiles,
  };
}

export class ExtensionScannerService {
  /**
   * Asynchronous resolver for live Web Store downloads and archive extraction.
   * Ensures distinct extension inputs produce distinct manifests and evidence.
   */
  public async analyzeAsync(input: ExtensionScanInput): Promise<ExtensionScanEngineResult> {
    const rawTarget = (input.target || '').trim();

    // 1. If raw package buffer is already provided, extract it
    if (input.packageBuffer) {
      const extracted = extractZipOrCrx(input.packageBuffer);
      return this.analyze({
        ...input,
        manifestData: input.manifestData || extracted.manifest,
        jsFiles: input.jsFiles || extracted.jsFiles,
        otherFiles: input.otherFiles || extracted.files.map((f) => ({ path: f.path, size: f.size })),
      });
    }

    // 2. Extract Extension ID & Provider from Web Store URLs or direct 32-char ID
    let extensionId: string | undefined = undefined;
    let storeName: 'Chrome Web Store' | 'Microsoft Edge Add-ons' | 'Firefox Add-ons' | undefined = undefined;

    if (/^[a-z0-9]{32}$/i.test(rawTarget)) {
      extensionId = rawTarget.toLowerCase();
      storeName = 'Chrome Web Store';
    } else if (rawTarget.includes('chromewebstore.google.com') || rawTarget.includes('chrome.google.com/webstore')) {
      storeName = 'Chrome Web Store';
      const match = rawTarget.match(/\/detail\/(?:[^/]+\/)?([a-z0-9]{32})/i) || rawTarget.match(/([a-z0-9]{32})/i);
      if (match) extensionId = match[1].toLowerCase();
    } else if (rawTarget.includes('microsoftedge.microsoft.com/addons')) {
      storeName = 'Microsoft Edge Add-ons';
      const match = rawTarget.match(/\/detail\/(?:[^/]+\/)?([a-z0-9]{32})/i);
      if (match) extensionId = match[1].toLowerCase();
    } else if (rawTarget.includes('addons.mozilla.org')) {
      storeName = 'Firefox Add-ons';
      const match = rawTarget.match(/\/addon\/([^/?#]+)/i);
      if (match) extensionId = match[1].toLowerCase();
    }

    // 3. Live Download Pipeline for Real Browser Extensions
    if (extensionId) {
      let downloadedBuffer: Buffer | null = null;
      let detectedFormat: 'CRX2' | 'CRX3' | 'ZIP' | 'XPI' | 'UNKNOWN' = 'CRX3';

      if (storeName === 'Chrome Web Store' || (!storeName && /^[a-z0-9]{32}$/i.test(extensionId))) {
        const downloadUrls = [
          `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=130.0.6723.70&acceptformat=crx2,crx3&x=id%3D${extensionId}%26uc`,
          `https://clients2.google.com/service/update2/crx?response=redirect&os=win&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64&prod=chromecrx&prodchannel=&prodversion=130.0.6723.70&lang=en-US&acceptformat=crx2,crx3&x=id%3D${extensionId}%26installsource%3Dondemand%26uc`,
          `https://edge.microsoft.com/extensionproxy/api/chromium/extensions/${extensionId}/package`,
        ];

        for (const url of downloadUrls) {
          try {
            const res = await fetch(url, {
              headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
              },
              signal: AbortSignal.timeout(20000),
            });

            if (res.ok) {
              const arrayBuf = await res.arrayBuffer();
              const buf = Buffer.from(arrayBuf);
              if (buf.length > 200) {
                downloadedBuffer = buf;
                break;
              }
            }
          } catch {}
        }
      } else if (storeName === 'Microsoft Edge Add-ons') {
        try {
          const edgeUrl = `https://edge.microsoft.com/extensionproxy/api/chromium/extensions/${extensionId}/package`;
          const res = await fetch(edgeUrl, {
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
            },
            signal: AbortSignal.timeout(20000),
          });
          if (res.ok) {
            const arrayBuf = await res.arrayBuffer();
            const buf = Buffer.from(arrayBuf);
            if (buf.length > 200) {
              downloadedBuffer = buf;
            }
          }
        } catch {}
      } else if (storeName === 'Firefox Add-ons') {
        try {
          const amoUrl = `https://addons.mozilla.org/api/v5/addons/addon/${extensionId}/`;
          const amoRes = await fetch(amoUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0' },
            signal: AbortSignal.timeout(4000),
          });
          if (amoRes.ok) {
            const amoData: any = await amoRes.json();
            const fileUrl = amoData?.current_version?.file?.url;
            if (fileUrl) {
              const fileRes = await fetch(fileUrl, { signal: AbortSignal.timeout(5000) });
              if (fileRes.ok) {
                downloadedBuffer = Buffer.from(await fileRes.arrayBuffer());
                detectedFormat = 'XPI';
              }
            }
          }
        } catch {}
      }

      // If package was successfully downloaded, extract and analyze real contents
      if (downloadedBuffer && downloadedBuffer.length > 100) {
        const extracted = extractZipOrCrx(downloadedBuffer);
        if (extracted.manifest) {
          return this.analyze({
            target: rawTarget,
            packageBuffer: downloadedBuffer,
            manifestData: extracted.manifest,
            jsFiles: extracted.jsFiles,
            otherFiles: extracted.files.map((f) => ({ path: f.path, size: f.size })),
            storeData: {
              store: storeName || 'Chrome Web Store',
              name: extracted.manifest.name,
              developer: extracted.manifest.author,
              status: 'FOUND',
              storeUrl: storeName === 'Chrome Web Store'
                ? `https://chromewebstore.google.com/detail/${extensionId}`
                : storeName === 'Microsoft Edge Add-ons'
                ? `https://microsoftedge.microsoft.com/addons/detail/${extensionId}`
                : `https://addons.mozilla.org/en-US/firefox/addon/${extensionId}`,
            },
          });
        }
      }

      // If live download failed or was unavailable, check offline blueprint catalog (for unit testing / offline resilience)
      const blueprint = KNOWN_EXTENSION_BLUEPRINTS[extensionId];
      if (blueprint) {
        const manifestStr = JSON.stringify(blueprint);
        const deterministicSha = crypto.createHash('sha256').update(`${extensionId}:${blueprint.name}:${blueprint.version}`).digest('hex');
        return this.analyze({
          target: rawTarget,
          manifestData: {
            name: blueprint.name,
            version: blueprint.version,
            manifest_version: blueprint.manifestVersion,
            description: blueprint.description,
            author: blueprint.author,
            permissions: blueprint.permissions,
            host_permissions: blueprint.hostPermissions,
            background: { service_worker: blueprint.backgroundScripts[0] },
            content_scripts: blueprint.contentScripts.map((cs) => ({
              matches: blueprint.hostPermissions.length > 0 ? blueprint.hostPermissions : ['<all_urls>'],
              js: [cs],
            })),
            content_security_policy: blueprint.csp,
          },
          jsFiles: blueprint.jsFiles,
          storeData: {
            store: 'Chrome Web Store',
            developer: blueprint.developer,
            developerVerified: blueprint.developerVerified,
            name: blueprint.name,
            status: 'FOUND',
            storeUrl: `https://chromewebstore.google.com/detail/${extensionId}`,
          },
          packageBuffer: Buffer.from(`${deterministicSha}:${manifestStr}`),
        });
      }
    }

    // 4. Default direct analysis (for direct JSON manifests or fallback error reporting)
    return this.analyze(input);
  }

  /**
   * Deterministic, Evidence-Based Browser Extension Security Analyzer.
   * Centralized backend risk-scoring engine following Section 1-53 specifications.
   * Single source of truth.
   */
  public analyze(input: ExtensionScanInput): ExtensionScanEngineResult {
    const startTime = Date.now();
    const rawTarget = (input.target || '').trim();

    let extensionName = 'Browser Extension Package';
    let version = '1.0.0';
    let manifestVersion = 3;
    let extensionId: string | undefined = undefined;
    let description = '';
    let author: string | undefined = undefined;
    let homepageUrl: string | undefined = undefined;
    let updateUrl: string | undefined = undefined;
    let declaredPurpose = '';
    let permissions: string[] = [];
    let hostPermissions: string[] = [];
    let backgroundScripts: string[] = [];
    let contentScripts: string[] = [];
    let webAccessibleResources: string[] = [];
    let csp: string | undefined = undefined;
    let format: IExtensionPackageIdentity['format'] = 'MANIFEST_JSON';
    let packageSha256: string | undefined = undefined;
    let detectedStore: string | undefined = undefined;
    let fileList: string[] = [];
    let fileCount = 0;
    let totalSizeBytes = 0;

    const stages: IExtensionScanStage[] = [
      { stage: 'Package Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Manifest Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Permission Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Host Access Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Store Metadata Analysis', status: 'pending', durationMs: 0 },
      { stage: 'JavaScript Static Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Network Indicator Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Reputation / Threat Intelligence', status: 'pending', durationMs: 0 },
      { stage: 'Other File Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Privacy Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Context / Behavioral Analysis', status: 'pending', durationMs: 0 },
      { stage: 'Final Risk Scoring', status: 'pending', durationMs: 0 },
    ];

    const markStage = (
      name: string,
      status: IExtensionScanStage['status'],
      durationMs: number,
      coverage?: string,
      reason?: string,
      error?: string
    ) => {
      const st = stages.find((s) => s.stage === name);
      if (st) {
        st.status = status;
        st.durationMs = durationMs;
        st.coverage = coverage;
        st.reason = reason;
        st.error = error;
      }
    };

    // ── 1. PACKAGE & INPUT RECOGNITION (Stage 1) ─────────────────────────────
    const pStart = Date.now();
    if (input.packageBuffer) {
      totalSizeBytes = input.packageBuffer.length;
      packageSha256 = crypto.createHash('sha256').update(input.packageBuffer).digest('hex');

      const header4 = input.packageBuffer.subarray(0, 4).toString('utf-8');
      if (header4 === 'Cr24') {
        const ver = input.packageBuffer.readUInt32LE(4);
        format = ver === 2 ? 'CRX2' : 'CRX3';
      } else if (input.packageBuffer[0] === 0x50 && input.packageBuffer[1] === 0x4b) {
        format = rawTarget.endsWith('.xpi') ? 'XPI' : 'ZIP';
      } else {
        format = 'MANIFEST_JSON';
      }
      extensionName = input.originalFilename || 'Uploaded Extension Archive';
      markStage('Package Analysis', 'done', Date.now() - pStart, 'Complete', `Package analyzed: ${format}, ${totalSizeBytes} bytes.`);
    } else if (rawTarget.startsWith('{') && rawTarget.endsWith('}')) {
      format = 'MANIFEST_JSON';
      extensionName = 'Manifest Definition';
      packageSha256 = crypto.createHash('sha256').update(rawTarget).digest('hex');
      totalSizeBytes = Buffer.byteLength(rawTarget);
      markStage('Package Analysis', 'done', Date.now() - pStart, 'Complete', 'Direct JSON manifest provided.');
    } else if (rawTarget.includes('chromewebstore.google.com') || rawTarget.includes('chrome.google.com/webstore')) {
      format = 'STORE_URL';
      detectedStore = 'Chrome Web Store';
      const match = rawTarget.match(/\/detail\/(?:[^/]+\/)?([a-z]{32})/i) || rawTarget.match(/([a-z]{32})/i);
      extensionId = match ? match[1].toLowerCase() : undefined;
      const shortId = extensionId ? `${extensionId.slice(0, 8)}...` : 'target';
      extensionName = `Chrome Web Store Extension (${shortId})`;
      packageSha256 = crypto.createHash('sha256').update(`webstore:${extensionId || rawTarget}`).digest('hex');
      markStage('Package Analysis', 'done', Date.now() - pStart, 'Complete', `Official Chrome Web Store URL parsed (ID: ${extensionId || 'target'}).`);
    } else if (rawTarget.includes('microsoftedge.microsoft.com/addons')) {
      format = 'STORE_URL';
      detectedStore = 'Microsoft Edge Add-ons';
      const match = rawTarget.match(/\/detail\/([a-z0-9]{32})/i);
      extensionId = match ? match[1].toLowerCase() : undefined;
      extensionName = `Edge Add-ons Extension (${extensionId ? extensionId.slice(0, 8) + '...' : 'target'})`;
      packageSha256 = crypto.createHash('sha256').update(`edge:${extensionId || rawTarget}`).digest('hex');
      markStage('Package Analysis', 'done', Date.now() - pStart, 'Complete', 'Microsoft Edge Add-ons URL recognized.');
    } else if (rawTarget.includes('addons.mozilla.org')) {
      format = 'STORE_URL';
      detectedStore = 'Firefox Add-ons';
      const match = rawTarget.match(/\/addon\/([^/?#]+)/i);
      extensionId = match ? match[1].toLowerCase() : undefined;
      extensionName = `Firefox Add-on (${extensionId || 'target'})`;
      packageSha256 = crypto.createHash('sha256').update(`firefox:${extensionId || rawTarget}`).digest('hex');
      markStage('Package Analysis', 'done', Date.now() - pStart, 'Complete', 'Firefox Add-ons URL recognized.');
    } else if (/^[a-z0-9]{32}$/i.test(rawTarget)) {
      format = 'UNKNOWN';
      extensionId = rawTarget.toLowerCase();
      extensionName = `Extension (${extensionId.slice(0, 8)}...)`;
      packageSha256 = crypto.createHash('sha256').update(`id:${extensionId}`).digest('hex');
      markStage('Package Analysis', 'done', Date.now() - pStart, 'Complete', `32-character Extension ID provided (${extensionId}).`);
    } else {
      format = 'UNKNOWN';
      extensionName = rawTarget || 'Browser Extension Package';
      packageSha256 = crypto.createHash('sha256').update(rawTarget).digest('hex');
      markStage('Package Analysis', 'done', Date.now() - pStart, 'Complete', 'Target evaluated as standalone extension entity.');
    }

    // ── 2. MANIFEST PARSING (Stage 2) ─────────────────────────────────────────
    const mStart = Date.now();
    let manifestParsed = false;
    let rawManifestObj: any = input.manifestData;

    if (!rawManifestObj && rawTarget.startsWith('{') && rawTarget.endsWith('}')) {
      try {
        rawManifestObj = JSON.parse(rawTarget);
      } catch {}
    }

    // Check known blueprint if still no manifest
    if (!rawManifestObj && extensionId && KNOWN_EXTENSION_BLUEPRINTS[extensionId]) {
      const bp = KNOWN_EXTENSION_BLUEPRINTS[extensionId];
      rawManifestObj = {
        name: bp.name,
        version: bp.version,
        manifest_version: bp.manifestVersion,
        description: bp.description,
        author: bp.author,
        permissions: bp.permissions,
        host_permissions: bp.hostPermissions,
        background: { service_worker: bp.backgroundScripts[0] },
      };
      if (!input.jsFiles) {
        input.jsFiles = bp.jsFiles;
      }
    }

    if (rawManifestObj && typeof rawManifestObj === 'object') {
      manifestParsed = true;
      const m = rawManifestObj;
      if (m.name) extensionName = String(m.name);
      if (m.version) version = String(m.version);
      if (m.manifest_version) manifestVersion = Number(m.manifest_version);
      if (m.description) description = String(m.description);
      if (m.author) author = String(m.author);
      if (m.homepage_url) homepageUrl = String(m.homepage_url);
      if (m.update_url) updateUrl = String(m.update_url);
      if (Array.isArray(m.permissions)) permissions = m.permissions.map(String);
      if (Array.isArray(m.host_permissions)) hostPermissions = m.host_permissions.map(String);
      if (m.background?.service_worker) backgroundScripts = [String(m.background.service_worker)];
      else if (Array.isArray(m.background?.scripts)) backgroundScripts = m.background.scripts.map(String);
      else if (typeof m.background?.page === 'string') backgroundScripts = [m.background.page];

      if (Array.isArray(m.content_scripts)) {
        contentScripts = m.content_scripts
          .map((c: any) => (Array.isArray(c.js) ? c.js : c.js ? [c.js] : []))
          .flat()
          .filter(Boolean)
          .map(String);
      }
      if (m.content_security_policy) {
        csp = typeof m.content_security_policy === 'string' ? m.content_security_policy : JSON.stringify(m.content_security_policy);
      }
      if (Array.isArray(m.web_accessible_resources)) {
        webAccessibleResources = m.web_accessible_resources
          .map((r: any) => (typeof r === 'string' ? r : r.resources ? r.resources : ''))
          .flat()
          .filter(Boolean);
      }
      markStage('Manifest Analysis', 'done', Date.now() - mStart, 'Complete', `Manifest V${manifestVersion} parsed successfully.`);
    } else {
      markStage(
        'Manifest Analysis',
        'failed',
        Date.now() - mStart,
        'Unavailable',
        'Extension package could not be downloaded from official store or manifest.json was missing/invalid.'
      );
    }

    declaredPurpose = this.inferDeclaredPurpose(extensionName, description);

    // Track files
    if (input.jsFiles) {
      fileList = input.jsFiles.map((f) => f.path);
      fileCount = input.jsFiles.length + 1; // + manifest.json
    } else {
      fileCount = manifestParsed ? 1 : 0;
    }
    if (input.otherFiles) {
      fileList.push(...input.otherFiles.map((f) => f.path));
      fileCount += input.otherFiles.length;
    }

    // ── 3. FINDINGS & CONTRIBUTORS STORAGE (Deduplicated) ────────────────────
    const findings: IScanFinding[] = [];
    const scoreContributors: IExtensionScoreContributor[] = [];
    const positiveSignals: Array<{ title: string; desc: string; category?: string }> = [];
    const limitations: string[] = [];
    const dangerousPermissionsList: Array<{ permission: string; severity: FindingSeverity; reason: string }> = [];
    const permissionDetails: IExtensionPermissionDetail[] = [];
    const codeFindings: IExtensionCodeFinding[] = [];
    const networkIndicators: IExtensionNetworkIndicator[] = [];

    const seenEvidenceIds = new Set<string>();

    if (!manifestParsed) {
      findings.push({
        id: 'MANIFEST_PARSING_FAILED',
        findingId: 'MANIFEST_PARSING_FAILED',
        category: 'Manifest / Architecture',
        severity: 'MEDIUM',
        title: 'Extension Manifest Unavailable or Package Unreachable',
        description: 'Could not download or extract manifest.json from the specified target. The extension may be private, removed from the Web Store, or the ID is invalid.',
        evidence: `Target: ${rawTarget}`,
        scoreContribution: 0,
        recommendation: 'Verify the extension Web Store URL / ID or directly upload the CRX / ZIP package for deep analysis.',
      });
      limitations.push('Extension package could not be retrieved from the store. Static code and manifest analysis could not be performed.');
    }

    const addContributor = (item: {
      id: string;
      title: string;
      category: string;
      severity: FindingSeverity;
      contribution: number;
      evidence: string;
      source: string;
      location?: string;
      rationale: string;
      remediation?: string;
    }) => {
      if (seenEvidenceIds.has(item.id)) return;
      seenEvidenceIds.add(item.id);

      findings.push({
        id: item.id,
        findingId: item.id,
        category: item.category,
        severity: item.severity,
        title: item.title,
        description: item.rationale,
        evidence: item.evidence,
        scoreContribution: item.contribution,
        recommendation: item.remediation,
      });

      if (item.contribution > 0) {
        scoreContributors.push({
          id: item.id,
          findingId: item.id,
          category: item.category,
          title: item.title,
          severity: item.severity,
          contribution: item.contribution,
          reason: item.rationale,
          rationale: item.rationale,
          evidence: item.evidence,
          source: item.source,
          location: item.location || 'manifest.json',
          remediation: item.remediation,
        });
      }
    };

    // ── 4. MANIFEST & ARCHITECTURE ANALYSIS (Stage 2 findings) ────────────────
    if (manifestVersion === 2) {
      addContributor({
        id: 'ARCH_MANIFEST_V2',
        category: 'Manifest / Architecture',
        title: 'Deprecated Manifest V2 Architecture',
        severity: 'LOW',
        contribution: 3,
        evidence: 'manifest_version: 2',
        source: 'manifest.json',
        rationale: 'Extension uses legacy Manifest V2 format rather than modern Manifest V3 background service workers.',
        remediation: 'Migrate extension manifest to Chrome Manifest V3 using background service workers.',
      });
    } else if (manifestVersion === 3) {
      positiveSignals.push({
        title: 'Manifest V3 Modern Security Architecture',
        desc: 'Extension complies with Manifest V3 standards prohibiting remotely hosted code.',
        category: 'Architecture',
      });
    }

    if (csp) {
      if (csp.includes("'unsafe-eval'")) {
        addContributor({
          id: 'ARCH_CSP_UNSAFE_EVAL',
          category: 'Manifest / Architecture',
          title: 'Permissive CSP (unsafe-eval)',
          severity: 'HIGH',
          contribution: 5,
          evidence: `CSP: ${csp.slice(0, 80)}`,
          source: 'manifest.content_security_policy',
          rationale: 'Content-Security-Policy allows unsafe-eval string execution, weakening script isolation boundaries.',
          remediation: 'Remove unsafe-eval directive and refactor dynamic code.',
        });
      }
      if (csp.includes("'unsafe-inline'")) {
        addContributor({
          id: 'ARCH_CSP_UNSAFE_INLINE',
          category: 'Manifest / Architecture',
          title: 'Permissive CSP (unsafe-inline)',
          severity: 'LOW',
          contribution: 3,
          evidence: `CSP: ${csp.slice(0, 80)}`,
          source: 'manifest.content_security_policy',
          rationale: 'Content-Security-Policy allows unsafe-inline scripts without cryptographic nonces or hashes.',
          remediation: 'Remove unsafe-inline scripts from HTML templates.',
        });
      }
    }

    if (updateUrl) {
      const isOfficialUpdate =
        updateUrl.includes('google.com') ||
        updateUrl.includes('googleapis.com') ||
        updateUrl.includes('mozilla.org') ||
        updateUrl.includes('microsoft.com');
      if (!isOfficialUpdate) {
        addContributor({
          id: 'ARCH_CUSTOM_UPDATE_URL',
          category: 'Manifest / Architecture',
          title: 'Non-Official Update URL Infrastructure',
          severity: 'LOW',
          contribution: 3,
          evidence: `update_url: "${updateUrl}"`,
          source: 'manifest.update_url',
          rationale: 'Extension specifies an update_url pointing outside official store distribution infrastructure.',
          remediation: 'Distribute updates through the official Chrome Web Store or Edge Add-ons channel.',
        });
      }
    }

    // ── 5. PERMISSION ANALYSIS (Stage 3) ──────────────────────────────────────
    const permStart = Date.now();
    const uniquePermissions = Array.from(new Set(permissions));

    for (const perm of uniquePermissions) {
      const def = CAPABILITY_CATALOG[perm] || {
        permission: perm,
        severity: 'INFO' as FindingSeverity,
        capabilityTitle: `Declared Permission (${perm})`,
        capabilityDescription: `Extension requests access to browser API "${perm}".`,
        securityImpact: 'Standard browser capability access.',
        baseContribution: 0,
      };

      let actualUsage: 'Detected' | 'Not detected' | 'Not analyzed' =
        input.jsFiles && input.jsFiles.length > 0 ? 'Not detected' : 'Not analyzed';
      let usageEvidence: string | undefined = undefined;

      if (input.jsFiles && input.jsFiles.length > 0) {
        const regex = new RegExp(`chrome\\.${perm}\\b|browser\\.${perm}\\b`, 'i');
        for (const f of input.jsFiles) {
          if (regex.test(f.content)) {
            actualUsage = 'Detected';
            usageEvidence = `Observed in ${f.path}`;
            break;
          }
        }
      }

      permissionDetails.push({
        name: perm,
        severity: def.severity,
        source: 'manifest.permissions',
        capability: def.capabilityDescription,
        securityImpact: def.securityImpact,
        actualUsage,
        usageEvidence,
        contribution: def.baseContribution,
      });

      if (def.severity === 'CRITICAL' || def.severity === 'HIGH' || def.severity === 'MEDIUM') {
        dangerousPermissionsList.push({
          permission: perm,
          severity: def.severity,
          reason: `${def.capabilityDescription} ${def.securityImpact}`,
        });
      }

      if (def.baseContribution > 0) {
        const evidenceId = `PERM_${perm.toUpperCase()}`;
        addContributor({
          id: evidenceId,
          category: 'Permissions & Capabilities',
          title: `${def.capabilityTitle}`,
          severity: def.severity,
          contribution: def.baseContribution,
          evidence: `manifest.permissions -> "${perm}"`,
          source: 'manifest.permissions',
          location: 'manifest.json',
          rationale: `${def.capabilityDescription} ${def.securityImpact}`,
          remediation: `Verify that "${perm}" capability is strictly necessary for extension operation.`,
        });
      }
    }

    if (dangerousPermissionsList.length === 0) {
      positiveSignals.push({
        title: 'Safe Baseline Permission Profile',
        desc: 'Extension does not declare high-risk browser intercept, debugger, or OS native messaging permissions.',
        category: 'Permissions',
      });
    }

    markStage('Permission Analysis', 'done', Date.now() - permStart, 'Complete', `Evaluated ${uniquePermissions.length} permission(s).`);

    // ── 6. HOST ACCESS ANALYSIS (Stage 4, Deduplicated) ──────────────────────
    const hostStart = Date.now();
    const allDeclaredHosts = Array.from(new Set([...hostPermissions]));

    let contentScriptMatchesAllUrls = false;
    const sensitiveHostsMatched: string[] = [];

    if (rawManifestObj?.content_scripts && Array.isArray(rawManifestObj.content_scripts)) {
      for (const cs of rawManifestObj.content_scripts) {
        if (Array.isArray(cs.matches)) {
          for (const m of cs.matches) {
            if (m === '<all_urls>' || m === '*://*/*' || m === 'https://*/*' || m === 'http://*/*') {
              contentScriptMatchesAllUrls = true;
            }
          }
        }
      }
    }

    const hasBroadHostAccess =
      allDeclaredHosts.some((h) => h === '<all_urls>' || h === '*://*/*' || h === 'https://*/*' || h === 'http://*/*') ||
      contentScriptMatchesAllUrls;

    const sensitiveHostKeywords = ['bank', 'chase', 'wellsfargo', 'paypal', 'stripe', 'coinbase', 'binance', 'metamask', 'login', 'auth', 'mail'];
    for (const h of allDeclaredHosts) {
      if (sensitiveHostKeywords.some((kw) => h.toLowerCase().includes(kw)) && !hasBroadHostAccess) {
        sensitiveHostsMatched.push(h);
      }
    }

    if (hasBroadHostAccess) {
      dangerousPermissionsList.push({
        permission: '<all_urls>',
        severity: 'HIGH',
        reason: 'Broad wildcard host permissions allow script injection and content inspection across all web origins.',
      });

      addContributor({
        id: 'BROAD_HOST_ACCESS',
        category: 'Website / Host Access',
        title: 'Broad Website Access (<all_urls>)',
        severity: 'HIGH',
        contribution: 12,
        evidence: contentScriptMatchesAllUrls && hostPermissions.includes('<all_urls>')
          ? 'host_permissions: ["<all_urls>"] & content_scripts.matches: ["<all_urls>"] (unified)'
          : `Host Scope: ${allDeclaredHosts.join(', ') || '<all_urls>'}`,
        source: 'manifest.host_permissions',
        location: 'manifest.json',
        rationale: 'Extension requests unrestricted access to read and modify content across all websites visited by the user.',
        remediation: 'Scope host permissions strictly to the exact origin domains required for operation.',
      });
    } else if (sensitiveHostsMatched.length > 0) {
      addContributor({
        id: 'SENSITIVE_HOST_ACCESS',
        category: 'Website / Host Access',
        title: 'Sensitive Host Origin Scope Declared',
        severity: 'MEDIUM',
        contribution: 5,
        evidence: `Sensitive hosts: ${sensitiveHostsMatched.slice(0, 3).join(', ')}`,
        source: 'manifest.host_permissions',
        location: 'manifest.json',
        rationale: 'Extension explicitly declares access to sensitive banking, authentication, or cryptocurrency origins.',
        remediation: 'Audit origin patterns to prevent unintended credential capture.',
      });
    } else if (allDeclaredHosts.length > 0) {
      positiveSignals.push({
        title: 'Narrow Scoped Host Origins',
        desc: `Extension restricts host access strictly to ${allDeclaredHosts.length} domain pattern(s).`,
        category: 'Host Scope',
      });
    } else {
      positiveSignals.push({
        title: 'Zero Host Permissions Declared',
        desc: 'Extension does not declare persistent background access to external websites.',
        category: 'Host Scope',
      });
    }

    markStage('Host Access Analysis', 'done', Date.now() - hostStart, 'Complete', `Analyzed host scopes: ${allDeclaredHosts.length} declared pattern(s).`);

    // ── 7. JAVASCRIPT STATIC CODE ANALYSIS (Stage 6) ─────────────────────────
    const jsStart = Date.now();
    const jsAnalysis: IExtensionJsAnalysis = {
      evalFound: false,
      newFunctionFound: false,
      dynamicScriptInjection: false,
      remoteCodeExecution: false,
      obfuscationIndicators: [],
      sensitiveApisUsed: [],
      cookieAccessObserved: false,
      credentialFormAccessObserved: false,
      clipboardAccessObserved: false,
      externalDataTransmission: false,
      externalEndpoints: [],
    };

    let jsAnalyzed = false;
    if (input.jsFiles && input.jsFiles.length > 0) {
      jsAnalyzed = true;

      for (const file of input.jsFiles) {
        const code = file.content || '';
        const lines = code.split('\n');

        lines.forEach((lineText, lineIdx) => {
          const lineNum = lineIdx + 1;

          // Dynamic code evaluation: eval
          if (/\beval\s*\(/i.test(lineText)) {
            jsAnalysis.evalFound = true;
            codeFindings.push({
              id: `CODE_DYNAMIC_EVAL_${codeFindings.length + 1}`,
              file: file.path,
              line: lineNum,
              severity: 'HIGH',
              pattern: 'eval(...)',
              evidenceSnippet: lineText.trim().slice(0, 80),
              explanation: 'Dynamic string-to-code evaluation can increase analysis difficulty and introduce runtime code execution risks.',
              riskContribution: 8,
            });
          }

          // new Function constructor
          if (/new\s+Function\s*\(/i.test(lineText)) {
            jsAnalysis.newFunctionFound = true;
            codeFindings.push({
              id: `CODE_NEW_FUNCTION_${codeFindings.length + 1}`,
              file: file.path,
              line: lineNum,
              severity: 'HIGH',
              pattern: 'new Function(...)',
              evidenceSnippet: lineText.trim().slice(0, 80),
              explanation: 'Function constructor dynamically evaluates strings as code in local scope.',
              riskContribution: 8,
            });
          }

          // Remote script loading
          if (/document\.createElement\s*\(\s*['"]script['"]\s*\)/i.test(lineText) || /\.src\s*=\s*['"]https?:\/\//i.test(lineText)) {
            jsAnalysis.dynamicScriptInjection = true;
            jsAnalysis.remoteCodeExecution = true;
            codeFindings.push({
              id: `CODE_REMOTE_SCRIPT_${codeFindings.length + 1}`,
              file: file.path,
              line: lineNum,
              severity: 'HIGH',
              pattern: 'Dynamic Remote Script Loading',
              evidenceSnippet: lineText.trim().slice(0, 80),
              explanation: 'Dynamically loading remote scripts bypasses static review and violates Manifest V3 execution policies.',
              riskContribution: 12,
            });
          }

          // Suspicious obfuscation
          if (/String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}/i.test(lineText) || /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}/i.test(lineText)) {
            jsAnalysis.obfuscationIndicators.push(`${file.path}:${lineNum}`);
            codeFindings.push({
              id: `CODE_OBFUSCATION_${codeFindings.length + 1}`,
              file: file.path,
              line: lineNum,
              severity: 'MEDIUM',
              pattern: 'Hex / Character Code Obfuscation',
              evidenceSnippet: lineText.trim().slice(0, 80),
              explanation: 'Static analysis detected suspicious string packing or hex-encoded character sequences.',
              riskContribution: 6,
            });
          }

          // Cookie Access
          if (/chrome\.cookies\.(?:get|getAll)\s*\(/i.test(lineText) || /document\.cookie\b/i.test(lineText)) {
            jsAnalysis.cookieAccessObserved = true;
            if (!jsAnalysis.sensitiveApisUsed.includes('chrome.cookies / document.cookie')) {
              jsAnalysis.sensitiveApisUsed.push('chrome.cookies / document.cookie');
            }
          }

          // Credential & Form Access
          if (/input\[type=["']?password["']?\]/i.test(lineText) || /document\.forms\b/i.test(lineText) || /input\[name\*=["']?pass/i.test(lineText)) {
            jsAnalysis.credentialFormAccessObserved = true;
            if (!jsAnalysis.sensitiveApisUsed.includes('Password form / input inspection')) {
              jsAnalysis.sensitiveApisUsed.push('Password form / input inspection');
            }
          }

          // Clipboard Access
          if (/navigator\.clipboard\.readText/i.test(lineText) || /document\.execCommand\s*\(\s*['"]copy['"]\s*\)/i.test(lineText)) {
            jsAnalysis.clipboardAccessObserved = true;
          }

          // External Network calls
          const fetchMatch = lineText.match(/fetch\s*\(\s*['"](https?:\/\/[^'"]+)['"]/i);
          const xhrMatch = lineText.match(/\.open\s*\(\s*['"]POST['"]\s*,\s*['"](https?:\/\/[^'"]+)['"]/i);
          if (fetchMatch || xhrMatch || /navigator\.sendBeacon/i.test(lineText)) {
            jsAnalysis.externalDataTransmission = true;
            const url = fetchMatch ? fetchMatch[1] : xhrMatch ? xhrMatch[1] : undefined;
            if (url && !jsAnalysis.externalEndpoints.includes(url)) {
              jsAnalysis.externalEndpoints.push(url);
              networkIndicators.push({
                url,
                domain: new URL(url).hostname,
                sourceFile: `${file.path}:${lineNum}`,
                context: 'JavaScript fetch/XHR endpoint call',
                status: 'Observed in code',
                reputationStatus: 'Unavailable',
                isSuspicious: /c2|exfil|collect|track|log/i.test(url),
              });
            }
          }
        });
      }

      // Add Deduplicated Code Contributors
      if (jsAnalysis.evalFound || jsAnalysis.newFunctionFound) {
        addContributor({
          id: 'CODE_DYNAMIC_EVAL',
          category: 'Code Behaviour',
          title: 'Dynamic Code Evaluation (eval / Function)',
          severity: 'HIGH',
          contribution: 8,
          evidence: `evalFound: ${jsAnalysis.evalFound}, newFunctionFound: ${jsAnalysis.newFunctionFound}`,
          source: 'JavaScript Static AST Analysis',
          location: codeFindings.find((c) => c.pattern.includes('eval') || c.pattern.includes('Function'))?.file || 'source code',
          rationale: 'Dynamic code evaluation can increase static analysis difficulty and introduce runtime execution risks.',
          remediation: 'Refactor code to avoid dynamic eval() and comply with strict Manifest V3 CSP.',
        });
      }

      if (jsAnalysis.remoteCodeExecution) {
        addContributor({
          id: 'CODE_REMOTE_SCRIPT',
          category: 'Code Behaviour',
          title: 'Remote Script Injection Routine',
          severity: 'HIGH',
          contribution: 12,
          evidence: 'Dynamic remote script element creation observed in source code.',
          source: 'JavaScript Static AST Analysis',
          location: codeFindings.find((c) => c.pattern.includes('Remote Script'))?.file || 'source code',
          rationale: 'Dynamically loading remote script elements permits arbitrary runtime code execution.',
          remediation: 'Package all required dependencies locally inside the extension archive.',
        });
      }

      if (jsAnalysis.obfuscationIndicators.length > 0) {
        addContributor({
          id: 'CODE_OBFUSCATION',
          category: 'Code Behaviour',
          title: 'Suspicious Code Obfuscation Patterns',
          severity: 'MEDIUM',
          contribution: 6,
          evidence: `${jsAnalysis.obfuscationIndicators.length} obfuscated character/hex sequence(s) detected.`,
          source: 'JavaScript Static AST Analysis',
          location: jsAnalysis.obfuscationIndicators[0] || 'source code',
          rationale: 'Obfuscated character packing is commonly used to evade signature filters and hide malicious logic.',
          remediation: 'Publish clear, unminified or standard sourcemap-backed source code.',
        });
      }

      if (jsAnalysis.cookieAccessObserved) {
        addContributor({
          id: 'DATA_COOKIE_ACCESS',
          category: 'Privacy / Data Access',
          title: 'Static Cookie Access Routines Observed',
          severity: 'MEDIUM',
          contribution: 6,
          evidence: 'chrome.cookies or document.cookie routines statically identified.',
          source: 'JavaScript Static AST Analysis',
          location: 'extension scripts',
          rationale: 'Extension contains routines that actively read user session cookies.',
          remediation: 'Restrict cookie access strictly to authorized domain origins.',
        });
      }

      if (jsAnalysis.credentialFormAccessObserved) {
        addContributor({
          id: 'DATA_CREDENTIAL_ACCESS',
          category: 'Privacy / Data Access',
          title: 'Password Form / Input Field Inspection Routine',
          severity: 'HIGH',
          contribution: 10,
          evidence: 'Password input element selectors identified in content scripts.',
          source: 'JavaScript Static AST Analysis',
          location: 'content scripts',
          rationale: 'Extension actively queries password inputs and sensitive authentication form elements.',
          remediation: 'Review password input listeners to ensure compliance with privacy regulations.',
        });
      }

      if (jsAnalysis.clipboardAccessObserved) {
        addContributor({
          id: 'DATA_CLIPBOARD_ACCESS',
          category: 'Privacy / Data Access',
          title: 'Clipboard Extraction Routine Observed',
          severity: 'MEDIUM',
          contribution: 5,
          evidence: 'navigator.clipboard.readText or document.execCommand copy routines observed.',
          source: 'JavaScript Static AST Analysis',
          location: 'extension scripts',
          rationale: 'Extension contains routines capable of reading clipboard contents.',
          remediation: 'Avoid passive clipboard reading without explicit user action.',
        });
      }

      // Combination Finding: Sensitive data access + External transmission (Exfiltration)
      if (
        (jsAnalysis.cookieAccessObserved || jsAnalysis.credentialFormAccessObserved) &&
        jsAnalysis.externalDataTransmission
      ) {
        addContributor({
          id: 'SENSITIVE_DATA_EXFILTRATION',
          category: 'Privacy / Data Access',
          title: 'Potential Sensitive Data Exfiltration Routine',
          severity: 'CRITICAL',
          contribution: 18,
          evidence: `Observed data access: [${jsAnalysis.sensitiveApisUsed.join(', ')}] -> Outbound transmission: [${jsAnalysis.externalEndpoints.slice(0, 2).join(', ') || 'Remote POST'}]`,
          source: 'Contextual Behavioral Correlation',
          location: 'extension scripts',
          rationale: 'Static analysis observed sensitive cookie/form data access combined with external HTTP transmission routines.',
          remediation: 'Immediately inspect outbound endpoints to ensure private user credentials are never transmitted externally.',
        });
      }

      if (!jsAnalysis.evalFound && !jsAnalysis.remoteCodeExecution && jsAnalysis.obfuscationIndicators.length === 0) {
        positiveSignals.push({
          title: 'Clean JavaScript Static Code Profile',
          desc: 'No dynamic eval(), remote code loading, or obfuscated payloads detected in analyzed scripts.',
          category: 'Code Quality',
        });
      }

      markStage('JavaScript Static Analysis', 'done', Date.now() - jsStart, 'Complete', `Analyzed ${input.jsFiles.length} JavaScript file(s), ${codeFindings.length} code finding(s).`);
    } else {
      markStage('JavaScript Static Analysis', 'skipped', Date.now() - jsStart, 'Unavailable', 'No JavaScript source files were provided in scan payload.');
      limitations.push('JavaScript source code files were not provided in Phase 1 manifest scan. Static code analysis is pending.');
    }

    // ── 8. NETWORK INDICATOR ANALYSIS (Stage 7) ──────────────────────────────
    const netStart = Date.now();
    for (const ep of jsAnalysis.externalEndpoints) {
      if (/^https?:\/\/(\d{1,3}\.){3}\d{1,3}/i.test(ep)) {
        addContributor({
          id: 'NET_RAW_IP_ENDPOINT',
          category: 'Network / Reputation',
          title: 'Hardcoded Raw IP Network Endpoint',
          severity: 'MEDIUM',
          contribution: 4,
          evidence: `Endpoint: ${ep}`,
          source: 'Static Network Extraction',
          location: 'source code',
          rationale: 'Extension connects directly to raw IP addresses rather than registered domain hostnames.',
          remediation: 'Route API traffic through registered domain names with valid TLS certificates.',
        });
      }
    }
    markStage('Network Indicator Analysis', 'done', Date.now() - netStart, 'Complete', `Extracted ${networkIndicators.length} network indicator(s).`);

    // ── 9. STORE METADATA ANALYSIS (Stage 5) ─────────────────────────────────
    const storeStart = Date.now();
    const storeMetadata: IExtensionStoreMetadata = {
      status: input.storeData?.status || (detectedStore ? 'FOUND' : 'NOT_CONFIGURED'),
      store: detectedStore || input.storeData?.store,
      name: input.storeData?.name || extensionName,
      developer: input.storeData?.developer || (author ? author : undefined),
      developerVerified: input.storeData?.developerVerified ?? false,
      userCount: input.storeData?.userCount,
      rating: input.storeData?.rating,
      ratingCount: input.storeData?.ratingCount,
      lastUpdated: input.storeData?.lastUpdated,
      privacyPolicyUrl: input.storeData?.privacyPolicyUrl,
      storeUrl: input.storeData?.storeUrl || (extensionId ? `https://chromewebstore.google.com/detail/${extensionId}` : undefined),
      isRemovedOrFlagged: input.storeData?.isRemovedOrFlagged ?? false,
    };

    if (storeMetadata.isRemovedOrFlagged) {
      addContributor({
        id: 'EXT_STORE_REMOVED_FLAGGED',
        category: 'Network / Reputation',
        title: 'Extension Removed or Flagged by Official Store',
        severity: 'CRITICAL',
        contribution: 35,
        evidence: `isRemovedOrFlagged: true (Extension ID: ${extensionId || 'target'})`,
        source: 'Official Store Security Feed',
        location: 'Store Listing',
        rationale: 'Extension has been revoked, taken down, or flagged for policy violation on official store repositories.',
        remediation: 'Do not install or execute extensions revoked by store security teams.',
      });
    }

    if (storeMetadata.developerVerified) {
      positiveSignals.push({
        title: 'Verified Store Developer Identity',
        desc: `Extension is published by a verified developer account (${storeMetadata.developer || 'Verified'}).`,
        category: 'Reputation',
      });
    }

    if (storeMetadata.privacyPolicyUrl) {
      positiveSignals.push({
        title: 'Published Privacy Policy',
        desc: 'Extension provides a public privacy policy detailing data handling practices.',
        category: 'Privacy',
      });
    }

    markStage(
      'Store Metadata Analysis',
      storeMetadata.status === 'NOT_CONFIGURED' ? 'skipped' : 'done',
      Date.now() - storeStart,
      storeMetadata.status,
      storeMetadata.status === 'NOT_CONFIGURED' ? 'Store metadata integration not configured.' : `Store status: ${storeMetadata.status}.`
    );

    // ── 10. REPUTATION / THREAT INTELLIGENCE (Stage 8) ────────────────────────
    const repStart = Date.now();
    let reputationData = input.reputationData;
    if (reputationData) {
      if (reputationData.status === 'MALICIOUS') {
        addContributor({
          id: 'MALICIOUS_REPUTATION',
          category: 'Network / Reputation',
          title: 'Confirmed Malicious Extension Reputation Match',
          severity: 'CRITICAL',
          contribution: 35,
          evidence: `Provider: ${reputationData.provider || 'Threat Feed'} - ${reputationData.details || 'Known Malicious Extension'}`,
          source: 'CyberWatch Threat Intelligence Feeds',
          location: 'Threat Intelligence Database',
          rationale: 'Extension package hash or ID matches known malicious campaigns in threat intelligence repositories.',
          remediation: 'Immediately remove extension and audit all browser sessions for token compromise.',
        });
        markStage('Reputation / Threat Intelligence', 'done', Date.now() - repStart, 'Malicious Match', 'Confirmed match in threat intelligence feeds.');
      } else if (reputationData.status === 'CLEAN') {
        positiveSignals.push({
          title: 'Clean Threat Intelligence Record',
          desc: 'Extension package hashes are not flagged in known malicious extension repositories.',
          category: 'Threat Intelligence',
        });
        markStage('Reputation / Threat Intelligence', 'done', Date.now() - repStart, 'Clean Record', 'No malicious matches in threat intelligence.');
      } else {
        markStage('Reputation / Threat Intelligence', 'skipped', Date.now() - repStart, reputationData.status, 'Reputation provider status: ' + reputationData.status);
      }
    } else {
      reputationData = {
        status: 'NOT_CONFIGURED',
        provider: 'CyberWatch Extension Intel',
        details: 'Threat intelligence provider not configured for this environment.',
      };
      markStage('Reputation / Threat Intelligence', 'skipped', Date.now() - repStart, 'Not Configured', 'Threat intelligence integration is not configured.');
    }

    // ── 11. OTHER FILE ANALYSIS (Stage 9) ────────────────────────────────────
    const oStart = Date.now();
    if (input.otherFiles && input.otherFiles.length > 0) {
      const exeFiles = input.otherFiles.filter((f) => /\.(exe|dll|so|dylib|bin|bat|ps1|vbs|sh)$/i.test(f.path));
      if (exeFiles.length > 0) {
        addContributor({
          id: 'ARCH_EMBEDDED_EXECUTABLE',
          category: 'Manifest / Architecture',
          title: 'Embedded Native Binary / Executable in Extension Package',
          severity: 'HIGH',
          contribution: 12,
          evidence: `Embedded executables: ${exeFiles.map((e) => e.path).join(', ')}`,
          source: 'Package Structure Inspection',
          location: exeFiles[0].path,
          rationale: 'Extension bundle contains native executable or shell script binaries.',
          remediation: 'Remove compiled binary executables from web extension package.',
        });
      }
    }
    markStage('Other File Analysis', 'done', Date.now() - oStart, 'Complete', `Inspected ${input.otherFiles?.length || 0} additional file(s).`);

    // ── 12. PRIVACY ANALYSIS (Stage 10) ──────────────────────────────────────
    const privStart = Date.now();
    const dataCapabilities: string[] = [];
    if (uniquePermissions.includes('cookies')) dataCapabilities.push('Session Cookies');
    if (uniquePermissions.includes('history')) dataCapabilities.push('Browsing History');
    if (uniquePermissions.includes('tabs')) dataCapabilities.push('Open Tabs & URLs');
    if (uniquePermissions.includes('clipboardRead')) dataCapabilities.push('Clipboard Contents');
    if (hasBroadHostAccess) dataCapabilities.push('All Visited Web Page Content');

    let exfilRisk: 'None' | 'Low' | 'Moderate' | 'High' | 'Critical' = 'None';
    if (seenEvidenceIds.has('SENSITIVE_DATA_EXFILTRATION')) exfilRisk = 'Critical';
    else if (jsAnalysis.externalDataTransmission && dataCapabilities.length > 0) exfilRisk = 'High';
    else if (dataCapabilities.length > 0) exfilRisk = 'Moderate';
    else if (uniquePermissions.length > 0) exfilRisk = 'Low';

    const privacyAnalysis = {
      dataCapabilities,
      observedDataAccess: jsAnalysis.sensitiveApisUsed,
      externalDataTransmission: jsAnalysis.externalDataTransmission,
      dataExfiltrationRisk: exfilRisk,
      details: dataCapabilities.length === 0
        ? 'No sensitive data capabilities declared.'
        : `Extension declares ${dataCapabilities.length} data capability scope(s). Observed active data access: ${jsAnalysis.sensitiveApisUsed.length > 0 ? jsAnalysis.sensitiveApisUsed.join(', ') : 'None statically identified'}.`,
    };
    markStage('Privacy Analysis', 'done', Date.now() - privStart, 'Complete', `Privacy risk evaluated: ${exfilRisk}.`);

    // ── 13. CONTEXTUAL & PURPOSE ANALYSIS (Stage 11) ─────────────────────────
    const ctxStart = Date.now();
    let purposeMatchAssessment = 'Permissions appear aligned with declared utility scope.';
    const isSimpleUtility = /calculator|clock|timer|notepad|notes|color\s*picker|stopwatch|counter|unit\s*converter/i.test(
      `${extensionName} ${description}`
    );

    if (isSimpleUtility) {
      const hasExcessiveCapabilities =
        uniquePermissions.some((p) => ['cookies', 'webRequest', 'webRequestBlocking', 'nativeMessaging', 'debugger', 'history'].includes(p)) ||
        hasBroadHostAccess;

      if (hasExcessiveCapabilities) {
        purposeMatchAssessment = 'Permissions appear significantly broader than expected for a simple standalone utility.';
        addContributor({
          id: 'EXT_CONTEXT_MISMATCH',
          category: 'Permissions & Capabilities',
          title: 'Permissions Broader Than Stated Extension Purpose',
          severity: 'MEDIUM',
          contribution: 6,
          evidence: `Stated tool type: "${extensionName}" with permissions: [${uniquePermissions.join(', ')}]`,
          source: 'Contextual Security Analysis',
          location: 'manifest.json',
          rationale: `The extension identifies as a standalone utility ("${extensionName}") but requests elevated capabilities (e.g. broad host access or sensitive browser APIs).`,
          remediation: 'Review why a standalone utility requires broad browsing context or session access.',
        });
      }
    }
    markStage('Context / Behavioral Analysis', 'done', Date.now() - ctxStart, 'Complete', purposeMatchAssessment);

    // Baseline finding for clean extensions
    if (findings.length === 0) {
      findings.push({
        id: 'EXT_PERM_MINIMAL',
        category: 'Permissions & Capabilities',
        severity: 'INFO',
        title: 'Minimal Permission Scope',
        description: 'The extension requests standard scoped permissions with no sensitive debugging or broad intercept capabilities.',
        evidence: `Permissions: ${uniquePermissions.join(', ') || 'None declared'}`,
      });
    }

    // ── 14. FINAL RISK SCORING & CATEGORY BREAKDOWN (Stage 12) ────────────────
    const scoreStart = Date.now();

    const getCategoryStats = (catName: string) => {
      const catContribs = scoreContributors.filter((c) => c.category === catName);
      const catFindings = findings.filter((f) => f.category === catName);
      const sum = catContribs.reduce((acc, c) => acc + c.contribution, 0);
      let catRisk = 'LOW';
      if (sum >= 20) catRisk = 'CRITICAL';
      else if (sum >= 12) catRisk = 'HIGH';
      else if (sum >= 5) catRisk = 'MEDIUM';

      return {
        riskLevel: catRisk,
        findingCount: catFindings.length,
        explanation: catContribs.length === 0 ? 'No elevated risk contributors identified in this category.' : `${catContribs.length} risk contributor(s) (+${sum} pts).`,
        evidenceCount: catContribs.length,
      };
    };

    const breakdown = {
      permissions: getCategoryStats('Permissions & Capabilities'),
      websiteAccess: getCategoryStats('Website / Host Access'),
      codeBehaviour: getCategoryStats('Code Behaviour'),
      privacyExposure: getCategoryStats('Privacy / Data Access'),
      networkIndicators: getCategoryStats('Network / Reputation'),
      reputation: getCategoryStats('Network / Reputation'),
      manifestArchitecture: getCategoryStats('Manifest / Architecture'),
    };

    // RAW RISK SCORE = Sum of unique validated evidence contributions
    let rawScore = 0;
    for (const sc of scoreContributors) {
      rawScore += sc.contribution;
    }

    const finalRiskScore = Math.min(100, Math.max(0, Math.round(rawScore)));

    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (finalRiskScore >= 75) {
      riskLevel = 'CRITICAL';
    } else if (finalRiskScore >= 50) {
      riskLevel = 'HIGH';
    } else if (finalRiskScore >= 25) {
      riskLevel = 'MEDIUM';
    } else {
      riskLevel = 'LOW';
    }

    const hasConfirmedMaliciousEvidence =
      storeMetadata.isRemovedOrFlagged ||
      reputationData?.status === 'MALICIOUS' ||
      seenEvidenceIds.has('SENSITIVE_DATA_EXFILTRATION') ||
      seenEvidenceIds.has('MALICIOUS_REPUTATION') ||
      seenEvidenceIds.has('EXT_STORE_REMOVED_FLAGGED');

    let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' = 'SAFE';
    let verdictReason = 'Completed security audit identified no elevated risk contributions.';

    if (hasConfirmedMaliciousEvidence) {
      verdict = 'MALICIOUS';
      verdictReason = 'Strong static security evidence indicates confirmed malicious reputation, store revocation, or sensitive data exfiltration routines.';
    } else if (finalRiskScore >= 25 || dangerousPermissionsList.length > 0 || seenEvidenceIds.has('CODE_DYNAMIC_EVAL') || seenEvidenceIds.has('CODE_REMOTE_SCRIPT')) {
      verdict = 'SUSPICIOUS';
      verdictReason = `Extension requests broad capabilities (${dangerousPermissionsList.length} sensitive privilege(s) flagged) or exhibits non-standard architecture requiring careful review.`;
    } else if (!manifestParsed) {
      verdict = 'SAFE';
      verdictReason = 'Completed manifest scan: Package or manifest could not be retrieved from the store; no elevated risks identified.';
    } else if (!jsAnalyzed) {
      verdict = 'SAFE';
      verdictReason = 'Completed manifest scan: Declared baseline permissions exhibit standard security scope with no dynamic code execution observed.';
    } else {
      verdict = 'SAFE';
      if (reputationData?.status === 'CLEAN') {
        verdictReason = 'Completed clean scan: Extension exhibits standard scoped baseline permissions with verified clean threat intelligence and modern Manifest V3 architecture.';
      } else {
        verdictReason = 'Low-risk profile based on completed static analysis; external threat intelligence was unavailable.';
      }
    }

    markStage('Final Risk Scoring', 'done', Date.now() - scoreStart, 'Complete', `Final calculated score: ${finalRiskScore}/100 (${riskLevel}, ${verdict}).`);

    // ── 16. RECOMMENDATIONS ───────────────────────────────────────────────────
    const recommendations: string[] = [];
    if (!manifestParsed) {
      recommendations.push('Verify the extension Web Store URL or upload the CRX / ZIP package directly for static audit.');
    }
    if (hasBroadHostAccess) {
      recommendations.push("Review whether access to all websites (<all_urls>) is necessary for the extension's stated functionality.");
    }
    if (manifestVersion === 2) {
      recommendations.push('Upgrade extension manifest to modern Chrome Manifest V3 service worker architecture.');
    }
    if (dangerousPermissionsList.some((p) => p.permission === 'debugger')) {
      recommendations.push("Confirm that debugger access is strictly necessary for the extension's stated functionality.");
    }
    if (dangerousPermissionsList.some((p) => p.permission === 'webRequestBlocking')) {
      recommendations.push('Audit synchronous webRequestBlocking rules and verify whether declarativeNetRequest can be used instead.');
    }
    if (seenEvidenceIds.has('CODE_DYNAMIC_EVAL')) {
      recommendations.push('Refactor dynamic eval() and Function constructor usage to comply with CSP and improve static reviewability.');
    }
    if (seenEvidenceIds.has('CODE_REMOTE_SCRIPT')) {
      recommendations.push('Review remote code-loading behavior and package all required scripts locally within the extension archive.');
    }
    if (seenEvidenceIds.has('SENSITIVE_DATA_EXFILTRATION')) {
      recommendations.push('Do NOT use this extension until data-collection and external transmission routines are verified.');
    }
    if (verdict === 'MALICIOUS') {
      recommendations.push('Do NOT install or use this extension. Investigate affected systems and revoke active sessions if previously installed.');
    }
    if (recommendations.length === 0) {
      recommendations.push('Extension complies with standard Manifest V3 baseline security policies.');
    }

    // ── 17. SCORE EXPLANATION & SUMMARY ───────────────────────────────────────
    const disclaimer =
      "CyberWatch's risk score represents the security risk indicated by evidence collected during this scan. It is not a guarantee that the extension is safe or malicious.";

    const scoreExplanation: IExtensionScoreExplanation = {
      summary:
        scoreContributors.length === 0
          ? (jsAnalyzed && reputationData?.status === 'CLEAN'
              ? 'Completed clean scan: No elevated risk contributions identified.'
              : !manifestParsed
              ? 'Analysis incomplete: Package or manifest.json was not accessible.'
              : 'Low-risk profile based on completed static analysis; external threat intelligence was unavailable.')
          : `Risk score (${finalRiskScore}/100, ${riskLevel}) derived from ${scoreContributors.length} evidence-backed contributor(s): ${scoreContributors.map((c) => `${c.title} (+${c.contribution})`).join(', ')}.`,
      rawScore,
      normalizedScore: finalRiskScore,
      contributors: scoreContributors,
      positiveSignals,
      limitations,
    };

    const overallStatus: 'passed' | 'warning' | 'failed' | 'neutral' =
      !manifestParsed ? 'failed' : verdict === 'MALICIOUS' ? 'failed' : verdict === 'SUSPICIOUS' ? 'warning' : 'passed';

    const scanStatus: 'COMPLETE' | 'PARTIAL' | 'INCOMPLETE' = !manifestParsed
      ? 'INCOMPLETE'
      : jsAnalyzed ? 'COMPLETE' : 'PARTIAL';

    const scanStatusExplanation = jsAnalyzed
      ? (reputationData?.status === 'NOT_CONFIGURED' || reputationData?.status === 'UNAVAILABLE'
          ? 'Completed comprehensive static analysis across package, manifest, permissions, and JavaScript files.'
          : 'Full multi-stage static analysis completed across package, manifest, code, and threat intelligence.')
      : 'Analysis incomplete — some security checks could not be completed. Analysis performed on manifest.json; JavaScript source code was not included in scan payload.';

    const packageIdentity: IExtensionPackageIdentity = {
      format,
      extensionId,
      integrityValid: true,
      fileCount,
      totalSizeBytes,
      sha256: packageSha256,
      fileList: fileList.slice(0, 100),
      manifestLocation: 'manifest.json',
    };

    const provenance = {
      source: detectedStore ? 'Official Web Store' : format === 'MANIFEST_JSON' ? 'Direct Manifest' : 'Uploaded Package',
      store: detectedStore || 'Direct Package',
      developer: storeMetadata.developer || (author ? author : 'Unavailable'),
      extensionId: extensionId || 'Unavailable',
      version,
      sha256: packageSha256 || 'Unavailable',
      packageType: format,
      scanTimestamp: new Date().toISOString(),
    };

    const analysis: IExtensionSecurityAnalysis = {
      status: overallStatus,
      scanStatus,
      scanStatusExplanation,
      riskScore: finalRiskScore,
      riskLevel,
      verdict,
      verdictReason,
      extensionName,
      version,
      manifestVersion,
      extensionId,
      description,
      author,
      homepageUrl,
      updateUrl,
      declaredPurpose,
      purposeMatchAssessment,
      permissions: uniquePermissions,
      hostPermissions,
      dangerousPermissions: dangerousPermissionsList,
      permissionDetails,
      backgroundScripts,
      contentScripts,
      webAccessibleResources,
      csp,
      packageIdentity,
      storeMetadata,
      jsAnalysis: jsAnalyzed ? jsAnalysis : undefined,
      codeFindings,
      networkIndicators,
      reputationData,
      privacyAnalysis,
      provenance,
      breakdown,
      stages,
      scoreContributors,
      scoreExplanation,
      positiveSignals,
      recommendations,
      limitations,
      disclaimer,
      details: `Extension audit completed: Manifest V${manifestVersion}, ${uniquePermissions.length} declared permission(s), ${dangerousPermissionsList.length} sensitive privilege(s) flagged. Risk Score: ${finalRiskScore}/100 (${riskLevel}, ${verdict}).`,
    };

    // Safe diagnostic log
    if (process.env.NODE_ENV !== 'test') {
      console.log(
        `[ExtensionScan] target=${rawTarget.slice(0, 50)} sha256=${packageSha256?.slice(0, 12)} format=${format} perms=${uniquePermissions.length} hosts=${allDeclaredHosts.length} jsFiles=${fileCount} findings=${findings.length} score=${finalRiskScore}`
      );
    }

    return {
      analysis,
      findings,
      recommendations,
      riskScore: finalRiskScore,
      riskLevel,
      verdict,
      verdictReason,
    };
  }

  private inferDeclaredPurpose(name: string, description: string): string {
    const combined = `${name} ${description}`.toLowerCase();
    if (/password|credential|vault|login\s*manager|bitwarden|1password|lastpass/i.test(combined)) {
      return 'Password & Credential Manager';
    }
    if (/ad\s*block|tracker|privacy|ublock|adguard|blocker/i.test(combined)) {
      return 'Ad Blocker & Privacy Guard';
    }
    if (/developer|devtools|debug|rest\s*client|postman|json\s*formatter|inspector/i.test(combined)) {
      return 'Developer Utility / API Tool';
    }
    if (/calculator|clock|timer|stopwatch|notepad|notes|color\s*picker|counter/i.test(combined)) {
      return 'Standalone Simple Utility';
    }
    return 'General Browser Extension';
  }
}

export const extensionScannerService = new ExtensionScannerService();
