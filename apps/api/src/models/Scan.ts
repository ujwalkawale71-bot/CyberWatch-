import { Schema, model, Document, Types } from 'mongoose';

export const SCAN_RESULT_CLASSIFICATIONS = ['Safe', 'Low Risk', 'Suspicious', 'High Risk', 'Critical'] as const;
export type ScanResultClassification = (typeof SCAN_RESULT_CLASSIFICATIONS)[number];

export const SCAN_TARGET_TYPES = ['URL', 'Website', 'API', 'Phishing', 'File', 'Extension'] as const;
export type ScanTargetType = (typeof SCAN_TARGET_TYPES)[number];

export const FINDING_SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export type SecurityEvidenceSource =
  | 'http'
  | 'tls'
  | 'headers'
  | 'cookies'
  | 'html'
  | 'redirect'
  | 'dns'
  | 'content'
  | 'technology';

export interface ISecurityEvidence {
  source: SecurityEvidenceSource;
  check: string;
  observed: string;
  expected?: string;
  location?: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export type FindingCategory =
  | 'CONFIRMED_VULNERABILITY'
  | 'SECURITY_WEAKNESS'
  | 'HARDENING_RECOMMENDATION'
  | 'INFORMATIONAL';

export type FindingVerificationStatus =
  | 'CONFIRMED'
  | 'PARTIALLY_VERIFIED'
  | 'OBSERVED'
  | 'NOT_VERIFIED';

export interface IScanFinding {
  id?: string;
  findingId?: string;
  source?: 'url' | 'phishing' | 'reputation' | 'content' | 'website' | string;
  scoreContribution?: number;
  category: string;
  findingCategory?: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  evidence?: string;
  evidences?: ISecurityEvidence[];
  confidence?: number;
  verificationStatus?: FindingVerificationStatus;
  impact?: string;
  verification?: string;
  recommendation?: string;
  references?: string[];
  affectedComponent?: string;
}

export interface IUrlSecurityAuditCheck {
  id?: string;
  name?: string;
  title?: string;
  category?: string;
  status: 'PASS' | 'WARN' | 'WARNING' | 'FAIL' | 'FAILED' | 'NOT DETECTED' | 'UNAVAILABLE' | 'REVIEW';
  severity?: FindingSeverity;
  evidence: string;
  explanation: string;
}

export interface IUrlRiskScoreContributor {
  name?: string;
  category: string;
  points: number;
  reason?: string;
  explanation?: string;
}

export type UrlExecutionOutcome =
  | 'COMPLETED'
  | 'INVALID_URL'
  | 'TARGET_UNREACHABLE'
  | 'ANALYSIS_UNAVAILABLE'
  | 'SCAN_FAILED'
  | 'BLOCKED_BY_SECURITY_POLICY';

export interface IUrlSecurityAnalysis {
  status: 'passed' | 'warning' | 'failed' | 'neutral';
  statusExplanation?: string;
  executionOutcome?: UrlExecutionOutcome;
  originalUrl?: string;
  normalizedUrl?: string;
  finalUrl?: string;
  finalHostname?: string;
  finalDomain?: string;
  registrableDomain?: string;
  urlLength: number;
  hostnameLength: number;
  pathLength?: number;
  queryLength?: number;
  punycodeHostname?: string;
  decodedHostname?: string;
  subdomainCount: number;
  subdomainsList?: string[];
  pathDepth: number;
  pathSegments?: string[];
  queryCount: number;
  queryParamKeys?: string[];
  hasEncodedChars: boolean;
  encodedSequences?: string[];
  hasPunycode: boolean;
  punycodeLabels?: string[];
  isDirectIp: boolean;
  isPrivateIp: boolean;
  isCustomPort: boolean;
  port: string;
  suspiciousPatterns: string[];
  resourceInterpretation: string;
  serverSoftware?: string;
  framework?: string;
  cdnProvider?: string;
  detectedTechnologies?: string[];
  threatIntelligence?: {
    status: string;
    provider?: string;
    result?: string;
    queried: boolean;
    timestamp?: string;
    indicators?: string[];
    details: string;
    providers?: Array<{
      provider: string;
      status: 'MATCH' | 'NO MATCH' | 'NOT CONFIGURED' | 'UNAVAILABLE' | 'RATE_LIMITED' | 'ERROR' | string;
      queried: boolean;
      queryTimeMs?: number;
      result: string;
      threatCategories?: string[];
      confidence?: 'HIGH' | 'MEDIUM' | 'LOW' | 'N/A' | string;
      details: string;
      sourceTimestamp?: string;
      stats?: {
        malicious?: number;
        suspicious?: number;
        harmless?: number;
        undetected?: number;
        timeout?: number;
        totalEngines?: number;
      };
    }>;
  };
  domainIntelligence?: {
    domain: string;
    hostname: string;
    isDirectIp?: boolean;
    isPrivate?: boolean;
    registrar?: string;
    registrationDate?: string;
    expirationDate?: string;
    updatedDate?: string;
    domainAgeDays?: number;
    domainAgeFormatted?: string;
    isNewlyRegistered?: boolean;
    domainStatus?: string[];
    nameservers?: string[];
    dnsRecords?: {
      a: string[];
      aaaa: string[];
      cname: string[];
      mx: Array<{ exchange: string; priority: number }>;
      ns: string[];
      txt: string[];
    };
    dnsResolved?: boolean;
    dnsError?: string;
    rdapStatus: 'OBSERVED' | 'NOT AVAILABLE' | 'LOOKUP_FAILED';
    rdapSource?: string;
    details: string;
  };
  certificateSummary?: {
    httpsEnabled: boolean;
    tlsVersion?: string;
    cipher?: string;
    subject?: string;
    issuer?: string;
    valid?: boolean;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    hostnameMatch?: boolean;
    statusText: string;
  };
  redirectJourney?: {
    totalHops: number;
    initialUrl: string;
    finalUrl: string;
    finalHostname: string;
    domainChanged: boolean;
    hasDowngrade?: boolean;
    protocolTransition?: string;
    hops: Array<{
      hopNumber: number;
      statusCode: number;
      statusText?: string;
      sourceUrl: string;
      destinationUrl: string;
      sourceHostname: string;
      destinationHostname: string;
      domainChanged: boolean;
      protocolTransition?: string;
      isDowngrade?: boolean;
    }>;
  };
  securityAudit: IUrlSecurityAuditCheck[];
  auditChecks?: IUrlSecurityAuditCheck[];
  scoreContributors: IUrlRiskScoreContributor[];
  positiveSignals: Array<{ title: string; desc: string }>;
  hasDowngrade?: boolean;
  whyVerdict?: string[];
  primaryFindings?: string[];
  limitations?: string[];
  details: string;
}

export interface ISecurityHeaderItem {
  name: string;
  status: 'present' | 'missing' | 'warning' | 'invalid';
  value?: string;
  explanation: string;
  recommendation: string;
  severity?: FindingSeverity;
}

export interface ICookieSecurityItem {
  name: string;
  valueMasked?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  domain?: string;
  path?: string;
  expires?: string;
  maxAge?: string;
  isFlagged?: boolean;
  issues?: string[];
  details?: string;
}

export interface IWebContentAnalysis {
  status: 'passed' | 'warning' | 'failed' | 'neutral';
  formsCount: number;
  passwordFormsCount: number;
  insecureFormsCount: number;
  externalFormActionsCount: number;
  scriptsCount: number;
  externalScriptsCount: number;
  iframesCount: number;
  mixedContentCount: number;
  mixedContentResources?: string[];
  externalDomains?: string[];
  details: string;
}

export interface IWebsiteOverview {
  pageTitle?: string;
  metaDescription?: string;
  category: string;
  purpose: string;
  primaryFunction: string;
  contentSummary: string;
  websiteType: string;
  confidence: 'High' | 'Medium' | 'Low';
  confidenceReason: string;
  evidence: {
    pageTitle?: string;
    metaDescription?: string;
    headings?: string[];
    keywordsDetected?: string[];
    hasLoginForm?: boolean;
    isSpaIndicator?: boolean;
  };
  observedBullets: string[];
}

export interface IWebsiteScoreContributor {
  findingId?: string;
  category: string;
  title: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  contribution: number;
  reason: string;
  evidence?: string;
  remediation?: string;
}

export interface IWebsiteScoreExplanation {
  summary: string;
  rawScore: number;
  normalizedScore: number;
  contributors: IWebsiteScoreContributor[];
  limitations: string[];
}

export interface IWebsiteAuditCheck {
  id: string;
  checkId?: string;
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL' | 'NOT DETECTED' | 'UNAVAILABLE';
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence: string;
  explanation: string;
}

export interface IWebsiteSecurityV2Analysis {
  riskScore: number;
  riskLevel: 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  confidence: number;
  executionOutcome?: 'COMPLETED' | 'BLOCKED_BY_SSRF_POLICY' | 'TARGET_UNREACHABLE' | 'TIMEOUT' | 'DNS_FAILURE' | 'ANALYSIS_UNAVAILABLE' | 'FAILED';
  counts: {
    confirmedVulnerabilities: number;
    securityWeaknesses: number;
    hardeningRecommendations: number;
    informationalFindings: number;
    total: number;
  };
  whyVerdict: string[];
  whyThisVerdict?: string[];
  scoreContributors?: IWebsiteScoreContributor[];
  scoreExplanation?: IWebsiteScoreExplanation;
  findingsCounts?: {
    confirmedVulnerabilities: number;
    securityWeaknesses: number;
    hardeningRecommendations: number;
    informationalFindings: number;
    total: number;
  };
  positiveControls: Array<{
    title: string;
    desc: string;
    evidence?: string;
    category?: string;
  }>;
  cookieSecuritySummary: {
    totalCookies: number;
    secureMissing: number;
    httpOnlyMissing: number;
    sameSiteMissing: number;
    table: Array<{
      name: string;
      domain?: string;
      path?: string;
      secure: boolean;
      httpOnly: boolean;
      sameSite?: string;
      expires?: string;
      isPotentiallySensitive: boolean;
      assessment: string;
    }>;
  };
  technologyDetections: Array<{
    technology: string;
    category?: string;
    evidence: string;
    confidence: number;
  }>;
  websiteUnderstanding: {
    websiteType: string;
    industry: string;
    primaryPurpose: string;
    confidence: number;
    confidenceLabel: 'High' | 'Medium' | 'Low' | 'Unknown';
    evidence: string[];
    pageTitle?: string;
    metaDescription?: string;
    headings?: string[];
    canonicalUrl?: string;
  };
  technicalEvidence: ISecurityEvidence[];
  errorLeakage: {
    detected: boolean;
    findings: string[];
    details?: string;
  };
  threatIntelligence?: {
    status: string;
    provider: string;
    result: string;
    queried: boolean;
    details: string;
  };
  formsAnalysis?: {
    totalForms: number;
    passwordForms: number;
    insecureForms: number;
    externalFormActions: number;
    forms: Array<{
      action: string;
      method: string;
      isExternal: boolean;
      isPlaintextHttp: boolean;
      hasPasswordField: boolean;
      fieldTypes: string[];
    }>;
  };
  externalResources?: {
    totalCount: number;
    scriptsCount: number;
    externalScriptsCount: number;
    stylesheetsCount: number;
    imagesCount: number;
    iframesCount: number;
    mixedContentCount: number;
    mixedContentResources: string[];
    externalDomains: string[];
  };
  auditChecks?: IWebsiteAuditCheck[];
  limitations?: string[];
}

export interface IApiSecurityAnalysis {
  status: 'passed' | 'warning' | 'failed' | 'neutral';
  endpointUrl: string;
  httpMethod: string;
  statusCode?: number;
  responseTimeMs?: number;
  contentType?: string;
  corsConfig: {
    allowOrigin?: string;
    allowMethods?: string;
    allowHeaders?: string;
    allowCredentials?: string;
    status: string;
    isPermissive: boolean;
  };
  authIndicators: {
    status: string;
    details: string;
    scheme?: string;
  };
  rateLimitIndicators: {
    status: string;
    details: string;
    limit?: string;
    remaining?: string;
    reset?: string;
  };
  informationDisclosure: {
    status: string;
    details: string;
    disclosedHeaders?: string[];
    disclosedSecrets?: string[];
  };
  supportedMethods?: string[];
  responseStructure?: {
    format: 'JSON' | 'XML' | 'HTML' | 'Text' | 'Unknown';
    isStructured: boolean;
    previewSnippet?: string;
  };
  details: string;
}

// ── File Security Scanner Stage Contract Types ───────────────────────────────
export type IScanStageStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped';

export interface IScanStageResult<T = unknown> {
  stage: string;
  status: IScanStageStatus;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  error?: string | null;
  data?: T;
}

export interface IFileHashesData {
  md5: string;
  sha1: string;
  sha256: string;
  ssdeep?: string;
}

export interface IFileReputationProviderResult {
  provider: 'VirusTotal' | 'MalwareBazaar' | 'Hybrid Analysis' | string;
  status: 'not_configured' | 'unavailable' | 'rate_limited' | 'not_found' | 'malicious' | 'no_match';
  maliciousCount?: number;
  totalEngines?: number;
  detectionNames?: string[];
  permalink?: string;
  details?: string;
}

export interface IFileReputationStageData {
  providers: IFileReputationProviderResult[];
  overallVerdict: 'malicious' | 'clean' | 'unknown';
}

export interface IFileTypeStageData {
  detectedMime: string;
  detectedFormat: string;
  claimedExtension: string;
  isMismatch: boolean;
  isDoubleExtension: boolean;
  isMasquerading: boolean;
  sizeBytes: number;
  sizeFormatted: string;
  sizeAnomaly?: string;
  headerAnomaly?: string;
}

export interface IFileEntropyStageData {
  entropy: number;
  analyzedBytes: number;
  interpretation: 'low_entropy' | 'moderate_entropy' | 'high_entropy' | 'very_high_entropy';
  isPackedOrEncrypted: boolean;
  blockEntropy?: Array<{ offset: number; entropy: number }>;
}

export interface IFileStringsStageData {
  totalExtracted: number;
  urls: string[];
  ips: string[];
  domains: string[];
  emails?: string[];
  registryKeys?: string[];
  filePaths?: string[];
  suspiciousApis: string[];
  shellCommands: string[];
  base64Blobs: string[];
  scriptingIndicators: string[];
  cryptoWallets?: string[];
  ransomwareIndicators?: string[];
}

export interface IFileYaraMatch {
  ruleName: string;
  namespace: string;
  tags: string[];
  matchedStrings: string[];
  severity?: FindingSeverity;
  description?: string;
  author?: string;
}

export interface IFileYaraStageData {
  matches: IFileYaraMatch[];
  rulesScanned: number;
  status: 'done' | 'skipped' | 'failed';
  reason?: string;
}

export interface IFilePeAnalysis {
  isPe: boolean;
  machine?: string;
  compileTime?: string;
  entryPoint?: string;
  imageBase?: string;
  numberOfSections?: number;
  sections?: Array<{
    name: string;
    virtualSize: number;
    rawSize: number;
    entropy: number;
    characteristics: string[];
  }>;
  imports?: Array<{ library: string; functions: string[] }>;
  suspiciousImports?: string[];
  hasOverlay?: boolean;
  overlaySizeBytes?: number;
  isDigitallySigned?: boolean;
  signatureValid?: boolean;
  packerDetected?: string;
}

export interface IFilePdfAnalysis {
  isPdf: boolean;
  version?: string;
  pageCount?: number;
  hasJavaScript: boolean;
  hasOpenAction: boolean;
  hasLaunch: boolean;
  hasEmbeddedFiles: boolean;
  suspiciousKeywords: string[];
  suspiciousLinks: string[];
}

export interface IFileOfficeAnalysis {
  isOffice: boolean;
  format?: string;
  hasVbaMacros: boolean;
  macroIndicators: string[];
  hasDde: boolean;
  externalLinks: string[];
  embeddedObjects: string[];
}

export interface IFileArchiveAnalysis {
  isArchive: boolean;
  format?: string;
  totalFiles: number;
  totalUncompressedBytes: number;
  compressionRatio: number;
  hasPathTraversal: boolean;
  hasZipSlip: boolean;
  hasExecutables: boolean;
  isPasswordProtected: boolean;
  filesList: Array<{
    path: string;
    size: number;
    compressedSize: number;
    isSuspicious: boolean;
  }>;
}

export interface IFileScriptAnalysis {
  isScript: boolean;
  scriptType?: string;
  hasObfuscation: boolean;
  hasEvalOrExec: boolean;
  hasEncodedCommand: boolean;
  hasNetworkCalls: boolean;
  suspiciousTokens: string[];
}

export interface IFileApkAnalysis {
  isApk: boolean;
  packageName?: string;
  permissions: string[];
  dangerousPermissions: string[];
  exportedComponents: string[];
}

export interface IFileMlStageData {
  status: 'available' | 'unavailable';
  reason?: string;
  prediction?: string;
  probability?: number;
  features?: Record<string, number | string>;
  shapExplanations?: Array<{ feature: string; contribution: number }>;
}

export interface IFileScoreContributor {
  findingId?: string;
  category: string;
  title: string;
  severity: FindingSeverity;
  contribution: number;
  reason: string;
  evidence?: string;
}

export interface IFileSecurityAnalysis {
  status: 'passed' | 'warning' | 'failed' | 'neutral';
  filename: string;
  sanitizedDisplayFilename?: string;
  extension: string;
  mimeType: string;
  detectedFormat?: string;
  fileSize?: number;
  fileSizeFormatted?: string;
  sha256?: string;
  md5?: string;
  sha1?: string;
  ssdeep?: string;
  magicBytes?: string;
  structureRisk?: string;
  archiveContents?: string[];
  entropy?: number;
  entropyInterpretation?: string;
  stages?: {
    hashing?: IScanStageResult<IFileHashesData>;
    reputation?: IScanStageResult<IFileReputationStageData>;
    fileType?: IScanStageResult<IFileTypeStageData>;
    entropy?: IScanStageResult<IFileEntropyStageData>;
    strings?: IScanStageResult<IFileStringsStageData>;
    yara?: IScanStageResult<IFileYaraStageData>;
    typeSpecific?: IScanStageResult<{
      pe?: IFilePeAnalysis;
      pdf?: IFilePdfAnalysis;
      office?: IFileOfficeAnalysis;
      archive?: IFileArchiveAnalysis;
      script?: IFileScriptAnalysis;
      apk?: IFileApkAnalysis;
    }>;
    ml?: IScanStageResult<IFileMlStageData>;
  };
  scoreContributors?: IFileScoreContributor[];
  details: string;
}

export interface IExtensionScoreContributor {
  id?: string;
  findingId?: string;
  category: string;
  title: string;
  severity: FindingSeverity;
  contribution: number;
  reason?: string;
  rationale?: string;
  evidence?: string;
  source?: string;
  location?: string;
  remediation?: string;
}

export interface IExtensionScoreExplanation {
  summary: string;
  rawScore: number;
  normalizedScore: number;
  contributors: IExtensionScoreContributor[];
  positiveSignals: Array<{ title: string; desc: string; category?: string }>;
  limitations: string[];
}

export interface IExtensionPackageIdentity {
  format?: 'CRX2' | 'CRX3' | 'ZIP' | 'XPI' | 'MANIFEST_JSON' | 'STORE_URL' | 'UNKNOWN';
  extensionId?: string;
  publicKey?: string;
  integrityValid?: boolean;
  fileCount?: number;
  totalSizeBytes?: number;
  sha256?: string;
  fileList?: string[];
  crxVersion?: number;
  manifestLocation?: string;
}

export interface IExtensionStoreMetadata {
  status: 'FOUND' | 'NOT_FOUND' | 'UNAVAILABLE' | 'NOT_APPLICABLE' | 'NOT_CONFIGURED';
  store?: 'Chrome Web Store' | 'Microsoft Edge Add-ons' | 'Firefox Add-ons' | string;
  name?: string;
  developer?: string;
  developerVerified?: boolean;
  userCount?: number;
  rating?: number;
  ratingCount?: number;
  lastUpdated?: string;
  privacyPolicyUrl?: string;
  storeUrl?: string;
  isRemovedOrFlagged?: boolean;
}

export interface IExtensionCodeFinding {
  id: string;
  file: string;
  line?: number | string;
  severity: FindingSeverity;
  pattern: string;
  evidenceSnippet?: string;
  explanation: string;
  riskContribution: number;
}

export interface IExtensionNetworkIndicator {
  url?: string;
  domain?: string;
  ip?: string;
  sourceFile?: string;
  context?: string;
  reputationStatus?: string;
  status: string;
  isSuspicious?: boolean;
}

export interface IExtensionPermissionDetail {
  name: string;
  severity: FindingSeverity;
  source: string;
  capability: string;
  securityImpact: string;
  actualUsage: 'Detected' | 'Not detected' | 'Not analyzed';
  usageEvidence?: string;
  contribution: number;
}

export interface IExtensionScanStage {
  stage: string;
  status: 'pending' | 'running' | 'done' | 'failed' | 'skipped';
  durationMs: number;
  reason?: string;
  coverage?: string;
  error?: string;
}

export interface IExtensionJsAnalysis {
  evalFound: boolean;
  newFunctionFound: boolean;
  dynamicScriptInjection: boolean;
  remoteCodeExecution: boolean;
  obfuscationIndicators: string[];
  sensitiveApisUsed: string[];
  cookieAccessObserved: boolean;
  credentialFormAccessObserved: boolean;
  clipboardAccessObserved: boolean;
  externalDataTransmission: boolean;
  externalEndpoints: string[];
}

export interface IExtensionSecurityAnalysis {
  status: 'passed' | 'warning' | 'failed' | 'neutral';
  scanStatus?: 'COMPLETE' | 'PARTIAL' | 'INCOMPLETE' | 'FAILED';
  scanStatusExplanation?: string;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'ANALYSIS INCOMPLETE';
  verdictReason: string;
  extensionName: string;
  version?: string;
  manifestVersion: number;
  extensionId?: string;
  description?: string;
  author?: string;
  homepageUrl?: string;
  updateUrl?: string;
  declaredPurpose?: string;
  purposeMatchAssessment?: string;
  permissions: string[];
  hostPermissions: string[];
  dangerousPermissions: Array<{
    permission: string;
    severity: FindingSeverity;
    reason: string;
  }>;
  permissionDetails?: IExtensionPermissionDetail[];
  backgroundScripts?: string[];
  contentScripts?: string[];
  webAccessibleResources?: string[];
  csp?: string;
  packageIdentity?: IExtensionPackageIdentity;
  storeMetadata?: IExtensionStoreMetadata;
  jsAnalysis?: IExtensionJsAnalysis;
  codeFindings?: IExtensionCodeFinding[];
  networkIndicators?: IExtensionNetworkIndicator[];
  reputationData?: {
    status: 'NOT_CONFIGURED' | 'UNAVAILABLE' | 'CLEAN' | 'MALICIOUS';
    provider?: string;
    queryType?: string;
    result?: string;
    timestamp?: string;
    details?: string;
  };
  privacyAnalysis?: {
    dataCapabilities: string[];
    observedDataAccess: string[];
    externalDataTransmission: boolean;
    dataExfiltrationRisk: 'None' | 'Low' | 'Moderate' | 'High' | 'Critical';
    details: string;
  };
  provenance?: {
    source: string;
    store?: string;
    developer?: string;
    extensionId?: string;
    version?: string;
    sha256?: string;
    packageType?: string;
    scanTimestamp: string;
  };
  breakdown?: {
    permissions: { riskLevel: string; findingCount: number; explanation: string; evidenceCount: number };
    websiteAccess: { riskLevel: string; findingCount: number; explanation: string; evidenceCount: number };
    codeBehaviour: { riskLevel: string; findingCount: number; explanation: string; evidenceCount: number };
    privacyExposure: { riskLevel: string; findingCount: number; explanation: string; evidenceCount: number };
    networkIndicators: { riskLevel: string; findingCount: number; explanation: string; evidenceCount: number };
    reputation: { riskLevel: string; findingCount: number; explanation: string; evidenceCount: number };
    manifestArchitecture: { riskLevel: string; findingCount: number; explanation: string; evidenceCount: number };
  };
  stages?: IExtensionScanStage[];
  scoreContributors: IExtensionScoreContributor[];
  scoreExplanation: IExtensionScoreExplanation;
  positiveSignals: Array<{ title: string; desc: string; category?: string }>;
  recommendations?: string[];
  limitations: string[];
  disclaimer: string;
  details: string;
}

export type PhishingIndicatorCategory =
  | 'URL_STRUCTURE'
  | 'DOMAIN_IDENTITY'
  | 'REDIRECT_BEHAVIOR'
  | 'PAGE_IDENTITY'
  | 'CREDENTIAL_COLLECTION'
  | 'FORM_DESTINATIONS'
  | 'SOCIAL_ENGINEERING'
  | 'TRANSPORT_SECURITY'
  | 'THREAT_INTELLIGENCE';

export interface IPhishingIndicator {
  id: string;
  category: PhishingIndicatorCategory;
  categoryLabel: string;
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL' | 'INFORMATIONAL' | 'NOT_CONFIGURED';
  severity?: FindingSeverity;
  scoreContribution: number;
  observed: string;
  explanation: string;
  evidence?: string;
}

export interface IPhishingScoreContributor {
  findingId?: string;
  category: string;
  title: string;
  severity: FindingSeverity;
  contribution: number;
  reason: string;
  evidence?: string;
  remediation?: string;
}

export interface IPhishingScoreExplanation {
  summary: string;
  rawScore: number;
  normalizedScore: number;
  contributors: IPhishingScoreContributor[];
  positiveSignals: Array<{ title: string; desc: string; category?: string }>;
  limitations: string[];
}

export interface IPhishingSecurityAnalysis {
  status: 'passed' | 'warning' | 'failed' | 'neutral';
  executionOutcome?: 'COMPLETED' | 'BLOCKED_BY_SSRF_POLICY' | 'TARGET_UNREACHABLE' | 'TIMEOUT' | 'DNS_FAILURE' | 'ANALYSIS_UNAVAILABLE' | 'FAILED';
  statusExplanation?: string;
  confidence: number;
  confidenceLabel: 'High' | 'Moderate' | 'Low' | 'Baseline';
  riskScore: number;
  riskLevel: 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  details: string;
  summary: string;

  targetProfile: {
    originalUrl: string;
    normalizedUrl: string;
    finalUrl: string;
    hostname: string;
    domain: string;
    registrableDomain?: string;
    isIpAddress: boolean;
    isPunycode: boolean;
    subdomainCount: number;
    pathDepth: number;
    queryParamCount: number;
  };

  redirectAnalysis: {
    totalHops: number;
    hasCrossDomainRedirect: boolean;
    hasProtocolDowngrade: boolean;
    chain: Array<{
      hopNumber: number;
      sourceUrl: string;
      destinationUrl: string;
      statusCode?: number;
      statusText?: string;
      isCrossDomain: boolean;
      isDowngrade?: boolean;
    }>;
    assessment: string;
  };

  domainIdentityAnalysis: {
    claimedBrand?: string;
    detectedBrands: string[];
    isLegitimateBrandDomain: boolean;
    impersonationDetected: boolean;
    impersonationEvidence?: string;
    homographDetected: boolean;
    punycodeLabels: string[];
    suspiciousSubdomains: string[];
    assessment: string;
  };

  pageIdentityAnalysis: {
    pageTitle?: string;
    metaDescription?: string;
    headings?: string[];
    claimedIdentity?: string;
    identityConsistency: 'CONSISTENT' | 'SUSPICIOUS_MISMATCH' | 'GENERIC_UNBRANDED' | 'UNAVAILABLE';
    assessment: string;
  };

  credentialAnalysis: {
    hasLoginForm: boolean;
    hasPasswordField: boolean;
    hasUsernameOrEmailField: boolean;
    hasMfaField: boolean;
    formCount: number;
    passwordFormCount: number;
    insecureFormCount: number;
    externalActionFormCount: number;
    forms: Array<{
      action: string;
      method: string;
      isExternal: boolean;
      isPlaintext: boolean;
      hasPasswordField: boolean;
      hasUsernameField: boolean;
      actionHostname?: string;
    }>;
    assessment: string;
  };

  socialEngineeringAnalysis: {
    urgencyKeywordsFound: string[];
    securityAlertKeywordsFound: string[];
    rewardKeywordsFound: string[];
    isHeuristicSignal: boolean;
    assessment: string;
  };

  transportAnalysis: {
    usesHttps: boolean;
    tlsValid?: boolean;
    tlsProtocol?: string;
    issuer?: string;
    certificateExpired?: boolean;
    hostnameMatch?: boolean;
    assessment: string;
  };

  threatIntelligence: {
    status: 'Not Configured' | 'Queried' | 'Unavailable' | 'Clean' | 'Threat Detected';
    provider?: string;
    queried: boolean;
    result?: string;
    details: string;
  };

  indicators: IPhishingIndicator[];
  scoreContributors: IPhishingScoreContributor[];
  scoreExplanation: IPhishingScoreExplanation;
  positiveSignals: Array<{ title: string; desc: string; category?: string }>;
  limitations: string[];
  technicalDetails: {
    originalUrl: string;
    finalUrl: string;
    hostname: string;
    resolvedIps: string[];
    httpStatus?: number;
    contentType?: string;
    responseTimeMs?: number;
    tlsVersion?: string;
    tlsCipher?: string;
    server?: string;
    dnsStatus?: string;
    scanDurationMs?: number;
  };
}

export interface IScanChecks {
  urlAnalysis: {
    status: 'passed' | 'warning' | 'failed' | 'neutral';
    scheme?: string;
    port?: string;
    path?: string;
    subdomains?: number;
    details: string;
  };
  sslAnalysis: {
    status: 'passed' | 'warning' | 'failed' | 'neutral';
    protocol?: string;
    issuer?: string;
    subject?: string;
    valid?: boolean;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    cipher?: string;
    details: string;
  };
  domainAnalysis: {
    status: 'passed' | 'warning' | 'failed' | 'neutral';
    hostname?: string;
    resolvedIps?: string[];
    ipVersion?: string;
    dnsStatus?: string;
    details: string;
  };
  httpAnalysis?: {
    status: 'passed' | 'warning' | 'failed' | 'neutral';
    statusCode?: number;
    statusText?: string;
    contentType?: string;
    contentLength?: number;
    server?: string;
    responseTimeMs?: number;
    finalUrl?: string;
    securityHeaders?: Record<string, string>;
    details: string;
  };
  securityHeadersAnalysis?: {
    status: 'passed' | 'warning' | 'failed' | 'neutral';
    score?: number;
    totalChecked: number;
    presentCount: number;
    missingCount: number;
    warningCount: number;
    headers: ISecurityHeaderItem[];
    details: string;
  };
  cookiesAnalysis?: {
    status: 'passed' | 'warning' | 'neutral';
    totalCookies: number;
    secureCookies: number;
    httpOnlyCookies: number;
    sameSiteCookies: number;
    flaggedCookies: number;
    cookies: ICookieSecurityItem[];
    details: string;
  };
  contentAnalysis?: IWebContentAnalysis;
  websiteOverview?: IWebsiteOverview;
  websiteSecurityV2?: IWebsiteSecurityV2Analysis;
  apiAnalysis?: IApiSecurityAnalysis;
  fileAnalysis?: IFileSecurityAnalysis;
  extensionAnalysis?: IExtensionSecurityAnalysis;
  urlSecurityAnalysis?: IUrlSecurityAnalysis;
  phishingSecurityAnalysis?: IPhishingSecurityAnalysis;

  phishingAnalysis: {
    status: 'passed' | 'warning' | 'failed' | 'neutral';
    confidence: number;
    details: string;
    riskScore?: number;
    riskLevel?: 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
    summary?: string;
    executionOutcome?: 'COMPLETED' | 'BLOCKED_BY_SSRF_POLICY' | 'TARGET_UNREACHABLE' | 'TIMEOUT' | 'DNS_FAILURE' | 'ANALYSIS_UNAVAILABLE' | 'FAILED';
  };
  redirectAnalysis: {
    status: 'passed' | 'warning' | 'failed' | 'neutral';
    redirectCount?: number;
    destination?: string;
    chain?: Array<{ url: string; statusCode?: number; statusText?: string }>;
    details: string;
  };
}

export interface IScan extends Document {
  userId?: Types.ObjectId;
  target: string;
  targetType: ScanTargetType;
  result: ScanResultClassification;
  riskScore: number;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  checks: IScanChecks;
  findings: IScanFinding[];
  recommendations: string[];
  scannedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

const scanFindingSchema = new Schema<IScanFinding>(
  {
    id: { type: String },
    findingId: { type: String },
    source: { type: String },
    scoreContribution: { type: Number },
    category: { type: String, required: true },
    findingCategory: {
      type: String,
      enum: ['CONFIRMED_VULNERABILITY', 'SECURITY_WEAKNESS', 'HARDENING_RECOMMENDATION', 'INFORMATIONAL'],
    },
    severity: {
      type: String,
      enum: FINDING_SEVERITIES,
      set: (v: string) => (typeof v === 'string' ? (v.toUpperCase() as FindingSeverity) : v),
      get: (v: string) => (typeof v === 'string' ? (v.toUpperCase() as FindingSeverity) : v),
      required: true,
    },
    title: { type: String, required: true },
    description: { type: String, required: true },
    evidence: { type: String },
    evidences: { type: Schema.Types.Mixed },
    confidence: { type: Number },
    verificationStatus: {
      type: String,
      enum: ['CONFIRMED', 'PARTIALLY_VERIFIED', 'OBSERVED', 'NOT_VERIFIED'],
    },
    impact: { type: String },
    verification: { type: String },
    recommendation: { type: String },
    references: [{ type: String }],
    affectedComponent: { type: String },
  },
  { _id: false }
);

const scanSchema = new Schema<IScan>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      index: true,
    },
    target: {
      type: String,
      required: [true, 'Target URL is required'],
      trim: true,
    },
    targetType: {
      type: String,
      enum: SCAN_TARGET_TYPES,
      default: 'URL',
    },
    result: {
      type: String,
      enum: SCAN_RESULT_CLASSIFICATIONS,
      required: true,
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      required: true,
    },
    status: {
      type: String,
      enum: ['pending', 'scanning', 'completed', 'failed'],
      default: 'completed',
    },
    checks: {
      urlAnalysis: {
        status: { type: String, enum: ['passed', 'warning', 'failed', 'neutral'], default: 'passed' },
        scheme: String,
        port: String,
        path: String,
        subdomains: Number,
        details: { type: String, default: '' },
      },
      sslAnalysis: {
        status: { type: String, enum: ['passed', 'warning', 'failed', 'neutral'], default: 'passed' },
        protocol: String,
        issuer: String,
        subject: String,
        valid: Boolean,
        validFrom: String,
        validTo: String,
        daysRemaining: Number,
        cipher: String,
        details: { type: String, default: '' },
      },
      domainAnalysis: {
        status: { type: String, enum: ['passed', 'warning', 'failed', 'neutral'], default: 'passed' },
        hostname: String,
        resolvedIps: [String],
        ipVersion: String,
        dnsStatus: String,
        details: { type: String, default: '' },
      },
      httpAnalysis: {
        status: { type: String, enum: ['passed', 'warning', 'failed', 'neutral'], default: 'passed' },
        statusCode: Number,
        statusText: String,
        contentType: String,
        contentLength: Number,
        server: String,
        responseTimeMs: Number,
        finalUrl: String,
        securityHeaders: { type: Map, of: String },
        details: { type: String, default: '' },
      },
      securityHeadersAnalysis: { type: Schema.Types.Mixed },
      cookiesAnalysis: { type: Schema.Types.Mixed },
      contentAnalysis: { type: Schema.Types.Mixed },
      websiteOverview: { type: Schema.Types.Mixed },
      websiteSecurityV2: { type: Schema.Types.Mixed },
      apiAnalysis: { type: Schema.Types.Mixed },
      fileAnalysis: { type: Schema.Types.Mixed },
      extensionAnalysis: { type: Schema.Types.Mixed },
      urlSecurityAnalysis: { type: Schema.Types.Mixed },
      phishingSecurityAnalysis: { type: Schema.Types.Mixed },
      phishingAnalysis: {
        status: { type: String, enum: ['passed', 'warning', 'failed', 'neutral'], default: 'passed' },
        confidence: { type: Number, default: 0 },
        details: { type: String, default: '' },
      },
      redirectAnalysis: {
        status: { type: String, enum: ['passed', 'warning', 'failed', 'neutral'], default: 'passed' },
        redirectCount: { type: Number, default: 0 },
        destination: String,
        chain: [{ url: String, statusCode: Number, statusText: String, _id: false }],
        details: { type: String, default: '' },
      },
    },
    findings: [scanFindingSchema],
    recommendations: [{ type: String }],
    scannedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

export function toSafeScanRecord(scan: IScan) {
  return {
    id: scan._id.toString(),
    userId: scan.userId ? scan.userId.toString() : undefined,
    target: scan.target,
    targetType: scan.targetType,
    result: scan.result,
    riskScore: scan.riskScore,
    status: scan.status,
    checks: scan.checks,
    findings: (scan.findings || []).map((f) => {
      const obj = (f && typeof (f as any).toObject === 'function') ? (f as any).toObject() : { ...f };
      if (obj && typeof obj.severity === 'string') {
        obj.severity = obj.severity.toUpperCase() as FindingSeverity;
      }
      return obj;
    }),
    recommendations: scan.recommendations,
    scannedAt: scan.scannedAt,
    createdAt: scan.createdAt,
  };
}

export type SafeScanRecord = ReturnType<typeof toSafeScanRecord>;

export const Scan = model<IScan>('Scan', scanSchema);
