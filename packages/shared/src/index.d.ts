export type HealthStatus = {
    success: boolean;
    service: string;
    status: string;
};
export type UserRole = 'USER' | 'ANALYST' | 'ADMIN';
export type User = {
    id: string;
    name: string;
    email: string;
    role: UserRole;
    isActive: boolean;
    createdAt: string | Date;
};
export type AuthResponse = {
    success: boolean;
    message: string;
    data: {
        user: User;
        token: string;
    };
};
export type ApiResponse<T = unknown> = {
    success: boolean;
    message: string;
    data?: T;
    errors?: Array<{
        field: string;
        message: string;
    }>;
};
export type ScanResultClassification = 'Safe' | 'Low Risk' | 'Suspicious' | 'High Risk' | 'Critical';
export type ScanTargetType = 'URL' | 'Website' | 'API' | 'Phishing' | 'File' | 'Extension';
export type FindingSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SecurityEvidenceSource = 'http' | 'tls' | 'headers' | 'cookies' | 'html' | 'redirect' | 'dns' | 'content' | 'technology';
export type SecurityEvidence = {
    source: SecurityEvidenceSource;
    check: string;
    observed: string;
    expected?: string;
    location?: string;
    confidence: number;
    metadata?: Record<string, unknown>;
};
export type FindingCategory = 'CONFIRMED_VULNERABILITY' | 'SECURITY_WEAKNESS' | 'HARDENING_RECOMMENDATION' | 'INFORMATIONAL';
export type FindingVerificationStatus = 'CONFIRMED' | 'PARTIALLY_VERIFIED' | 'OBSERVED' | 'NOT_VERIFIED';
export type ScanFinding = {
    id?: string;
    category: string;
    findingCategory?: FindingCategory;
    severity: FindingSeverity;
    title: string;
    description: string;
    evidence?: string;
    evidences?: SecurityEvidence[];
    confidence?: number;
    verificationStatus?: FindingVerificationStatus;
    impact?: string;
    verification?: string;
    recommendation?: string;
    references?: string[];
    affectedComponent?: string;
};
export type UrlSecurityAuditCheck = {
    id?: string;
    name?: string;
    title?: string;
    category?: string;
    status: 'PASS' | 'WARN' | 'WARNING' | 'FAIL' | 'FAILED' | 'NOT DETECTED' | 'UNAVAILABLE' | 'REVIEW';
    severity?: FindingSeverity;
    evidence: string;
    explanation: string;
};
export type UrlRiskScoreContributor = {
    name?: string;
    category: string;
    points: number;
    reason?: string;
    explanation?: string;
};
export type UrlExecutionOutcome = 'COMPLETED' | 'INVALID_URL' | 'TARGET_UNREACHABLE' | 'ANALYSIS_UNAVAILABLE' | 'SCAN_FAILED' | 'BLOCKED_BY_SECURITY_POLICY';
export type UrlSecurityAnalysis = {
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
            mx: Array<{
                exchange: string;
                priority: number;
            }>;
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
    securityAudit: UrlSecurityAuditCheck[];
    auditChecks?: UrlSecurityAuditCheck[];
    scoreContributors: UrlRiskScoreContributor[];
    positiveSignals: Array<{
        title: string;
        desc: string;
    }>;
    hasDowngrade?: boolean;
    whyVerdict?: string[];
    primaryFindings?: string[];
    limitations?: string[];
    details: string;
};
export type SecurityHeaderItem = {
    name: string;
    status: 'present' | 'missing' | 'warning' | 'invalid';
    value?: string;
    explanation: string;
    recommendation: string;
    severity?: FindingSeverity;
};
export type CookieSecurityItem = {
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
};
export type WebContentAnalysis = {
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
};
export type WebsiteOverview = {
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
};
export type WebsiteScoreContributor = {
    findingId?: string;
    category: string;
    title: string;
    severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    contribution: number;
    reason: string;
    evidence?: string;
    remediation?: string;
};
export type WebsiteScoreExplanation = {
    summary: string;
    rawScore: number;
    normalizedScore: number;
    contributors: WebsiteScoreContributor[];
    limitations: string[];
};
export type WebsiteAuditCheck = {
    id: string;
    checkId?: string;
    name: string;
    status: 'PASS' | 'WARN' | 'FAIL' | 'NOT DETECTED' | 'UNAVAILABLE';
    severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    evidence: string;
    explanation: string;
};
export type WebsiteSecurityV2Analysis = {
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
    scoreContributors?: WebsiteScoreContributor[];
    scoreExplanation?: WebsiteScoreExplanation;
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
    technicalEvidence: SecurityEvidence[];
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
    auditChecks?: WebsiteAuditCheck[];
    limitations?: string[];
};
export type ApiSecurityAnalysis = {
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
};
export type ScanStageStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped';
export interface ScanStageResult<T = unknown> {
    stage: string;
    status: ScanStageStatus;
    startedAt: string;
    completedAt: string;
    durationMs: number;
    error?: string | null;
    data?: T;
}
export interface FileHashesData {
    md5: string;
    sha1: string;
    sha256: string;
    ssdeep?: string;
}
export interface FileReputationProviderResult {
    provider: 'VirusTotal' | 'MalwareBazaar' | 'Hybrid Analysis' | string;
    status: 'not_configured' | 'unavailable' | 'rate_limited' | 'not_found' | 'malicious' | 'no_match';
    maliciousCount?: number;
    totalEngines?: number;
    detectionNames?: string[];
    permalink?: string;
    details?: string;
}
export interface FileReputationStageData {
    providers: FileReputationProviderResult[];
    overallVerdict: 'malicious' | 'clean' | 'unknown';
}
export interface FileTypeStageData {
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
export interface FileEntropyStageData {
    entropy: number;
    analyzedBytes: number;
    interpretation: 'low_entropy' | 'moderate_entropy' | 'high_entropy' | 'very_high_entropy';
    isPackedOrEncrypted: boolean;
    blockEntropy?: Array<{
        offset: number;
        entropy: number;
    }>;
}
export interface FileStringsStageData {
    totalExtracted: number;
    urls: string[];
    ips: string[];
    domains: string[];
    suspiciousApis: string[];
    shellCommands: string[];
    base64Blobs: string[];
    scriptingIndicators: string[];
}
export interface FileYaraMatch {
    ruleName: string;
    namespace: string;
    tags: string[];
    matchedStrings: string[];
    severity?: FindingSeverity;
    description?: string;
    author?: string;
}
export interface FileYaraStageData {
    matches: FileYaraMatch[];
    rulesScanned: number;
    status: 'done' | 'skipped' | 'failed';
    reason?: string;
}
export interface FilePeAnalysis {
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
    imports?: Array<{
        library: string;
        functions: string[];
    }>;
    suspiciousImports?: string[];
    hasOverlay?: boolean;
    overlaySizeBytes?: number;
    isDigitallySigned?: boolean;
    signatureValid?: boolean;
    packerDetected?: string;
}
export interface FilePdfAnalysis {
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
export interface FileOfficeAnalysis {
    isOffice: boolean;
    format?: string;
    hasVbaMacros: boolean;
    macroIndicators: string[];
    hasDde: boolean;
    externalLinks: string[];
    embeddedObjects: string[];
}
export interface FileArchiveAnalysis {
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
export interface FileScriptAnalysis {
    isScript: boolean;
    scriptType?: string;
    hasObfuscation: boolean;
    hasEvalOrExec: boolean;
    hasEncodedCommand: boolean;
    hasNetworkCalls: boolean;
    suspiciousTokens: string[];
}
export interface FileApkAnalysis {
    isApk: boolean;
    packageName?: string;
    permissions: string[];
    dangerousPermissions: string[];
    exportedComponents: string[];
}
export interface FileMlStageData {
    status: 'available' | 'unavailable';
    reason?: string;
    prediction?: string;
    probability?: number;
    features?: Record<string, number | string>;
    shapExplanations?: Array<{
        feature: string;
        contribution: number;
    }>;
}
export interface FileScoreContributor {
    findingId?: string;
    category: string;
    title: string;
    severity: FindingSeverity;
    contribution: number;
    reason: string;
    evidence?: string;
}
export type FileSecurityAnalysis = {
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
        hashing?: ScanStageResult<FileHashesData>;
        reputation?: ScanStageResult<FileReputationStageData>;
        fileType?: ScanStageResult<FileTypeStageData>;
        entropy?: ScanStageResult<FileEntropyStageData>;
        strings?: ScanStageResult<FileStringsStageData>;
        yara?: ScanStageResult<FileYaraStageData>;
        typeSpecific?: ScanStageResult<{
            pe?: FilePeAnalysis;
            pdf?: FilePdfAnalysis;
            office?: FileOfficeAnalysis;
            archive?: FileArchiveAnalysis;
            script?: FileScriptAnalysis;
            apk?: FileApkAnalysis;
        }>;
        ml?: ScanStageResult<FileMlStageData>;
    };
    scoreContributors?: FileScoreContributor[];
    details: string;
};
export interface ExtensionScoreContributor {
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
export interface ExtensionScoreExplanation {
    summary: string;
    rawScore: number;
    normalizedScore: number;
    contributors: ExtensionScoreContributor[];
    positiveSignals: Array<{
        title: string;
        desc: string;
        category?: string;
    }>;
    limitations: string[];
}
export interface ExtensionPackageIdentity {
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
export interface ExtensionStoreMetadata {
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
export interface ExtensionCodeFinding {
    id: string;
    file: string;
    line?: number | string;
    severity: FindingSeverity;
    pattern: string;
    evidenceSnippet?: string;
    explanation: string;
    riskContribution: number;
}
export interface ExtensionNetworkIndicator {
    url?: string;
    domain?: string;
    ip?: string;
    sourceFile?: string;
    context?: string;
    reputationStatus?: string;
    status: string;
    isSuspicious?: boolean;
}
export interface ExtensionPermissionDetail {
    name: string;
    severity: FindingSeverity;
    source: string;
    capability: string;
    securityImpact: string;
    actualUsage: 'Detected' | 'Not detected' | 'Not analyzed';
    usageEvidence?: string;
    contribution: number;
}
export interface ExtensionScanStage {
    stage: string;
    status: 'pending' | 'running' | 'done' | 'failed' | 'skipped';
    durationMs: number;
    reason?: string;
    coverage?: string;
    error?: string;
}
export interface ExtensionJsAnalysis {
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
export type ExtensionSecurityAnalysis = {
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
    permissionDetails?: ExtensionPermissionDetail[];
    backgroundScripts?: string[];
    contentScripts?: string[];
    webAccessibleResources?: string[];
    csp?: string;
    packageIdentity?: ExtensionPackageIdentity;
    storeMetadata?: ExtensionStoreMetadata;
    jsAnalysis?: ExtensionJsAnalysis;
    codeFindings?: ExtensionCodeFinding[];
    networkIndicators?: ExtensionNetworkIndicator[];
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
        permissions: {
            riskLevel: string;
            findingCount: number;
            explanation: string;
            evidenceCount: number;
        };
        websiteAccess: {
            riskLevel: string;
            findingCount: number;
            explanation: string;
            evidenceCount: number;
        };
        codeBehaviour: {
            riskLevel: string;
            findingCount: number;
            explanation: string;
            evidenceCount: number;
        };
        privacyExposure: {
            riskLevel: string;
            findingCount: number;
            explanation: string;
            evidenceCount: number;
        };
        networkIndicators: {
            riskLevel: string;
            findingCount: number;
            explanation: string;
            evidenceCount: number;
        };
        reputation: {
            riskLevel: string;
            findingCount: number;
            explanation: string;
            evidenceCount: number;
        };
        manifestArchitecture: {
            riskLevel: string;
            findingCount: number;
            explanation: string;
            evidenceCount: number;
        };
    };
    stages?: ExtensionScanStage[];
    scoreContributors: ExtensionScoreContributor[];
    scoreExplanation: ExtensionScoreExplanation;
    positiveSignals: Array<{
        title: string;
        desc: string;
        category?: string;
    }>;
    recommendations?: string[];
    limitations: string[];
    disclaimer: string;
    details: string;
};
export type PhishingIndicatorCategory = 'URL_STRUCTURE' | 'DOMAIN_IDENTITY' | 'REDIRECT_BEHAVIOR' | 'PAGE_IDENTITY' | 'CREDENTIAL_COLLECTION' | 'FORM_DESTINATIONS' | 'SOCIAL_ENGINEERING' | 'TRANSPORT_SECURITY' | 'THREAT_INTELLIGENCE';
export type PhishingIndicator = {
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
};
export type PhishingScoreContributor = {
    findingId?: string;
    category: string;
    title: string;
    severity: FindingSeverity;
    contribution: number;
    reason: string;
    evidence?: string;
    remediation?: string;
};
export type PhishingScoreExplanation = {
    summary: string;
    rawScore: number;
    normalizedScore: number;
    contributors: PhishingScoreContributor[];
    positiveSignals: Array<{
        title: string;
        desc: string;
        category?: string;
    }>;
    limitations: string[];
};
export type PhishingSecurityAnalysis = {
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
    indicators: PhishingIndicator[];
    scoreContributors: PhishingScoreContributor[];
    scoreExplanation: PhishingScoreExplanation;
    positiveSignals: Array<{
        title: string;
        desc: string;
        category?: string;
    }>;
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
};
export type ScanCheckResults = {
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
        bodySnippet?: string;
        details: string;
    };
    securityHeadersAnalysis?: {
        status: 'passed' | 'warning' | 'failed' | 'neutral';
        score?: number;
        totalChecked: number;
        presentCount: number;
        missingCount: number;
        warningCount: number;
        headers: SecurityHeaderItem[];
        details: string;
    };
    cookiesAnalysis?: {
        status: 'passed' | 'warning' | 'neutral';
        totalCookies: number;
        secureCookies: number;
        httpOnlyCookies: number;
        sameSiteCookies: number;
        flaggedCookies: number;
        cookies: CookieSecurityItem[];
        details: string;
    };
    contentAnalysis?: WebContentAnalysis;
    websiteOverview?: WebsiteOverview;
    websiteSecurityV2?: WebsiteSecurityV2Analysis;
    apiAnalysis?: ApiSecurityAnalysis;
    fileAnalysis?: FileSecurityAnalysis;
    extensionAnalysis?: ExtensionSecurityAnalysis;
    urlSecurityAnalysis?: UrlSecurityAnalysis;
    phishingSecurityAnalysis?: PhishingSecurityAnalysis;
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
        chain?: Array<{
            url: string;
            statusCode?: number;
            statusText?: string;
        }>;
        details: string;
    };
};
export type ScanRecord = {
    id: string;
    userId?: string;
    target: string;
    targetType: ScanTargetType;
    result: ScanResultClassification;
    riskScore: number;
    status: 'pending' | 'scanning' | 'completed' | 'failed';
    checks: ScanCheckResults;
    findings: ScanFinding[];
    recommendations: string[];
    scannedAt: string | Date;
    createdAt: string | Date;
};
export type ScanStats = {
    totalScans: number;
    scansToday?: number;
    threatsDetected: number;
    securityFindings?: number;
    safeResults?: number;
    reportsCount: number;
    activeMonitoring: string;
    monitoringStatus?: string;
    lastScannedAt: string | Date | null;
    latestScan?: ScanRecord | null;
};
export type ThreatIntelIndicatorType = 'URL' | 'DOMAIN' | 'IP' | 'HASH_MD5' | 'HASH_SHA1' | 'HASH_SHA256' | 'EXTENSION_ID' | 'EXTENSION_HASH';
export type ThreatIntelProviderStatus = 'CONFIGURED' | 'NOT_CONFIGURED' | 'SUCCESS' | 'FAILED' | 'TIMEOUT' | 'RATE_LIMITED' | 'NOT_FOUND';
export type ThreatIntelReputation = 'MALICIOUS' | 'SUSPICIOUS' | 'UNKNOWN' | 'NO_MATCH' | 'INFORMATIONAL' | 'NOT_CONFIGURED' | 'UNAVAILABLE';
export type ThreatIntelConfidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export type ThreatIntelCategory = 'Malware' | 'Phishing' | 'Spam' | 'Botnet' | 'Command & Control' | 'Suspicious' | 'Scam' | 'Exploit' | 'Credential Theft' | 'Malicious Infrastructure' | 'Unwanted Software' | 'Unknown' | string;
export interface NormalizedIndicator {
    raw: string;
    type: ThreatIntelIndicatorType;
    canonical: string;
    normalized: string;
    display: string;
    isValid: boolean;
    validationError?: string;
    isPrivate?: boolean;
    metadata?: {
        ipVersion?: 'IPv4' | 'IPv6';
        hostname?: string;
        domain?: string;
        registrableDomain?: string;
        path?: string;
        hashType?: 'MD5' | 'SHA1' | 'SHA256';
        extensionStore?: 'Chrome' | 'Edge' | 'Firefox' | 'Generic';
    };
}
export interface ThreatIntelEvidenceItem {
    id: string;
    indicator: string;
    indicatorType: ThreatIntelIndicatorType;
    provider: string;
    evidenceType: string;
    category: ThreatIntelCategory;
    severity: FindingSeverity;
    confidence: ThreatIntelConfidence;
    value: string;
    description: string;
    firstSeen?: string;
    lastSeen?: string;
    sourceReference?: string;
    timestamp: string;
    rawSummary?: string;
}
export interface ThreatIntelRelatedIndicator {
    indicator: string;
    type: string;
    relationship: string;
    source: string;
    firstSeen?: string;
    lastSeen?: string;
}
export interface ThreatIntelProviderResult {
    providerId: string;
    providerName: string;
    configured: boolean;
    status: ThreatIntelProviderStatus;
    reputation: ThreatIntelReputation;
    queryType: string;
    responseTimeMs?: number;
    timestamp: string;
    errorCategory?: string;
    errorMessage?: string;
    detectionSummary?: {
        malicious: number;
        total?: number;
        suspicious?: number;
        harmless?: number;
        undetected?: number;
    };
    categories: ThreatIntelCategory[];
    evidence: ThreatIntelEvidenceItem[];
    relatedIndicators: ThreatIntelRelatedIndicator[];
    firstSeen?: string;
    lastSeen?: string;
    lastAnalysisDate?: string;
    details: string;
    sanitizedRawMetadata?: Record<string, unknown>;
}
export interface ThreatIntelAnalysisReport {
    analysisId: string;
    indicator: string;
    indicatorType: ThreatIntelIndicatorType;
    normalizedIndicator: string;
    canonicalValue: string;
    displayValue: string;
    status: 'MATCH_FOUND' | 'NO_MATCH' | 'PARTIAL' | 'UNAVAILABLE' | 'NOT_CONFIGURED' | 'ERROR';
    overallReputation: ThreatIntelReputation;
    confidence: ThreatIntelConfidence;
    confidenceExplanation: string;
    recommendation: string;
    detectionSummary?: {
        flaggedCount: number;
        totalEnginesQueried: number;
        providersWithDetections: number;
    };
    threatCategories: ThreatIntelCategory[];
    providersChecked: number;
    providersTotal: number;
    providers: ThreatIntelProviderResult[];
    evidence: ThreatIntelEvidenceItem[];
    relatedIndicators: ThreatIntelRelatedIndicator[];
    temporalData?: {
        firstSeen?: string;
        lastSeen?: string;
        lastAnalysisDate?: string;
        recentActivitySummary?: string;
    };
    correlationWithCyberWatch?: {
        targetMatchesExistingScanner?: boolean;
        suggestedScanner?: 'url' | 'website' | 'phishing' | 'file' | 'extension' | 'api';
        contextNote?: string;
    };
    createdAt: string;
    cached?: boolean;
}
export interface UnifiedEvidenceItem {
    sourceType: 'SCANNER' | 'THREAT_INTELLIGENCE';
    source: string;
    indicator: string;
    indicatorType: ThreatIntelIndicatorType;
    severity: FindingSeverity;
    confidence?: string;
    description: string;
    timestamp: string;
    reference?: string;
    relationship?: string;
}
export interface ExtractedIndicator {
    originalValue: string;
    normalizedValue: string;
    type: ThreatIntelIndicatorType;
    contextSource: string;
    isPrimary: boolean;
}
export interface UnifiedCorrelationResult {
    primaryIndicator: string;
    indicatorType: ThreatIntelIndicatorType;
    reputationStatus: ThreatIntelReputation;
    overallThreatStatus: 'MATCH_FOUND' | 'NO_MATCH' | 'PARTIAL' | 'UNAVAILABLE' | 'NOT_CONFIGURED';
    unifiedEvidence: UnifiedEvidenceItem[];
    scannerFindingsCount: number;
    threatIntelEvidenceCount: number;
    correlations: Array<{
        scannerIndicator: string;
        tiFinding: string;
        provider: string;
        correlationReason: string;
    }>;
}
export interface SecurityAdvisoryItem {
    cveId: string;
    title: string;
    summary: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    cvssScore?: number;
    affectedVersions?: string[];
    fixedVersions?: string[];
    publishedDate?: string;
    modifiedDate?: string;
    references: string[];
    source: string;
}
export interface StoredThreatIndicatorItem {
    id: string;
    analysisId: string;
    indicator: string;
    indicatorType: ThreatIntelIndicatorType;
    status: 'MATCH_FOUND' | 'NO_MATCH' | 'PARTIAL' | 'UNAVAILABLE' | 'NOT_CONFIGURED' | 'ERROR';
    overallReputation: ThreatIntelReputation;
    confidence: ThreatIntelConfidence;
    evidenceCount: number;
    sourcesCount: number;
    sources: string[];
    firstSeen?: string;
    lastSeen?: string;
    lastAnalysisDate: string;
    createdAt: string;
}
export interface RiskDistribution {
    low: number;
    medium: number;
    high: number;
    critical: number;
}
export interface ScannerTelemetrySummary {
    scanner: ScanTargetType | string;
    label: string;
    totalScans: number;
    completedScans: number;
    averageRiskScore: number | null;
    latestRiskScore: number | null;
    latestVerdict: string | null;
    criticalFindings: number;
    highFindings: number;
    riskDistribution: RiskDistribution;
}
export interface ReportOverviewStats {
    totalScans: number;
    completedScans: number;
    partialScans: number;
    failedScans: number;
    safeScans: number;
    findingsSeverity: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        total: number;
    };
    scannerBreakdown: Record<string, number>;
    scannerTelemetry: Record<string, ScannerTelemetrySummary>;
    hasData: boolean;
}
export type SupportCategory = 'SCANNER_ISSUE' | 'INCORRECT_SCAN_RESULT' | 'THREAT_INTELLIGENCE' | 'REPORT_EXPORT' | 'ACCOUNT_LOGIN' | 'BILLING_SUBSCRIPTION' | 'TECHNICAL_ISSUE' | 'FEATURE_REQUEST' | 'SECURITY_VULNERABILITY' | 'OTHER';
export type SupportPriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
export type SupportStatus = 'OPEN' | 'INVESTIGATING' | 'WAITING_FOR_USER' | 'RESOLVED' | 'CLOSED';
export type SupportSenderType = 'USER' | 'SUPPORT' | 'SYSTEM';
export interface SupportAttachment {
    id: string;
    originalName: string;
    sanitizedName: string;
    mimeType: string;
    sizeBytes: number;
    downloadUrl: string;
    createdAt: string;
}
export interface SupportMessage {
    id: string;
    senderType: SupportSenderType;
    senderUserId?: string;
    senderName: string;
    message: string;
    attachments: SupportAttachment[];
    createdAt: string;
}
export interface SupportTicket {
    id: string;
    ticketNumber: string;
    userId: string;
    name: string;
    email: string;
    category: SupportCategory;
    priority: SupportPriority;
    subject: string;
    description: string;
    scanId?: string;
    reportId?: string;
    targetUrl?: string;
    browserEnvironment?: string;
    status: SupportStatus;
    assignedTo?: string;
    assignedAgentName?: string;
    messages: SupportMessage[];
    attachments: SupportAttachment[];
    isSecurityReport?: boolean;
    metadata?: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
    resolvedAt?: string;
    closedAt?: string;
}
export type SecurityVulnerabilityType = 'AUTHENTICATION' | 'AUTHORIZATION' | 'XSS' | 'CSRF' | 'SSRF' | 'INJECTION' | 'DATA_EXPOSURE' | 'API_SECURITY' | 'PRIVACY' | 'ACCOUNT_TAKEOVER' | 'OTHER';
export type SecurityReportSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SecurityReportStatus = 'SUBMITTED' | 'TRIAGED' | 'FIX_IN_PROGRESS' | 'RESOLVED' | 'CLOSED' | 'INVALID';
export interface SecurityReport {
    id: string;
    reportNumber: string;
    userId?: string;
    email: string;
    vulnerabilityType: SecurityVulnerabilityType;
    severity: SecurityReportSeverity;
    affectedComponent: string;
    affectedUrl?: string;
    description: string;
    stepsToReproduce: string;
    impact: string;
    suggestedFix?: string;
    attachments: SupportAttachment[];
    status: SecurityReportStatus;
    createdAt: string;
    updatedAt: string;
}
export type SupportChatSessionStatus = 'CONNECTING' | 'WAITING_FOR_AGENT' | 'WAITING' | 'ACTIVE' | 'CLOSED' | 'ENDED';
export interface SupportChatMessage {
    id: string;
    senderType: SupportSenderType;
    senderName: string;
    message: string;
    createdAt: string;
    readAt?: string;
    attachments?: SupportAttachment[];
}
export interface SupportChatSession {
    id: string;
    sessionId: string;
    userId?: string;
    userName: string;
    userEmail: string;
    status: SupportChatSessionStatus;
    agentName?: string;
    assignedAgentId?: string;
    assignedAgentName?: string;
    priority?: SupportPriority;
    messages: SupportChatMessage[];
    convertedTicketNumber?: string;
    createdAt: string;
    updatedAt: string;
    endedAt?: string;
    closedAt?: string;
}
export interface SupportPublicConfig {
    supportEmail: string;
    securityEmail: string;
    supportPhone: string;
    supportWhatsapp: string;
    liveChatEnabled: boolean;
    supportHours: string;
    maxAttachmentSizeMb: number;
    allowedAttachmentExtensions: string[];
    allowedAttachmentMimeTypes: string[];
}
export interface CreateSupportTicketInput {
    name: string;
    email: string;
    category: SupportCategory;
    priority: SupportPriority;
    subject: string;
    description: string;
    scanId?: string;
    reportId?: string;
    targetUrl?: string;
    browserEnvironment?: string;
}
export interface CreateSecurityReportInput {
    email: string;
    vulnerabilityType: SecurityVulnerabilityType;
    severity: SecurityReportSeverity;
    affectedComponent: string;
    affectedUrl?: string;
    description: string;
    stepsToReproduce: string;
    impact: string;
    suggestedFix?: string;
}
export interface AISupportMessage {
    id: string;
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp: string;
    suggestedActions?: string[];
    sources?: string[];
    scanContext?: {
        scanId?: string;
        target: string;
        targetType?: string;
        riskScore: number;
        riskLevel: string;
        findingsCount?: number;
    };
    escalateToHuman?: boolean;
}
export interface ScanFindingContext {
    title: string;
    severity: string;
    description?: string;
    recommendation?: string;
    evidence?: unknown;
}
export interface ScanContextData {
    scanId?: string;
    target?: string;
    targetType?: string;
    riskScore?: number;
    riskLevel?: string;
    verdict?: string;
    findingsCount?: number;
    findings?: ScanFindingContext[] | unknown[];
    evidence?: unknown[] | Record<string, unknown> | unknown;
    recommendations?: string[] | unknown[];
    threatIntelligence?: unknown;
    domainIntelligence?: unknown;
    httpTlsInfo?: unknown;
    phishingFindings?: unknown[];
    extensionFindings?: unknown[];
    fileFindings?: unknown[];
}
export interface AISupportChatRequest {
    message: string;
    conversationId?: string;
    conversationHistory?: Array<{
        role: 'user' | 'assistant' | 'system';
        content: string;
    }>;
    scanId?: string;
    scanContext?: ScanContextData;
    contextType?: 'scan' | 'general' | 'troubleshooting' | 'threat_intel';
}
export interface AISupportChatResponse {
    reply: string;
    conversationId?: string;
    suggestedActions: string[];
    sources: string[];
    scanContext?: {
        scanId?: string;
        target: string;
        targetType?: string;
        riskScore: number;
        riskLevel: string;
        findingsCount?: number;
    };
    escalateToHuman: boolean;
    provider: string;
}
export interface AISupportQuickAction {
    id: string;
    title: string;
    description: string;
    prompt: string;
    category: 'scans' | 'findings' | 'threat_intel' | 'troubleshooting' | 'escalation';
    icon: string;
}
export type NotificationCategory = 'SECURITY' | 'SCAN' | 'THREAT_INTELLIGENCE' | 'REPORT' | 'BROWSER_EXTENSION' | 'ACCOUNT' | 'ACCOUNT_SECURITY' | 'SYSTEM' | 'SUPPORT';
export type NotificationSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type NotificationType = 'SCAN_COMPLETED' | 'SCAN_FAILED' | 'CRITICAL_FINDING' | 'HIGH_RISK_DETECTED' | 'THREAT_INTEL_MATCH' | 'REPORT_READY' | 'REPORT_GENERATED' | 'REPORT_FAILED' | 'REPORT_EXPORTED' | 'SUPPORT_TICKET_CREATED' | 'SUPPORT_MESSAGE_RECEIVED' | 'SUPPORT_RESPONSE_RECEIVED' | 'SUPPORT_STATUS_CHANGED' | 'ACCOUNT_LOGIN' | 'ACCOUNT_SECURITY' | 'SECURITY_SETTING_CHANGED' | 'BROWSER_EXTENSION_ALERT' | 'SYSTEM_ANNOUNCEMENT';
export interface Notification {
    id: string;
    _id?: string;
    userId: string;
    type: NotificationType;
    category: NotificationCategory;
    severity: NotificationSeverity;
    title: string;
    message: string;
    entityType?: 'scan' | 'indicator' | 'report' | 'ticket' | 'user' | 'system' | 'extension' | string;
    entityId?: string;
    metadata?: Record<string, unknown>;
    actionUrl?: string;
    actionText?: string;
    isRead: boolean;
    readAt?: string | null;
    createdAt: string;
    expiresAt?: string | null;
}
export interface NotificationPreferences {
    securityAlerts: boolean;
    scanCompletion?: boolean;
    scanCompletions?: boolean;
    threatIntelAlerts: boolean;
    reportReady?: boolean;
    reportNotifications?: boolean;
    supportUpdates: boolean;
    accountSecurity?: boolean;
    accountSecurityAlerts?: boolean;
    browserExtensionAlerts?: boolean;
    systemAnnouncements?: boolean;
    emailNotifications?: boolean;
    inAppNotifications?: boolean;
}
export interface GetNotificationsQuery {
    page?: number;
    limit?: number;
    category?: NotificationCategory | 'ALL';
    severity?: NotificationSeverity;
    isRead?: boolean | 'true' | 'false' | 'all';
    unreadOnly?: boolean;
    search?: string;
}
export interface GetNotificationsResponse {
    notifications: Notification[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
    pagination?: {
        total: number;
        page: number;
        limit: number;
        totalPages: number;
    };
    unreadCount: number;
}
//# sourceMappingURL=index.d.ts.map