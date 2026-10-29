import { Types } from 'mongoose';
import {
  Scan,
  toSafeScanRecord,
  SafeScanRecord,
  FindingSeverity,
  IScanFinding,
  ScanTargetType,
} from '../models/Scan';
import { ThreatIntel } from '../models/ThreatIntel';
import { ThreatIntelCorrelationService } from './threat-intel-correlation.service';
import { pdfReportService } from './pdf-report.service';

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
  recentScans: SafeScanRecord[];
  recentFindings: EnrichedFinding[];
  hasData: boolean;
}

export interface EnrichedFinding extends IScanFinding {
  uniqueFindingId: string;
  scanId: string;
  target: string;
  targetType: ScanTargetType;
  detectedAt: Date;
  status?: string;
  threatIntel?: any;
}

export interface FindingsFilterOptions {
  severity?: FindingSeverity | 'ALL';
  scanner?: ScanTargetType | 'ALL';
  category?: string;
  search?: string;
  target?: string;
  startDate?: string;
  endDate?: string;
  page?: number;
  limit?: number;
}

export interface HistoryFilterOptions {
  scanner?: ScanTargetType | 'ALL';
  riskLevel?: string | 'ALL';
  status?: string | 'ALL';
  target?: string;
  search?: string;
  startDate?: string;
  endDate?: string;
  sortBy?: 'newest' | 'oldest' | 'highest_risk' | 'lowest_risk';
  page?: number;
  limit?: number;
}

export interface NormalizedScanReportDTO {
  scanId: string;
  target: string;
  targetType: ScanTargetType;
  scanner: string;
  status: 'completed' | 'partial' | 'failed' | 'scanning' | 'pending';
  riskScore: number;
  riskLevel: string;
  verdict: string;
  findings: IScanFinding[];
  checks: any;
  recommendations: string[];
  threatIntelligence?: any;
  metadata: {
    scannedAt: Date;
    createdAt: Date;
    reportGeneratedAt: string;
    engineVersion: string;
    isPartial: boolean;
  };
}

/**
 * Sanitizes a string for CSV export to prevent spreadsheet formula injection.
 * Prepends a single quote if the cell begins with =, +, -, @, TAB, or CR.
 */
export function sanitizeCsvField(value: any): string {
  if (value === null || value === undefined) return '""';
  let str = String(value);
  // Redact known sensitive strings if any
  str = redactSensitiveText(str);
  
  // Neutralize potential CSV injection characters
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  // Escape internal quotes and wrap in quotes
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * Redacts common sensitive tokens, api keys, authorization headers and passwords.
 */
export function redactSensitiveText(text: string): string {
  if (!text) return text;
  return text
    .replace(/(bearer\s+)[a-zA-Z0-9_\-\.]{20,}/gi, '$1[REDACTED_TOKEN]')
    .replace(/(api[_-]?key\s*[:=]\s*)[a-zA-Z0-9_\-]{16,}/gi, '$1[REDACTED_API_KEY]')
    .replace(/(password\s*[:=]\s*)[^\s,;]+/gi, '$1[REDACTED_PASSWORD]')
    .replace(/(secret\s*[:=]\s*)[a-zA-Z0-9_\-]{16,}/gi, '$1[REDACTED_SECRET]');
}

export function redactSensitiveObject<T>(obj: T): T {
  if (!obj) return obj;
  try {
    const jsonStr = JSON.stringify(obj);
    const redacted = redactSensitiveText(jsonStr);
    return JSON.parse(redacted);
  } catch {
    return obj;
  }
}

export class ReportService {
  /**
   * Retrieves high-level report dashboard overview metrics for the user.
   */
  async getReportsOverview(userId: string): Promise<ReportOverviewStats> {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;
    const scans = await Scan.find({ userId: userFilter as any })
      .sort({ createdAt: -1 });

    const totalScans = scans.length;
    let completedScans = 0;
    let partialScans = 0;
    let failedScans = 0;
    let safeScans = 0;

    const findingsSeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0,
    };

    const targetTypes: ScanTargetType[] = ['URL', 'Website', 'API', 'Phishing', 'File', 'Extension'];
    const scannerLabels: Record<ScanTargetType, string> = {
      URL: 'URL Security',
      Website: 'Website Security',
      API: 'API Security',
      Phishing: 'Phishing Security',
      File: 'File Security',
      Extension: 'Browser Extension',
    };

    const scannerBreakdown: Record<string, number> = {
      URL: 0,
      Website: 0,
      API: 0,
      Phishing: 0,
      File: 0,
      Extension: 0,
    };

    const scannerTelemetry: Record<string, ScannerTelemetrySummary> = {};
    const validScoresPerScanner: Record<string, number[]> = {};

    for (const t of targetTypes) {
      scannerTelemetry[t] = {
        scanner: t,
        label: scannerLabels[t],
        totalScans: 0,
        completedScans: 0,
        averageRiskScore: null,
        latestRiskScore: null,
        latestVerdict: null,
        criticalFindings: 0,
        highFindings: 0,
        riskDistribution: {
          low: 0,
          medium: 0,
          high: 0,
          critical: 0,
        },
      };
      validScoresPerScanner[t] = [];
    }

    const allEnrichedFindings: EnrichedFinding[] = [];

    for (const scan of scans) {
      const tType = (scan.targetType || 'URL') as ScanTargetType;
      scannerBreakdown[tType] = (scannerBreakdown[tType] || 0) + 1;

      const tel = scannerTelemetry[tType];
      if (tel) {
        tel.totalScans++;
      }

      if (scan.status === 'completed') {
        completedScans++;
        if (tel) tel.completedScans++;

        // Calculate Safe Scans count based on actual verdict = SAFE
        const resUpper = (scan.result || '').toUpperCase();
        if (resUpper.includes('SAFE')) {
          safeScans++;
        }

        // Latest verdict from the most recent completed scan
        if (tel && tel.latestVerdict === null && scan.result) {
          tel.latestVerdict = scan.result;
        }

        // Only include numeric, defined risk scores for completed scans
        if (typeof scan.riskScore === 'number' && !isNaN(scan.riskScore) && scan.riskScore !== null) {
          if (tel && tel.latestRiskScore === null) {
            tel.latestRiskScore = scan.riskScore;
          }
          if (validScoresPerScanner[tType]) {
            validScoresPerScanner[tType].push(scan.riskScore);
          }

          // Real Risk Distribution (0-24 low, 25-49 medium, 50-74 high, 75-100 critical)
          if (tel) {
            if (scan.riskScore >= 75) {
              tel.riskDistribution.critical++;
            } else if (scan.riskScore >= 50) {
              tel.riskDistribution.high++;
            } else if (scan.riskScore >= 25) {
              tel.riskDistribution.medium++;
            } else {
              tel.riskDistribution.low++;
            }
          }
        }
      } else if (scan.status === 'failed') {
        failedScans++;
      } else if (scan.status === 'pending' || scan.status === 'scanning') {
        partialScans++;
      }

      if (scan.findings && Array.isArray(scan.findings)) {
        scan.findings.forEach((f: any, idx: number) => {
          const sev = (f.severity || 'INFO').toUpperCase() as FindingSeverity;
          if (sev === 'CRITICAL') {
            findingsSeverity.critical++;
            if (tel) tel.criticalFindings++;
          } else if (sev === 'HIGH') {
            findingsSeverity.high++;
            if (tel) tel.highFindings++;
          } else if (sev === 'MEDIUM') {
            findingsSeverity.medium++;
          } else if (sev === 'LOW') {
            findingsSeverity.low++;
          } else {
            findingsSeverity.info++;
          }
          findingsSeverity.total++;

          const uniqueId = f.findingId || f.id || `${scan._id}_finding_${idx}`;
          allEnrichedFindings.push({
            uniqueFindingId: uniqueId,
            id: uniqueId,
            findingId: uniqueId,
            scanId: scan._id.toString(),
            target: scan.target,
            targetType: scan.targetType,
            detectedAt: scan.scannedAt || scan.createdAt,
            title: f.title || 'Security Finding',
            description: f.description || '',
            severity: sev,
            category: f.category || 'Security Assessment',
            evidence: f.evidence || '',
            evidences: f.evidences,
            impact: f.impact || '',
            recommendation: f.recommendation || '',
            affectedComponent: f.affectedComponent || '',
            source: f.source || scan.targetType,
            confidence: f.confidence,
            verificationStatus: f.verificationStatus,
          });
        });
      }
    }

    // Calculate real average risk scores for each scanner
    for (const t of targetTypes) {
      const scores = validScoresPerScanner[t] || [];
      if (scores.length > 0) {
        const sum = scores.reduce((a, b) => a + b, 0);
        scannerTelemetry[t].averageRiskScore = Math.round(sum / scores.length);
      } else {
        // Explicitly null when no completed scans with valid scores exist (NEVER convert to 0!)
        scannerTelemetry[t].averageRiskScore = null;
      }
    }

    return {
      totalScans,
      completedScans,
      partialScans,
      failedScans,
      safeScans,
      findingsSeverity,
      scannerBreakdown,
      scannerTelemetry,
      recentScans: scans.slice(0, 5).map(toSafeScanRecord),
      recentFindings: allEnrichedFindings.slice(0, 10),
      hasData: totalScans > 0,
    };
  }

  /**
   * Retrieves paginated security findings across all scans for a user with deep filtering.
   */
  async getSecurityFindings(userId: string, options: FindingsFilterOptions = {}) {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;
    const {
      severity = 'ALL',
      scanner = 'ALL',
      category,
      search,
      target,
      startDate,
      endDate,
      page = 1,
      limit = 20,
    } = options;

    const query: any = { userId: userFilter };
    if (scanner !== 'ALL' && scanner) {
      query.targetType = scanner;
    }
    if (target) {
      query.target = { $regex: target, $options: 'i' };
    }
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    // Fetch matching scans to extract findings
    const scans = await Scan.find(query).sort({ createdAt: -1 });

    let allFindings: EnrichedFinding[] = [];

    for (const scan of scans) {
      if (!scan.findings || !Array.isArray(scan.findings)) continue;

      scan.findings.forEach((f: any, idx: number) => {
        const sev = (f.severity || 'INFO').toUpperCase() as FindingSeverity;
        const uniqueId = f.findingId || f.id || `${scan._id}_finding_${idx}`;

        const enriched: EnrichedFinding = {
          uniqueFindingId: uniqueId,
          id: uniqueId,
          findingId: uniqueId,
          scanId: scan._id.toString(),
          target: scan.target,
          targetType: scan.targetType,
          detectedAt: scan.scannedAt || scan.createdAt,
          title: f.title || 'Security Finding',
          description: f.description || '',
          severity: sev,
          category: f.category || 'Security Finding',
          evidence: f.evidence || '',
          evidences: f.evidences,
          impact: f.impact || '',
          recommendation: f.recommendation || '',
          affectedComponent: f.affectedComponent || '',
          source: f.source || scan.targetType,
          confidence: f.confidence,
          verificationStatus: f.verificationStatus,
        };

        allFindings.push(enriched);
      });
    }

    // Apply in-memory filters for findings
    if (severity !== 'ALL' && severity) {
      allFindings = allFindings.filter((f) => f.severity === severity.toUpperCase());
    }

    if (category) {
      allFindings = allFindings.filter((f) =>
        f.category.toLowerCase().includes(category.toLowerCase())
      );
    }

    if (search) {
      const q = search.toLowerCase();
      allFindings = allFindings.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.target.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q) ||
          (f.evidence && f.evidence.toLowerCase().includes(q))
      );
    }

    const total = allFindings.length;
    const startIndex = (page - 1) * limit;
    const paginatedFindings = allFindings.slice(startIndex, startIndex + limit);

    return {
      findings: paginatedFindings,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit) || 1,
      },
    };
  }

  /**
   * Retrieves a single finding detail with technical context and correlated Threat Intel.
   */
  async getFindingById(userId: string, uniqueFindingId: string): Promise<EnrichedFinding | null> {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;

    let scanId: string | null = null;
    if (uniqueFindingId.includes('_finding_')) {
      scanId = uniqueFindingId.split('_finding_')[0];
    }

    let scans: any[] = [];
    if (scanId && Types.ObjectId.isValid(scanId)) {
      const singleScan = await Scan.findOne({ _id: new Types.ObjectId(scanId), userId: userFilter as any });
      if (singleScan) scans = [singleScan];
    } else {
      scans = await Scan.find({ userId: userFilter as any }).sort({ createdAt: -1 });
    }

    for (const scan of scans) {
      if (!scan.findings || !Array.isArray(scan.findings)) continue;

      for (let idx = 0; idx < scan.findings.length; idx++) {
        const f = scan.findings[idx];
        const uId = f.findingId || f.id || `${scan._id}_finding_${idx}`;

        if (uId === uniqueFindingId || f.id === uniqueFindingId || f.findingId === uniqueFindingId) {
          const sev = (f.severity || 'INFO').toUpperCase() as FindingSeverity;

          let tiCorrelation = null;
          try {
            tiCorrelation = await ThreatIntelCorrelationService.correlateScanWithThreatIntel(
              scan.targetType,
              scan.target,
              [f],
              scan
            );
          } catch {
            tiCorrelation = null;
          }

          return {
            uniqueFindingId: uId,
            id: uId,
            findingId: uId,
            scanId: scan._id.toString(),
            target: scan.target,
            targetType: scan.targetType,
            detectedAt: scan.scannedAt || scan.createdAt,
            title: f.title || 'Security Finding',
            description: f.description || '',
            severity: sev,
            category: f.category || 'Security Assessment',
            evidence: f.evidence || '',
            evidences: f.evidences,
            impact: f.impact || '',
            recommendation: f.recommendation || '',
            affectedComponent: f.affectedComponent || '',
            source: f.source || scan.targetType,
            confidence: f.confidence,
            verificationStatus: f.verificationStatus,
            threatIntel: tiCorrelation,
          };
        }
      }
    }

    return null;
  }

  /**
   * Retrieves scan history with advanced sorting, filtering, and pagination.
   */
  async getScanHistory(userId: string, options: HistoryFilterOptions = {}) {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;
    const {
      scanner = 'ALL',
      riskLevel = 'ALL',
      status = 'ALL',
      target,
      search,
      startDate,
      endDate,
      sortBy = 'newest',
      page = 1,
      limit = 10,
    } = options;

    const query: any = { userId: userFilter };

    if (scanner !== 'ALL' && scanner) {
      query.targetType = scanner;
    }

    if (riskLevel !== 'ALL' && riskLevel) {
      query.result = riskLevel;
    }

    if (status !== 'ALL' && status) {
      query.status = status.toLowerCase();
    }

    const searchTerm = search || target;
    if (searchTerm) {
      query.target = { $regex: searchTerm, $options: 'i' };
    }

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    let sortQuery: any = { createdAt: -1 };
    if (sortBy === 'oldest') {
      sortQuery = { createdAt: 1 };
    } else if (sortBy === 'highest_risk') {
      sortQuery = { riskScore: -1, createdAt: -1 };
    } else if (sortBy === 'lowest_risk') {
      sortQuery = { riskScore: 1, createdAt: -1 };
    }

    const skip = (page - 1) * limit;

    const [scans, total] = await Promise.all([
      Scan.find(query).sort(sortQuery).skip(skip).limit(limit),
      Scan.countDocuments(query),
    ]);

    return {
      scans: scans.map(toSafeScanRecord),
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit) || 1,
      },
    };
  }

  /**
   * Normalized Scan Report DTO getter aggregating existing scan evidence and Threat Intel.
   */
  async getScanReport(scanId: string, userId?: string): Promise<NormalizedScanReportDTO | null> {
    const scanFilter = Types.ObjectId.isValid(scanId) ? new Types.ObjectId(scanId) : scanId;
    const query: any = { _id: scanFilter };
    if (userId) {
      query.userId = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;
    }

    const scan = await Scan.findOne(query);
    if (!scan) return null;

    const safe = toSafeScanRecord(scan);

    // Correlate with Threat Intelligence
    let threatIntel: any = null;
    try {
      threatIntel = await ThreatIntelCorrelationService.correlateScanWithThreatIntel(
        scan.targetType,
        scan.target,
        safe.findings,
        scan
      );
    } catch {
      threatIntel = null;
    }

    const scannerNames: Record<ScanTargetType, string> = {
      URL: 'URL Security Scanner',
      Website: 'Website Security Scanner',
      API: 'API Security Scanner',
      Phishing: 'Phishing Security Scanner',
      File: 'File Security Scanner',
      Extension: 'Browser Extension Scanner',
    };

    return {
      scanId: safe.id,
      target: safe.target,
      targetType: safe.targetType,
      scanner: scannerNames[safe.targetType] || `${safe.targetType} Scanner`,
      status: safe.status as any,
      riskScore: safe.riskScore,
      riskLevel: safe.result,
      verdict: safe.result,
      findings: safe.findings,
      checks: safe.checks,
      recommendations: safe.recommendations,
      threatIntelligence: threatIntel,
      metadata: {
        scannedAt: safe.scannedAt,
        createdAt: safe.createdAt,
        reportGeneratedAt: new Date().toISOString(),
        engineVersion: 'CyberWatch v2.4-Core',
        isPartial: safe.status !== 'completed',
      },
    };
  }

  /**
   * Compares two historical scans of the same target.
   */
  async compareScans(scanId1: string, scanId2: string, userId: string) {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;

    const [scan1, scan2] = await Promise.all([
      Scan.findOne({ _id: new Types.ObjectId(scanId1), userId: userFilter as any }),
      Scan.findOne({ _id: new Types.ObjectId(scanId2), userId: userFilter as any }),
    ]);

    if (!scan1 || !scan2) {
      throw new Error('One or both scans could not be found for comparison.');
    }

    const safe1 = toSafeScanRecord(scan1);
    const safe2 = toSafeScanRecord(scan2);

    const scoreDiff = safe2.riskScore - safe1.riskScore;
    const findings1Map = new Map((safe1.findings || []).map((f) => [f.title, f]));
    const findings2Map = new Map((safe2.findings || []).map((f) => [f.title, f]));

    const newFindings = (safe2.findings || []).filter((f) => !findings1Map.has(f.title));
    const resolvedFindings = (safe1.findings || []).filter((f) => !findings2Map.has(f.title));
    const persistentFindings = (safe2.findings || []).filter((f) => findings1Map.has(f.title));

    return {
      target: safe1.target,
      targetType: safe1.targetType,
      scan1: {
        id: safe1.id,
        date: safe1.scannedAt,
        riskScore: safe1.riskScore,
        verdict: safe1.result,
        findingCount: (safe1.findings || []).length,
      },
      scan2: {
        id: safe2.id,
        date: safe2.scannedAt,
        riskScore: safe2.riskScore,
        verdict: safe2.result,
        findingCount: (safe2.findings || []).length,
      },
      comparison: {
        scoreDifference: scoreDiff,
        isImprovement: scoreDiff < 0,
        newFindingsCount: newFindings.length,
        resolvedFindingsCount: resolvedFindings.length,
        persistentFindingsCount: persistentFindings.length,
        newFindings,
        resolvedFindings,
        persistentFindings,
      },
    };
  }

  /**
   * Exports scan report, findings, or scan history as CSV.
   */
  async exportCsv(userId: string, type: 'scan' | 'findings' | 'history', scanId?: string): Promise<string> {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;

    if (type === 'scan' && scanId) {
      const scan = await Scan.findOne({ _id: new Types.ObjectId(scanId), userId: userFilter as any });
      if (!scan) throw new Error('Scan not found.');

      const headers = ['Scan ID', 'Target', 'Target Type', 'Risk Score', 'Verdict', 'Finding Title', 'Severity', 'Category', 'Evidence', 'Recommendation'];
      const rows = [headers.map(sanitizeCsvField).join(',')];

      if (scan.findings && scan.findings.length > 0) {
        for (const f of scan.findings) {
          rows.push([
            sanitizeCsvField(scan._id.toString()),
            sanitizeCsvField(scan.target),
            sanitizeCsvField(scan.targetType),
            sanitizeCsvField(scan.riskScore),
            sanitizeCsvField(scan.result),
            sanitizeCsvField(f.title),
            sanitizeCsvField(f.severity),
            sanitizeCsvField(f.category),
            sanitizeCsvField(f.evidence || ''),
            sanitizeCsvField(f.recommendation || ''),
          ].join(','));
        }
      } else {
        rows.push([
          sanitizeCsvField(scan._id.toString()),
          sanitizeCsvField(scan.target),
          sanitizeCsvField(scan.targetType),
          sanitizeCsvField(scan.riskScore),
          sanitizeCsvField(scan.result),
          sanitizeCsvField('No findings detected'),
          sanitizeCsvField('INFO'),
          sanitizeCsvField('Informational'),
          sanitizeCsvField(''),
          sanitizeCsvField(''),
        ].join(','));
      }

      return rows.join('\r\n');
    }

    if (type === 'findings') {
      const scans = await Scan.find({ userId: userFilter as any }).sort({ createdAt: -1 });
      const headers = ['Finding ID', 'Scan ID', 'Target', 'Scanner', 'Severity', 'Title', 'Category', 'Evidence', 'Impact', 'Recommendation', 'Detected At'];
      const rows = [headers.map(sanitizeCsvField).join(',')];

      for (const scan of scans) {
        if (!scan.findings || !Array.isArray(scan.findings)) continue;
        scan.findings.forEach((f: any, idx: number) => {
          const uniqueId = f.findingId || f.id || `${scan._id}_finding_${idx}`;
          rows.push([
            sanitizeCsvField(uniqueId),
            sanitizeCsvField(scan._id.toString()),
            sanitizeCsvField(scan.target),
            sanitizeCsvField(scan.targetType),
            sanitizeCsvField((f.severity || 'INFO').toUpperCase()),
            sanitizeCsvField(f.title || ''),
            sanitizeCsvField(f.category || ''),
            sanitizeCsvField(f.evidence || ''),
            sanitizeCsvField(f.impact || ''),
            sanitizeCsvField(f.recommendation || ''),
            sanitizeCsvField(scan.scannedAt?.toISOString() || scan.createdAt?.toISOString() || ''),
          ].join(','));
        });
      }

      return rows.join('\r\n');
    }

    // Default: History CSV export
    const scans = await Scan.find({ userId: userFilter as any }).sort({ createdAt: -1 });
    const headers = ['Scan ID', 'Target', 'Scanner', 'Status', 'Risk Score', 'Verdict', 'Finding Count', 'Scanned Date'];
    const rows = [headers.map(sanitizeCsvField).join(',')];

    for (const scan of scans) {
      rows.push([
        sanitizeCsvField(scan._id.toString()),
        sanitizeCsvField(scan.target),
        sanitizeCsvField(scan.targetType),
        sanitizeCsvField(scan.status),
        sanitizeCsvField(scan.riskScore),
        sanitizeCsvField(scan.result),
        sanitizeCsvField(scan.findings ? scan.findings.length : 0),
        sanitizeCsvField(scan.scannedAt?.toISOString() || scan.createdAt?.toISOString() || ''),
      ].join(','));
    }

    return rows.join('\r\n');
  }

  /**
   * Exports scan report, findings, or scan history as JSON.
   */
  async exportJson(userId: string, type: 'scan' | 'findings' | 'history', scanId?: string): Promise<any> {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;

    if (type === 'scan' && scanId) {
      const report = await this.getScanReport(scanId, userId);
      if (!report) throw new Error('Scan report not found.');
      return redactSensitiveObject({
        platform: 'CyberWatch Unified Threat Detection Platform',
        reportType: 'Security Scan Analysis',
        exportedAt: new Date().toISOString(),
        scan: report,
      });
    }

    if (type === 'findings') {
      const findingsData = await this.getSecurityFindings(userId, { limit: 1000 });
      return redactSensitiveObject({
        platform: 'CyberWatch Unified Threat Detection Platform',
        reportType: 'Aggregated Security Findings',
        exportedAt: new Date().toISOString(),
        totalFindings: findingsData.pagination.total,
        findings: findingsData.findings,
      });
    }

    const historyData = await this.getScanHistory(userId, { limit: 1000 });
    return redactSensitiveObject({
      platform: 'CyberWatch Unified Threat Detection Platform',
      reportType: 'Scan History Investigation Log',
      exportedAt: new Date().toISOString(),
      totalScans: historyData.pagination.total,
      scans: historyData.scans,
    });
  }

  /**
   * Generates PDF for a scan report.
   */
  async exportPdf(scanId: string, userId: string): Promise<Buffer> {
    const userFilter = Types.ObjectId.isValid(userId) ? new Types.ObjectId(userId) : userId;
    const scan = await Scan.findOne({ _id: new Types.ObjectId(scanId), userId: userFilter as any });
    if (!scan) throw new Error('Scan report not found.');

    const safeScan = toSafeScanRecord(scan);
    return pdfReportService.generatePdfBuffer(safeScan);
  }
}

export const reportService = new ReportService();
