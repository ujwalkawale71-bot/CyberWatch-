import { jsPDF } from 'jspdf';
import type { ScanRecord, FindingSeverity } from '../types';
import type { ParsedTargetUrl } from './urlParser';

export function getPdfSeverityColors(severity?: FindingSeverity | string): { color: [number, number, number]; bg: [number, number, number] } {
  const sev = String(severity || 'INFO').toUpperCase();
  if (sev === 'CRITICAL' || sev === 'HIGH') {
    return { color: [220, 38, 38], bg: [254, 242, 242] };
  } else if (sev === 'MEDIUM') {
    return { color: [217, 119, 6], bg: [254, 243, 199] };
  } else if (sev === 'LOW') {
    return { color: [2, 132, 199], bg: [240, 249, 255] };
  } else {
    return { color: [71, 85, 105], bg: [241, 245, 249] };
  }
}

/**
 * Generates a clean, professional, light-themed A4 PDF Security Report
 * matching the exact scan data displayed on the result page.
 */
export function generateScanPdfReport(scan: ScanRecord, parsedTarget: ParsedTargetUrl): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = 210;
  const pageHeight = 297;
  const margin = 14;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  function checkPageBreak(neededHeight: number) {
    if (y + neededHeight > pageHeight - 18) {
      doc.addPage();
      y = margin + 8;
    }
  }

  // ── HEADER & BRANDING ──────────────────────────────────────────────────────
  doc.setFillColor(37, 99, 235); // #2563eb
  doc.rect(margin, y, contentWidth, 3, 'F');
  y += 7;

  // Title & Subtitle
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(15, 23, 42); // #0f172a
  doc.text('CYBERWATCH', margin, y);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139); // #64748b
  doc.text('Unified Web & Browser Threat Detection Platform', margin + 50, y);
  y += 6;

  let reportTitle = 'URL Security Analysis Report';
  let reportTargetLabel = 'SCANNED TARGET URL';
  let filePrefix = 'CyberWatch_URL_Security_Report';

  const isApiScan = scan.targetType === 'API';
  const isUrlScan = scan.targetType === 'URL' || !scan.targetType;
  const isWebsiteScan = scan.targetType === 'Website';

  switch (scan.targetType) {
    case 'Website':
      reportTitle = 'Website Security Analysis Report';
      reportTargetLabel = 'SCANNED TARGET WEBSITE';
      filePrefix = 'CyberWatch_Website_Security_Report';
      break;
    case 'API':
      reportTitle = 'API Security Analysis Report';
      reportTargetLabel = 'SCANNED API ENDPOINT';
      filePrefix = 'CyberWatch_API_Security_Report';
      break;
    case 'Phishing':
      reportTitle = 'Phishing Threat Detection Report';
      reportTargetLabel = 'SUSPICIOUS TARGET URL';
      filePrefix = 'CyberWatch_Phishing_Report';
      break;
    case 'File':
      reportTitle = 'File Security Analysis Report';
      reportTargetLabel = 'SCANNED FILE TARGET';
      filePrefix = 'CyberWatch_File_Security_Report';
      break;
    case 'Extension':
      reportTitle = 'Browser Extension Security Report';
      reportTargetLabel = 'BROWSER EXTENSION TARGET';
      filePrefix = 'CyberWatch_Extension_Security_Report';
      break;
    case 'URL':
    default:
      reportTitle = 'URL Security Analysis Report';
      reportTargetLabel = 'SCANNED TARGET URL';
      filePrefix = 'CyberWatch_URL_Security_Report';
      break;
  }

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(37, 99, 235);
  doc.text(reportTitle, margin, y);

  const scanDate = scan.scannedAt ? new Date(scan.scannedAt).toUTCString() : new Date().toUTCString();
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  doc.text(`Generated: ${new Date().toLocaleDateString()} | Scan UTC: ${scanDate}`, pageWidth - margin, y, { align: 'right' });
  y += 6;

  // Divider
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.4);
  doc.line(margin, y, margin + contentWidth, y);
  y += 5;

  // ── SCANNED TARGET CALLOUT (MASKED) ────────────────────────────────────────
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(margin, y, contentWidth, 16, 2, 2, 'F');
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentWidth, 16, 2, 2, 'S');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(100, 116, 139);
  doc.text(reportTargetLabel, margin + 4, y + 4.5);

  doc.setFont('courier', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  const targetLines = doc.splitTextToSize(parsedTarget.fullUrl, contentWidth - 8);
  doc.text(targetLines.slice(0, 2), margin + 4, y + 9.5);
  y += 21;

  // ── WEBSITE SECURITY V2 OVERVIEW & SUMMARY (WEBSITE SCANS ONLY) ────────
  const v2 = scan.checks?.websiteSecurityV2;
  const overview = scan.checks?.websiteOverview;

  if (isWebsiteScan) {
    // ── 1. VERDICT & SCORE CARD ─────────────────────────────────────────────
    checkPageBreak(38);
    const riskLevel = v2?.riskLevel || scan.result || 'Safe';
    const riskScore = v2?.riskScore ?? scan.riskScore ?? 0;
    const confidencePct = Math.round((v2?.confidence || 0.95) * 100);

    let vColor: [number, number, number] = [22, 163, 74];
    let vBg: [number, number, number] = [236, 253, 245];
    if (riskLevel === 'CRITICAL' || riskLevel === 'Critical') {
      vColor = [220, 38, 38];
      vBg = [254, 242, 242];
    } else if (riskLevel === 'HIGH' || riskLevel === 'High Risk') {
      vColor = [234, 88, 12];
      vBg = [255, 247, 237];
    } else if (riskLevel === 'MODERATE' || riskLevel === 'Suspicious') {
      vColor = [217, 119, 6];
      vBg = [254, 243, 199];
    } else if (riskLevel === 'LOW' || riskLevel === 'Low Risk') {
      vColor = [2, 132, 199];
      vBg = [240, 249, 255];
    }

    doc.setFillColor(vBg[0], vBg[1], vBg[2]);
    doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'F');
    doc.setDrawColor(vColor[0], vColor[1], vColor[2]);
    doc.setLineWidth(0.5);
    doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('WEBSITE SECURITY V2 POSTURE', margin + 4, y + 5.5);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(vColor[0], vColor[1], vColor[2]);
    doc.text(`RISK LEVEL: ${String(riskLevel).toUpperCase()}`, margin + 4, y + 13);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    doc.text(`Confidence: ${confidencePct}% | Evidence-Based Weighted Risk Assessment`, margin + 4, y + 18.5);

    // Score Box
    doc.setFillColor(255, 255, 255);
    doc.roundedRect(pageWidth - margin - 42, y + 3, 38, 18, 1.5, 1.5, 'F');
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.roundedRect(pageWidth - margin - 42, y + 3, 38, 18, 1.5, 1.5, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text('RISK SCORE', pageWidth - margin - 23, y + 7.5, { align: 'center' });

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(vColor[0], vColor[1], vColor[2]);
    doc.text(`${riskScore} / 100`, pageWidth - margin - 23, y + 14, { align: 'center' });

    y += 28;

    // ── 2. FINDING BREAKDOWN COUNTERS ───────────────────────────────────────
    checkPageBreak(16);
    const counts = v2?.counts || v2?.findingsCounts || {
      confirmedVulnerabilities: 0,
      securityWeaknesses: 0,
      hardeningRecommendations: 0,
      informationalFindings: 0,
    };

    const countColWidth = (contentWidth - 9) / 4;
    const countItems = [
      { label: 'Confirmed Vulns', val: counts.confirmedVulnerabilities, color: [220, 38, 38] as [number, number, number] },
      { label: 'Weaknesses', val: counts.securityWeaknesses, color: [217, 119, 6] as [number, number, number] },
      { label: 'Hardening Recs', val: counts.hardeningRecommendations, color: [37, 99, 235] as [number, number, number] },
      { label: 'Informational', val: counts.informationalFindings, color: [100, 116, 139] as [number, number, number] },
    ];

    countItems.forEach((item, idx) => {
      const cx = margin + idx * (countColWidth + 3);
      doc.setFillColor(248, 250, 252);
      doc.roundedRect(cx, y, countColWidth, 12, 1, 1, 'F');
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(cx, y, countColWidth, 12, 1, 1, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(100, 116, 139);
      doc.text(item.label, cx + countColWidth / 2, y + 4.2, { align: 'center' });

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(item.color[0], item.color[1], item.color[2]);
      doc.text(String(item.val), cx + countColWidth / 2, y + 9.5, { align: 'center' });
    });

    y += 16;

    // ── 3. WHY THIS VERDICT & SCORE CONTRIBUTORS ───────────────────────────
    const whyBullets: string[] = v2?.whyVerdict || v2?.whyThisVerdict || [];
    if (whyBullets.length > 0) {
      checkPageBreak(whyBullets.length * 5 + 10);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text('Why This Verdict?', margin, y);
      y += 4.5;

      whyBullets.forEach((bullet: string) => {
        checkPageBreak(6);
        doc.setFillColor(37, 99, 235);
        doc.circle(margin + 2.5, y + 2.5, 0.8, 'F');
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(51, 65, 85);
        const bLines = doc.splitTextToSize(bullet, contentWidth - 8);
        doc.text(bLines, margin + 6, y + 3.2);
        y += bLines.length * 4.2;
      });
      y += 3;
    }

    // Score Contributors Breakdown
    const scoreContribs = v2?.scoreExplanation?.contributors || [];
    if (scoreContribs.length > 0) {
      checkPageBreak(scoreContribs.length * 7 + 12);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`Score Contributors Breakdown (+${v2?.scoreExplanation?.rawScore ?? riskScore} Raw Pts)`, margin, y);
      y += 4.5;

      scoreContribs.forEach((sc: any) => {
        checkPageBreak(7.5);
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(margin, y, contentWidth, 6.5, 1, 1, 'F');
        doc.setDrawColor(226, 232, 240);
        doc.roundedRect(margin, y, contentWidth, 6.5, 1, 1, 'S');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(15, 23, 42);
        doc.text(`[+${sc.contribution}] ${sc.title}`, margin + 3, y + 4.2);

        doc.setFont('courier', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(100, 116, 139);
        const evLine = (sc.evidence || '').slice(0, 75);
        doc.text(evLine, margin + 65, y + 4.2);

        y += 7.5;
      });
      y += 3;
    }

    // ── 4. WEBSITE UNDERSTANDING ────────────────────────────────────────────
    const understanding = v2?.websiteUnderstanding || (overview ? {
      websiteType: overview.websiteType,
      industry: overview.category,
      primaryPurpose: overview.purpose,
      confidence: overview.confidence === 'High' ? 0.9 : overview.confidence === 'Medium' ? 0.75 : 0.5,
      evidence: overview.observedBullets || [],
    } : null);

    if (understanding) {
      checkPageBreak(30);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text('Website Understanding', margin, y);
      y += 4.5;

      doc.setFillColor(248, 250, 252);
      doc.roundedRect(margin, y, contentWidth, 20, 1.5, 1.5, 'F');
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentWidth, 20, 1.5, 1.5, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(`Type: ${understanding.websiteType}  |  Industry: ${understanding.industry}  |  Confidence: ${Math.round((understanding.confidence || 0.8) * 100)}%`, margin + 4, y + 5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(51, 65, 85);
      const purpLines = doc.splitTextToSize(`Purpose: ${understanding.primaryPurpose}`, contentWidth - 8);
      doc.text(purpLines.slice(0, 2), margin + 4, y + 10.5);

      if (understanding.evidence && understanding.evidence.length > 0) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(6.5);
        doc.setTextColor(100, 116, 139);
        const evLine = `Evidence: ${understanding.evidence.slice(0, 3).join('; ')}`;
        const splitEv = doc.splitTextToSize(evLine, contentWidth - 8);
        doc.text(splitEv[0] || '', margin + 4, y + 16.5);
      }

      y += 24;
    }

    // ── 5. VERIFIED SECURITY FINDINGS & WEAKNESSES ───────────────────────────
    const v2Findings = scan.findings || [];

    checkPageBreak(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(`Security Findings & Observations (${v2Findings.length})`, margin, y);
    y += 4.5;

    if (v2Findings.length === 0) {
      doc.setFillColor(240, 253, 244);
      doc.roundedRect(margin, y, contentWidth, 12, 1.5, 1.5, 'F');
      doc.setDrawColor(187, 247, 208);
      doc.roundedRect(margin, y, contentWidth, 12, 1.5, 1.5, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(22, 101, 52);
      doc.text('No security findings identified. Target demonstrates solid baseline security configuration.', margin + 4, y + 7.5);
      y += 16;
    } else {
      v2Findings.forEach((f) => {
        const { color: fColor, bg: fBg } = getPdfSeverityColors(f.severity);

        const cat = f.findingCategory || f.category || 'FINDING';
        const verStatus = f.verificationStatus || 'OBSERVED';
        const cardHeight = f.recommendation ? 22 : f.evidence ? 18 : 14;

        doc.setFillColor(fBg[0], fBg[1], fBg[2]);
        doc.roundedRect(margin, y, contentWidth, cardHeight, 1.5, 1.5, 'F');
        doc.setDrawColor(226, 232, 240);
        doc.roundedRect(margin, y, contentWidth, cardHeight, 1.5, 1.5, 'S');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(6.5);
        doc.setTextColor(fColor[0], fColor[1], fColor[2]);
        doc.text(`[${f.severity.toUpperCase()}] ${cat} • ${verStatus}`, margin + 3, y + 4.2);

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(15, 23, 42);
        doc.text(f.title, margin + 3, y + 8.5);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(51, 65, 85);
        const descLines = doc.splitTextToSize(f.description, contentWidth - 6);
        doc.text(descLines[0] || '', margin + 3, y + 12);

        if (f.evidence) {
          doc.setFont('courier', 'normal');
          doc.setFontSize(6.5);
          doc.setTextColor(100, 116, 139);
          const evLines = doc.splitTextToSize(`Evidence: ${f.evidence}`, contentWidth - 6);
          doc.text(evLines[0] || '', margin + 3, y + 16);
        }

        if (f.recommendation && cardHeight > 18) {
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(6.5);
          doc.setTextColor(37, 99, 235);
          const recLines = doc.splitTextToSize(`Remediation: ${f.recommendation}`, contentWidth - 6);
          doc.text(recLines[0] || '', margin + 3, y + 19.8);
        }

        y += cardHeight + 3;
      });
    }

    // ── 6. COOKIE SECURITY SUMMARY ──────────────────────────────────────────
    const cookiesAnalysis: any = v2?.cookieSecuritySummary || (v2 as any)?.cookieAnalysis || scan.checks?.cookiesAnalysis;
    const cookieList: any[] = cookiesAnalysis?.table || cookiesAnalysis?.cookies || [];
    if (cookieList.length > 0) {
      checkPageBreak(35);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`Cookie Security Analysis (${cookieList.length} Total, ${cookiesAnalysis?.flaggedCookies || 0} Flagged)`, margin, y);
      y += 4.5;

      cookieList.slice(0, 6).forEach((c: any, idx: number) => {
        checkPageBreak(6);
        if (idx % 2 === 0) {
          doc.setFillColor(248, 250, 252);
          doc.rect(margin, y, contentWidth, 5.2, 'F');
        }
        doc.setFont('courier', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(15, 23, 42);
        doc.text((c.name || 'cookie').slice(0, 24), margin + 2, y + 3.7);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(71, 85, 105);
        const flags = `Secure: ${c.secure ? 'Yes' : 'No'} | HttpOnly: ${c.httpOnly ? 'Yes' : 'No'} | SameSite: ${c.sameSite || 'None'}`;
        doc.text(flags, margin + 50, y + 3.7);

        if (c.isFlagged || (!c.secure && (c.isPotentiallySensitive || scan.target.startsWith('https')))) {
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(217, 119, 6);
          doc.text('FLAGGED', pageWidth - margin - 2, y + 3.7, { align: 'right' });
        } else {
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(22, 163, 74);
          doc.text('PASS', pageWidth - margin - 2, y + 3.7, { align: 'right' });
        }
        y += 5.2;
      });
      y += 4;
    }

    // ── 7. DETECTED TECHNOLOGIES ────────────────────────────────────────────
    const techList: any[] = v2?.technologyDetections || (v2 as any)?.technologyDetection || [];
    if (techList.length > 0) {
      checkPageBreak(25);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`Detected Technologies (${techList.length})`, margin, y);
      y += 4.5;

      techList.forEach((t: any) => {
        checkPageBreak(5.5);
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 5.2, 'F');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(15, 23, 42);
        doc.text(`${t.technology} (${t.category || 'Technology'})`, margin + 2, y + 3.7);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(100, 116, 139);
        const evSplit = doc.splitTextToSize(t.evidence || '', contentWidth - 65);
        doc.text(evSplit[0] || '', margin + 55, y + 3.7);

        y += 5.2;
      });
      y += 4;
    }

    // ── 8. POSITIVE SECURITY CONTROLS ───────────────────────────────────────
    const positiveControls = v2?.positiveControls || [];
    if (positiveControls.length > 0) {
      checkPageBreak(25);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`Positive Security Controls (${positiveControls.length})`, margin, y);
      y += 4.5;

      positiveControls.forEach((ctrl) => {
        checkPageBreak(6.5);
        doc.setFillColor(22, 163, 74);
        doc.circle(margin + 2.8, y + 2.5, 0.9, 'F');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(30, 41, 59);
        doc.text(`${ctrl.title}: `, margin + 6, y + 3.5);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(71, 85, 105);
        const titleWidth = doc.getTextWidth(`${ctrl.title}: `);
        const descText = ctrl.desc || (ctrl as any).description || '';
        const descLines = doc.splitTextToSize(descText, contentWidth - 8 - titleWidth);
        doc.text(descLines[0] || '', margin + 6 + titleWidth, y + 3.5);
        y += 4.5;
      });
      y += 4;
    }
  }

  // ── WHAT THIS URL APPEARS TO POINT TO (URL SCANS ONLY) ───────────────────
  const urlSec = scan.checks?.urlSecurityAnalysis;
  const http = scan.checks?.httpAnalysis;
  const domain = scan.checks?.domainAnalysis;
  const ssl = scan.checks?.sslAnalysis;
  const redirects = scan.checks?.redirectAnalysis;

  if (isUrlScan) {
    checkPageBreak(25);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text('What This URL Appears To Point To', margin, y);
    y += 4.5;

    const interpText = urlSec?.resourceInterpretation ||
      (http?.statusCode
        ? `This URL points to a publicly reachable web page. The endpoint returned an HTTP ${http.statusCode} response.`
        : 'The scanner could not determine the resource type from the available response.');
    const interpLines = doc.splitTextToSize(interpText, contentWidth - 8);
    const boxHeight = interpLines.length > 1 ? 16 : 13;
    doc.setFillColor(240, 249, 255);
    doc.roundedRect(margin, y, contentWidth, boxHeight, 1.5, 1.5, 'F');
    doc.setDrawColor(186, 230, 253);
    doc.roundedRect(margin, y, contentWidth, boxHeight, 1.5, 1.5, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(3, 105, 161);
    doc.text(interpLines.slice(0, 2), margin + 4, y + 4.8);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6);
    doc.setTextColor(100, 116, 139);
    doc.text('* Evaluated purely on HTTP and content-type evidence without speculative business categorization.', margin + 4, y + boxHeight - 2.5);
    y += boxHeight + 4;
  }

  // ── OVERALL SECURITY RESULT & VERDICT (NON-WEBSITE SCANS) ─────────────────
  if (!isWebsiteScan) {
    checkPageBreak(35);

    const verdict = scan.result || 'Safe';
    let badgeColor: [number, number, number] = [22, 163, 74]; // Emerald
    let badgeBg: [number, number, number] = [236, 253, 245];
    if (verdict === 'Critical' || verdict === 'High Risk') {
      badgeColor = [220, 38, 38]; // Red
      badgeBg = [254, 242, 242];
    } else if (verdict === 'Suspicious') {
      badgeColor = [217, 119, 6]; // Amber
      badgeBg = [254, 243, 199];
    } else if (verdict === 'Low Risk') {
      badgeColor = [2, 132, 199]; // Blue
      badgeBg = [240, 249, 255];
    }

    // Verdict Box
    doc.setFillColor(badgeBg[0], badgeBg[1], badgeBg[2]);
    doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'F');
    doc.setDrawColor(badgeColor[0], badgeColor[1], badgeColor[2]);
    doc.setLineWidth(0.5);
    doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(isApiScan ? 'OVERALL API SECURITY RESULT' : isUrlScan ? 'OVERALL URL SECURITY RESULT' : 'OVERALL SECURITY RESULT', margin + 4, y + 5.5);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(badgeColor[0], badgeColor[1], badgeColor[2]);
    doc.text(`${verdict.toUpperCase()}`, margin + 4, y + 13);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(51, 65, 85);
    const verdictSummary = isUrlScan
      ? (urlSec?.resourceInterpretation ||
          (verdict === 'Safe' || verdict === 'Low Risk'
            ? 'The URL resolved successfully over HTTPS and no strong URL-level security indicators were observed.'
            : verdict === 'Suspicious'
            ? 'Suspicious — Anomalies or deceptive structures observed in URL properties. Review recommended.'
            : 'High Risk — Significant URL-level risk indicators detected. Review recommended before opening.'))
      : isApiScan
      ? (verdict === 'Safe' || verdict === 'Low Risk'
          ? 'Passive endpoint security checks observed standard posture with no severe misconfigurations detected.'
          : verdict === 'Suspicious'
          ? 'Observed configuration indicators or error disclosures warrant review. Hardening recommended.'
          : 'Significant API security risks or insecure configurations identified. Immediate remediation advised.')
      : (verdict === 'Safe' || verdict === 'Low Risk'
          ? 'The available analysis did not identify active security vulnerabilities or critical header misconfigurations.'
          : verdict === 'Suspicious'
          ? 'Security weaknesses, missing defensive headers, or resource anomalies were detected. Review recommended.'
          : 'Significant security risks or vulnerabilities identified. Hardening strongly recommended before production use.');
    
    const vSummaryLines = doc.splitTextToSize(verdictSummary, contentWidth - 48);
    doc.text(vSummaryLines.slice(0, 2), margin + 4, y + 18.5);

    // Score Box on Right
    doc.setFillColor(255, 255, 255);
    doc.roundedRect(pageWidth - margin - 42, y + 3, 38, 18, 1.5, 1.5, 'F');
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.roundedRect(pageWidth - margin - 42, y + 3, 38, 18, 1.5, 1.5, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text('RISK SCORE', pageWidth - margin - 23, y + 7.5, { align: 'center' });

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(badgeColor[0], badgeColor[1], badgeColor[2]);
    const scoreText = typeof scan.riskScore === 'number' && !isNaN(scan.riskScore) ? `${scan.riskScore} / 100` : 'Unavailable';
    doc.text(scoreText, pageWidth - margin - 23, y + 14, { align: 'center' });

    y += 29;

    if (isUrlScan && urlSec?.whyVerdict && urlSec.whyVerdict.length > 0) {
      checkPageBreak(25);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text('Why This Result?', margin, y);
      y += 4.5;

      urlSec.whyVerdict.forEach((reason) => {
        checkPageBreak(8);
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 5.5, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(37, 99, 235);
        doc.text('•', margin + 3, y + 3.8);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(51, 65, 85);
        const rLines = doc.splitTextToSize(reason, contentWidth - 10);
        doc.text(rLines[0] || reason, margin + 7, y + 3.8);
        y += 5.5;
      });
      y += 4;
    }
  }

  // ── TARGET INFORMATION TABLE ──────────────────────────────────────────────
  checkPageBreak(50);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text(isApiScan ? 'API Target Information' : isUrlScan ? 'URL Target Information' : 'Target Information & Web Response Metrics', margin, y);
  y += 4;

  const targetData: Array<[string, string]> = isUrlScan
    ? [
        ['Original Target URL', urlSec?.originalUrl || parsedTarget.fullUrl],
        ['Normalized URL', urlSec?.normalizedUrl || parsedTarget.fullUrl],
        ['Final Destination URL', urlSec?.finalUrl || urlSec?.redirectJourney?.finalUrl || redirects?.destination || parsedTarget.fullUrl],
        ['Hostname & Domain', `${urlSec?.finalHostname || parsedTarget.hostname} (${urlSec?.registrableDomain || parsedTarget.domain})`],
        ['Protocol & Scheme', `${parsedTarget.protocol} (${parsedTarget.scheme})`],
        ['Port', `${parsedTarget.port} ${parsedTarget.port === '443' ? '(Default HTTPS)' : parsedTarget.port === '80' ? '(Default HTTP)' : '(Custom Port)'}`],
        ['Path & Depth', `${parsedTarget.path || '/'} (${parsedTarget.pathDepth ?? 0} segments)`],
        ['Query Parameters', parsedTarget.queryParamKeys && parsedTarget.queryParamKeys.length > 0 ? parsedTarget.queryParamKeys.map((k: string) => `${k}=REDACTED`).join('&') : 'None'],
        ['DNS Resolution Status', domain?.dnsStatus || (parsedTarget.isIpAddress ? 'Direct Host IP' : 'Resolved')],
        ['HTTP Status & Timing', `HTTP ${http?.statusCode || 200} ${http?.statusText || 'OK'} (${http?.responseTimeMs || 0} ms)`],
        ['TLS Security & Validity', parsedTarget.protocol === 'HTTPS' ? `${ssl?.protocol || 'TLS'} • ${ssl?.valid !== false ? 'Valid & Trusted' : 'Invalid/Expired'} (Issuer: ${ssl?.issuer || 'Standard CA'})` : 'Plaintext HTTP (No TLS)'],
        ['Threat Intelligence', urlSec?.threatIntelligence?.status || 'Not Configured'],
      ]
    : isApiScan
    ? [
        ['Full Endpoint URL', parsedTarget.fullUrl],
        ['Hostname', parsedTarget.hostname],
        ['Path', parsedTarget.path || '/'],
        ['Protocol / Scheme', `${parsedTarget.protocol} (${parsedTarget.scheme})`],
        ['Port', `${parsedTarget.port} ${parsedTarget.port === '443' ? '(Default HTTPS)' : parsedTarget.port === '80' ? '(Default HTTP)' : ''}`],
        ['HTTP Method', scan.checks?.apiAnalysis?.httpMethod || 'GET'],
        ['HTTP Status', scan.checks?.httpAnalysis?.statusCode ? `HTTP ${scan.checks.httpAnalysis.statusCode} ${scan.checks.httpAnalysis.statusText || ''}` : 'Not available'],
        ['Response Time', scan.checks?.httpAnalysis?.responseTimeMs !== undefined ? `${scan.checks.httpAnalysis.responseTimeMs} ms` : 'Not available'],
        ['Response Content-Type', scan.checks?.httpAnalysis?.contentType || 'Not available'],
        ['Response Size', scan.checks?.httpAnalysis?.contentLength ? `${scan.checks.httpAnalysis.contentLength} bytes` : 'Not available'],
        ['Response Server Info', scan.checks?.httpAnalysis?.server || 'Not disclosed / Not available'],
      ]
    : scan.targetType === 'File'
    ? [
        ['Target File URL', parsedTarget.fullUrl],
        ['Extracted Filename', scan.checks?.fileAnalysis?.filename || parsedTarget.path.split('/').pop() || 'file.bin'],
        ['File Extension', scan.checks?.fileAnalysis?.extension ? `.${scan.checks.fileAnalysis.extension.replace(/^\\./, '')}` : 'none'],
        ['MIME Content-Type', scan.checks?.fileAnalysis?.mimeType || 'application/octet-stream'],
        ['File Size', scan.checks?.fileAnalysis?.fileSizeFormatted || (scan.checks?.fileAnalysis?.fileSize ? `${scan.checks.fileAnalysis.fileSize} bytes` : 'Remote asset stream')],
        ['SHA-256 Checksum', scan.checks?.fileAnalysis?.sha256 || 'N/A'],
        ['MD5 Checksum', scan.checks?.fileAnalysis?.md5 || 'N/A'],
        ['Static Structure Risk', scan.checks?.fileAnalysis?.structureRisk || 'Standard / Low Structural Risk'],
        ['Transport Protocol', `${parsedTarget.protocol} (${parsedTarget.scheme})`],
        ['Hosting Domain', parsedTarget.hostname],
      ]
    : scan.targetType === 'Extension'
    ? [
        ['Extension Target URL', parsedTarget.fullUrl],
        ['Extension Name', scan.checks?.extensionAnalysis?.extensionName || 'Browser Extension Package'],
        ['Manifest Architecture', `Manifest V${scan.checks?.extensionAnalysis?.manifestVersion || 3}`],
        ['Declared Permissions Count', `${scan.checks?.extensionAnalysis?.permissions?.length || 0} permissions`],
        ['Host Scopes Count', `${scan.checks?.extensionAnalysis?.hostPermissions?.length || 0} host pattern(s)`],
        ['Sensitive Permissions', `${scan.checks?.extensionAnalysis?.dangerousPermissions?.length || 0} flagged`],
        ['Transport Protocol', `${parsedTarget.protocol} (${parsedTarget.scheme})`],
        ['Hosting Domain', parsedTarget.hostname],
      ]
    : scan.targetType === 'Phishing'
    ? [
        ['Suspicious URL', parsedTarget.fullUrl],
        ['Hostname', parsedTarget.hostname],
        ['Domain / Root Domain', parsedTarget.domain],
        ['Subdomain Depth', `${parsedTarget.subdomainCount} level(s)`],
        ['Protocol / Scheme', `${parsedTarget.protocol} (${parsedTarget.scheme})`],
        ['Port', `${parsedTarget.port}`],
        ['Path', parsedTarget.path || '/'],
        ['Query Parameters', parsedTarget.queryParamKeys && parsedTarget.queryParamKeys.length > 0 ? parsedTarget.queryParamKeys.join('&') : 'None'],
        ['Phishing Confidence Index', `${scan.checks?.phishingAnalysis?.confidence || 0}%`],
        ['DNS Resolution', scan.checks?.domainAnalysis?.dnsStatus || 'Resolved'],
        ['HTTP Status', scan.checks?.httpAnalysis?.statusCode ? `HTTP ${scan.checks.httpAnalysis.statusCode} ${scan.checks.httpAnalysis.statusText || ''}` : 'Not available'],
      ]
    : [
        ['Full URL', parsedTarget.fullUrl],
        ['Domain / Hostname', `${parsedTarget.domain} (${parsedTarget.hostname})`],
        ['Protocol / Scheme', `${parsedTarget.protocol} (${parsedTarget.scheme})`],
        ['Port', `${parsedTarget.port} ${parsedTarget.port === '443' ? '(Default HTTPS)' : parsedTarget.port === '80' ? '(Default HTTP)' : ''}`],
        ['Path & Query', `${parsedTarget.path} ${parsedTarget.search ? `(${parsedTarget.search})` : ''}`],
        ['DNS Resolution', scan.checks?.domainAnalysis?.dnsStatus || (parsedTarget.isIpAddress ? 'Direct IP Address Host' : 'Domain Syntax Valid')],
        ['Resolved IP(s)', scan.checks?.domainAnalysis?.resolvedIps?.join(', ') || (parsedTarget.isIpAddress ? parsedTarget.hostname : 'Not resolved / unavailable')],
        ['HTTP Status Code', scan.checks?.httpAnalysis?.statusCode ? `HTTP ${scan.checks.httpAnalysis.statusCode} ${scan.checks.httpAnalysis.statusText || ''} (${scan.checks.httpAnalysis.responseTimeMs || 0}ms)` : (scan.checks?.sslAnalysis?.protocol || 'Analyzed')],
        ['Content-Type & Size', `${scan.checks?.httpAnalysis?.contentType || 'N/A'} ${scan.checks?.httpAnalysis?.contentLength ? `(${scan.checks.httpAnalysis.contentLength} bytes)` : ''}`],
        ['Redirect Count & Final Target', scan.checks?.redirectAnalysis?.redirectCount !== undefined ? `${scan.checks.redirectAnalysis.redirectCount} hop(s) -> ${scan.checks.redirectAnalysis.destination || parsedTarget.fullUrl}` : 'Direct target (0 redirects)'],
      ];

  const rowHeight = 5.2;
  targetData.forEach(([label, val], idx) => {
    checkPageBreak(rowHeight + 2);
    const isEven = idx % 2 === 0;
    if (isEven) {
      doc.setFillColor(248, 250, 252);
      doc.rect(margin, y, contentWidth, rowHeight, 'F');
    }
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    doc.text(label, margin + 2, y + 3.7);

    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(15, 23, 42);
    const maxValLen = contentWidth - 55;
    const splitVal = doc.splitTextToSize(val || 'N/A', maxValLen);
    doc.text(splitVal[0] || 'N/A', margin + 50, y + 3.7);

    y += rowHeight;
  });
  y += 5;

  // ── URL STRUCTURE ANALYSIS (URL SCANS) ───────────────────────────────────
  if (isUrlScan) {
    checkPageBreak(40);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text('URL Structure & Network Intelligence', margin, y);
    y += 4;

    const structRows: Array<[string, string]> = [
      ['URL Length', `${parsedTarget.urlLength} characters`],
      ['Hostname Length', `${parsedTarget.hostnameLength || parsedTarget.hostname.length} characters`],
      ['Subdomain Depth', `${parsedTarget.subdomainCount} level(s)`],
      ['Path Depth', `${parsedTarget.pathDepth ?? (parsedTarget.path ? parsedTarget.path.split('/').filter(Boolean).length : 0)} segments`],
      ['Query Parameter Count', `${parsedTarget.queryCount} parameter(s)`],
      ['Percent Encoding', parsedTarget.hasPercentEncoding ? 'Detected' : 'None'],
      ['Direct IP Hostname', parsedTarget.isIpAddress ? 'Yes (IP Host)' : 'No (Registered Domain)'],
      ['Punycode / IDN', parsedTarget.isPunycode ? 'Detected (xn--)' : 'Not Detected'],
      ['DNS Resolution Status', domain?.dnsStatus || 'Resolved'],
      ['Resolved IPv4 / IPv6', domain?.resolvedIps?.join(', ') || parsedTarget.hostname],
      ['CDN / Edge Proxy', urlSec?.cdnProvider || 'Not detected'],
      ['TLS Certificate & Protocol', parsedTarget.protocol === 'HTTPS' ? `${ssl?.protocol || 'TLS 1.3'} (Issuer: ${ssl?.issuer || 'Standard CA'})` : 'Plaintext HTTP (No TLS)'],
    ];

    structRows.forEach(([k, v], idx) => {
      checkPageBreak(5.5);
      if (idx % 2 === 0) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 5.2, 'F');
      }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(k, margin + 2, y + 3.7);

      doc.setFont('courier', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(15, 23, 42);
      const splitV = doc.splitTextToSize(v, contentWidth - 55);
      doc.text(splitV[0] || 'N/A', margin + 50, y + 3.7);
      y += 5.2;
    });
    y += 4;
  }

  // ── URL SECURITY ANALYSIS (13 AUDIT CHECKS) ──────────────────────────────
  if (isUrlScan && urlSec?.auditChecks && urlSec.auditChecks.length > 0) {
    checkPageBreak(40);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(`URL Security Analysis Checklist (${urlSec.auditChecks.length} Checks)`, margin, y);
    y += 4;

    urlSec.auditChecks.forEach((check, idx) => {
      checkPageBreak(11);
      const isPass = check.status === 'PASS' || check.status === 'NOT DETECTED';
      const isWarn = check.status === 'WARN' || (check.status as string) === 'WARNING';
      const isFail = check.status === 'FAIL' || (check.status as string) === 'FAILED';

      let chkColor: [number, number, number] = isPass ? [22, 163, 74] : isWarn ? [217, 119, 6] : isFail ? [220, 38, 38] : [100, 116, 139];
      let chkBg: [number, number, number] = isPass ? [240, 253, 244] : isWarn ? [254, 243, 199] : isFail ? [254, 242, 242] : [248, 250, 252];

      doc.setFillColor(chkBg[0], chkBg[1], chkBg[2]);
      doc.roundedRect(margin, y, contentWidth, 9.5, 1, 1, 'F');
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y, contentWidth, 9.5, 1, 1, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`${idx + 1}. ${check.name}`, margin + 3, y + 4);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(chkColor[0], chkColor[1], chkColor[2]);
      doc.text(check.status, pageWidth - margin - 3, y + 4, { align: 'right' });

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(71, 85, 105);
      const evSnippet = `Evidence: ${check.evidence} | ${check.explanation}`;
      const splitEv = doc.splitTextToSize(evSnippet, contentWidth - 6);
      doc.text(splitEv[0] || '', margin + 3, y + 7.5);

      y += 11;
    });
    y += 4;
  }

  // ── API SECURITY SPECIFIC AUDIT SECTION (API SCANS) ──────────────────────
  if (isApiScan) {
    checkPageBreak(40);
    const api = scan.checks?.apiAnalysis;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text('API Security Posture & Configuration Audit', margin, y);
    y += 4;

    const apiRows: Array<[string, string]> = [
      ['CORS Origin Policy', api?.corsConfig?.allowOrigin || 'Same-origin default (No wildcard header)'],
      ['CORS Allowed Methods', api?.corsConfig?.allowMethods || 'GET (Default)'],
      ['CORS Credentials Mode', api?.corsConfig?.allowCredentials || 'false (Not permitted)'],
      ['CORS Evaluation Status', api?.corsConfig?.status || 'Restricted / Secure'],
      ['Authentication Challenge', api?.authIndicators?.status || 'Public / Unauthenticated'],
      ['Authentication Details', api?.authIndicators?.details || 'No credentials required'],
      ['Rate Limiting Status', api?.rateLimitIndicators?.status || 'Unverified from passive response'],
      ['Rate Limit Thresholds', api?.rateLimitIndicators?.limit ? `Limit: ${api.rateLimitIndicators.limit}, Remaining: ${api.rateLimitIndicators.remaining || 'N/A'}` : 'Not published in response headers'],
      ['Information Disclosure', api?.informationDisclosure?.status || 'Clean (No excessive technical disclosures)'],
      ['Response Format & Payload', `${api?.responseStructure?.format || 'Unknown'} (Structured: ${api?.responseStructure?.isStructured ? 'Yes' : 'No'})`],
    ];

    apiRows.forEach(([k, v], idx) => {
      checkPageBreak(5.5);
      if (idx % 2 === 0) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 5.2, 'F');
      }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(k, margin + 2, y + 3.7);

      doc.setFont('courier', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(15, 23, 42);
      const splitV = doc.splitTextToSize(v, contentWidth - 55);
      doc.text(splitV[0] || 'N/A', margin + 50, y + 3.7);
      y += 5.2;
    });
    y += 4;
  }

  // ── FILE SECURITY SPECIFIC AUDIT SECTION (FILE SCANS) ────────────────────
  const isFileScan = scan.targetType === 'File';
  if (isFileScan) {
    checkPageBreak(40);
    const file = scan.checks?.fileAnalysis;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text('File Security & Static Structure Analysis', margin, y);
    y += 4;

    const fileRows: Array<[string, string]> = [
      ['Target Filename', file?.filename || parsedTarget.path.split('/').pop() || 'file.bin'],
      ['File Extension', file?.extension ? `.${file.extension.replace(/^\\./, '')}` : 'none'],
      ['MIME Content-Type', file?.mimeType || 'application/octet-stream'],
      ['File Size', file?.fileSizeFormatted || (file?.fileSize ? `${file.fileSize} bytes` : 'Remote stream')],
      ['SHA-256 Checksum', file?.sha256 || 'N/A'],
      ['MD5 Checksum', file?.md5 || 'N/A'],
      ['Magic Bytes / Signature', file?.magicBytes || 'Standard header'],
      ['Static Structure Risk', file?.structureRisk || 'Standard / Low Structural Risk'],
      ['Transport Security', parsedTarget.protocol === 'HTTPS' ? 'Encrypted HTTPS' : 'Unencrypted HTTP (Cleartext)'],
    ];

    fileRows.forEach(([k, v], idx) => {
      checkPageBreak(5.5);
      if (idx % 2 === 0) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 5.2, 'F');
      }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(k, margin + 2, y + 3.7);

      doc.setFont('courier', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(15, 23, 42);
      const splitV = doc.splitTextToSize(v, contentWidth - 55);
      doc.text(splitV[0] || 'N/A', margin + 50, y + 3.7);
      y += 5.2;
    });
    y += 4;
  }

  // ── EXTENSION SECURITY SPECIFIC AUDIT SECTION (EXTENSION SCANS) ──────────
  const isExtensionScan = scan.targetType === 'Extension';
  if (isExtensionScan) {
    checkPageBreak(40);
    const ext = scan.checks?.extensionAnalysis;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text('Browser Extension Manifest & Permissions Audit', margin, y);
    y += 4;

    const extRows: Array<[string, string]> = [
      ['Extension Package / ID', ext?.extensionName || 'Browser Extension Target'],
      ['Manifest Architecture', `Manifest V${ext?.manifestVersion || 3} Standard`],
      ['Total Permissions Requested', `${ext?.permissions?.length || 0} permissions declared`],
      ['Declared Permissions', ext?.permissions?.length ? ext.permissions.join(', ') : 'None (Zero privileged APIs)'],
      ['Host Access Scope', ext?.hostPermissions?.length ? ext.hostPermissions.join(', ') : 'Restricted (No broad host access)'],
      ['Sensitive Permissions Flagged', `${ext?.dangerousPermissions?.length || 0} sensitive permissions`],
      ['Background Scripts / Workers', ext?.backgroundScripts?.length ? ext.backgroundScripts.join(', ') : 'None declared'],
      ['Content Scripts Injected', ext?.contentScripts?.length ? ext.contentScripts.join(', ') : 'None declared'],
    ];

    extRows.forEach(([k, v], idx) => {
      checkPageBreak(5.5);
      if (idx % 2 === 0) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 5.2, 'F');
      }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(k, margin + 2, y + 3.7);

      doc.setFont('courier', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(15, 23, 42);
      const splitV = doc.splitTextToSize(v, contentWidth - 55);
      doc.text(splitV[0] || 'N/A', margin + 50, y + 3.7);
      y += 5.2;
    });
    y += 4;
  }

  // ── PHISHING THREAT SPECIFIC AUDIT SECTION (PHISHING SCANS) ──────────────
  const isPhishingScan = scan.targetType === 'Phishing';
  if (isPhishingScan) {
    checkPageBreak(45);
    const phish = (scan.checks as any)?.phishingSecurityAnalysis || (scan.checks?.phishingAnalysis as any)?.phishingSecurityAnalysis || scan.checks?.phishingAnalysis;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text('Phishing & Deceptive Indicator Assessment', margin, y);
    y += 4;

    const brandImpersonationStatus = phish?.domainIdentityAnalysis?.impersonationDetected
      ? `Deceptive Impersonation (${phish.domainIdentityAnalysis.claimedBrand || 'Brand'} Mismatch)`
      : 'No Brand Impersonation Detected';

    const formDestStatus = phish?.credentialAnalysis?.externalActionFormCount && phish.credentialAnalysis.externalActionFormCount > 0
      ? `Insecure External Actions (${phish.credentialAnalysis.externalActionFormCount} form(s))`
      : phish?.credentialAnalysis?.hasLoginForm
      ? 'Same-Origin Authenticated Forms'
      : 'No Credential Forms Detected';

    const phishRows: Array<[string, string]> = [
      ['Target Hostname', parsedTarget.hostname],
      ['Registrable Domain', phish?.targetProfile?.registrableDomain || parsedTarget.domain],
      ['Subdomain Nesting Depth', `${parsedTarget.subdomainCount} level(s)`],
      ['Punycode / Homograph', parsedTarget.isPunycode ? 'Punycode Labels Detected' : 'Standard ASCII'],
      ['Brand Impersonation Status', brandImpersonationStatus],
      ['Form Submission Destinations', formDestStatus],
      ['Social Engineering Urgency', phish?.socialEngineeringAnalysis?.urgencyKeywordsFound?.length ? `Urgency Phrases Detected (${phish.socialEngineeringAnalysis.urgencyKeywordsFound.join(', ')})` : 'Neutral Profile (No Coercive Lures)'],
      ['Transport Security Status', parsedTarget.protocol === 'HTTPS' ? 'HTTPS Encrypted (TLS)' : 'Plaintext HTTP (Insecure)'],
      ['Threat Intelligence Feeds', phish?.threatIntelligence?.status || 'Not Configured (Direct Evidence Analysis)'],
      ['Heuristic Indicator Confidence', `${phish?.confidence || 0}% Confidence (${phish?.confidenceLabel || 'Heuristic Assessment'})`],
    ];

    phishRows.forEach(([k, v], idx) => {
      checkPageBreak(5.5);
      if (idx % 2 === 0) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 5.2, 'F');
      }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(k, margin + 2, y + 3.7);

      doc.setFont('courier', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(15, 23, 42);
      const splitV = doc.splitTextToSize(v, contentWidth - 55);
      doc.text(splitV[0] || 'N/A', margin + 50, y + 3.7);
      y += 5.2;
    });
    y += 4;

    // Score Contributors in PDF
    const contributors = phish?.scoreContributors || phish?.scoreExplanation?.contributors || [];
    if (contributors.length > 0) {
      checkPageBreak(30);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text('Risk Score Breakdown (Contributors)', margin, y);
      y += 3.5;

      contributors.forEach((c: any) => {
        checkPageBreak(8);
        doc.setFillColor(254, 242, 242);
        doc.rect(margin, y, contentWidth, 6, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(153, 27, 27);
        doc.text(`+${c.contribution} pts: ${c.title}`, margin + 2, y + 4);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(71, 85, 105);
        const reasonText = doc.splitTextToSize(c.reason, contentWidth - 80);
        doc.text(reasonText[0] || '', margin + 75, y + 4);
        y += 6.5;
      });
      y += 3;
    }
  }

  // ── NON-WEBSITE SECURITY FINDINGS ─────────────────────────────────────────
  if (!isWebsiteScan) {
    checkPageBreak(40);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(`Security Findings (${scan.findings?.length || 0})`, margin, y);
    y += 4;

    if (!scan.findings || scan.findings.length === 0) {
      doc.setFillColor(240, 253, 244);
      doc.roundedRect(margin, y, contentWidth, 12, 1.5, 1.5, 'F');
      doc.setDrawColor(187, 247, 208);
      doc.roundedRect(margin, y, contentWidth, 12, 1.5, 1.5, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(22, 101, 52);
      doc.text(
        isUrlScan
          ? 'No security findings identified based on observed URL-level evidence.'
          : 'No security findings or active anomalies were detected by the available checks.',
        margin + 4,
        y + 7.5
      );
      y += 16;
    } else {
      scan.findings.forEach((f) => {
        const { color: fColor, bg: fBg } = getPdfSeverityColors(f.severity);

        const cardHeight = f.impact || f.recommendation ? 22 : f.evidence ? 18 : 14;
        doc.setFillColor(fBg[0], fBg[1], fBg[2]);
        doc.roundedRect(margin, y, contentWidth, cardHeight, 1.5, 1.5, 'F');
        doc.setDrawColor(226, 232, 240);
        doc.roundedRect(margin, y, contentWidth, cardHeight, 1.5, 1.5, 'S');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(6.5);
        doc.setTextColor(fColor[0], fColor[1], fColor[2]);
        doc.text(`[${f.severity.toUpperCase()}] ${f.category}`, margin + 3, y + 4.2);

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(15, 23, 42);
        doc.text(f.title, margin + 3, y + 8.5);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(51, 65, 85);
        const descLines = doc.splitTextToSize(f.description, contentWidth - 6);
        doc.text(descLines[0] || '', margin + 3, y + 12);

        if (f.evidence) {
          doc.setFont('courier', 'normal');
          doc.setFontSize(6.5);
          doc.setTextColor(100, 116, 139);
          const evLines = doc.splitTextToSize(`Evidence: ${f.evidence}`, contentWidth - 6);
          doc.text(evLines[0] || '', margin + 3, y + 16);
        }

        if (f.recommendation && cardHeight > 18) {
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(6.5);
          doc.setTextColor(37, 99, 235);
          const recLines = doc.splitTextToSize(`Remediation: ${f.recommendation}`, contentWidth - 6);
          doc.text(recLines[0] || '', margin + 3, y + 19.8);
        }

        y += cardHeight + 3;
      });
    }
    y += 2;
  }

  // ── POSITIVE SECURITY SIGNALS (NON-WEBSITE SCANS) ─────────────────────────
  if (!isWebsiteScan) {
    const positiveSignals: Array<{ title: string; desc: string }> = [];
    if (isUrlScan && urlSec?.positiveSignals && urlSec.positiveSignals.length > 0) {
      positiveSignals.push(...urlSec.positiveSignals);
    } else if (isApiScan) {
      if (parsedTarget.protocol === 'HTTPS') {
        positiveSignals.push({
          title: 'HTTPS Transport Encryption Active',
          desc: 'API communications are secured in transit with standard TLS encryption.',
        });
      }
      if (scan.checks?.httpAnalysis?.statusCode && scan.checks.httpAnalysis.statusCode < 400) {
        positiveSignals.push({
          title: 'Endpoint Reachable and Responsive',
          desc: `Target responded with valid HTTP ${scan.checks.httpAnalysis.statusCode} in ${scan.checks.httpAnalysis.responseTimeMs || 0}ms.`,
        });
      }
      if (scan.checks?.apiAnalysis?.responseStructure?.isStructured) {
        positiveSignals.push({
          title: 'Structured API Payload',
          desc: `Target returned valid structured ${scan.checks.apiAnalysis.responseStructure.format} response data.`,
        });
      }
      if (!scan.checks?.apiAnalysis?.corsConfig?.isPermissive && scan.checks?.apiAnalysis?.corsConfig?.allowOrigin) {
        positiveSignals.push({
          title: 'Restricted CORS Origin Policy',
          desc: `Cross-origin access is explicitly restricted to: ${scan.checks.apiAnalysis.corsConfig.allowOrigin}`,
        });
      }
    } else if (isFileScan) {
      if (scan.checks?.fileAnalysis?.sha256) {
        positiveSignals.push({
          title: 'Cryptographic Checksum Verified',
          desc: `SHA-256 fingerprint generated successfully (${scan.checks.fileAnalysis.sha256.slice(0, 16)}...).`,
        });
      }
      if (parsedTarget.protocol === 'HTTPS') {
        positiveSignals.push({
          title: 'Secure Transport Protocol (HTTPS)',
          desc: 'File download endpoint operates over encrypted TLS/HTTPS.',
        });
      }
      if (scan.checks?.fileAnalysis?.structureRisk?.includes('Standard') || scan.checks?.fileAnalysis?.structureRisk?.includes('Low')) {
        positiveSignals.push({
          title: 'Standard Static Structure',
          desc: 'File extension and format do not exhibit executable disguise or evasion patterns.',
        });
      }
    } else if (isExtensionScan) {
      if (scan.checks?.extensionAnalysis?.manifestVersion === 3) {
        positiveSignals.push({
          title: 'Manifest V3 Architecture',
          desc: 'Extension complies with modern Chrome Manifest V3 security model.',
        });
      }
      if (!scan.checks?.extensionAnalysis?.dangerousPermissions || scan.checks.extensionAnalysis.dangerousPermissions.length === 0) {
        positiveSignals.push({
          title: 'Safe Permissions Scope',
          desc: 'Extension does not declare high-risk browser intercept or debugger capabilities.',
        });
      }
    } else if (isPhishingScan) {
      if (scan.checks?.phishingAnalysis?.status === 'passed') {
        positiveSignals.push({
          title: 'Clean Credential Profile',
          desc: 'No known credential harvesting or authentication lure keywords detected in URL structure.',
        });
      }
      if (parsedTarget.subdomainCount <= 2) {
        positiveSignals.push({
          title: 'Normal Subdomain Depth',
          desc: 'Hostname does not exhibit deep nesting or multi-tier deceptive subdomains.',
        });
      }
      if (parsedTarget.protocol === 'HTTPS') {
        positiveSignals.push({
          title: 'Transport Encryption Active',
          desc: 'Target URL establishes an encrypted HTTPS transport channel.',
        });
      }
    } else {
      if (parsedTarget.protocol === 'HTTPS') {
        positiveSignals.push({
          title: 'Transport Encryption Active',
          desc: 'Site forces secure HTTPS communication with valid TLS certificate.',
        });
      }
      if (scan.checks?.domainAnalysis?.dnsStatus === 'passed' || scan.checks?.domainAnalysis?.dnsStatus === 'Domain syntax valid') {
        positiveSignals.push({
          title: 'Standard Domain Identity',
          desc: 'Domain syntax and DNS infrastructure resolved successfully.',
        });
      }
    }

    if (positiveSignals.length > 0) {
      checkPageBreak(25);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42);
      doc.text(`Positive Security Signals (${positiveSignals.length})`, margin, y);
      y += 4;

      positiveSignals.forEach((sig) => {
        checkPageBreak(6.5);
        doc.setFillColor(22, 163, 74);
        doc.circle(margin + 2.8, y + 2.5, 0.9, 'F');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(30, 41, 59);
        doc.text(`${sig.title}: `, margin + 6, y + 3.5);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(71, 85, 105);
        const titleWidth = doc.getTextWidth(`${sig.title}: `);
        const sigLines = doc.splitTextToSize(sig.desc, contentWidth - 8 - titleWidth);
        doc.text(sigLines[0] || '', margin + 6 + titleWidth, y + 3.5);
        y += 4.5;
      });
      y += 3;
    }
  }

  // ── RISK SCORE CONTRIBUTORS (URL SCANS) ──────────────────────────────────
  if (isUrlScan && urlSec?.scoreContributors && urlSec.scoreContributors.length > 0) {
    checkPageBreak(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(`Risk Score Contributors (${scan.riskScore ?? 0}/100)`, margin, y);
    y += 4;

    urlSec.scoreContributors.forEach((c) => {
      checkPageBreak(6);
      doc.setFillColor(248, 250, 252);
      doc.rect(margin, y, contentWidth, 5.2, 'F');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(15, 23, 42);
      doc.text(c.name || c.category, margin + 2, y + 3.7);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(100, 116, 139);
      const rLines = doc.splitTextToSize(c.explanation || c.reason || '', contentWidth - 45);
      doc.text(rLines[0] || '', margin + 35, y + 3.7);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(c.points > 0 ? 217 : 22, c.points > 0 ? 119 : 163, c.points > 0 ? 6 : 74);
      doc.text(`+${c.points}`, pageWidth - margin - 2, y + 3.7, { align: 'right' });
      y += 5.2;
    });
    y += 4;
  }

  // ── RECOMMENDATIONS & GUIDANCE (NON-WEBSITE SCANS) ────────────────────────
  if (!isWebsiteScan && scan.recommendations && scan.recommendations.length > 0) {
    checkPageBreak(25);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(isApiScan ? 'Recommendations & Remediation Guidance' : 'Recommendations & Hardening Actions', margin, y);
    y += 4;

    scan.recommendations.forEach((rec) => {
      checkPageBreak(8);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(37, 99, 235);
      doc.text('•', margin + 2, y + 3.5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(30, 41, 59);
      const recLines = doc.splitTextToSize(rec, contentWidth - 8);
      doc.text(recLines, margin + 6, y + 3.5);
      y += recLines.length * 4.2;
    });
    y += 3;
  }

  // ── TECHNICAL DETAILS & SCANNER METADATA (MASKED) ─────────────────────────
  checkPageBreak(30);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text('Technical Details & Engine Metadata', margin, y);
  y += 4;

  const techRows: Array<[string, string]> = [
    ['Scan ID', scan.id || (scan as any)._id?.toString() || 'N/A'],
    ['Scan Engine Status', scan.status ? scan.status.toUpperCase() : 'COMPLETED'],
    ['Scan Timestamp', scan.scannedAt ? String(scan.scannedAt) : new Date().toISOString()],
    ['Target URL (Redacted)', parsedTarget.fullUrl],
    ['Hostname', parsedTarget.hostname],
    ['Protocol', parsedTarget.protocol === 'HTTPS' ? 'HTTPS / TLS' : 'HTTP'],
    ['Port', parsedTarget.port],
    ['Resolved IP(s)', domain?.resolvedIps?.join(', ') || (parsedTarget.isIpAddress ? parsedTarget.hostname : 'Not available')],
    ['HTTP Status', http?.statusCode ? `HTTP ${http.statusCode} ${http.statusText || ''}` : 'Not available'],
    ['Response Server Header', http?.server || (http as any)?.headers?.['server'] || 'Not disclosed'],
    ['Response Content-Type', http?.contentType || 'Not available'],
    ['Response Size', http?.contentLength ? `${http.contentLength} bytes` : 'Not available'],
    ['Response Time', http?.responseTimeMs !== undefined ? `${http.responseTimeMs} ms` : 'Not available'],
  ];

  techRows.forEach(([k, v]) => {
    checkPageBreak(5);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text(k, margin + 2, y + 3.5);

    doc.setFont('courier', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(15, 23, 42);
    doc.text(v, margin + 45, y + 3.5);
    y += 4.5;
  });

  // ── ANALYSIS LIMITATIONS ─────────────────────────────────────────────────
  checkPageBreak(18);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(margin, y, contentWidth, 12, 1, 1, 'F');
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentWidth, 12, 1, 1, 'S');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6.5);
  doc.setTextColor(100, 116, 139);
  doc.text('ANALYSIS LIMITATIONS & SCOPE NOTICE', margin + 3, y + 4);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.setTextColor(71, 85, 105);
  const limitTxt = isUrlScan
    ? 'This URL scan performs automated, non-destructive network and structural security analysis. It inspects transport security, routing trajectories, DNS resolution, and structural deception indicators without executing active penetration exploits or intrusive attacks.'
    : isApiScan
    ? 'This scan performs passive, non-destructive endpoint security assessment based on observed HTTP headers and response behavior. It does not perform active exploit verification, authentication brute-forcing, injection testing, or penetration testing.'
    : isFileScan
    ? 'This file scan performs safe, passive static analysis of file extension, MIME metadata, and cryptographic checksums. It does not perform dynamic malware detonation or runtime execution in a sandbox environment.'
    : isExtensionScan
    ? 'This extension scan evaluates static manifest definitions, declared permissions, and host access scopes. Dynamic runtime behavior analysis is not implemented; extension code was not executed.'
    : isPhishingScan
    ? 'This phishing assessment evaluates URL structure, deceptive tokens, domain characteristics, and transport security. It provides evidence-based threat indicators but does not guarantee immunity against all social engineering campaigns.'
    : 'This scan performs automated, non-destructive web-level security analysis. It does not constitute a full penetration test, vulnerability exploit verification, or guarantee that the target is free from web application vulnerabilities.';
  const limitLines = doc.splitTextToSize(limitTxt, contentWidth - 6);
  doc.text(limitLines, margin + 3, y + 7.5);
  y += 15;

  // ── FOOTER & PAGE NUMBERING ──────────────────────────────────────────────
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 12, margin + contentWidth, pageHeight - 12);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184); // #94a3b8
    doc.text('CyberWatch Threat Intelligence Platform • Confidential Security Assessment', margin, pageHeight - 7);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 7, { align: 'right' });
  }

  // Sanitize filename
  const cleanDomain = (parsedTarget.hostname || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStamp = new Date().toISOString().split('T')[0];
  const filename = `${filePrefix}_${cleanDomain}_${dateStamp}.pdf`;

  doc.save(filename);
}
