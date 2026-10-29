import { jsPDF } from 'jspdf';
import { SafeScanRecord } from '../models/Scan';

export class PdfReportService {
  /**
   * Generates a clean A4 PDF report buffer from a stored scan record.
   */
  generatePdfBuffer(scan: SafeScanRecord): Buffer {
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

    // Header bar
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

    let reportTitle = 'URL & Phishing Security Threat Analysis Report';
    if (scan.targetType === 'Website') reportTitle = 'Website Security Analysis Report';
    if (scan.targetType === 'API') reportTitle = 'API Security Analysis Report';
    if (scan.targetType === 'File') reportTitle = 'File Security Analysis Report';
    if (scan.targetType === 'Extension') reportTitle = 'Browser Extension Security Report';

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(37, 99, 235);
    doc.text(reportTitle, margin, y);

    const scanDate = scan.scannedAt ? new Date(scan.scannedAt).toUTCString() : new Date().toUTCString();
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(`Generated: ${new Date().toLocaleDateString()} | Scan UTC: ${scanDate}`, pageWidth - margin, y, { align: 'right' });
    y += 6;

    // Divider
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.4);
    doc.line(margin, y, margin + contentWidth, y);
    y += 5;

    const isExtension = scan.targetType === 'Extension';
    const extSec = scan.checks?.extensionAnalysis;

    // ── Target Identity Box ────────────────────────────────────────────────
    doc.setFillColor(248, 250, 252);
    doc.roundedRect(margin, y, contentWidth, isExtension ? 20 : 14, 2, 2, 'F');
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, y, contentWidth, isExtension ? 20 : 14, 2, 2, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text(isExtension ? 'SCANNED BROWSER EXTENSION' : 'SCANNED TARGET URL', margin + 4, y + 4.5);

    if (isExtension && extSec) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text(extSec.extensionName || scan.target, margin + 4, y + 9.5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(71, 85, 105);
      const metaLine = `Version: ${extSec.version || '1.0.0'} | ID: ${extSec.extensionId || 'N/A'} | Developer: ${extSec.storeMetadata?.developer || extSec.author || 'Not verified'} | Store: ${extSec.storeMetadata?.store || 'Direct Package'}`;
      doc.text(metaLine, margin + 4, y + 14);

      if (extSec.packageIdentity?.sha256) {
        doc.setFont('courier', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(100, 116, 139);
        doc.text(`SHA-256: ${extSec.packageIdentity.sha256}`, margin + 4, y + 18);
      }
      y += 24;
    } else {
      doc.setFont('courier', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(15, 23, 42);
      const targetLines = doc.splitTextToSize(scan.target, contentWidth - 8);
      doc.text(targetLines.slice(0, 2), margin + 4, y + 9.5);
      y += 18;
    }

    // ── Overall Risk Card ──────────────────────────────────────────────────
    checkPageBreak(30);
    const riskScore = scan.riskScore ?? 0;
    const verdict = scan.result || 'Safe';

    let vColor: [number, number, number] = [22, 163, 74];
    let vBg: [number, number, number] = [236, 253, 245];
    if (verdict === 'Critical' || riskScore >= 75) {
      vColor = [220, 38, 38];
      vBg = [254, 242, 242];
    } else if (verdict === 'High Risk' || riskScore >= 50) {
      vColor = [234, 88, 12];
      vBg = [255, 247, 237];
    } else if (verdict === 'Suspicious' || riskScore >= 25) {
      vColor = [217, 119, 6];
      vBg = [254, 243, 199];
    } else if (verdict === 'Low Risk' || riskScore >= 12) {
      vColor = [2, 132, 199];
      vBg = [240, 249, 255];
    }

    doc.setFillColor(vBg[0], vBg[1], vBg[2]);
    doc.roundedRect(margin, y, contentWidth, 22, 2, 2, 'F');
    doc.setDrawColor(vColor[0], vColor[1], vColor[2]);
    doc.setLineWidth(0.5);
    doc.roundedRect(margin, y, contentWidth, 22, 2, 2, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('OVERALL SECURITY STATUS', margin + 4, y + 5);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(vColor[0], vColor[1], vColor[2]);
    doc.text(`VERDICT: ${String(verdict).toUpperCase()}`, margin + 4, y + 11.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    const summaryText =
      isExtension && extSec?.scoreExplanation?.summary
        ? extSec.scoreExplanation.summary
        : "CyberWatch's risk score represents the security risk indicated by evidence collected during this scan.";
    const splitSummary = doc.splitTextToSize(summaryText, contentWidth - 45);
    doc.text(splitSummary.slice(0, 2), margin + 4, y + 16.5);

    // Score box
    doc.setFillColor(255, 255, 255);
    doc.roundedRect(pageWidth - margin - 38, y + 3, 34, 16, 1.5, 1.5, 'F');
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(pageWidth - margin - 38, y + 3, 34, 16, 1.5, 1.5, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(100, 116, 139);
    doc.text('RISK SCORE', pageWidth - margin - 21, y + 7, { align: 'center' });

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(vColor[0], vColor[1], vColor[2]);
    doc.text(`${riskScore} / 100`, pageWidth - margin - 21, y + 13.5, { align: 'center' });
    y += 26;

    // ── Static Analysis Banner for Extensions ──────────────────────────────
    if (isExtension) {
      checkPageBreak(10);
      doc.setFillColor(241, 245, 249);
      doc.roundedRect(margin, y, contentWidth, 7, 1, 1, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7);
      doc.setTextColor(71, 85, 105);
      doc.text('STATIC ANALYSIS NOTICE: Extension code was not executed during this scan. Analysis is based on static inspection.', margin + 3, y + 4.5);
      y += 10;
    }

    // ── Score Contributors Breakdown ─────────────────────────────────────────
    const urlSec = scan.checks?.urlSecurityAnalysis;
    const phishSec = scan.checks?.phishingSecurityAnalysis;
    const fileSec = scan.checks?.fileAnalysis;
    const contributors = extSec?.scoreContributors || phishSec?.scoreContributors || urlSec?.scoreContributors || fileSec?.scoreContributors || [];

    if (contributors.length > 0) {
      checkPageBreak(contributors.length * 6 + 10);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text('Why This Score? (Contributors)', margin, y);
      y += 4.5;

      contributors.forEach((c: any) => {
        checkPageBreak(6.5);
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(margin, y, contentWidth, 5.8, 1, 1, 'F');
        doc.setDrawColor(226, 232, 240);
        doc.roundedRect(margin, y, contentWidth, 5.8, 1, 1, 'S');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(15, 23, 42);
        const nameText = `[+${c.points ?? (c as any).contribution ?? 0}] ${c.name || (c as any).title || c.category}`;
        doc.text(nameText, margin + 3, y + 3.8);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(100, 116, 139);
        const expl = (c.explanation || (c as any).reason || (c as any).evidence || '').slice(0, 80);
        doc.text(expl, margin + 70, y + 3.8);
        y += 6.5;
      });
      y += 3;
    }

    // ── Positive Security Signals for Extensions ────────────────────────────
    if (isExtension && extSec?.positiveSignals && extSec.positiveSignals.length > 0) {
      checkPageBreak(extSec.positiveSignals.length * 5 + 10);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text(`Positive Security Signals (${extSec.positiveSignals.length})`, margin, y);
      y += 4.5;

      extSec.positiveSignals.forEach((sig: any) => {
        checkPageBreak(5.5);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(22, 163, 74);
        doc.text('[VERIFIED]', margin + 3, y + 3.5);

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(15, 23, 42);
        doc.text(sig.title, margin + 20, y + 3.5);

        if (sig.desc) {
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(6.5);
          doc.setTextColor(100, 116, 139);
          doc.text(sig.desc.slice(0, 90), margin + 65, y + 3.5);
        }
        y += 5;
      });
      y += 3;
    }

    // ── Security Findings ───────────────────────────────────────────────────
    const findings = scan.findings || [];
    checkPageBreak(25);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`Security Findings (${findings.length})`, margin, y);
    y += 4.5;

    if (findings.length === 0) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text(
        isExtension
          ? 'Completed static analysis did not identify elevated-risk extension permissions, suspicious code patterns, or confirmed malicious indicators in the evidence that was successfully analyzed.'
          : 'No active risk indicators observed during this scan.',
        margin,
        y
      );
      y += 6;
    } else {
      findings.forEach((f: any) => {
        checkPageBreak(12);
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(margin, y, contentWidth, 10, 1, 1, 'F');
        doc.setDrawColor(226, 232, 240);
        doc.roundedRect(margin, y, contentWidth, 10, 1, 1, 'S');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(15, 23, 42);
        doc.text(`[${f.severity}] ${f.title}`, margin + 3, y + 4);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(71, 85, 105);
        const desc = (f.evidence ? `Evidence: ${f.evidence}` : f.description).slice(0, 110);
        doc.text(desc, margin + 3, y + 8);
        y += 11.5;
      });
      y += 2;
    }

    // ── Recommendations ─────────────────────────────────────────────────────
    const recs = scan.recommendations || [];
    if (recs.length > 0) {
      checkPageBreak(recs.length * 5 + 10);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text('Security Recommendations', margin, y);
      y += 4.5;

      recs.forEach((r: string) => {
        checkPageBreak(5);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(37, 99, 235);
        doc.text('•', margin + 3, y + 3.5);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(51, 65, 85);
        const rLines = doc.splitTextToSize(r, contentWidth - 8);
        doc.text(rLines[0], margin + 6, y + 3.5);
        y += 4.8;
      });
      y += 3;
    }

    // ── Limitations ─────────────────────────────────────────────────────────
    checkPageBreak(18);
    doc.setFillColor(241, 245, 249);
    doc.roundedRect(margin, y, contentWidth, 14, 1.5, 1.5, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(71, 85, 105);
    doc.text('SCAN COVERAGE & LIMITATIONS', margin + 3, y + 4);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6);
    doc.setTextColor(100, 116, 139);
    if (isExtension) {
      doc.text('CyberWatch analyzes observable extension package architecture, manifest declarations, permission scopes, and static JavaScript AST patterns.', margin + 3, y + 8);
      doc.text('Extension code was not executed during this scan. A completed scan reflects target state at scan time and does not guarantee that a target is completely safe.', margin + 3, y + 11.5);
    } else {
      doc.text('CyberWatch analyzes observable URL structure, DNS resolution, network responses, redirect routing, TLS certificates, and page forms.', margin + 3, y + 8);
      doc.text('A completed scan reflects target state at scan time and does not guarantee that a target is completely safe or malicious.', margin + 3, y + 11.5);
    }

    const pdfArray = doc.output('arraybuffer');
    return Buffer.from(pdfArray);
  }
}

export const pdfReportService = new PdfReportService();
