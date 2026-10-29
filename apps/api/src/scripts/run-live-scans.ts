import dotenv from 'dotenv';
dotenv.config();

import { connectDatabase, disconnectDatabase } from '../config/database';
import { scanService } from '../services/scan.service';

async function runLiveScans() {
  console.log('='.repeat(80));
  console.log('CYBERWATCH MEGA URL + PHISHING THREAT SCANNER — LIVE SCORING BREAKDOWN');
  console.log('='.repeat(80));

  try {
    await connectDatabase();
  } catch {
    console.log('[Notice] Running in standalone inspection mode.');
  }

  const targets = [
    'https://example.com',
    'http://example.com',
    'https://httpbin.org/redirect/2',
  ];

  for (const target of targets) {
    console.log('\n' + '#'.repeat(80));
    console.log(`SCAN TARGET: ${target}`);
    console.log('#'.repeat(80));

    try {
      const result = await scanService.analyzeAndSave({
        target,
        targetType: 'URL',
      });

      console.log(`\n--- RESULT SUMMARY ---`);
      console.log(`Target:             ${result.target}`);
      console.log(`Status:             ${result.status}`);
      console.log(`Final Risk Score:   ${result.riskScore} / 100`);
      console.log(`Verdict:            ${result.result}`);

      const urlSec = result.checks.urlSecurityAnalysis;
      const phishSec = result.checks.phishingSecurityAnalysis;

      console.log(`\n--- DEDUPLICATED FINDINGS & EVIDENCE ---`);
      if (!result.findings || result.findings.length === 0) {
        console.log('No findings recorded.');
      } else {
        result.findings.forEach((f, idx) => {
          const fid = (f as any).findingId || f.id || `finding-${idx + 1}`;
          const pts = (f as any).scoreContribution !== undefined ? (f as any).scoreContribution : (f.severity === 'INFO' ? 0 : 'N/A');
          const source = (f as any).source || 'unified';
          console.log(`\n  [Finding #${idx + 1}] ${f.title}`);
          console.log(`    - Finding ID:         ${fid}`);
          console.log(`    - Category:           ${f.category}`);
          console.log(`    - Severity:           ${f.severity}`);
          console.log(`    - Source:             ${source}`);
          console.log(`    - Score Contribution: +${pts} pts`);
          console.log(`    - Description:        ${f.description}`);
          if (f.evidence) {
            console.log(`    - Evidence:           ${f.evidence}`);
          }
        });
      }

      console.log(`\n--- SCORE CONTRIBUTORS BREAKDOWN ---`);
      const contributors = (urlSec?.scoreContributors || phishSec?.scoreContributors || []) as any[];
      if (contributors.length === 0) {
        console.log('  No risk points contributed (Baseline: 0 pts).');
      } else {
        let totalPts = 0;
        contributors.forEach((c: any, idx: number) => {
          const pts = c.points || c.contribution || 0;
          totalPts += pts;
          console.log(`  ${idx + 1}. [${c.category || 'Risk'}] ${c.name || c.title || 'Factor'}: +${pts} pts — ${c.reason || c.explanation || ''}`);
        });
        console.log(`  Total Raw Risk: ${totalPts} pts -> Clamped Final Risk: ${Math.min(100, Math.max(0, totalPts))} / 100`);
      }

      if (urlSec?.whyVerdict && urlSec.whyVerdict.length > 0) {
        console.log(`\n--- WHY THIS VERDICT ---`);
        urlSec.whyVerdict.forEach((w, idx) => {
          console.log(`  ${idx + 1}. ${w}`);
        });
      }

      console.log(`\n--- TRANSPORT & REDIRECT METRICS ---`);
      console.log(`  - HTTPS Active:       ${urlSec?.certificateSummary?.httpsEnabled ?? 'N/A'}`);
      console.log(`  - TLS Protocol:       ${urlSec?.certificateSummary?.tlsVersion || 'None'}`);
      console.log(`  - Certificate Issuer: ${urlSec?.certificateSummary?.issuer || 'None'}`);
      console.log(`  - Final URL:          ${urlSec?.finalUrl || result.checks.httpAnalysis?.finalUrl || target}`);
      console.log(`  - Redirect Count:     ${result.checks.redirectAnalysis?.redirectCount ?? 0}`);
      if (result.checks.redirectAnalysis?.chain && result.checks.redirectAnalysis.chain.length > 0) {
        console.log(`  - Redirect Chain:`);
        result.checks.redirectAnalysis.chain.forEach((hop, idx) => {
          console.log(`      Hop ${idx + 1}: ${hop.url} [${hop.statusCode || 302}]`);
        });
      }
      console.log(`  - Threat Intel:       ${urlSec?.threatIntelligence?.status || 'Not Configured'}`);

    } catch (err: any) {
      console.error(`Error scanning ${target}:`, err.message || err);
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log('LIVE SCAN COMPLETED SUCCESSFULLY');
  console.log('='.repeat(80));

  await disconnectDatabase();
  process.exit(0);
}

runLiveScans().catch((err) => {
  console.error(err);
  process.exit(1);
});
