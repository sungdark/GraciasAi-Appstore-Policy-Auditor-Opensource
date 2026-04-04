/**
 * Android Play Store Audit Report Generator
 * Generates structured markdown reports for Android app compliance audits
 */

import { PLAY_STORE_CATEGORIES, SEVERITY_LABELS, getSeverityForFinding } from './config.js';

/**
 * Generates the audit report in markdown format
 */
export function generateAuditReport(files, findings, metadata = {}) {
  const { appName = 'Android App', filesScanned = 0, apkInfo = {} } = metadata;
  
  // Count findings by severity
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, PASS: 0 };
  const issues = [];
  
  for (const finding of findings) {
    if (finding.status === 'PASS') {
      counts.PASS++;
    } else {
      const severity = finding.severity || getSeverityForFinding(finding.description);
      counts[severity]++;
      issues.push({ ...finding, severity });
    }
  }
  
  // Sort issues by severity
  issues.sort((a, b) => {
    const aIdx = SEVERITY_LABELS.indexOf(a.severity);
    const bIdx = SEVERITY_LABELS.indexOf(b.severity);
    return aIdx - bIdx;
  });
  
  // Determine overall risk level
  const overallRisk = determineRiskLevel(counts);
  
  // Generate report sections
  let report = '';
  
  report += generateHeader(appName, apkInfo);
  report += generateDashboard(counts, overallRisk, issues.length, filesScanned);
  report += generateExecutiveSummary(appName, issues, counts, overallRisk);
  report += generateDetailedFindings(findings);
  report += generateRemediationPlan(issues);
  report += generateSubmissionReadiness(overallRisk, issues);
  report += generateFooter();
  
  return report;
}

/**
 * Generates the report header
 */
function generateHeader(appName, apkInfo) {
  const date = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  
  return `# Google Play Store Compliance Audit Report

**App Name:** ${appName}
**Audit Date:** ${date}
**Platform:** Android

${apkInfo.packageName ? `**Package Name:** \`${apkInfo.packageName}\`` : ''}
${apkInfo.versionName ? `**Version:** ${apkInfo.versionName}` : ''}
${apkInfo.versionCode ? `**Version Code:** ${apkInfo.versionCode}` : ''}

---

`;
}

/**
 * Generates the dashboard summary table
 */
function generateDashboard(counts, overallRisk, issueCount, filesScanned) {
  const riskEmoji = {
    '🟢 LOW RISK': 'LOW RISK',
    '🟡 MEDIUM RISK': 'MEDIUM RISK',
    '🔴 HIGH RISK': 'HIGH RISK',
    '🔴🔴 CRITICAL RISK': 'CRITICAL RISK',
  };
  
  const recommendation = counts.CRITICAL > 0 || counts.HIGH > 2
    ? 'NO — Issues must be resolved'
    : counts.HIGH > 0 || counts.MEDIUM > 3
      ? 'NOT READY — Resolve critical issues first'
      : 'YES — Ready to submit with minor fixes';
  
  const readinessScore = calculateReadinessScore(counts);
  
  return `## Audit Dashboard

| Metric | Value |
|--------|-------|
| Overall Risk Level | ${overallRisk} |
| Submission Recommendation | ${recommendation} |
| Readiness Score | ${readinessScore}/100 |
| Files Analyzed | ${filesScanned} |
| Critical Issues | ${counts.CRITICAL} |
| High Issues | ${counts.HIGH} |
| Medium Issues | ${counts.MEDIUM} |
| Low Issues | ${counts.LOW} |
| Passed Checks | ${counts.PASS} |

---

`;
}

/**
 * Generates the executive summary
 */
function generateExecutiveSummary(appName, issues, counts, overallRisk) {
  const totalIssues = issues.length;
  const criticalCount = counts.CRITICAL;
  const highCount = counts.HIGH;
  
  let summary = `## Executive Summary

`;
  
  if (criticalCount > 0) {
    summary += `This audit identified **${criticalCount} critical issue${criticalCount > 1 ? 's' : ''}** that require${criticalCount === 1 ? 's' : ''} immediate attention before submission to the Google Play Store. `;
  } else if (highCount > 0) {
    summary += `This audit identified **${highCount} high-severity issue${highCount > 1 ? 's' : ''}** that should be addressed before Play Store submission. `;
  } else if (totalIssues > 0) {
    summary += `This audit identified **${totalIssues} issue${totalIssues > 1 ? 's' : ''}** that should be reviewed and resolved where applicable. `;
  } else {
    summary += `This app appears to be well-aligned with Google Play Store policies based on the code analyzed. `;
  }
  
  summary += `The overall risk assessment is **${overallRisk}**. `;
  
  if (criticalCount > 0 || highCount > 0) {
    summary += `Please review the detailed findings below and address the highest-priority items before resubmission.`;
  } else if (totalIssues > 0) {
    summary += `These items are recommended improvements that will enhance your app's compliance posture.`;
  } else {
    summary += `Continue to monitor policy updates and ensure any future changes maintain this compliance level.`;
  }
  
  summary += '\n\n';
  
  return summary;
}

/**
 * Generates detailed findings section
 */
function generateDetailedFindings(findings) {
  let section = `## Phase 1: Policy Compliance Checks

`;
  
  // Group findings by category
  const grouped = {};
  for (const categoryKey of Object.keys(PLAY_STORE_CATEGORIES)) {
    grouped[categoryKey] = {
      name: PLAY_STORE_CATEGORIES[categoryKey].name,
      findings: findings.filter(f => f.category === categoryKey),
    };
  }
  
  for (const [categoryKey, category] of Object.entries(grouped)) {
    section += `### ${category.name}\n\n`;
    
    if (category.findings.length === 0) {
      section += `> **[STATUS: PASS]** No issues identified in this category.\n\n`;
      continue;
    }
    
    for (const finding of category.findings) {
      section += generateFindingBlock(finding);
    }
    
    section += '\n';
  }
  
  return section;
}

/**
 * Generates a single finding block
 */
function generateFindingBlock(finding) {
  const status = finding.status === 'PASS' ? 'PASS' : finding.severity || 'MEDIUM';
  const statusIcon = status === 'PASS' ? '✅' : status === 'CRITICAL' ? '🔴' : status === 'HIGH' ? '🟠' : status === 'MEDIUM' ? '🟡' : '🔵';
  
  let block = `> **[STATUS: ${statusIcon} ${status}]** ${finding.policyName || finding.checkName || 'Policy Check'}\n>\n`;
  block += `> **Guideline:** ${finding.guideline || 'Google Play Store Policy'}\n>\n`;
  block += `> **Finding:** ${finding.description || finding.finding || 'No issues found.'}\n>\n`;
  
  if (finding.files && finding.files.length > 0) {
    const fileList = finding.files.map(f => `\`${f.file}:${f.line || 'N/A'}\``).join(', ');
    block += `> **File(s):** ${fileList}\n>\n`;
  }
  
  if (finding.status !== 'PASS') {
    block += `> **Action:** ${finding.action || finding.remediation || 'Review and address this finding.'}\n`;
  }
  
  block += '\n';
  
  return block;
}

/**
 * Generates the remediation plan table
 */
function generateRemediationPlan(issues) {
  let section = `## Phase 2: Remediation Plan\n\n`;
  
  if (issues.length === 0) {
    section += `No remediation items required. Your app appears to be compliant with Play Store policies.\n\n`;
    return section;
  }
  
  section += `| # | Issue | Severity | Category | File(s) | Fix Description | Effort |\n`;
  section += `|---|-------|----------|----------|---------|-----------------|--------|\n`;
  
  issues.forEach((issue, idx) => {
    const issueName = issue.policyName || issue.checkName || 'Policy Issue';
    const files = issue.files ? issue.files.map(f => `\`${f.file}:${f.line || 'N/A'}\``).join(', ') : '-';
    const fix = issue.action || issue.remediation || 'Review and resolve';
    const effort = estimateEffort(issue);
    
    section += `| ${idx + 1} | ${issueName} | ${issue.severity} | ${issue.categoryName || 'General'} | ${files} | ${fix} | ${effort} |\n`;
  });
  
  section += '\n';
  
  // Add priority summary
  section += `### Remediation Priority\n\n`;
  
  if (issues.some(i => i.severity === 'CRITICAL')) {
    section += `**Priority 1 (Critical):** Address all critical issues immediately. These will result in app suspension or rejection.\n\n`;
  }
  if (issues.some(i => i.severity === 'HIGH')) {
    section += `**Priority 2 (High):** Resolve high-severity issues before publication. These frequently trigger policy violations.\n\n`;
  }
  if (issues.some(i => i.severity === 'MEDIUM')) {
    section += `**Priority 3 (Medium):** Review medium-severity items and address where applicable.\n\n`;
  }
  if (issues.some(i => i.severity === 'LOW')) {
    section += `**Priority 4 (Low):** Consider improvements for best practices compliance.\n\n`;
  }
  
  return section;
}

/**
 * Generates submission readiness section
 */
function generateSubmissionReadiness(overallRisk, issues) {
  const criticalHigh = issues.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH');
  
  let verdict = 'READY';
  let summary = '';
  
  if (criticalHigh.length > 0) {
    verdict = 'NOT READY';
    summary = `This app is **not ready for submission** to the Google Play Store. ${criticalHigh.length} critical or high-severity issue${criticalHigh.length > 1 ? 's' : ''} must be resolved before publication. `;
    summary += `Failure to address these issues will likely result in app rejection or suspension.`;
  } else if (issues.length > 0) {
    verdict = 'READY WITH CAVEATS';
    summary = `This app is **conditionally ready** for submission. There are ${issues.length} medium or low-severity issue${issues.length > 1 ? 's' : ''} that should be reviewed. `;
    summary += `These are not immediate blockers but should be addressed to ensure long-term compliance.`;
  } else {
    summary = `This app appears to be **fully compliant** with Google Play Store policies based on this audit. `;
    summary += `However, always verify the latest policy changes and ensure your Data Safety form accurately reflects your app's data practices.`;
  }
  
  return `## Submission Readiness

**Score:** ${calculateReadinessScore({ issues })}/100

**Verdict:** ${verdict}

${summary}

### Next Steps

1. **Immediate:** Address any CRITICAL and HIGH severity items
2. **Before Submission:** Complete the Data Safety form in Play Console to match your actual data practices
3. **Before Launch:** Review Google Play's latest policy updates for any changes
4. **Ongoing:** Set up policy alerts in Play Console and monitor for any violations

---

`;
}

/**
 * Generates the report footer
 */
function generateFooter() {
  return `## Contact

For professional assistance with your app development and Play Store compliance:

**Email:** business@gracias.sh
**Website:** https://gracias.sh

---

*This audit report was generated by Gracias AI - Google Play Store Compliance Auditor. The findings are based on automated code analysis and should be verified manually for accuracy. Policy interpretations may vary based on specific app functionality and use cases.*

*Report generated on: ${new Date().toISOString()}*
`;
}

/**
 * Determines overall risk level based on issue counts
 */
function determineRiskLevel(counts) {
  if (counts.CRITICAL > 0) return '🔴🔴 CRITICAL RISK';
  if (counts.HIGH > 0) return '🔴 HIGH RISK';
  if (counts.MEDIUM > 3) return '🟡 MEDIUM RISK';
  if (counts.MEDIUM > 0) return '🟡 LOW-MEDIUM RISK';
  if (counts.LOW > 0) return '🟢 LOW RISK';
  return '🟢 PASSED';
}

/**
 * Calculates readiness score (0-100)
 */
function calculateReadinessScore(counts) {
  const { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, PASS = 0 } = counts;
  
  const total = CRITICAL + HIGH + MEDIUM + LOW + PASS;
  if (total === 0) return 100;
  
  const score = Math.max(0, 100 - (CRITICAL * 25) - (HIGH * 15) - (MEDIUM * 5) - (LOW * 1));
  return Math.round(score);
}

/**
 * Estimates remediation effort
 */
function estimateEffort(issue) {
  const severity = issue.severity;
  const desc = (issue.description || '').toLowerCase();
  
  // Quick heuristic based on common patterns
  if (desc.includes('metadata') || desc.includes('listing') || desc.includes('screenshot')) {
    return 'Low';
  }
  if (desc.includes('permission') && !desc.includes('background')) {
    return 'Low';
  }
  if (desc.includes('billing') || desc.includes('payment')) {
    return 'High';
  }
  if (desc.includes('data collection') || desc.includes('privacy policy')) {
    return 'Medium';
  }
  if (desc.includes('background location')) {
    return 'High';
  }
  if (desc.includes('crash') || desc.includes('stability')) {
    return 'Medium';
  }
  
  return severity === 'CRITICAL' ? 'High' : severity === 'HIGH' ? 'Medium' : 'Low';
}

/**
 * Creates a streaming-friendly metadata event
 */
export function createMetaEvent(files, metadata = {}) {
  return JSON.stringify({
    type: 'meta',
    filesScanned: files.length,
    fileNames: files.map(f => f.path),
    platform: 'android',
    ...metadata,
  }) + '\n';
}

/**
 * Creates a streaming content event
 */
export function createContentEvent(text) {
  return JSON.stringify({
    type: 'content',
    text,
  }) + '\n';
}

/**
 * Creates a streaming error event
 */
export function createErrorEvent(message) {
  return JSON.stringify({
    type: 'error',
    message,
  }) + '\n';
}
