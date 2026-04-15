import { getScoreLabel, SECRET_PATTERNS } from "@ghscan/scanner-core";
const MARKER = "<!-- ghscan-report -->";
/** Generate markdown report for PR comment */
export function generateMarkdownReport(result, threshold) {
    const { label } = getScoreLabel(result.score);
    const passed = result.score >= threshold;
    const statusIcon = passed ? "✅" : "❌";
    const lines = [];
    lines.push(MARKER);
    lines.push(`## ${statusIcon} GHScan Security Report`);
    lines.push("");
    lines.push(`**Score: ${result.score}/100** (${label}) — Threshold: ${threshold}`);
    lines.push("");
    // Summary table
    lines.push("| Check | Findings |");
    lines.push("|-------|----------|");
    const critSecrets = result.exposedSecrets.filter((s) => s.severity === "critical").length;
    const highSecrets = result.exposedSecrets.filter((s) => s.severity === "high").length;
    const secretSummary = result.exposedSecrets.length === 0
        ? "None found"
        : `${result.exposedSecrets.length} (${critSecrets} critical, ${highSecrets} high)`;
    const critVulns = result.vulnerabilities.filter((v) => v.severity === "CRITICAL").length;
    const highVulns = result.vulnerabilities.filter((v) => v.severity === "HIGH").length;
    const vulnSummary = result.vulnerabilities.length === 0
        ? "None found"
        : `${result.vulnerabilities.length} (${critVulns} critical, ${highVulns} high)`;
    lines.push(`| Secrets (${SECRET_PATTERNS.length} patterns) | ${secretSummary} |`);
    lines.push(`| Dependencies | ${vulnSummary} |`);
    lines.push(`| Source Maps | ${result.sourceMapLeaks.length === 0 ? "None found" : `${result.sourceMapLeaks.length} exposed`} |`);
    lines.push(`| Homoglyphs | ${result.homoglyphIssues.length === 0 ? "None found" : `${result.homoglyphIssues.length} issues`} |`);
    lines.push("");
    // Critical/High findings detail
    const criticalFindings = result.exposedSecrets.filter((s) => s.severity === "critical");
    const highFindings = result.exposedSecrets.filter((s) => s.severity === "high");
    if (criticalFindings.length > 0 || highFindings.length > 0) {
        lines.push("<details>");
        lines.push(`<summary>🔴 ${criticalFindings.length + highFindings.length} Critical/High Secrets</summary>`);
        lines.push("");
        lines.push("| Severity | Pattern | File | Line |");
        lines.push("|----------|---------|------|------|");
        for (const s of [...criticalFindings, ...highFindings]) {
            lines.push(`| ${s.severity.toUpperCase()} | ${s.patternName} | \`${s.file}\` | ${s.line} |`);
        }
        lines.push("");
        lines.push("</details>");
        lines.push("");
    }
    // Vulnerability detail
    const critVulnList = result.vulnerabilities.filter((v) => v.severity === "CRITICAL" || v.severity === "HIGH");
    if (critVulnList.length > 0) {
        lines.push("<details>");
        lines.push(`<summary>🟠 ${critVulnList.length} Critical/High Vulnerabilities</summary>`);
        lines.push("");
        lines.push("| Severity | ID | Package | Fix |");
        lines.push("|----------|----|---------|----|");
        for (const v of critVulnList) {
            lines.push(`| ${v.severity} | [${v.id}](${v.reference}) | ${v.affected} | ${v.fixedIn ?? "N/A"} |`);
        }
        lines.push("");
        lines.push("</details>");
        lines.push("");
    }
    lines.push("---");
    lines.push("*Scanned by [GHScan](https://ghscan.vercel.app)*");
    return lines.join("\n");
}
/** Check if a PR comment is a GHScan report */
export function isGhscanComment(body) {
    return body.includes(MARKER);
}
