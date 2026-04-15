export function calculateScore(result) {
    let score = 100;
    // Vulnerability deductions
    for (const vuln of result.vulnerabilities) {
        switch (vuln.severity) {
            case "CRITICAL":
                score -= 25;
                break;
            case "HIGH":
                score -= 15;
                break;
            case "MEDIUM":
                score -= 8;
                break;
            case "LOW":
                score -= 3;
                break;
        }
    }
    // Source map leak deductions (cap at -20)
    score -= Math.min(result.sourceMapLeaks.length * 5, 20);
    // Exposed secret deductions (by severity)
    for (const secret of result.exposedSecrets) {
        switch (secret.severity) {
            case "critical":
                score -= 25;
                break;
            case "high":
                score -= 15;
                break;
            case "medium":
                score -= 8;
                break;
            case "low":
                score -= 3;
                break;
        }
    }
    // Homoglyph deductions
    score -= result.homoglyphIssues.length * 10;
    // Bonus: no dependencies = less attack surface
    if (result.dependencies.length === 0) {
        score = Math.min(score + 5, 100);
    }
    return Math.max(0, Math.min(100, score));
}
export function getScoreLabel(score) {
    if (score >= 90)
        return { label: "Excellent", color: "text-green-500" };
    if (score >= 70)
        return { label: "Good", color: "text-blue-500" };
    if (score >= 50)
        return { label: "Fair", color: "text-yellow-500" };
    if (score >= 30)
        return { label: "Poor", color: "text-orange-500" };
    return { label: "Critical", color: "text-red-500" };
}
//# sourceMappingURL=scorer.js.map