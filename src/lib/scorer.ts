import type { ScanResult } from "./types";

export function calculateScore(result: Omit<ScanResult, "score" | "scannedAt">): number {
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

  // Source map leak deductions
  score -= result.sourceMapLeaks.length * 5;

  // Exposed secret deductions
  for (const secret of result.exposedSecrets) {
    switch (secret.type) {
      case "api-key":
      case "token":
        score -= 20;
        break;
      case "password":
        score -= 25;
        break;
      case "email":
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

export function getScoreLabel(score: number): {
  label: string;
  color: string;
} {
  if (score >= 90) return { label: "Excellent", color: "text-green-600" };
  if (score >= 70) return { label: "Good", color: "text-blue-600" };
  if (score >= 50) return { label: "Fair", color: "text-yellow-600" };
  if (score >= 30) return { label: "Poor", color: "text-orange-600" };
  return { label: "Critical", color: "text-red-600" };
}
