"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { getScoreLabel } from "@/lib/scorer";
import type { ScanResult } from "@/lib/types";

export function ScoreCard({ result }: { result: ScanResult }) {
  const { label, color } = getScoreLabel(result.score);

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center justify-between">
          <span>
            {result.repo.owner}/{result.repo.repo}
          </span>
          <span className={`text-3xl font-bold ${color}`}>
            {result.score}
          </span>
        </CardTitle>
        {result.repo.description && (
          <p className="text-sm text-muted-foreground">{result.repo.description}</p>
        )}
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className={`font-medium ${color}`}>{label}</span>
            <span className="text-muted-foreground">
              {result.repo.language ?? "Unknown"} / {result.repo.stars.toLocaleString()} stars
            </span>
          </div>
          <Progress value={result.score} className="h-3" />

          <div className="grid grid-cols-2 gap-4 pt-2 sm:grid-cols-4">
            <StatBlock
              label="Vulnerabilities"
              value={result.vulnerabilities.length}
              danger={result.vulnerabilities.length > 0}
            />
            <StatBlock
              label="Source Maps"
              value={result.sourceMapLeaks.length}
              danger={result.sourceMapLeaks.length > 0}
            />
            <StatBlock
              label="Secrets"
              value={result.exposedSecrets.length}
              danger={result.exposedSecrets.length > 0}
            />
            <StatBlock
              label="Homoglyphs"
              value={result.homoglyphIssues.length}
              danger={result.homoglyphIssues.length > 0}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatBlock({
  label,
  value,
  danger,
}: {
  label: string;
  value: number;
  danger: boolean;
}) {
  return (
    <div className="rounded-lg border p-3 text-center">
      <div className={`text-2xl font-bold ${danger ? "text-red-500" : "text-green-500"}`}>
        {value}
      </div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}
