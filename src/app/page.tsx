"use client";

import { ScanInput } from "@/components/scan-input";
import { ScoreCard } from "@/components/score-card";
import { ResultsTabs } from "@/components/results-tabs";
import { useScanner } from "@/lib/use-scanner";

export default function HomePage() {
  const { phase, result, error, scan, reset } = useScanner();

  return (
    <main className="mx-auto w-full max-w-4xl flex-1 px-4 py-8 sm:px-6">
      <header className="mb-8 text-center">
        <h1 className="text-3xl font-bold tracking-tight">Repo Security Scan</h1>
        <p className="mt-2 text-muted-foreground">
          Scan any public GitHub repository for vulnerabilities, source map leaks, exposed secrets,
          and homoglyph attacks.
        </p>
      </header>

      <div className="space-y-6">
        <ScanInput onScan={scan} phase={phase} onReset={reset} />

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
            {error}
          </div>
        )}

        {result && (
          <>
            <ScoreCard result={result} />
            <ResultsTabs result={result} />
          </>
        )}

        {phase === "idle" && !result && (
          <div className="space-y-4 pt-8 text-center text-sm text-muted-foreground">
            <p>Enter a GitHub repository URL to start scanning.</p>
            <div className="mx-auto grid max-w-lg grid-cols-1 gap-3 sm:grid-cols-2">
              <FeatureCard
                title="Vulnerability Scan"
                desc="Checks npm dependencies against the OSV.dev vulnerability database"
              />
              <FeatureCard
                title="Source Map Detection"
                desc="Finds exposed .map files that could leak your source code"
              />
              <FeatureCard
                title="Secret Scanner"
                desc="Detects exposed API keys, tokens, passwords, and emails"
              />
              <FeatureCard
                title="Homoglyph Detection"
                desc="Identifies Unicode spoofing in repo URLs and contributor names"
              />
            </div>
          </div>
        )}
      </div>

      <footer className="mt-12 border-t pt-6 text-center text-xs text-muted-foreground">
        <p>
          Pure client-side scanning using GitHub REST API + OSV.dev. No data is stored or sent to
          any server.
        </p>
      </footer>
    </main>
  );
}

function FeatureCard({ title, desc }: { title: string; desc: string }) {
  return (
    <div className="rounded-lg border p-4 text-left">
      <p className="font-medium">{title}</p>
      <p className="mt-1 text-xs text-muted-foreground">{desc}</p>
    </div>
  );
}
