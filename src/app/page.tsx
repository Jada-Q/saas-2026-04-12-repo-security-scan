"use client";

import { Suspense } from "react";
import { ScanInput } from "@/components/scan-input";
import { ScoreCard } from "@/components/score-card";
import { ResultsTabs } from "@/components/results-tabs";
import { useScanner } from "@/lib/use-scanner";

export default function HomePage() {
  return (
    <Suspense>
      <HomePageInner />
    </Suspense>
  );
}

function HomePageInner() {
  const { phase, result, error, scan, reset } = useScanner();

  return (
    <main className="mx-auto w-full max-w-4xl flex-1 px-4 py-8 sm:px-6">
      <header className="mb-8 text-center">
        <h1 className="text-3xl font-bold tracking-tight">Is Your Code Leaking Secrets?</h1>
        <p className="mt-2 text-muted-foreground">
          Check if your API keys, passwords, or database credentials are exposed in your GitHub repo.
          152+ secret patterns. Takes ~15 seconds.
        </p>
      </header>

      <div className="space-y-6">
        <ScanInput onScan={scan} phase={phase} onReset={reset} error={error} />

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <p>{error}</p>
            {error.includes("rate limit") && (
              <p className="mt-2 text-xs">
                To fix this, add a GitHub token: go to{" "}
                <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer" className="underline">
                  github.com/settings/tokens
                </a>
                {" "}→ Generate new token (classic) → No scopes needed → paste it below.
              </p>
            )}
          </div>
        )}

        {result && (
          <>
            <ScoreCard result={result} />
            <ResultsTabs result={result} />
          </>
        )}

        {phase === "idle" && !result && (
          <div className="space-y-6 pt-8 text-center text-sm text-muted-foreground">
            <div className="mx-auto grid max-w-lg grid-cols-1 gap-3 sm:grid-cols-2">
              <FeatureCard
                title="Exposed API Keys"
                desc="Your OpenAI or Stripe key might be in your JS bundle right now"
              />
              <FeatureCard
                title="Vulnerable Dependencies"
                desc="Known security holes in your npm packages that attackers can exploit"
              />
              <FeatureCard
                title="Database Credentials"
                desc="Supabase, Firebase, or Postgres connection strings visible to anyone"
              />
              <FeatureCard
                title="Source Code Leaks"
                desc="Source maps exposing your original code to the public"
              />
            </div>
            <div>
              <button
                type="button"
                onClick={() => scan("vercel/next.js")}
                className="text-sm text-blue-600 hover:text-blue-800 hover:underline dark:text-blue-400 dark:hover:text-blue-300"
              >
                Try a demo scan on vercel/next.js
              </button>
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
