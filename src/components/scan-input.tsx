"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { ScanPhase } from "@/lib/types";

const PHASE_LABELS: Record<ScanPhase, string> = {
  idle: "",
  "fetching-repo": "Fetching repository info...",
  "scanning-deps": "Scanning dependencies for vulnerabilities...",
  "checking-sourcemaps": "Checking for source map leaks...",
  "scanning-secrets": "Scanning for exposed secrets...",
  "checking-homoglyphs": "Detecting homoglyph attacks...",
  scoring: "Calculating security score...",
  done: "Scan complete!",
  error: "Scan failed",
};

export function ScanInput({
  onScan,
  phase,
  onReset,
}: {
  onScan: (url: string) => void;
  phase: ScanPhase;
  onReset: () => void;
}) {
  const [url, setUrl] = useState("");
  const isScanning = phase !== "idle" && phase !== "done" && phase !== "error";

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || isScanning) return;
    onScan(url.trim());
  };

  const handleNewScan = () => {
    setUrl("");
    onReset();
  };

  return (
    <Card>
      <CardContent className="pt-6">
        <form onSubmit={handleSubmit} className="flex flex-col gap-4 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label
              htmlFor="repo-url"
              className="mb-2 block text-sm font-medium text-muted-foreground"
            >
              GitHub Repository URL or owner/repo
            </label>
            <input
              id="repo-url"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="e.g. facebook/react or https://github.com/vercel/next.js"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              disabled={isScanning}
            />
          </div>

          {phase === "done" || phase === "error" ? (
            <Button type="button" onClick={handleNewScan} variant="outline">
              New Scan
            </Button>
          ) : (
            <Button type="submit" disabled={!url.trim() || isScanning}>
              {isScanning ? "Scanning..." : "Scan"}
            </Button>
          )}
        </form>

        {phase !== "idle" && phase !== "done" && (
          <div className="mt-4 flex items-center gap-2">
            <div className="h-2 w-2 animate-pulse rounded-full bg-blue-500" />
            <span className="text-sm text-muted-foreground">{PHASE_LABELS[phase]}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
