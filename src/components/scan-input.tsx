"use client";

import { useState, useEffect, useRef } from "react";
import { useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import type { ScanPhase } from "@/lib/types";
import { getStoredToken, setStoredToken } from "@/lib/github";

const SCAN_STEPS: ScanPhase[] = [
  "fetching-repo",
  "scanning-deps",
  "checking-sourcemaps",
  "scanning-secrets",
  "checking-homoglyphs",
  "scoring",
];

function ScanProgress({ phase }: { phase: ScanPhase }) {
  const currentIndex = SCAN_STEPS.indexOf(phase);
  const progress = currentIndex >= 0 ? ((currentIndex + 1) / SCAN_STEPS.length) * 100 : 0;

  return (
    <div className="space-y-2">
      <Progress value={progress} className="h-2" />
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>Step {currentIndex + 1} of {SCAN_STEPS.length}</span>
        <span>{Math.round(progress)}%</span>
      </div>
    </div>
  );
}

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
  const [showToken, setShowToken] = useState(false);
  const [token, setToken] = useState("");
  const searchParams = useSearchParams();
  const autoScannedRef = useRef(false);
  const isScanning = phase !== "idle" && phase !== "done" && phase !== "error";

  // Load saved token
  useEffect(() => {
    const saved = getStoredToken();
    if (saved) setToken(saved);
  }, []);

  const handleTokenSave = () => {
    setStoredToken(token.trim() || null);
    setShowToken(false);
  };

  // Auto-scan from URL params: ?repo=facebook/react
  useEffect(() => {
    if (autoScannedRef.current) return;
    const repoParam = searchParams.get("repo");
    if (repoParam) {
      autoScannedRef.current = true;
      setUrl(repoParam);
      onScan(repoParam);
    }
  }, [searchParams, onScan]);

  // Auto-scan on paste
  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    const pasted = e.clipboardData.getData("text").trim();
    if (pasted && (pasted.includes("github.com/") || pasted.includes("/"))) {
      setTimeout(() => onScan(pasted), 50);
    }
  };

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
              onPaste={handlePaste}
              placeholder="e.g. facebook/react or https://github.com/vercel/next.js"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              disabled={isScanning}
              autoFocus
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

        <div className="mt-3 flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowToken(!showToken)}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {token ? "Token configured (5,000 req/hr)" : "Add GitHub token for higher rate limits (optional)"}
          </button>
        </div>

        {showToken && (
          <div className="mt-2 flex gap-2">
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="ghp_... or github_pat_..."
              className="flex-1 rounded-md border border-input bg-background px-3 py-1.5 text-xs ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
            <Button size="sm" variant="outline" onClick={handleTokenSave}>
              Save
            </Button>
          </div>
        )}

        {phase !== "idle" && phase !== "done" && phase !== "error" && (
          <div className="mt-4 space-y-3">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 animate-pulse rounded-full bg-blue-500" />
              <span className="text-sm text-muted-foreground">{PHASE_LABELS[phase]}</span>
            </div>
            <ScanProgress phase={phase} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
