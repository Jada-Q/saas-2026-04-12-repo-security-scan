"use client";

import { useState, useCallback } from "react";
import type { ScanResult, ScanPhase } from "./types";
import { fetchRepoInfo, fetchPackageJson, fetchFileTree, fetchFileContent, fetchContributors } from "./github";
import { checkVulnerabilities } from "./osv";
import { detectSourceMapLeaks, scanSecrets, detectHomoglyphs } from "./scanners";
import { calculateScore } from "./scorer";

// High-risk files most likely to contain leaked secrets
const HIGH_RISK_FILES = [
  ".env", ".env.local", ".env.production", ".env.development",
  "config.json", "config.yml", "config.yaml", "config.toml",
  "secrets.json", "credentials.json", "service-account.json",
  "docker-compose.yml", "docker-compose.yaml",
  ".npmrc", ".pypirc",
];

const SCANNABLE_EXTENSIONS = [
  ".env", ".cfg", ".conf", ".ini",
  ".json", ".yml", ".yaml", ".toml",
  ".js", ".ts", ".py",
];

const MAX_FILE_SIZE_SCAN = 15; // reduced from 50 to save API calls

export function useScanner() {
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const scan = useCallback(async (input: string) => {
    setError(null);
    setResult(null);

    try {
      // Phase 1: Fetch repo info
      setPhase("fetching-repo");
      const repo = await fetchRepoInfo(input);

      // Phase 2: Scan dependencies
      setPhase("scanning-deps");
      const dependencies = await fetchPackageJson(repo.owner, repo.repo, repo.defaultBranch);
      const vulnerabilities = await checkVulnerabilities(dependencies);

      // Phase 3: Check source maps
      setPhase("checking-sourcemaps");
      const files = await fetchFileTree(repo.owner, repo.repo, repo.defaultBranch);
      const sourceMapLeaks = detectSourceMapLeaks(files, repo.owner, repo.repo, repo.defaultBranch);

      // Phase 4: Scan secrets
      setPhase("scanning-secrets");
      // Prioritize high-risk files, then scan by extension
      const highRisk = files.filter((f) =>
        HIGH_RISK_FILES.some((hr) => f.endsWith(hr) || f.split("/").pop() === hr)
      );
      const byExtension = files
        .filter((f) => SCANNABLE_EXTENSIONS.some((ext) => f.endsWith(ext)))
        .filter((f) => !f.includes("node_modules/") && !f.includes("vendor/"))
        .filter((f) => !highRisk.includes(f));
      const scannableFiles = [...highRisk, ...byExtension].slice(0, MAX_FILE_SIZE_SCAN);

      const allSecrets = [];
      for (const filePath of scannableFiles) {
        const content = await fetchFileContent(repo.owner, repo.repo, filePath, repo.defaultBranch);
        if (content) {
          const secrets = scanSecrets(content, filePath);
          allSecrets.push(...secrets);
        }
      }

      // Phase 5: Check homoglyphs
      setPhase("checking-homoglyphs");
      const homoglyphIssues = [];

      // Check repo URL
      const repoUrl = `${repo.owner}/${repo.repo}`;
      homoglyphIssues.push(...detectHomoglyphs(repoUrl, "repo-url"));

      // Check contributors
      const contributors = await fetchContributors(repo.owner, repo.repo);
      for (const contributor of contributors) {
        homoglyphIssues.push(...detectHomoglyphs(contributor, `contributor:${contributor}`));
      }

      // Check description
      if (repo.description) {
        homoglyphIssues.push(...detectHomoglyphs(repo.description, "description"));
      }

      // Phase 6: Score
      setPhase("scoring");
      const partial = {
        repo,
        dependencies,
        vulnerabilities,
        sourceMapLeaks,
        exposedSecrets: allSecrets,
        homoglyphIssues,
      };

      const score = calculateScore(partial);
      const scanResult: ScanResult = {
        ...partial,
        score,
        scannedAt: new Date().toISOString(),
      };

      setResult(scanResult);
      setPhase("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred");
      setPhase("error");
    }
  }, []);

  const reset = useCallback(() => {
    setPhase("idle");
    setResult(null);
    setError(null);
  }, []);

  return { phase, result, error, scan, reset };
}
