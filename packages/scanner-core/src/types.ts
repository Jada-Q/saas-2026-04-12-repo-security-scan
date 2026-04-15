export interface RepoInfo {
  owner: string;
  repo: string;
  defaultBranch: string;
  description: string | null;
  stars: number;
  language: string | null;
}

export interface Dependency {
  name: string;
  version: string;
  isDev: boolean;
}

export interface Vulnerability {
  id: string;
  summary: string;
  details: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  affected: string;
  fixedIn: string | null;
  reference: string;
}

export interface SourceMapLeak {
  file: string;
  url: string;
}

export interface ExposedSecret {
  type: "email" | "api-key" | "token" | "password" | "private-key" | "connection-string" | "webhook";
  severity: "critical" | "high" | "medium" | "low";
  patternName: string;
  value: string;
  file: string;
  line: number;
}

export interface HomoglyphIssue {
  original: string;
  ascii: string;
  position: string;
  codePoint: string;
  script: string;
}

export type ScanPhase =
  | "idle"
  | "fetching-repo"
  | "scanning-deps"
  | "checking-sourcemaps"
  | "scanning-secrets"
  | "checking-homoglyphs"
  | "scoring"
  | "done"
  | "error";

export interface ScanResult {
  repo: RepoInfo;
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
  sourceMapLeaks: SourceMapLeak[];
  exposedSecrets: ExposedSecret[];
  homoglyphIssues: HomoglyphIssue[];
  score: number;
  scannedAt: string;
}
