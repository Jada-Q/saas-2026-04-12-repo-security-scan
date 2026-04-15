// Types
export type {
  RepoInfo,
  Dependency,
  Vulnerability,
  SourceMapLeak,
  ExposedSecret,
  HomoglyphIssue,
  ScanPhase,
  ScanResult,
} from "./types.js";

// Scanners
export {
  detectSourceMapLeaks,
  scanSecrets,
  detectHomoglyphs,
} from "./scanners.js";

// Vulnerability checking
export { checkVulnerabilities } from "./osv.js";

// Scoring
export { calculateScore, getScoreLabel } from "./scorer.js";

// Secret patterns
export { SECRET_PATTERNS, getPatternCategories, getPatternStats } from "./secret-patterns.js";
export type { SecretPattern, SecretSeverity, SecretType } from "./secret-patterns.js";
