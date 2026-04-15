export type { RepoInfo, Dependency, Vulnerability, SourceMapLeak, ExposedSecret, HomoglyphIssue, ScanPhase, ScanResult, } from "./types.js";
export { detectSourceMapLeaks, scanSecrets, detectHomoglyphs, } from "./scanners.js";
export { checkVulnerabilities } from "./osv.js";
export { calculateScore, getScoreLabel } from "./scorer.js";
export { SECRET_PATTERNS, getPatternCategories, getPatternStats } from "./secret-patterns.js";
export type { SecretPattern, SecretSeverity, SecretType } from "./secret-patterns.js";
//# sourceMappingURL=index.d.ts.map