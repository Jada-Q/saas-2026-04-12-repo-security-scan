import type { SourceMapLeak, ExposedSecret, HomoglyphIssue } from "./types.js";
export declare function detectSourceMapLeaks(files: string[], owner: string, repo: string, branch: string): SourceMapLeak[];
export declare function scanSecrets(content: string, filePath: string): ExposedSecret[];
export declare function detectHomoglyphs(text: string, context: string): HomoglyphIssue[];
//# sourceMappingURL=scanners.d.ts.map