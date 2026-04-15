import type { Dependency } from "@ghscan/scanner-core";
interface FileEntry {
    path: string;
    relativePath: string;
    isHighRisk: boolean;
}
/** Recursively collect scannable files from the workspace */
export declare function collectFiles(rootDir: string, maxFiles: number): FileEntry[];
/** Read file content, returns null if unreadable */
export declare function readFileContent(filePath: string): string | null;
/** Collect all file paths for source map detection */
export declare function collectAllFilePaths(rootDir: string): string[];
/** Parse package.json from workspace root */
export declare function parsePackageJson(rootDir: string): Dependency[];
export {};
