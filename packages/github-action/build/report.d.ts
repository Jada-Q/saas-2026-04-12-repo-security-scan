import type { ScanResult } from "@ghscan/scanner-core";
/** Generate markdown report for PR comment */
export declare function generateMarkdownReport(result: ScanResult, threshold: number): string;
/** Check if a PR comment is a GHScan report */
export declare function isGhscanComment(body: string): boolean;
