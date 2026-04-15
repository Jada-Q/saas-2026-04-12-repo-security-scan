import type { ScanResult } from "./types.js";
export declare function calculateScore(result: Omit<ScanResult, "score" | "scannedAt">): number;
export declare function getScoreLabel(score: number): {
    label: string;
    color: string;
};
//# sourceMappingURL=scorer.d.ts.map