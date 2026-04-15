/**
 * Comprehensive secret detection patterns organized by category.
 * Each pattern includes a regex, classification, and severity level.
 */
export type SecretSeverity = "critical" | "high" | "medium" | "low";
export type SecretType = "api-key" | "token" | "password" | "private-key" | "connection-string" | "webhook" | "email";
export interface SecretPattern {
    id: string;
    name: string;
    pattern: RegExp;
    type: SecretType;
    severity: SecretSeverity;
    category: string;
}
export declare const SECRET_PATTERNS: SecretPattern[];
/** Get unique categories from all patterns */
export declare function getPatternCategories(): string[];
/** Get pattern count by category */
export declare function getPatternStats(): Record<string, number>;
//# sourceMappingURL=secret-patterns.d.ts.map