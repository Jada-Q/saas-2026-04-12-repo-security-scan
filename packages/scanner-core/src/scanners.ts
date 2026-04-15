import type { SourceMapLeak, ExposedSecret, HomoglyphIssue } from "./types.js";
import { SECRET_PATTERNS } from "./secret-patterns.js";

// --- Source Map Detection ---

const SOURCE_MAP_EXTENSIONS = [".js.map", ".css.map", ".mjs.map"];

const SOURCE_MAP_IGNORE_DIRS = [
  "test", "tests", "__tests__", "fixtures", "__fixtures__",
  "spec", "__mocks__", "vendor", "third_party", "node_modules",
];

export function detectSourceMapLeaks(
  files: string[],
  owner: string,
  repo: string,
  branch: string
): SourceMapLeak[] {
  const leaks: SourceMapLeak[] = [];

  for (const file of files) {
    if (!SOURCE_MAP_EXTENSIONS.some((ext) => file.endsWith(ext))) continue;

    const parts = file.toLowerCase().split("/");
    if (parts.some((p) => SOURCE_MAP_IGNORE_DIRS.includes(p))) continue;

    leaks.push({
      file,
      url: `https://github.com/${owner}/${repo}/blob/${branch}/${file}`,
    });
  }

  return leaks;
}

// --- Secret Detection ---

const EMAIL_PATTERN = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

const IGNORE_FILES = [
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  ".env.example",
  ".env.template",
  ".env.sample",
  "CHANGELOG.md",
  "LICENSE",
  "LICENSE.md",
];

const FALSE_POSITIVE_VALUES = [
  "xxx", "YOUR_", "REPLACE_", "INSERT_", "TODO",
  "undefined", "null", "placeholder", "example",
  "test_key", "dummy", "changeme", "sk-xxx",
  "sk-your-", "pk_test_", "sk_test_",
];

export function scanSecrets(
  content: string,
  filePath: string
): ExposedSecret[] {
  if (IGNORE_FILES.some((f) => filePath.endsWith(f))) return [];
  if (filePath.includes("node_modules/")) return [];
  if (filePath.includes("vendor/")) return [];

  const secrets: ExposedSecret[] = [];
  const seen = new Set<string>();
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*") || trimmed.startsWith("<!--")) {
      continue;
    }

    if (!filePath.endsWith(".md") && !filePath.endsWith(".txt")) {
      const emailMatches = line.match(EMAIL_PATTERN);
      if (emailMatches) {
        for (const email of emailMatches) {
          if (email.includes("example.com") || email.includes("placeholder") || email.includes("@types") || email.includes("@localhost")) {
            continue;
          }
          const key = `email:${email}:${filePath}`;
          if (!seen.has(key)) {
            seen.add(key);
            secrets.push({ type: "email", severity: "low", patternName: "Email Address", value: email, file: filePath, line: i + 1 });
          }
        }
      }
    }

    for (const sp of SECRET_PATTERNS) {
      const regex = new RegExp(sp.pattern.source, sp.pattern.flags);
      let match;
      while ((match = regex.exec(line)) !== null) {
        const value = match[1] ?? match[0];

        if (isFalsePositive(value)) continue;

        const dedupeKey = `${sp.id}:${maskSecret(value)}:${filePath}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        secrets.push({
          type: sp.type,
          severity: sp.severity,
          patternName: sp.name,
          value: maskSecret(value),
          file: filePath,
          line: i + 1,
        });
      }
    }
  }

  return secrets;
}

function isFalsePositive(value: string): boolean {
  const lower = value.toLowerCase();
  return FALSE_POSITIVE_VALUES.some((fp) => lower.includes(fp.toLowerCase()));
}

function maskSecret(value: string): string {
  if (value.length <= 8) return "****";
  return value.slice(0, 4) + "..." + value.slice(-4);
}

// --- Homoglyph Detection ---

const CONFUSABLES: Record<string, string> = {
  "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
  "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
  "\u0455": "s", "\u0458": "j", "\u04BB": "h", "\u0501": "d",
  "\u051B": "q", "\u0261": "g", "\u026A": "i", "\u0432": "b",
  "\u043D": "h", "\u0433": "r",
  "\u03B1": "a", "\u03B5": "e", "\u03BF": "o", "\u03C1": "p",
  "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
  "\u0399": "I", "\u039A": "K", "\u039C": "M", "\u039D": "N",
  "\u039F": "O", "\u03A1": "P", "\u03A4": "T", "\u03A5": "Y",
  "\u03A7": "X", "\u03A6": "Z",
  "\uFF41": "a", "\uFF42": "b", "\uFF43": "c", "\uFF44": "d", "\uFF45": "e",
  "\u0131": "i",
};

const SCRIPT_NAMES: Record<string, string> = {
  "\u0430": "Cyrillic", "\u0435": "Cyrillic", "\u043E": "Cyrillic",
  "\u0440": "Cyrillic", "\u0441": "Cyrillic", "\u0443": "Cyrillic",
  "\u0445": "Cyrillic", "\u0456": "Cyrillic", "\u0455": "Cyrillic",
  "\u0458": "Cyrillic", "\u04BB": "Cyrillic", "\u0501": "Cyrillic",
  "\u051B": "Cyrillic", "\u0432": "Cyrillic", "\u043D": "Cyrillic",
  "\u0433": "Cyrillic",
  "\u0261": "Latin Extended", "\u026A": "Latin Extended",
  "\u03B1": "Greek", "\u03B5": "Greek", "\u03BF": "Greek", "\u03C1": "Greek",
  "\u0391": "Greek", "\u0392": "Greek", "\u0395": "Greek", "\u0397": "Greek",
  "\u0399": "Greek", "\u039A": "Greek", "\u039C": "Greek", "\u039D": "Greek",
  "\u039F": "Greek", "\u03A1": "Greek", "\u03A4": "Greek", "\u03A5": "Greek",
  "\u03A7": "Greek", "\u03A6": "Greek",
  "\uFF41": "Fullwidth", "\uFF42": "Fullwidth", "\uFF43": "Fullwidth",
  "\uFF44": "Fullwidth", "\uFF45": "Fullwidth",
  "\u0131": "Turkish",
};

export function detectHomoglyphs(text: string, context: string): HomoglyphIssue[] {
  const issues: HomoglyphIssue[] = [];

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const ascii = CONFUSABLES[char];
    if (ascii) {
      const codePoint = `U+${char.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`;
      issues.push({
        original: char,
        ascii,
        position: `${context}[${i}]`,
        codePoint,
        script: SCRIPT_NAMES[char] ?? "Unknown",
      });
    }
  }

  return issues;
}
