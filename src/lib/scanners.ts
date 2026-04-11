import type { SourceMapLeak, ExposedSecret, HomoglyphIssue } from "./types";

// --- Source Map Detection ---

const SOURCE_MAP_EXTENSIONS = [".js.map", ".css.map", ".mjs.map"];

export function detectSourceMapLeaks(
  files: string[],
  owner: string,
  repo: string,
  branch: string
): SourceMapLeak[] {
  const leaks: SourceMapLeak[] = [];

  for (const file of files) {
    if (SOURCE_MAP_EXTENSIONS.some((ext) => file.endsWith(ext))) {
      leaks.push({
        file,
        url: `https://github.com/${owner}/${repo}/blob/${branch}/${file}`,
      });
    }
  }

  return leaks;
}

// --- Secret Detection ---

const EMAIL_PATTERN = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

const API_KEY_PATTERNS = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']([^"']{20,})["']/gi, type: "api-key" as const },
  { pattern: /(?:secret|token)\s*[:=]\s*["']([^"']{20,})["']/gi, type: "token" as const },
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']/gi, type: "password" as const },
  { pattern: /AIza[0-9A-Za-z_-]{35}/g, type: "api-key" as const }, // Google API key
  { pattern: /sk-[a-zA-Z0-9]{20,}/g, type: "api-key" as const }, // OpenAI / Stripe secret
  { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: "token" as const }, // GitHub PAT
  { pattern: /AKIA[0-9A-Z]{16}/g, type: "api-key" as const }, // AWS Access Key
];

const IGNORE_FILES = [
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  ".env.example",
  ".env.template",
  "CHANGELOG.md",
  "LICENSE",
];

export function scanSecrets(
  content: string,
  filePath: string
): ExposedSecret[] {
  if (IGNORE_FILES.some((f) => filePath.endsWith(f))) return [];
  if (filePath.includes("node_modules/")) return [];

  const secrets: ExposedSecret[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments
    if (line.trim().startsWith("//") || line.trim().startsWith("#") || line.trim().startsWith("*")) {
      continue;
    }

    // Check for emails (only in code files, not docs)
    if (!filePath.endsWith(".md") && !filePath.endsWith(".txt")) {
      const emailMatches = line.match(EMAIL_PATTERN);
      if (emailMatches) {
        for (const email of emailMatches) {
          // Skip common false positives
          if (email.includes("example.com") || email.includes("placeholder") || email.includes("@types")) {
            continue;
          }
          secrets.push({ type: "email", value: email, file: filePath, line: i + 1 });
        }
      }
    }

    // Check for API keys and tokens
    for (const { pattern, type } of API_KEY_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(line)) !== null) {
        const value = match[1] ?? match[0];
        // Skip common false positives
        if (value.includes("xxx") || value.includes("YOUR_") || value === "undefined") {
          continue;
        }
        secrets.push({ type, value: maskSecret(value), file: filePath, line: i + 1 });
      }
    }
  }

  return secrets;
}

function maskSecret(value: string): string {
  if (value.length <= 8) return "****";
  return value.slice(0, 4) + "..." + value.slice(-4);
}

// --- Homoglyph Detection ---

// Common confusable character mappings (Unicode → ASCII)
const CONFUSABLES: Record<string, string> = {
  "\u0430": "a", // Cyrillic а
  "\u0435": "e", // Cyrillic е
  "\u043E": "o", // Cyrillic о
  "\u0440": "p", // Cyrillic р
  "\u0441": "c", // Cyrillic с
  "\u0443": "y", // Cyrillic у
  "\u0445": "x", // Cyrillic х
  "\u0456": "i", // Cyrillic і
  "\u0455": "s", // Cyrillic ѕ
  "\u0458": "j", // Cyrillic ј
  "\u04BB": "h", // Cyrillic һ
  "\u0501": "d", // Cyrillic ԁ
  "\u051B": "q", // Cyrillic ԛ
  "\u0261": "g", // Latin ɡ
  "\u026A": "i", // Latin ɪ
  "\u0432": "b", // Cyrillic в (close to 6/b)
  "\u043D": "h", // Cyrillic н
  "\u0433": "r", // Cyrillic г (in some fonts)
  "\u03B1": "a", // Greek α
  "\u03B5": "e", // Greek ε (sometimes)
  "\u03BF": "o", // Greek ο
  "\u03C1": "p", // Greek ρ
  "\u0391": "A", // Greek Α
  "\u0392": "B", // Greek Β
  "\u0395": "E", // Greek Ε
  "\u0397": "H", // Greek Η
  "\u0399": "I", // Greek Ι
  "\u039A": "K", // Greek Κ
  "\u039C": "M", // Greek Μ
  "\u039D": "N", // Greek Ν
  "\u039F": "O", // Greek Ο
  "\u03A1": "P", // Greek Ρ
  "\u03A4": "T", // Greek Τ
  "\u03A5": "Y", // Greek Υ
  "\u03A7": "X", // Greek Χ
  "\u03A6": "Z", // Greek Ζ
  "\uFF41": "a", // Fullwidth ａ
  "\uFF42": "b",
  "\uFF43": "c",
  "\uFF44": "d",
  "\uFF45": "e",
  "\u0131": "i", // Turkish dotless ı
};

const SCRIPT_NAMES: Record<string, string> = {
  "\u0430": "Cyrillic",
  "\u0435": "Cyrillic",
  "\u043E": "Cyrillic",
  "\u0440": "Cyrillic",
  "\u0441": "Cyrillic",
  "\u0443": "Cyrillic",
  "\u0445": "Cyrillic",
  "\u0456": "Cyrillic",
  "\u0455": "Cyrillic",
  "\u0458": "Cyrillic",
  "\u04BB": "Cyrillic",
  "\u0501": "Cyrillic",
  "\u051B": "Cyrillic",
  "\u0432": "Cyrillic",
  "\u043D": "Cyrillic",
  "\u0433": "Cyrillic",
  "\u0261": "Latin Extended",
  "\u026A": "Latin Extended",
  "\u03B1": "Greek",
  "\u03B5": "Greek",
  "\u03BF": "Greek",
  "\u03C1": "Greek",
  "\u0391": "Greek",
  "\u0392": "Greek",
  "\u0395": "Greek",
  "\u0397": "Greek",
  "\u0399": "Greek",
  "\u039A": "Greek",
  "\u039C": "Greek",
  "\u039D": "Greek",
  "\u039F": "Greek",
  "\u03A1": "Greek",
  "\u03A4": "Greek",
  "\u03A5": "Greek",
  "\u03A7": "Greek",
  "\u03A6": "Greek",
  "\uFF41": "Fullwidth",
  "\uFF42": "Fullwidth",
  "\uFF43": "Fullwidth",
  "\uFF44": "Fullwidth",
  "\uFF45": "Fullwidth",
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
