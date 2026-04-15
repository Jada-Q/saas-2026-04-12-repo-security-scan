import { readFileSync, readdirSync, statSync, readFile } from "node:fs";
import { join, relative, extname } from "node:path";
import type { Dependency } from "@ghscan/scanner-core";

const SCANNABLE_EXTENSIONS = new Set([
  ".env", ".cfg", ".conf", ".ini",
  ".json", ".yml", ".yaml", ".toml",
  ".js", ".ts", ".jsx", ".tsx",
  ".py", ".rb", ".go", ".rs",
  ".java", ".kt", ".cs",
  ".sh", ".bash", ".zsh",
  ".xml", ".properties",
  ".tf", ".tfvars",
  ".dockerfile",
]);

const IGNORE_DIRS = new Set([
  "node_modules", ".git", ".next", ".vercel",
  "dist", "build", "out", ".output",
  "vendor", "target", "__pycache__",
  ".turbo", ".cache", "coverage",
]);

const IGNORE_FILES = new Set([
  "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
  ".env.example", ".env.template", ".env.sample",
]);

const HIGH_RISK_FILES = new Set([
  ".env", ".env.local", ".env.production", ".env.development",
  "config.json", "config.yml", "config.yaml",
  "secrets.json", "credentials.json", "service-account.json",
  "docker-compose.yml", "docker-compose.yaml",
  ".npmrc", ".pypirc",
]);

interface FileEntry {
  path: string;
  relativePath: string;
  isHighRisk: boolean;
}

/** Recursively collect scannable files from the workspace */
export function collectFiles(rootDir: string, maxFiles: number): FileEntry[] {
  const files: FileEntry[] = [];

  function walk(dir: string): void {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry)) continue;

      const fullPath = join(dir, entry);
      let stat;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.isDirectory()) {
        walk(fullPath);
      } else if (stat.isFile()) {
        const rel = relative(rootDir, fullPath);
        const fileName = entry;

        if (IGNORE_FILES.has(fileName)) continue;

        const isHighRisk = HIGH_RISK_FILES.has(fileName);
        const ext = extname(fileName).toLowerCase();

        // Include high-risk files regardless of extension
        // Include Dockerfile (no extension but specific name)
        if (isHighRisk || SCANNABLE_EXTENSIONS.has(ext) || fileName === "Dockerfile") {
          files.push({ path: fullPath, relativePath: rel, isHighRisk });
        }
      }
    }
  }

  walk(rootDir);

  // Sort: high-risk first, then by path
  files.sort((a, b) => {
    if (a.isHighRisk && !b.isHighRisk) return -1;
    if (!a.isHighRisk && b.isHighRisk) return 1;
    return a.relativePath.localeCompare(b.relativePath);
  });

  if (maxFiles > 0) {
    return files.slice(0, maxFiles);
  }

  return files;
}

/** Read file content, returns null if unreadable */
export function readFileContent(filePath: string): string | null {
  try {
    return readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

/** Collect all file paths for source map detection */
export function collectAllFilePaths(rootDir: string): string[] {
  const paths: string[] = [];

  function walk(dir: string): void {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry)) continue;

      const fullPath = join(dir, entry);
      let stat;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.isDirectory()) {
        walk(fullPath);
      } else if (stat.isFile()) {
        paths.push(relative(rootDir, fullPath));
      }
    }
  }

  walk(rootDir);
  return paths;
}

/** Parse package.json from workspace root */
export function parsePackageJson(rootDir: string): Dependency[] {
  try {
    const content = readFileSync(join(rootDir, "package.json"), "utf-8");
    const pkg = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };

    const deps: Dependency[] = [];

    if (pkg.dependencies) {
      for (const [name, version] of Object.entries(pkg.dependencies)) {
        deps.push({ name, version, isDev: false });
      }
    }

    if (pkg.devDependencies) {
      for (const [name, version] of Object.entries(pkg.devDependencies)) {
        deps.push({ name, version, isDev: true });
      }
    }

    return deps;
  } catch {
    return [];
  }
}
