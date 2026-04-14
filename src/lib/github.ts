import type { RepoInfo, Dependency } from "./types";

const TOKEN_KEY = "gh_token";

export function getStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token: string | null): void {
  if (typeof window === "undefined") return;
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

function parseRepoUrl(input: string): { owner: string; repo: string } | null {
  const trimmed = input.trim().replace(/\/+$/, "");

  // Handle full URLs
  const urlPattern = /github\.com\/([^/]+)\/([^/]+)/;
  const urlMatch = trimmed.match(urlPattern);
  if (urlMatch) {
    return { owner: urlMatch[1], repo: urlMatch[2].replace(/\.git$/, "") };
  }

  // Handle owner/repo format
  const shortPattern = /^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/;
  const shortMatch = trimmed.match(shortPattern);
  if (shortMatch) {
    return { owner: shortMatch[1], repo: shortMatch[2] };
  }

  return null;
}

async function ghFetch<T>(path: string): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const headers: Record<string, string> = { Accept: "application/vnd.github.v3+json" };
    const token = getStoredToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const res = await fetch(`https://api.github.com${path}`, {
      headers,
      signal: controller.signal,
    });
    if (!res.ok) {
      if (res.status === 404) throw new Error("Repository not found. Make sure it is public.");
      if (res.status === 403) {
        const resetHeader = res.headers.get("x-ratelimit-reset");
        const resetTime = resetHeader
          ? new Date(parseInt(resetHeader) * 1000).toLocaleTimeString()
          : "a few minutes";
        throw new Error(`GitHub API rate limit exceeded. Resets at ${resetTime}. Unauthenticated limit is 60 requests/hour.`);
      }
      throw new Error(`GitHub API error: ${res.status}`);
    }
    return res.json() as Promise<T>;
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error("Request timed out. The GitHub API may be slow — try again.");
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchRepoInfo(input: string): Promise<RepoInfo> {
  const parsed = parseRepoUrl(input);
  if (!parsed) throw new Error("Invalid GitHub URL. Use format: https://github.com/owner/repo or owner/repo");

  const data = await ghFetch<{
    name: string;
    owner: { login: string };
    default_branch: string;
    description: string | null;
    stargazers_count: number;
    language: string | null;
  }>(`/repos/${parsed.owner}/${parsed.repo}`);

  return {
    owner: data.owner.login,
    repo: data.name,
    defaultBranch: data.default_branch,
    description: data.description,
    stars: data.stargazers_count,
    language: data.language,
  };
}

export async function fetchPackageJson(
  owner: string,
  repo: string,
  branch: string
): Promise<Dependency[]> {
  try {
    const data = await ghFetch<{ content: string }>(
      `/repos/${owner}/${repo}/contents/package.json?ref=${branch}`
    );
    const decoded = atob(data.content.replace(/\n/g, ""));
    const pkg = JSON.parse(decoded) as {
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

interface TreeItem {
  path: string;
  type: string;
  url?: string;
}

export async function fetchFileTree(
  owner: string,
  repo: string,
  branch: string
): Promise<string[]> {
  try {
    const data = await ghFetch<{ tree: TreeItem[] }>(
      `/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
    );
    return data.tree
      .filter((item: TreeItem) => item.type === "blob")
      .map((item: TreeItem) => item.path);
  } catch {
    return [];
  }
}

export async function fetchFileContent(
  owner: string,
  repo: string,
  path: string,
  branch: string
): Promise<string | null> {
  try {
    const data = await ghFetch<{ content: string; encoding: string }>(
      `/repos/${owner}/${repo}/contents/${path}?ref=${branch}`
    );
    if (data.encoding === "base64") {
      return atob(data.content.replace(/\n/g, ""));
    }
    return data.content;
  } catch {
    return null;
  }
}

export async function fetchContributors(
  owner: string,
  repo: string
): Promise<string[]> {
  try {
    const data = await ghFetch<Array<{ login: string }>>(
      `/repos/${owner}/${repo}/contributors?per_page=30`
    );
    return data.map((c) => c.login);
  } catch {
    return [];
  }
}
