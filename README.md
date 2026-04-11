# Repo Security Scan

Scan any public GitHub repository for security issues — entirely client-side.

## Features

- **Dependency Vulnerabilities** — Checks npm dependencies against the OSV.dev vulnerability database (Critical/High/Medium/Low)
- **Source Map Detection** — Finds exposed `.map` files that could leak source code
- **Secret Scanner** — Detects API keys, tokens, passwords, and email addresses in code files
- **Homoglyph Detection** — Identifies Unicode spoofing characters in repo URLs, contributors, and descriptions
- **Security Score** — Unified 0-100 score across all dimensions
- **Markdown Export** — One-click report download

## Tech Stack

- Next.js (App Router) + TypeScript
- Tailwind CSS + shadcn/ui
- pnpm

## Getting Started

```bash
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

## How It Works

All scanning runs in the browser:

1. Fetches repo metadata via GitHub REST API
2. Queries OSV.dev for known vulnerabilities in `package.json` dependencies
3. Scans the file tree for `.map` files (source map leaks)
4. Reads up to 50 code files to detect hardcoded secrets via pattern matching
5. Checks repo URL, contributor names, and description for Unicode homoglyphs
6. Calculates a composite security score

No login required. No data stored.
