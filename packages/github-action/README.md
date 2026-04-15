# GHScan GitHub Action

Scan your repository for exposed secrets, vulnerable dependencies, and security misconfigurations on every push and PR.

- **152+ secret patterns** (AWS, OpenAI, Stripe, Supabase, Firebase, etc.)
- **Dependency vulnerability scanning** via OSV.dev
- **Source map leak detection**
- **PR comments** with scan results
- **File annotations** pointing to exact lines with issues

## Quick Start

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ghscan/action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `fail-threshold` | Minimum score to pass (0-100) | `70` |
| `scan-secrets` | Enable secret scanning | `true` |
| `scan-dependencies` | Enable dependency scanning | `true` |
| `scan-sourcemaps` | Enable source map detection | `true` |
| `github-token` | Token for PR comments | `${{ github.token }}` |
| `comment-on-pr` | Post results as PR comment | `true` |
| `max-files` | Max files to scan (0 = unlimited) | `0` |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `vulnerabilities` | Number of vulnerabilities found |
| `secrets` | Number of secrets found |
| `sourcemaps` | Number of source map leaks |
| `passed` | Whether scan passed threshold |

## Example: Block PRs with Critical Findings

```yaml
- uses: ghscan/action@v1
  with:
    fail-threshold: "50"
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Example: Secrets Only (Fast Scan)

```yaml
- uses: ghscan/action@v1
  with:
    scan-dependencies: "false"
    scan-sourcemaps: "false"
    github-token: ${{ secrets.GITHUB_TOKEN }}
```
