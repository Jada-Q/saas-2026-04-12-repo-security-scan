import * as core from "@actions/core";
import * as github from "@actions/github";
import { scanSecrets, detectSourceMapLeaks, checkVulnerabilities, calculateScore, SECRET_PATTERNS, } from "@ghscan/scanner-core";
import { collectFiles, readFileContent, collectAllFilePaths, parsePackageJson } from "./scan-files.js";
import { generateMarkdownReport, isGhscanComment } from "./report.js";
async function run() {
    try {
        const threshold = parseInt(core.getInput("fail-threshold") || "70", 10);
        const scanSecretsEnabled = core.getInput("scan-secrets") !== "false";
        const scanDepsEnabled = core.getInput("scan-dependencies") !== "false";
        const scanSourcemapsEnabled = core.getInput("scan-sourcemaps") !== "false";
        const commentOnPr = core.getInput("comment-on-pr") !== "false";
        const maxFiles = parseInt(core.getInput("max-files") || "0", 10);
        const token = core.getInput("github-token");
        const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
        const { owner, repo } = github.context.repo;
        core.info(`GHScan: scanning ${owner}/${repo} with ${SECRET_PATTERNS.length} secret patterns`);
        core.info(`Workspace: ${workspace}`);
        // --- Scan secrets ---
        let allSecrets = [];
        if (scanSecretsEnabled) {
            core.startGroup("Scanning for secrets");
            const files = collectFiles(workspace, maxFiles);
            core.info(`Found ${files.length} scannable files (${files.filter((f) => f.isHighRisk).length} high-risk)`);
            for (const file of files) {
                const content = readFileContent(file.path);
                if (content) {
                    const secrets = scanSecrets(content, file.relativePath);
                    allSecrets.push(...secrets);
                }
            }
            core.info(`Found ${allSecrets.length} potential secrets`);
            core.endGroup();
        }
        // --- Scan dependencies ---
        let vulnerabilities = [];
        if (scanDepsEnabled) {
            core.startGroup("Scanning dependencies");
            const deps = parsePackageJson(workspace);
            core.info(`Found ${deps.length} dependencies`);
            if (deps.length > 0) {
                vulnerabilities = await checkVulnerabilities(deps);
                core.info(`Found ${vulnerabilities.length} vulnerabilities`);
            }
            core.endGroup();
        }
        // --- Scan source maps ---
        let sourceMapLeaks = [];
        if (scanSourcemapsEnabled) {
            core.startGroup("Checking source maps");
            const allPaths = collectAllFilePaths(workspace);
            const branch = github.context.ref.replace("refs/heads/", "");
            sourceMapLeaks = detectSourceMapLeaks(allPaths, owner, repo, branch);
            core.info(`Found ${sourceMapLeaks.length} source map leaks`);
            core.endGroup();
        }
        // --- Calculate score ---
        const scanResult = {
            repo: {
                owner,
                repo,
                defaultBranch: github.context.ref.replace("refs/heads/", ""),
                description: null,
                stars: 0,
                language: null,
            },
            dependencies: parsePackageJson(workspace),
            vulnerabilities,
            sourceMapLeaks,
            exposedSecrets: allSecrets,
            homoglyphIssues: [],
            score: 0,
            scannedAt: new Date().toISOString(),
        };
        scanResult.score = calculateScore(scanResult);
        // --- Set outputs ---
        const passed = scanResult.score >= threshold;
        core.setOutput("score", scanResult.score.toString());
        core.setOutput("vulnerabilities", vulnerabilities.length.toString());
        core.setOutput("secrets", allSecrets.length.toString());
        core.setOutput("sourcemaps", sourceMapLeaks.length.toString());
        core.setOutput("passed", passed.toString());
        // --- Annotate files with findings ---
        for (const secret of allSecrets) {
            const level = secret.severity === "critical" || secret.severity === "high" ? "error" : "warning";
            const annotation = {
                file: secret.file,
                startLine: secret.line,
                endLine: secret.line,
            };
            if (level === "error") {
                core.error(`${secret.patternName}: ${secret.value}`, annotation);
            }
            else {
                core.warning(`${secret.patternName}: ${secret.value}`, annotation);
            }
        }
        for (const vuln of vulnerabilities) {
            if (vuln.severity === "CRITICAL" || vuln.severity === "HIGH") {
                core.error(`${vuln.severity} vulnerability: ${vuln.id} in ${vuln.affected}`);
            }
        }
        // --- PR comment ---
        if (commentOnPr && token && github.context.payload.pull_request) {
            core.startGroup("Posting PR comment");
            const octokit = github.getOctokit(token);
            const prNumber = github.context.payload.pull_request.number;
            const report = generateMarkdownReport(scanResult, threshold);
            // Find existing GHScan comment to update
            const { data: comments } = await octokit.rest.issues.listComments({
                owner,
                repo,
                issue_number: prNumber,
                per_page: 50,
            });
            const existingComment = comments.find((c) => c.body && isGhscanComment(c.body));
            if (existingComment) {
                await octokit.rest.issues.updateComment({
                    owner,
                    repo,
                    comment_id: existingComment.id,
                    body: report,
                });
                core.info(`Updated existing PR comment #${existingComment.id}`);
            }
            else {
                await octokit.rest.issues.createComment({
                    owner,
                    repo,
                    issue_number: prNumber,
                    body: report,
                });
                core.info("Created new PR comment");
            }
            core.endGroup();
        }
        // --- Summary ---
        core.info(`\nSecurity Score: ${scanResult.score}/100 (threshold: ${threshold})`);
        core.info(`Secrets: ${allSecrets.length} | Vulnerabilities: ${vulnerabilities.length} | Source Maps: ${sourceMapLeaks.length}`);
        if (!passed) {
            core.setFailed(`Security score ${scanResult.score} is below threshold ${threshold}`);
        }
    }
    catch (error) {
        if (error instanceof Error) {
            core.setFailed(error.message);
        }
        else {
            core.setFailed("An unexpected error occurred");
        }
    }
}
run();
