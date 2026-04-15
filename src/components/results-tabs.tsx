"use client";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import type { ScanResult } from "@/lib/types";
import { exportToMarkdown } from "@/lib/export-markdown";
import { SECRET_PATTERNS } from "@/lib/secret-patterns";

const SECRET_PATTERNS_COUNT = SECRET_PATTERNS.length;

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-400 text-white",
};

const SECRET_SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-400 text-white",
};

const SECRET_SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

const SEVERITY_FIX_HINTS: Record<string, string> = {
  critical: "Rotate these credentials immediately, then move them to .env and add .env to .gitignore.",
  high: "These should be rotated and moved to environment variables before your next deploy.",
  medium: "Verify these are not real credentials. If they are, move them to .env.",
  low: "Low risk, but review to make sure no sensitive data is exposed.",
};

export function ResultsTabs({ result }: { result: ScanResult }) {
  const handleExport = () => {
    const md = exportToMarkdown(result);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-scan-${result.repo.owner}-${result.repo.repo}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={handleExport} variant="outline" size="sm">
          Export Markdown
        </Button>
      </div>

      <Tabs defaultValue="vulnerabilities">
        <TabsList className="w-full justify-start">
          <TabsTrigger value="vulnerabilities">
            Vulnerabilities ({result.vulnerabilities.length})
          </TabsTrigger>
          <TabsTrigger value="sourcemaps">
            Source Maps ({result.sourceMapLeaks.length})
          </TabsTrigger>
          <TabsTrigger value="secrets">
            Secrets ({result.exposedSecrets.length})
          </TabsTrigger>
          <TabsTrigger value="homoglyphs">
            Homoglyphs ({result.homoglyphIssues.length})
          </TabsTrigger>
          <TabsTrigger value="deps">
            Dependencies ({result.dependencies.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="vulnerabilities">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Dependency Vulnerabilities</CardTitle>
            </CardHeader>
            <CardContent>
              {result.vulnerabilities.length === 0 ? (
                <EmptyState message="No known vulnerabilities found in production dependencies." />
              ) : (
                <div className="space-y-4">
                  {result.vulnerabilities.map((vuln) => (
                    <div key={vuln.id} className="rounded-lg border p-4">
                      <div className="flex items-start justify-between gap-2">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <Badge className={SEVERITY_COLORS[vuln.severity]}>
                              {vuln.severity}
                            </Badge>
                            <a
                              href={vuln.reference}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-sm text-blue-600 hover:underline"
                            >
                              {vuln.id}
                            </a>
                          </div>
                          <p className="text-sm font-medium">{vuln.summary}</p>
                          <p className="text-xs text-muted-foreground">
                            Affected: <code>{vuln.affected}</code>
                            {vuln.fixedIn && (
                              <>
                                {" "}
                                — Fix: upgrade to <code>{vuln.fixedIn}</code>
                              </>
                            )}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sourcemaps">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Source Map Leaks</CardTitle>
            </CardHeader>
            <CardContent>
              {result.sourceMapLeaks.length === 0 ? (
                <EmptyState message="No exposed source map files detected." />
              ) : (
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    Source maps expose your original source code. These should not be committed to
                    public repositories.
                  </p>
                  <Separator />
                  {result.sourceMapLeaks.map((leak) => (
                    <div key={leak.file} className="flex items-center justify-between rounded border p-3">
                      <code className="text-sm">{leak.file}</code>
                      <a
                        href={leak.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-blue-600 hover:underline"
                      >
                        View
                      </a>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="secrets">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Exposed Secrets</CardTitle>
            </CardHeader>
            <CardContent>
              {result.exposedSecrets.length === 0 ? (
                <EmptyState message="No exposed secrets (emails, API keys, tokens) detected in scanned files." />
              ) : (
                <div className="space-y-4">
                  <p className="text-sm text-muted-foreground">
                    {result.exposedSecrets.length} secret(s) detected across {SECRET_PATTERNS_COUNT} patterns. Verify and rotate any real credentials.
                  </p>
                  <Separator />
                  {SECRET_SEVERITY_ORDER.map((severity) => {
                    const filtered = result.exposedSecrets.filter((s) => s.severity === severity);
                    if (filtered.length === 0) return null;
                    return (
                      <div key={severity} className="space-y-2">
                        <div className="flex items-center gap-2">
                          <Badge className={SECRET_SEVERITY_COLORS[severity]}>
                            {severity.toUpperCase()}
                          </Badge>
                          <span className="text-sm text-muted-foreground">
                            {filtered.length} finding(s)
                          </span>
                        </div>
                        <p className="ml-2 text-xs text-muted-foreground italic">
                          {SEVERITY_FIX_HINTS[severity]}
                        </p>
                        {filtered.map((secret, i) => (
                          <div key={`${secret.file}-${secret.line}-${i}`} className="ml-2 rounded border p-3">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{secret.patternName}</span>
                              <code className="text-sm text-muted-foreground">{secret.value}</code>
                            </div>
                            <p className="mt-1 text-xs text-muted-foreground">
                              {secret.file}:{secret.line}
                            </p>
                          </div>
                        ))}
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="homoglyphs">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Homoglyph Detection</CardTitle>
            </CardHeader>
            <CardContent>
              {result.homoglyphIssues.length === 0 ? (
                <EmptyState message="No Unicode homoglyph (spoofing) issues detected in repo URL, contributors, or description." />
              ) : (
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    Homoglyphs are characters that look like ASCII but are from different Unicode
                    scripts. They can be used for phishing attacks.
                  </p>
                  <Separator />
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b text-left">
                          <th className="p-2">Character</th>
                          <th className="p-2">Looks Like</th>
                          <th className="p-2">Code Point</th>
                          <th className="p-2">Script</th>
                          <th className="p-2">Location</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.homoglyphIssues.map((h, i) => (
                          <tr key={i} className="border-b">
                            <td className="p-2 font-mono text-red-600">{h.original}</td>
                            <td className="p-2 font-mono">{h.ascii}</td>
                            <td className="p-2 font-mono text-muted-foreground">{h.codePoint}</td>
                            <td className="p-2">
                              <Badge variant="outline">{h.script}</Badge>
                            </td>
                            <td className="p-2 text-muted-foreground">{h.position}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="deps">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Dependencies</CardTitle>
            </CardHeader>
            <CardContent>
              {result.dependencies.length === 0 ? (
                <EmptyState message="No package.json found or no dependencies listed." />
              ) : (
                <div className="space-y-1">
                  <div className="mb-3 text-sm text-muted-foreground">
                    {result.dependencies.filter((d) => !d.isDev).length} production /{" "}
                    {result.dependencies.filter((d) => d.isDev).length} dev dependencies
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {result.dependencies
                      .filter((d) => !d.isDev)
                      .map((dep) => (
                        <div key={dep.name} className="flex items-center justify-between border-b py-2">
                          <code className="text-sm">{dep.name}</code>
                          <span className="text-sm text-muted-foreground">{dep.version}</span>
                        </div>
                      ))}
                    {result.dependencies.some((d) => d.isDev) && (
                      <>
                        <Separator className="my-3" />
                        <p className="mb-2 text-xs font-medium text-muted-foreground">Dev Dependencies</p>
                        {result.dependencies
                          .filter((d) => d.isDev)
                          .map((dep) => (
                            <div key={dep.name} className="flex items-center justify-between border-b py-2">
                              <code className="text-sm text-muted-foreground">{dep.name}</code>
                              <span className="text-sm text-muted-foreground">{dep.version}</span>
                            </div>
                          ))}
                      </>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center rounded-lg border border-dashed py-8">
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );
}
