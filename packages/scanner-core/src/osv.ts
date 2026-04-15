import type { Dependency, Vulnerability } from "./types.js";

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  database_specific?: {
    severity?: string;
  };
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    ranges?: Array<{
      events?: Array<{ fixed?: string }>;
    }>;
  }>;
  references?: Array<{ url: string }>;
}

interface OsvResponse {
  vulns?: OsvVulnerability[];
}

function cleanVersion(version: string): string {
  return version.replace(/^[\^~>=<]+/, "").split(" ")[0];
}

function extractSeverity(vuln: OsvVulnerability): Vulnerability["severity"] {
  if (vuln.database_specific?.severity) {
    const s = vuln.database_specific.severity.toUpperCase();
    if (s === "CRITICAL" || s === "HIGH" || s === "MEDIUM" || s === "LOW") return s;
  }

  if (vuln.severity?.length) {
    for (const s of vuln.severity) {
      if (s.type === "CVSS_V3") {
        const score = parseFloat(s.score);
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MEDIUM";
        return "LOW";
      }
    }
  }

  return "MEDIUM";
}

export async function checkVulnerabilities(deps: Dependency[]): Promise<Vulnerability[]> {
  const prodDeps = deps.filter((d) => !d.isDev);
  if (prodDeps.length === 0) return [];

  const vulnerabilities: Vulnerability[] = [];

  const batchSize = 10;
  for (let i = 0; i < prodDeps.length; i += batchSize) {
    const batch = prodDeps.slice(i, i + batchSize);

    const promises = batch.map(async (dep) => {
      try {
        const res = await fetch("https://api.osv.dev/v1/query", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            package: { name: dep.name, ecosystem: "npm" },
            version: cleanVersion(dep.version),
          }),
        });

        if (!res.ok) return [];

        const data = (await res.json()) as OsvResponse;
        if (!data.vulns?.length) return [];

        return data.vulns.map((vuln: OsvVulnerability): Vulnerability => {
          const fixedVersion = vuln.affected?.[0]?.ranges?.[0]?.events?.find(
            (e) => e.fixed
          )?.fixed ?? null;

          return {
            id: vuln.id,
            summary: vuln.summary ?? "No summary available",
            details: vuln.details?.slice(0, 200) ?? "",
            severity: extractSeverity(vuln),
            affected: `${dep.name}@${dep.version}`,
            fixedIn: fixedVersion,
            reference: vuln.references?.[0]?.url ?? `https://osv.dev/vulnerability/${vuln.id}`,
          };
        });
      } catch {
        return [];
      }
    });

    const results = await Promise.all(promises);
    for (const r of results) {
      vulnerabilities.push(...r);
    }
  }

  const seen = new Set<string>();
  return vulnerabilities.filter((v) => {
    if (seen.has(v.id)) return false;
    seen.add(v.id);
    return true;
  });
}
