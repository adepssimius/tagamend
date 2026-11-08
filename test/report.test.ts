import { describe, expect, it } from "vitest";
import { parseVulnerabilityReport } from "@/lib/trivy/report";
import { fixtureReports, reportNamed } from "./report-fixtures";

describe("parseVulnerabilityReport", () => {
  it("parses every captured report", () => {
    for (const raw of fixtureReports()) {
      const res = parseVulnerabilityReport(raw);
      expect(res.ok, res.ok ? "" : res.error).toBe(true);
    }
  });

  it("normalises a ReplicaSet report into a DigestScan", () => {
    const res = parseVulnerabilityReport(reportNamed(fixtureReports(), "replicaset-demo-api-7c4967f8db-demo-api"));
    if (!res.ok) throw new Error(res.error);
    const r = res.report;
    expect(r.id).toBe("team-a/replicaset-demo-api-7c4967f8db-demo-api");
    expect(r.resource).toEqual({ kind: "ReplicaSet", name: "demo-api-7c4967f8db", namespace: "team-a", container: "demo-api" });
    expect([r.registry, r.repository, r.tag]).toEqual(["ghcr.io", "example/demo-api", "latest"]);
    expect(r.scan).toMatchObject({
      digest: "sha256:23f03846bdc538562a26ad33e2183876d8b9f7fdb7bee63d4a5969c1bc6ce5bc",
      osFamily: "debian",
      osName: "13.7",
      scannedAt: "2026-11-07T19:13:37.000Z",
      reportUpdatedAt: "2026-11-07T19:13:37.000Z",
      scannerVersion: "0.76.1",
    });
    const high = r.scan.findings.find((f) => f.vulnId === "CVE-2025-69720");
    // An empty fixedVersion means no fix; it is stored as null.
    expect(high).toMatchObject({ severity: "HIGH", fixedVersion: null });
    expect(r.scan.findings.find((f) => f.vulnId === "CVE-2026-109518")).toMatchObject({
      package: "apt",
      installedVersion: "3.0.3",
      fixedVersion: "3.0.4",
      severity: "UNKNOWN",
      score: 8.1,
      link: "https://avd.aquasec.com/nvd/cve-2026-109518",
    });
  });

  it("normalises odd severities and tolerates missing optional fields", () => {
    const raw = structuredClone(reportNamed(fixtureReports(), "statefulset-trivy-server-trivy-server"));
    raw.report.vulnerabilities = [
      { vulnerabilityID: "CVE-1", resource: "p", installedVersion: "1", severity: "high" },
      { vulnerabilityID: "CVE-2", resource: "p", installedVersion: "1", severity: "NONE", score: null },
    ];
    delete raw.report.os;
    delete raw.report.scanner;
    const res = parseVulnerabilityReport(raw);
    if (!res.ok) throw new Error(res.error);
    expect(res.report.scan.findings.map((f) => [f.severity, f.score, f.title, f.fixedVersion])).toEqual([
      ["HIGH", null, null, null],
      ["UNKNOWN", null, null, null],
    ]);
    expect([res.report.scan.osFamily, res.report.scan.scannerVersion]).toEqual([null, null]);
  });

  it("rejects a report without a digest or workload labels, naming it", () => {
    const raw = structuredClone(reportNamed(fixtureReports(), "replicaset-demo-web-5c558b58bf-demo-web"));
    raw.report.artifact.digest = "";
    delete raw.metadata.labels["trivy-operator.container.name"];
    const res = parseVulnerabilityReport(raw);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.id).toBe("team-b/replicaset-demo-web-5c558b58bf-demo-web");
    expect(res.error).toContain("report.artifact.digest");
    expect(res.error).toContain("trivy-operator.container.name");
    expect(parseVulnerabilityReport(null)).toMatchObject({ ok: false, id: "?/?" });
  });
});
