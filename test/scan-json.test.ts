import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { extractJson, parseTrivyScan } from "@/lib/trivy/scan-json";

const fixture = (name: string) => readFileSync(path.join(import.meta.dirname, "fixtures/trivy", name), "utf8");
const D18 = "sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11";

describe("trivy scan JSON", () => {
  it("parses a real client/server scan of alpine 3.18.0", () => {
    const s = parseTrivyScan(fixture("alpine-3.18.0.json"), D18);
    expect(s.digest).toBe(D18);
    expect([s.osFamily, s.osName]).toEqual(["alpine", "3.18.0"]);
    // The server's version, not the 0.76.2 client's.
    expect(s.scannerVersion).toBe("0.76.1");
    expect(s.reportUpdatedAt).toBeNull();
    expect(s.scannedAt).toBe("2026-11-08T14:40:34.274Z");
    expect(s.findings).toHaveLength(35);
    expect(s.findings[0]).toEqual({
      vulnId: "CVE-2022-48174",
      package: "busybox",
      installedVersion: "1.36.0-r9",
      fixedVersion: "1.36.1-r1",
      severity: "CRITICAL",
      score: 9.8,
      title: "busybox: stack overflow vulnerability in ash.c leads to arbitrary code execution",
      link: "https://avd.aquasec.com/nvd/cve-2022-48174",
    });
    expect([...new Set(s.findings.map((f) => f.severity))].sort()).toEqual(["CRITICAL", "HIGH", "MEDIUM"]);
  });

  it("parses a scan with no OS and no Results", () => {
    const s = parseTrivyScan(fixture("busybox-no-os.json"), D18);
    expect([s.osFamily, s.osName, s.findings]).toEqual([null, null, []]);
  });

  it("skips log lines before the document, as a pod log can have", () => {
    const out = `2026-11-08T14:40:33Z\tWARN\tsomething\n${fixture("alpine-3.20.10.json")}\n`;
    expect((extractJson(out) as { SchemaVersion: number }).SchemaVersion).toBe(2);
    expect(parseTrivyScan(out, D18).findings).toHaveLength(2);
  });

  it("rejects output that is not a scan", () => {
    expect(() => parseTrivyScan("FATAL\terror: unauthorized", D18)).toThrow("no JSON document");
    expect(() => parseTrivyScan({ SchemaVersion: 1, ArtifactName: "x" }, D18)).toThrow(z.ZodError);
  });
});
