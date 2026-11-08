import { describe, expect, it } from "vitest";
import { diffSummary, diffVulnerabilities, type DiffVuln } from "@/lib/trivy/diff";

const v = (vuln_id: string, pkg: string, fixed: string | null = null): DiffVuln => ({
  vuln_id, package: pkg, installed_version: "1", fixed_version: fixed, severity: "HIGH", title: null,
});

describe("diff", () => {
  it("splits fixed, still present, and new by (id, package)", () => {
    const d = diffVulnerabilities([v("A", "x", "2"), v("B", "x"), v("A", "y")], [v("B", "x"), v("C", "z"), v("A", "y")]);
    expect(d.fixed.map((x) => x.vuln_id + x.package)).toEqual(["Ax"]);
    expect(d.stillPresent.map((s) => [s.running.vuln_id + s.running.package, s.fixAvailableUpstream])).toEqual([
      ["Bx", false],
      ["Ay", false],
    ]);
    expect(d.introduced.map((x) => x.vuln_id)).toEqual(["C"]);
    expect(diffSummary(d)).toBe("fixes 1, leaves 2, adds 1");
  });
});
