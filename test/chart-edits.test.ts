import { describe, expect, it } from "vitest";
import type { PinnedImage } from "@/lib/charts/types";
import { planChartEdits } from "@/lib/gitops/chart-edits";
import { ChartEditError } from "@/lib/gitops/chart-yaml";

const HR = `# The demo app.
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo-extra
data:
  version: "1.0.0"
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo # the release
spec:
  interval: 15m
  chart:
    spec:
      chart: demo
      version: "1.2.0"   # bumped by hand until now
      sourceRef:
        kind: HelmRepository
        name: example
  values:
    server:
      image:
        repository: ghcr.io/example/demo-server
        tag: 'v1.2.0' # keep in step with the chart
    workers:
      - name: main
        image:
          tag: 1.10
`;
const KUSTOMIZATION = "namespace: apps\nresources:\n  - helmrelease.yaml\n";

const pin = (valuesPath: (string | number)[], pinnedTag: string, defaultTag: string | null): PinnedImage => ({
  key: `Deployment/demo-${valuesPath[0]}:spec.template.spec.containers[0].image`,
  kind: "Deployment",
  name: `demo-${valuesPath[0]}`,
  valuesPath,
  pinnedTag,
  chartDefault: defaultTag
    ? { key: "k", kind: "Deployment", name: "n", ref: `ghcr.io/example/demo:${defaultTag}`, registry: "ghcr.io", repository: "example/demo", tag: defaultTag, digest: null }
    : null,
});

const files = (extra: Record<string, string> = {}) =>
  new Map(Object.entries({ "apps/demo/helmrelease.yaml": HR, "apps/demo/kustomization.yaml": KUSTOMIZATION, ...extra }));

describe("planChartEdits", () => {
  it("replaces only the version scalar, keeping quotes and comments", () => {
    const plan = planChartEdits(files(), { namespace: "apps", name: "demo", toVersion: "1.3.0", pins: [], updatePins: false });
    const out = plan.files.get("apps/demo/helmrelease.yaml")!;
    expect(out).toBe(HR.replace(`version: "1.2.0"   # bumped`, `version: "1.3.0"   # bumped`));
    expect(plan.edits).toEqual([
      {
        path: "apps/demo/helmrelease.yaml",
        line: 19,
        before: `      version: "1.2.0"   # bumped by hand until now`,
        after: `      version: "1.3.0"   # bumped by hand until now`,
        field: "spec.chart.spec.version",
        object: "HelmRelease/apps/demo",
      },
    ]);
    expect(plan.version).toMatchObject({ kind: "HelmRelease", was: "1.2.0", wasRange: false });
    // The ConfigMap's own "1.0.0" is a different document and stays.
    expect(out).toContain(`  version: "1.0.0"`);
  });

  it("moves nested and list-indexed pins, keeping each one's quoting", () => {
    const plan = planChartEdits(files(), {
      namespace: "apps",
      name: "demo",
      toVersion: "1.3.0",
      pins: [pin(["server", "image", "tag"], "v1.2.0", "v1.3.0"), pin(["workers", 0, "image", "tag"], "1.10", "1.20")],
      updatePins: true,
    });
    const out = plan.files.get("apps/demo/helmrelease.yaml")!;
    expect(out).toContain(`        tag: 'v1.3.0' # keep in step with the chart`);
    // 1.20 plain would read as the number 1.2, so it is quoted.
    expect(out).toContain(`          tag: "1.20"\n`);
    expect(plan.edits.map((e) => e.field)).toEqual(["spec.chart.spec.version", "spec.values.server.image.tag", "spec.values.workers.0.image.tag"]);
    expect(plan.pins.map((p) => p.outcome)).toEqual(["moved", "moved"]);
    expect(out.split("\n")).toHaveLength(HR.split("\n").length);
  });

  it("edits a values key shared by two images once", () => {
    const shared = ["server", "image", "tag"];
    const plan = planChartEdits(files(), {
      namespace: "apps",
      name: "demo",
      toVersion: "1.3.0",
      pins: [
        { ...pin(shared, "v1.2.0", "v1.3.0"), key: "Deployment/a:image", name: "a" },
        { ...pin(shared, "v1.2.0", "v1.3.0"), key: "Deployment/b:image", name: "b" },
      ],
      updatePins: true,
    });
    expect(plan.pins.map((p) => p.outcome)).toEqual(["moved", "moved"]);
    expect(plan.edits).toHaveLength(2); // the chart version and the one shared pin
    expect(() =>
      planChartEdits(files(), {
        namespace: "apps",
        name: "demo",
        toVersion: "1.3.0",
        pins: [pin(shared, "v1.2.0", "v1.3.0"), pin(shared, "v1.2.0", "v9.9.9")],
        updatePins: true,
      }),
    ).toThrow("chart defaults differ");
  });

  it("lists a pin set in a valuesFrom ConfigMap instead of failing", () => {
    const plan = planChartEdits(files(), {
      namespace: "apps",
      name: "demo",
      toVersion: "1.3.0",
      pins: [pin(["valuesFrom:ConfigMap/demo-values", "image", "tag"], "v1.2.0", "v1.3.0")],
      updatePins: true,
    });
    expect(plan.pins.map((p) => p.outcome)).toEqual(["external"]);
    expect(plan.edits).toHaveLength(1); // the chart version only
  });

  it("leaves pins alone unless asked, and reports them", () => {
    const plan = planChartEdits(files(), { namespace: "apps", name: "demo", toVersion: "1.3.0", pins: [pin(["server", "image", "tag"], "v1.2.0", "v1.3.0")], updatePins: false });
    expect(plan.edits).toHaveLength(1);
    expect(plan.pins[0]!.outcome).toBe("kept");
  });

  it("pins a version range and says it was one", () => {
    const f = files({ "apps/demo/helmrelease.yaml": HR.replace(`version: "1.2.0"`, "version: '>=1.0.0 <2.0.0'") });
    const plan = planChartEdits(f, { namespace: "apps", name: "demo", toVersion: "1.3.0", pins: [], updatePins: false });
    expect(plan.version).toMatchObject({ was: ">=1.0.0 <2.0.0", wasRange: true });
    expect(plan.files.get("apps/demo/helmrelease.yaml")).toContain("version: '1.3.0'   # bumped");
  });

  it("quotes a plain * range's replacement only when it must", () => {
    const f = files({ "apps/demo/helmrelease.yaml": HR.replace(`version: "1.2.0"`, `version: "*"`) });
    expect(planChartEdits(f, { namespace: "apps", name: "demo", toVersion: "1.3.0", pins: [], updatePins: false }).version.wasRange).toBe(true);
    const plain = files({ "apps/demo/helmrelease.yaml": HR.replace(`version: "1.2.0"`, "version: 1.2.0") });
    expect(planChartEdits(plain, { namespace: "apps", name: "demo", toVersion: "1.3.0", pins: [], updatePins: false }).files.get("apps/demo/helmrelease.yaml")).toContain(
      "      version: 1.3.0   # bumped",
    );
  });

  it("edits the OCIRepository a chartRef names, not the HelmRelease", () => {
    const hr = `apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: apps
spec:
  chartRef:
    kind: OCIRepository
    name: demo-chart
  values:
    replicas: 1
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo-two
  namespace: apps
spec:
  chartRef: {kind: OCIRepository, name: demo-chart}
`;
    const oci = `apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: demo-chart
  namespace: apps
spec:
  interval: 1h
  url: oci://ghcr.io/example/charts/demo
  ref:
    tag: 0.9.1 # chart version
`;
    const f = new Map([
      ["apps/demo/hr.yaml", hr],
      ["apps/demo/oci.yaml", oci],
    ]);
    const plan = planChartEdits(f, { namespace: "apps", name: "demo", toVersion: "0.10.0", pins: [], updatePins: false });
    expect([...plan.files.keys()]).toEqual(["apps/demo/oci.yaml"]);
    expect(plan.files.get("apps/demo/oci.yaml")).toBe(oci.replace("tag: 0.9.1 #", "tag: 0.10.0 #"));
    expect(plan.version).toMatchObject({ kind: "OCIRepository", name: "demo-chart", field: "spec.ref.tag", was: "0.9.1", sharedWith: ["apps/demo-two"] });

    const semver = new Map([...f, ["apps/demo/oci.yaml", oci.replace("tag: 0.9.1", 'semver: ">=0.9.0"')]]);
    const p2 = planChartEdits(semver, { namespace: "apps", name: "demo", toVersion: "0.10.0", pins: [], updatePins: false });
    expect(p2.version).toMatchObject({ field: "spec.ref.semver", wasRange: true });
    expect(p2.files.get("apps/demo/oci.yaml")).toContain(`semver: "0.10.0" # chart version`);

    const digest = new Map([...f, ["apps/demo/oci.yaml", oci.replace("tag: 0.9.1", "digest: sha256:abc")]]);
    expect(() => planChartEdits(digest, { namespace: "apps", name: "demo", toVersion: "0.10.0", pins: [], updatePins: false })).toThrow(/pins the chart by spec\.ref\.digest/);
  });

  it("fails with a reason when something cannot be found or safely replaced", () => {
    const plan = (f: Map<string, string>, o: Partial<Parameters<typeof planChartEdits>[1]> = {}) => () =>
      planChartEdits(f, { namespace: "apps", name: "demo", toVersion: "1.3.0", pins: [], updatePins: false, ...o });
    expect(plan(files(), { name: "missing" })).toThrow(ChartEditError);
    expect(plan(files(), { name: "missing" })).toThrow("no HelmRelease apps/missing in the repo");
    expect(plan(files(), { namespace: "other" })).toThrow("found in other namespaces: apps in apps/demo/helmrelease.yaml");
    expect(plan(files({ "apps/demo/helmrelease.yaml": HR.replace(/ {6}version:.*\n/, "") }))).toThrow("has no spec.chart.spec.version");
    expect(plan(files({ "apps/demo/helmrelease.yaml": HR.replace(`"1.2.0"`, `"\${DEMO_VERSION}"`) }))).toThrow("a Flux variable");
    expect(plan(files(), { toVersion: "1.2.0" })).toThrow("already has spec.chart.spec.version: 1.2.0");
    expect(plan(files({ "other/hr.yaml": HR.replace("name: demo #", "namespace: apps\n  name: demo #") }))).toThrow("is defined more than once");
    expect(plan(files(), { updatePins: true, pins: [pin(["nope", "tag"], "x", "y")] })).toThrow("has no spec.values.nope.tag");
    expect(plan(files(), { updatePins: true, pins: [pin(["server", "image", "tag"], "v1.1.0", "v1.3.0")] })).toThrow(
      "is `v1.2.0`, not the pinned `v1.1.0`",
    );
    expect(plan(files(), { updatePins: true, pins: [pin(["server", "image", "tag"], "v1.2.0", null)] })).toThrow("default tag for Deployment/demo-server is not known");
  });
});
