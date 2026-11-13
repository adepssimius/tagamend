import { describe, expect, it } from "vitest";
import { describeRelease, indexSources, type K8sObject } from "@/lib/charts/discover";
import { diffImages, extractImages } from "@/lib/charts/images";
import { deepMerge, findTagKeys, valuesAtTargetPath, withoutKey } from "@/lib/charts/values";
import {
  chooseChartCandidates,
  compareSemver,
  ociLocation,
  parseIndex,
  parseSemver,
  stripFluxDigest,
} from "@/lib/charts/versions";

const v = (version: string, appVersion: string | null = null) => ({ version, appVersion });

describe("chart versions", () => {
  it("parses strict semver with an optional v", () => {
    expect(parseSemver("v1.18.7")).toMatchObject({ major: 1, minor: 18, patch: 7, prerelease: null });
    expect(parseSemver("2.4.1+9d4c36d65b6d")).toMatchObject({ major: 2, minor: 4, patch: 1 });
    expect(parseSemver("1.2.3-rc.1")?.prerelease).toBe("rc.1");
    expect(parseSemver("1.2")).toBeNull();
    expect(parseSemver("latest")).toBeNull();
    expect(parseSemver("01.2.3")).toBeNull();
  });

  it("orders by precedence, prereleases before their release", () => {
    const s = (t: string) => parseSemver(t)!;
    expect(compareSemver(s("1.10.0"), s("1.9.9"))).toBeGreaterThan(0);
    expect(compareSemver(s("1.0.0-rc.1"), s("1.0.0"))).toBeLessThan(0);
    expect(compareSemver(s("1.0.0-rc.2"), s("1.0.0-rc.10"))).toBeLessThan(0);
    expect(compareSemver(s("v1.0.0"), s("1.0.0+abc"))).toBe(0);
  });

  it("strips the digest Flux appends to an OCI chart version", () => {
    expect(stripFluxDigest("2.4.1+9d4c36d65b6d")).toBe("2.4.1");
    expect(stripFluxDigest("2.4.1+build.7")).toBe("2.4.1+build.7");
  });

  it("chooses the newest three, the own line and the newest of each higher major", () => {
    const versions = ["1.2.0", "1.2.1", "1.2.2", "1.3.0", "1.4.0", "2.0.0", "2.1.0", "3.0.0-rc.1", "3.0.0", "3.1.0", "1.1.0"].map((x) => v(x));
    const out = chooseChartCandidates("1.2.0", versions);
    expect(out.map((c) => c.version)).toEqual(["3.1.0", "3.0.0", "2.1.0", "1.2.2"]);
    expect(out[0]!.reason).toMatch(/newest chart version after 1\.2\.0; newest in major 3/);
    expect(out[2]!.reason).toMatch(/3rd newest.*newest in major 2/);
    expect(out[3]!.reason).toBe("newest in 1.2.0's own line (1.2.*)");
  });

  it("keeps a leading v and offers nothing when up to date", () => {
    expect(chooseChartCandidates("v1.18.7", [v("v1.18.7"), v("v1.18.8"), v("v1.19.0-beta.1")]).map((c) => c.version)).toEqual(["v1.18.8"]);
    expect(chooseChartCandidates("1.0.0", [v("1.0.0"), v("0.9.0")])).toEqual([]);
    expect(() => chooseChartCandidates("*", [])).toThrow(/not semver/);
  });

  it("reads a chart's entries from a repository index", () => {
    const index = `apiVersion: v1
entries:
  demo:
    - version: 1.1.0
      appVersion: "2.0"
    - version: 1.0.0
      appVersion: 1.9
  other:
    - version: 9.9.9
`;
    expect(parseIndex(index, "demo")).toEqual([v("1.1.0", "2.0"), v("1.0.0", "1.9")]);
    expect(() => parseIndex(index, "missing")).toThrow(/not in the repository index/);
  });

  it("maps oci URLs to a registry and repository", () => {
    expect(ociLocation("oci://registry-1.docker.io/examplecharts/demo")).toEqual({ registry: "index.docker.io", repository: "examplecharts/demo" });
    expect(ociLocation("oci://ghcr.io/example/charts/demo/")).toEqual({ registry: "ghcr.io", repository: "example/charts/demo" });
  });
});

describe("chart values", () => {
  it("merges maps deeply and replaces everything else", () => {
    expect(deepMerge({ a: { b: 1, c: [1] }, d: 1 }, { a: { c: [2], e: 3 }, d: { x: 1 } })).toEqual({ a: { b: 1, c: [2], e: 3 }, d: { x: 1 } });
  });

  it("builds plain target paths and refuses --set syntax", () => {
    expect(valuesAtTargetPath("image.tag", "1.0")).toEqual({ image: { tag: "1.0" } });
    expect(valuesAtTargetPath("list[0].tag", "1.0")).toBeNull();
    expect(valuesAtTargetPath("a\\.b", "1.0")).toBeNull();
  });

  it("finds tag keys and the layer that set them", () => {
    const layers = [
      { origin: "ConfigMap/base", values: { a: { image: { tag: "1.0" } }, b: { image: { tag: "2.0" } } } },
      { origin: "inline", values: { b: { image: { tag: "2.1" } }, c: { tag: 5 } } },
    ];
    expect(findTagKeys(layers)).toEqual([
      { path: ["a", "image", "tag"], value: "1.0", origin: "ConfigMap/base" },
      { path: ["b", "image", "tag"], value: "2.1", origin: "inline" },
    ]);
  });

  it("removes a key without touching the input", () => {
    const values = { a: { image: { tag: "1", repository: "r" } } };
    expect(withoutKey(values, ["a", "image", "tag"])).toEqual({ a: { image: { repository: "r" } } });
    expect(values.a.image.tag).toBe("1");
    expect(withoutKey(values, ["x", "y"])).toBe(values);
  });
});

describe("chart images", () => {
  const render = (tag: string, extra = "") => `---
# Source: demo/templates/deploy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: busybox:1.36
      containers:
        - name: app
          image: "ghcr.io/example/demo:${tag}"
          env:
            - name: image
              value: not-an-image-key
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo-config
data:
  image: "{{ not an image }}"
${extra}`;

  it("extracts every image key with a stable path", () => {
    const images = extractImages(render("v1.0.0"));
    expect(images.map((i) => i.key)).toEqual([
      "Deployment/demo:spec.template.spec.containers[0].image",
      "Deployment/demo:spec.template.spec.initContainers[0].image",
    ]);
    expect(images[0]).toMatchObject({ registry: "ghcr.io", repository: "example/demo", tag: "v1.0.0", digest: null, kind: "Deployment", name: "demo" });
    expect(images[1]).toMatchObject({ registry: "index.docker.io", repository: "library/busybox", tag: "1.36" });
  });

  it("finds images in operator CRs", () => {
    const cr = `---
apiVersion: ceph.example.io/v1
kind: StorageCluster
metadata:
  name: store
spec:
  version:
    image: quay.io/example/store:v18.2.4
`;
    expect(extractImages(render("v1", cr)).map((i) => i.key)).toContain("StorageCluster/store:spec.version.image");
  });

  it("diffs by key: changed, added and removed", () => {
    const a = extractImages(render("v1.0.0"));
    const b = extractImages(render("v1.1.0")).filter((i) => !i.key.includes("initContainers"));
    const extra = { ...b[0]!, key: "Deployment/new:spec.image", name: "new" };
    const changes = diffImages(a, [...b, extra]);
    expect(changes.map((c) => [c.key, c.from?.tag ?? null, c.to?.tag ?? null])).toEqual([
      ["Deployment/demo:spec.template.spec.containers[0].image", "v1.0.0", "v1.1.0"],
      ["Deployment/demo:spec.template.spec.initContainers[0].image", "1.36", null],
      ["Deployment/new:spec.image", null, "v1.1.0"],
    ]);
  });
});

describe("HelmRelease discovery", () => {
  const sources = indexSources([
    { kind: "HelmRepository", metadata: { namespace: "flux", name: "example" }, spec: { url: "https://charts.example.test/" } },
    { kind: "HelmRepository", metadata: { namespace: "flux", name: "ocirepo" }, spec: { type: "oci", url: "oci://ghcr.io/example/charts" } },
    { kind: "HelmRepository", metadata: { namespace: "flux", name: "private" }, spec: { url: "https://private.example.test", secretRef: { name: "creds" } } },
    { kind: "OCIRepository", metadata: { namespace: "apps", name: "demo" }, spec: { url: "oci://registry-1.docker.io/examplecharts/demo", ref: { tag: "2.4.1" } } },
  ]);
  const hr = (spec: Record<string, unknown>, status: Record<string, unknown> = {}): K8sObject => ({
    kind: "HelmRelease",
    metadata: { namespace: "apps", name: "demo", generation: 3 },
    spec,
    status,
  });
  const chartSpec = (name: string, version = "1.0.0") => ({ chart: { spec: { chart: "demo", version, sourceRef: { kind: "HelmRepository", name, namespace: "flux" } } } });

  it("reads a classic repository release", () => {
    const r = describeRelease(hr({ ...chartSpec("example"), values: { a: 1 }, valuesFrom: [{ kind: "ConfigMap", name: "vals", optional: true }] }, { history: [{ chartVersion: "0.9.0" }] }), sources)!;
    expect(r).toMatchObject({
      releaseName: "demo",
      releaseNamespace: "apps",
      chart: "demo",
      version: "1.0.0",
      installedVersion: "0.9.0",
      sourceKind: "HelmRepository",
      sourceUrl: "https://charts.example.test",
      pullRef: "demo",
      repo: "https://charts.example.test",
      ociUrl: null,
      values: { a: 1 },
      valuesFrom: [{ kind: "ConfigMap", name: "vals", optional: true }],
      unsupported: null,
    });
  });

  it("names the release after targetNamespace unless releaseName is set", () => {
    expect(describeRelease(hr({ ...chartSpec("example"), targetNamespace: "other" }), sources)).toMatchObject({ releaseName: "other-demo", releaseNamespace: "other" });
    expect(describeRelease(hr({ ...chartSpec("example"), targetNamespace: "other", releaseName: "rel" }), sources)).toMatchObject({ releaseName: "rel", releaseNamespace: "other" });
  });

  it("reads an OCI HelmRepository and an OCIRepository chartRef", () => {
    expect(describeRelease(hr(chartSpec("ocirepo")), sources)).toMatchObject({ pullRef: "oci://ghcr.io/example/charts/demo", repo: null, ociUrl: "oci://ghcr.io/example/charts/demo" });
    const r = describeRelease(hr({ chartRef: { kind: "OCIRepository", name: "demo" } }, { lastAttemptedRevision: "2.4.1+9d4c36d65b6d" }), sources)!;
    expect(r).toMatchObject({ sourceKind: "OCIRepository", chart: "demo", version: "2.4.1", installedVersion: "2.4.1", ociUrl: "oci://registry-1.docker.io/examplecharts/demo" });
  });

  it("flags credentials and missing sources, and skips git charts", () => {
    expect(describeRelease(hr(chartSpec("private")), sources)?.unsupported).toMatch(/secretRef/);
    expect(describeRelease(hr(chartSpec("nope")), sources)?.unsupported).toMatch(/not found/);
    expect(describeRelease(hr({ chart: { spec: { chart: "./x", sourceRef: { kind: "GitRepository", name: "g" } } } }), sources)).toBeNull();
  });
});
