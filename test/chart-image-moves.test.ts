import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import type { ChartImage, ImageMoveTarget, ImageTagKey } from "@/lib/charts/types";
import type { Chart } from "@/lib/db/schema";
import { buildTargets, buildImageMoveContent, planImageMoves } from "@/lib/gitops/chart-image-moves";
import { ChartEditError } from "@/lib/gitops/chart-yaml";

const HR = `apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: immich
spec:
  interval: 15m
  chart:
    spec:
      chart: immich
      version: 0.12.0 # chart only
  values:
    server:
      persistence:
        library:
          existingClaim: immich-library
    valkey:
      image:
        tag: 9.1-alpine
    env:
      TZ: UTC
`;
const KUSTOMIZATION = "namespace: personal-data\nresources:\n  - helmrelease.yaml\n";
const files = (hr = HR) => new Map([["apps/immich/helmrelease.yaml", hr], ["apps/immich/kustomization.yaml", KUSTOMIZATION]]);

const target = (name: string, valuesPath: string[], from: string | null, to: string): ImageMoveTarget => ({
  key: `Deployment/${name}:spec.template.spec.containers[0].image`,
  kind: "Deployment",
  name,
  registry: "ghcr.io",
  repository: `immich-app/${name}`,
  valuesPath,
  from,
  to,
});

const plan = (targets: ImageMoveTarget[], hr?: string) => planImageMoves(files(hr), { namespace: "personal-data", name: "immich", targets });

describe("planImageMoves", () => {
  it("adds keys the chart's defaults set today, under maps that exist, and replaces ones that do", () => {
    const out = plan([
      target("immich-server", ["server", "controllers", "main", "containers", "main", "image", "tag"], "v2.6.3", "v2.7.0"),
      target("immich-machine-learning", ["machine-learning", "controllers", "main", "containers", "main", "image", "tag"], "v2.6.3", "v2.7.0"),
      target("immich-valkey", ["valkey", "image", "tag"], "9.1-alpine", "9.2-alpine"),
    ]);
    const text = out.files.get("apps/immich/helmrelease.yaml")!;
    const values = (parse(text) as { spec: { values: Record<string, any> } }).spec.values;
    expect(values.server.controllers.main.containers.main.image.tag).toBe("v2.7.0");
    expect(values.server.persistence.library.existingClaim).toBe("immich-library");
    expect(values["machine-learning"].controllers.main.containers.main.image.tag).toBe("v2.7.0");
    expect(values.valkey.image.tag).toBe("9.2-alpine");
    expect(values.env.TZ).toBe("UTC");
    // Everything else is byte for byte as it was.
    expect(text).toContain("      version: 0.12.0 # chart only\n");
    expect(text).toContain(`    server:
      persistence:
        library:
          existingClaim: immich-library
      controllers:
        main:
          containers:
            main:
              image:
                tag: v2.7.0
    valkey:`);
    expect(out.edits.map((e) => [e.line, e.added ?? false, e.field])).toEqual([
      [15, true, "spec.values.server.controllers.main.containers.main.image.tag"],
      [18, false, "spec.values.valkey.image.tag"],
      [20, true, "spec.values.machine-learning.controllers.main.containers.main.image.tag"],
    ]);
    expect(out.edits[1]).toMatchObject({ before: "        tag: 9.1-alpine", after: "        tag: 9.2-alpine" });
  });

  it("writes a key two images share once", () => {
    const path = ["controllers", "main", "containers", "main", "image", "tag"];
    const out = plan([target("immich-server", path, "v2.6.3", "v2.7.0"), target("immich-machine-learning", path, "v2.6.3", "v2.7.0")]);
    expect(out.edits).toHaveLength(1);
    expect((parse(out.files.get("apps/immich/helmrelease.yaml")!) as any).spec.values.controllers.main.containers.main.image.tag).toBe("v2.7.0");
  });

  it("adds spec.values when the HelmRelease has none", () => {
    const hr = HR.slice(0, HR.indexOf("  values:"));
    const out = plan([target("immich-valkey", ["valkey", "image", "tag"], "9.1-alpine", "9.2-alpine")], hr);
    expect((parse(out.files.get("apps/immich/helmrelease.yaml")!) as any).spec.values.valkey.image.tag).toBe("9.2-alpine");
  });

  it("quotes a tag that would not read back as a string", () => {
    const out = plan([target("immich-valkey", ["valkey", "image", "tag"], "9.1-alpine", "9.10")]);
    expect(out.edits[0]!.after).toBe('        tag: "9.10"');
  });

  it("refuses when the repo no longer holds the running tag", () => {
    expect(() => plan([target("immich-valkey", ["valkey", "image", "tag"], "9.0-alpine", "9.2-alpine")])).toThrow(/not the running `9.0-alpine`/);
  });

  it("refuses to add under an inline map", () => {
    const hr = HR.replace("    env:\n      TZ: UTC\n", "    env: {}\n");
    expect(() => plan([target("immich-server", ["env", "image", "tag"], null, "v1")], hr)).toThrow(ChartEditError);
  });
});

const img = (name: string, tag: string): ChartImage => ({
  key: `Deployment/${name}:spec.template.spec.containers[0].image`,
  kind: "Deployment",
  name,
  ref: `ghcr.io/immich-app/${name}:${tag}`,
  registry: "ghcr.io",
  repository: `immich-app/${name}`,
  tag,
  digest: null,
});
const chartWith = (keys: ImageTagKey[], images: ChartImage[]): Chart =>
  ({ id: 1, namespace: "personal-data", name: "immich", version: "0.12.0", installed_version: "0.12.0", current_images: JSON.stringify(images), image_keys: JSON.stringify(keys) }) as Chart;
const key = (name: string, valuesPath: string[] | null, origin = "default"): ImageTagKey => ({
  key: `Deployment/${name}:spec.template.spec.containers[0].image`,
  valuesPath,
  origin,
  digestHeld: false,
});

describe("buildTargets", () => {
  const images = [img("server", "v2.6.3"), img("ml", "v2.6.3")];
  it("takes per-image tags and skips images left as they are", () => {
    const chart = chartWith([key("server", ["server", "tag"]), key("ml", ["ml", "tag"])], images);
    const t = buildTargets(chart, { [images[0]!.key]: "v2.7.0", [images[1]!.key]: "" });
    expect(t.map((x) => [x.name, x.from, x.to])).toEqual([["server", "v2.6.3", "v2.7.0"]]);
  });

  it("moves an image that shares the key, and refuses two tags for one key", () => {
    const chart = chartWith([key("server", ["tag"]), key("ml", ["tag"])], images);
    expect(buildTargets(chart, { [images[0]!.key]: "v2.7.0" }).map((x) => x.name).sort()).toEqual(["ml", "server"]);
    expect(() => buildTargets(chart, { [images[0]!.key]: "v2.7.0", [images[1]!.key]: "v2.7.1" })).toThrow(/same key/);
  });

  it("refuses images it cannot move, and tags that are not tags", () => {
    const chart = chartWith([key("server", null), key("ml", ["ml", "tag"], "ConfigMap/immich-values")], images);
    expect(() => buildTargets(chart, { [images[0]!.key]: "v2.7.0" })).toThrow(/no values key/);
    expect(() => buildTargets(chart, { [images[1]!.key]: "v2.7.0" })).toThrow(/valuesFrom ConfigMap\/immich-values/);
    const ok = chartWith([key("server", ["s", "tag"]), key("ml", ["m", "tag"])], images);
    expect(() => buildTargets(ok, { [images[0]!.key]: "v2.7.0; rm -rf" })).toThrow(/not a valid image tag/);
    expect(() => buildTargets(ok, {})).toThrow(/no image was given a new tag/);
  });
});

describe("buildImageMoveContent", () => {
  it("names each move and says the chart version stays", () => {
    const targets = [target("immich-server", ["server", "tag"], "v2.6.3", "v2.7.0")];
    const c = buildImageMoveContent({ chart: chartWith([], []), targets, edits: plan(targets).edits, chartUrl: "https://t.example/charts/1", requestedBy: "bp" });
    expect(c.title).toBe("immich: move images (immich-server v2.6.3 → v2.7.0)");
    expect(c.body).toMatch(/chart version \(0\.12\.0\) does not change/);
    expect(c.body).toContain("tag: v2.7.0");
  });
});
