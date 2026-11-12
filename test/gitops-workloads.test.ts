import { describe, expect, it } from "vitest";
import { findImageEdits, ownerOf } from "@/lib/gitops/locate";
import { narrowToWorkloads } from "@/lib/gitops/queue";

const files = new Map<string, string>([
  ["apps/media/kustomization.yaml", "namespace: media\nresources:\n  - ./seerr.yaml\n"],
  [
    "apps/media/seerr.yaml",
    `apiVersion: apps/v1
kind: Deployment
metadata:
  name: seerr
spec:
  template:
    spec:
      containers:
        - image: ghcr.io/example/seerr:2.1.0
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: seerr-test
  namespace: media
spec:
  template:
    spec:
      containers:
        - image: ghcr.io/example/seerr:2.1.0
`,
  ],
  [
    "apps/tv/kustomization.yaml",
    `namespace: tv
resources:
  - ./main
  - ./kids
images:
  - name: ghcr.io/example/tv
    newTag: 4.0.1
`,
  ],
]);
const target = { registry: "ghcr.io", repository: "example/seerr", fromTags: ["2.1.0"], toTag: "2.2.0" };
const seerr = { namespace: "media", kind: "Deployment", name: "seerr" };
const seerrTest = { namespace: "media", kind: "Deployment", name: "seerr-test" };

describe("workload attribution", () => {
  it("reads kind, name and namespace from the line's YAML document, falling back to the kustomization", () => {
    expect(ownerOf(files, "apps/media/seerr.yaml", 9)).toEqual({ kind: "Deployment", name: "seerr", namespace: "media" });
    expect(ownerOf(files, "apps/media/seerr.yaml", 20)).toEqual({ kind: "Deployment", name: "seerr-test", namespace: "media" });
    expect(ownerOf(files, "apps/tv/kustomization.yaml", 7)).toEqual({ kind: "Kustomization", name: "apps/tv", namespace: "tv" });
  });

  it("moves only the chosen workload, so one instance can try a version first", () => {
    const found = findImageEdits(files, target);
    expect(found.edits).toHaveLength(2);
    const { edits, skipped } = narrowToWorkloads(found, [seerrTest], [seerr, seerrTest]);
    expect(edits.map((e) => e.line)).toEqual([20]);
    expect(skipped.map((s) => s.reason)).toEqual(["media/seerr was not chosen"]);
  });

  it("leaves a tag that several workloads share when only some are chosen", () => {
    const tv = { registry: "ghcr.io", repository: "example/tv", fromTags: ["4.0.1"], toTag: "4.0.2" };
    const main = { namespace: "tv", kind: "Deployment", name: "tv" };
    const kids = { namespace: "tv", kind: "Deployment", name: "tv-kids" };
    const found = findImageEdits(files, tv);
    const some = narrowToWorkloads(found, [kids], [main, kids]);
    expect(some.edits).toEqual([]);
    expect(some.skipped[0]!.reason).toContain("sets the tag for more workloads than were chosen");
    expect(narrowToWorkloads(found, [main, kids], [main, kids]).edits).toHaveLength(1);
  });
});
