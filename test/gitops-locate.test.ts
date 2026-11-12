import { describe, expect, it } from "vitest";
import { applyEdits, findImageEdits } from "@/lib/gitops/locate";

const files = new Map<string, string>([
  [
    "apps/books/deployment.yaml",
    `spec:
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/example/books:2.32.1
        - name: sidecar
          image: "ghcr.io/example/books:2.32.1" # keep me
`,
  ],
  [
    "apps/web/deployment.yaml",
    `      containers:
        - image: nginx:1.27.3-alpine
        - image: docker.io/library/nginx:1.27.3-bookworm
        - image: index.docker.io/library/nginx@sha256:${"a".repeat(64)}
`,
  ],
  [
    "apps/own/deployment.yaml",
    `          image: ghcr.io/example/books:2.32.1 # {"$imagepolicy": "flux-system:books"}
`,
  ],
  [
    "apps/tv/kustomization.yaml",
    `resources:
  - ./deployment.yaml
images:
  - name: ghcr.io/example/tv
    newTag: 4.0.16.2946
  - name: ghcr.io/example/movies
    digest: sha256:${"b".repeat(64)}
`,
  ],
  ["apps/tv/deployment.yaml", "          image: ghcr.io/example/tv\n"],
  [
    "infra/cache/helmrelease.yaml",
    `  values:
    image:
      registry: docker.io
      repository: example/cache
      tag: "8.0.2-debian-12-r4"
    other:
      repository: example/other
      tag: 1.0
`,
  ],
]);

describe("findImageEdits", () => {
  it("moves inline references, keeping quotes and comments", () => {
    const { edits, skipped } = findImageEdits(files, {
      registry: "ghcr.io",
      repository: "example/books",
      fromTags: ["2.32.1"],
      toTag: "2.37.2",
    });
    expect(edits.map((e) => [e.path, e.line, e.after.trim(), e.fromTag])).toEqual([
      ["apps/books/deployment.yaml", 6, "image: ghcr.io/example/books:2.37.2", "2.32.1"],
      ["apps/books/deployment.yaml", 8, 'image: "ghcr.io/example/books:2.37.2" # keep me', "2.32.1"],
    ]);
    expect(skipped).toEqual([
      expect.objectContaining({ path: "apps/own/deployment.yaml", line: 1, reason: "Flux image automation manages this line" }),
    ]);
    const changed = applyEdits(files, edits);
    expect([...changed.keys()]).toEqual(["apps/books/deployment.yaml"]);
    expect(changed.get("apps/books/deployment.yaml")).toContain("        - name: sidecar\n          image: \"ghcr.io/example/books:2.37.2\" # keep me\n");
  });

  it("normalises Docker Hub names and leaves other variants and digest pins alone", () => {
    const { edits, skipped } = findImageEdits(files, {
      registry: "index.docker.io",
      repository: "library/nginx",
      fromTags: ["1.27.3-alpine", "1.27.3-bookworm"],
      toTag: "1.28.0-alpine",
    });
    expect(edits.map((e) => e.after.trim())).toEqual(["- image: nginx:1.28.0-alpine"]);
    expect(skipped.map((s) => s.reason)).toEqual([
      "tag 1.27.3-bookworm has a different shape from 1.28.0-alpine",
      "pinned by digest",
    ]);
  });

  it("moves the tag of a split repository/tag block and ignores other blocks", () => {
    const { edits } = findImageEdits(files, {
      registry: "index.docker.io",
      repository: "example/cache",
      fromTags: ["8.0.2-debian-12-r4"],
      toTag: "8.0.3-debian-12-r1",
    });
    expect(edits).toEqual([
      expect.objectContaining({ path: "infra/cache/helmrelease.yaml", line: 5, after: '      tag: "8.0.3-debian-12-r1"' }),
    ]);
  });

  it("moves a Kustomize newTag and ignores the tag-less image line it overrides", () => {
    const { edits, skipped } = findImageEdits(files, {
      registry: "ghcr.io",
      repository: "example/tv",
      fromTags: ["4.0.16.2946"],
      toTag: "4.0.17.2952",
    });
    expect(edits).toEqual([
      expect.objectContaining({ path: "apps/tv/kustomization.yaml", line: 5, after: "    newTag: 4.0.17.2952" }),
    ]);
    expect(skipped).toEqual([]);
    const movies = findImageEdits(files, { registry: "ghcr.io", repository: "example/movies", fromTags: ["1"], toTag: "2" });
    expect(movies).toEqual({ edits: [], skipped: [expect.objectContaining({ reason: "pinned by digest" })] });
  });

  it("only moves running tags", () => {
    const { edits, skipped } = findImageEdits(files, {
      registry: "ghcr.io",
      repository: "example/books",
      fromTags: ["2.30.0"],
      toTag: "2.37.2",
    });
    expect(edits).toEqual([]);
    expect(skipped.map((s) => s.reason)).toContain("tag 2.32.1 is not a running tag");
  });

  it("refuses to apply an edit to a line that changed", () => {
    expect(() =>
      applyEdits(files, [{ path: "apps/books/deployment.yaml", line: 6, before: "nope", after: "x", fromTag: "1" }]),
    ).toThrow("changed since it was read");
  });
});
