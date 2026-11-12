import { gzipSync } from "node:zlib";

import { describe, expect, it } from "vitest";
import { readTarGz } from "@/lib/gitops/tar";
import { entry, pax } from "./tar-writer";

describe("readTarGz", () => {
  it("strips the top directory, follows PAX paths, and keeps only what is asked for", () => {
    const top = "owner-repo-abc123/";
    const long = `${top}${"deep/".repeat(30)}values.yaml`;
    const tar = Buffer.concat([
      ...entry("pax_global_header", "52 comment=abc123\n", "g"),
      ...entry(top, "", "5"),
      ...entry(`${top}apps/a.yaml`, "image: x:1\n"),
      ...entry(`${top}README.md`, "# hi\n"),
      ...pax(long),
      ...entry("ignored-short-name", "tag: 2\n"),
      Buffer.alloc(1024),
    ]);
    const files = readTarGz(gzipSync(tar), (p) => p.endsWith(".yaml"));
    expect([...files]).toEqual([
      ["apps/a.yaml", "image: x:1\n"],
      [`${"deep/".repeat(30)}values.yaml`, "tag: 2\n"],
    ]);
  });
});
