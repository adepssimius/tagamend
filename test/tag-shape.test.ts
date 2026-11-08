import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { chooseCandidates, compareTags, isShaLike, MAJORS_KEPT, NEWEST_KEPT, parseTag } from "@/lib/registry/tag-shape";

const fixtures = path.resolve(import.meta.dirname, "fixtures");
const corpus = readFileSync(path.join(fixtures, "tag-corpus.txt"), "utf8").split("\n").filter(Boolean);
const registryTags = (name: string): string[] =>
  (JSON.parse(readFileSync(path.join(fixtures, "registry", `${name}.json`), "utf8")) as { tags: string[] }).tags;

const chosen = (run: string, tags: string[]) => {
  const c = chooseCandidates(run, tags);
  if (c.mode !== "version") throw new Error(`${run} is ${c.mode}`);
  return c.candidates.map((x) => x.tag);
};

describe("parseTag", () => {
  it.each([
    ["1.27.3-alpine", "N.N.N-alpine", ["1", "27", "3"]],
    ["1.28.0-bookworm", "N.N.N-bookworm", ["1", "28", "0"]],
    ["4.0.15.2941-ls290", "N.N.N.N-lsN", ["4", "0", "15", "2941", "290"]],
    ["v1.18.1", "vN.N.N", ["1", "18", "1"]],
    ["2024.10.1", "N.N.N", ["2024", "10", "1"]],
    ["2026-03-04-alpine", "N-N-N-alpine", ["2026", "3", "4"]],
    ["20260903T183717Z", "NTNZ", ["20260903", "183717"]],
    ["1.0.0-rc1", "N.N.N-rcN", ["1", "0", "0", "1"]],
    ["2.78.01", "N.N.N", ["2", "78", "1"]],
    ["8.0.2-debian-12-r4", "N.N.N-debian-N-rN", ["8", "0", "2", "12", "4"]],
    ["version-2.6.5.5623", "version-N.N.N.N", ["2", "6", "5", "5623"]],
    ["3.12-alpine3.20", "N.N-alpineN.N", ["3", "12", "3", "20"]],
  ])("%s has shape %s", (tag, shape, numbers) => {
    const p = parseTag(tag);
    expect(p.shape).toBe(shape);
    expect(p.numbers).toEqual(numbers);
    expect(p.kind).toBe("version");
  });

  it("replaces commit hashes, which are not ordered", () => {
    expect(parseTag("master-372-441d4ba")).toMatchObject({ shape: "master-N-<sha>", numbers: ["372"] });
    expect(parseTag("1.43.5.11079-b3b13e506")).toMatchObject({ shape: "N.N.N.N-<sha>", numbers: ["1", "43", "5", "11079"] });
    expect(parseTag("v1.2.3-4-g1a2b3c4")).toMatchObject({ shape: "vN.N.N-N-<sha>", numbers: ["1", "2", "3", "4"] });
  });

  it("treats a sha-only tag as floating", () => {
    expect(parseTag("sha-441d4ba").kind).toBe("floating");
    expect(parseTag("441d4bacafe").kind).toBe("floating");
  });

  it("recognises a CI hash with no letters or no digits by its position", () => {
    expect(parseTag("main-102-1234567")).toMatchObject({ shape: "main-N-<sha>", numbers: ["102"] });
    expect(parseTag("main-102-abcdefa")).toMatchObject({ shape: "main-N-<sha>", numbers: ["102"] });
    expect(parseTag("main-102-1234567").shape).toBe(parseTag("main-103-e438f9f").shape);
  });

  it("keeps a long numeric suffix as a number", () => {
    expect(parseTag("bookworm-12-20240101")).toMatchObject({ shape: "bookworm-N-N", numbers: ["12", "20240101"] });
    expect(parseTag("1.2.3-20240101")).toMatchObject({ shape: "N.N.N-N" });
  });

  it("does not take ordinary words for hashes", () => {
    expect(isShaLike("bookworm")).toBe(false);
    expect(isShaLike("deadbeef")).toBe(false); // letters only
    expect(isShaLike("20240101")).toBe(false); // digits only
    expect(isShaLike("441d4ba")).toBe(true);
    expect(isShaLike("abc123")).toBe(false); // too short
  });

  it.each(["latest", "stable", "main", "master-web", "debian", "edge", "main-rootless-oidc-experimental"])(
    "%s is floating",
    (tag) => expect(parseTag(tag)).toMatchObject({ kind: "floating", numbers: [] }),
  );

  it.each([
    ["1.0.0-rc1", true],
    ["1.0.0-RC.1", true],
    ["2.0.1-beta", true],
    ["3.0.0-alpha.2", true],
    ["1.2.3-dev", true],
    ["nightly-version-1.2.3", true],
    ["1.0.0-pre", true],
    ["1.0.0rc2", true],
    ["1.27.3-alpine", false],
    ["1.0.2-stable", false],
    ["0.27.1-rootless", false],
    ["18.4-system-trixie", false],
    ["5.0.0-debian-12-r4", false],
  ])("prerelease(%s) is %s", (tag, want) => expect(parseTag(tag).prerelease).toBe(want));
});

describe("compareTags", () => {
  const cmp = (a: string, b: string) => Math.sign(compareTags(parseTag(a), parseTag(b)));

  it("compares numbers as integers, not as text", () => {
    expect(cmp("1.10.0", "1.9.0")).toBe(1);
    expect(cmp("2.0.0", "10.0.0")).toBe(-1);
    expect(cmp("4.0.15.2941-ls290", "4.0.15.2941-ls29")).toBe(1);
  });

  it("treats leading zeros as equal", () => {
    expect(cmp("2.78.01", "2.78.1")).toBe(0);
    expect(cmp("2.78.02", "2.78.1")).toBe(1);
  });

  it("handles numbers beyond Number.MAX_SAFE_INTEGER", () => {
    expect(cmp("1.99999999999999999999", "1.100000000000000000000")).toBe(-1);
  });

  it("orders left to right", () => {
    expect(cmp("1.2.9", "1.3.0")).toBe(-1);
    expect(cmp("2026-03-04-alpine", "2026-02-28-alpine")).toBe(1);
  });

  it("refuses to compare different shapes", () => {
    expect(() => cmp("1.2.3", "1.2.3-alpine")).toThrow(/cannot compare/);
  });
});

describe("chooseCandidates", () => {
  it("does not offer a variant change", () => {
    expect(chosen("1.27.3-alpine", ["1.27.4-alpine", "1.28.0-bookworm", "1.28.0", "1.27.3-alpine"])).toEqual(["1.27.4-alpine"]);
  });

  it("orders linuxserver build suffixes", () => {
    expect(chosen("4.0.15.2941-ls290", ["4.0.15.2941-ls289", "4.0.15.2941-ls291", "4.0.16.2946-ls291", "amd64-4.0.16.2946-ls291"])).toEqual([
      "4.0.16.2946-ls291",
      "4.0.15.2941-ls291",
    ]);
  });

  it("does not cross a v prefix", () => {
    expect(chosen("v1.2.3", ["v1.2.4", "1.2.5"])).toEqual(["v1.2.4"]);
    expect(chosen("1.2.3", ["v1.2.4", "1.2.5"])).toEqual(["1.2.5"]);
  });

  it("orders date tags", () => {
    expect(chosen("2024.10.1", ["2024.9.30", "2024.10.2", "2024.11.1", "2023.12.31"])).toEqual(["2024.11.1", "2024.10.2"]);
  });

  it("orders timestamp tags", () => {
    expect(chosen("20260903T183717Z", ["20260904T010000Z", "20260902T235959Z"])).toEqual(["20260904T010000Z"]);
  });

  it("excludes prereleases unless the running tag is one", () => {
    expect(chosen("1.0.0", ["1.0.1-rc1", "1.0.1"])).toEqual(["1.0.1"]);
    expect(chosen("1.0.0-rc1", ["1.0.0-rc2", "1.0.1-rc1", "1.0.1", "1.0.0-beta2"])).toEqual(["1.0.1-rc1", "1.0.0-rc2"]);
    expect(chosen("nightly-1.0.0", ["nightly-1.0.1", "1.0.1"])).toEqual(["nightly-1.0.1"]);
  });

  it("orders CI build tags by the counter and ignores the hash", () => {
    expect(chosen("main-102-e438f9f", ["main-99-ffffff1", "main-103-1a2b3c4", "main-104-0000000", "dev-200-1a2b3c4"])).toEqual([
      "main-104-0000000",
      "main-103-1a2b3c4",
    ]);
  });

  it("keeps the newest five", () => {
    const tags = Array.from({ length: 20 }, (_, i) => `v1.0.${i}`);
    const out = chosen("v1.0.1", tags);
    expect(out.slice(0, NEWEST_KEPT)).toEqual(["v1.0.19", "v1.0.18", "v1.0.17", "v1.0.16", "v1.0.15"]);
    expect(out).toHaveLength(NEWEST_KEPT);
  });

  it("adds the newest of each higher major", () => {
    const tags = ["1.0.1", "1.1.0", "2.0.0", "2.5.0", "3.0.0", "3.0.1", "3.1.0", "3.2.0", "3.3.0", "3.4.0", "3.5.0"];
    const out = chosen("1.0.0", tags);
    // 2.5.0 for major 2, and 1.0.1 for the running 1.0.* line.
    expect(out).toEqual(["3.5.0", "3.4.0", "3.3.0", "3.2.0", "3.1.0", "2.5.0", "1.0.1"]);
  });

  it("adds the newest of the running line when the newest five have moved on", () => {
    const tags = ["1.2.3", "1.2.9", "1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.5"];
    const c = chooseCandidates("1.2.3", tags);
    expect(c.mode === "version" && c.candidates.map((x) => x.tag)).toEqual(["1.3.5", "1.3.4", "1.3.3", "1.3.2", "1.3.1", "1.2.9"]);
    expect(c.mode === "version" && c.candidates.at(-1)!.reason).toMatch(/own line/);
  });

  it("caps the extra majors", () => {
    const tags = Array.from({ length: 40 }, (_, i) => `${i + 2}.0.0`);
    const out = chosen("1.0.0", tags);
    expect(out.length).toBeLessThanOrEqual(NEWEST_KEPT + MAJORS_KEPT);
    expect(out[0]).toBe("41.0.0");
  });

  it("has no major rule for a build counter or a timestamp", () => {
    const builds = Array.from({ length: 40 }, (_, i) => `main-${200 + i}-1a2b3c${i % 10}`);
    expect(chosen("main-102-e438f9f", builds)).toHaveLength(NEWEST_KEPT);
    const stamps = Array.from({ length: 40 }, (_, i) => `2026090${i % 10}T${100000 + i}Z`).concat(
      Array.from({ length: 30 }, (_, i) => `202610${10 + i}T100000Z`),
    );
    expect(chosen("20260903T183717Z", stamps)).toHaveLength(NEWEST_KEPT);
  });

  it("gives a floating tag no ordering", () => {
    expect(chooseCandidates("latest", ["1.0.0", "2.0.0"])).toEqual({ mode: "floating" });
  });

  it("explains each choice", () => {
    const c = chooseCandidates("1.0.0", ["1.0.1", "2.0.0"]);
    if (c.mode !== "version") throw new Error("expected version");
    expect(c.candidates[0]).toEqual({
      tag: "2.0.0",
      reason: "newest tag of shape N.N.N after 1.0.0; newest in major 2, above 1.0.0's major 1",
    });
    expect(c.candidates[1]!.reason).toBe("2nd newest tag of shape N.N.N after 1.0.0; newest in 1.0.0's own line (1.0.*)");
  });
});

describe("against real registry tag lists", () => {
  it("source-controller: stays on the v-prefixed releases", () => {
    const out = chosen("v1.8.5", registryTags("ghcr.io-fluxcd-source-controller"));
    expect(out).toHaveLength(NEWEST_KEPT);
    for (const t of out) expect(t).toMatch(/^v1\.\d+\.\d+$/);
  });

  it("prowlarr: ignores the arch-prefixed and nightly tags among 15,000", () => {
    const tags = registryTags("lscr.io-linuxserver-prowlarr");
    expect(tags.length).toBeGreaterThan(10_000);
    for (const t of chosen("version-2.6.5.5623", tags)) expect(t).toMatch(/^version-\d+\.\d+\.\d+\.\d+$/);
  });

  it("node: a floating major tag only sees other floating major tags", () => {
    expect(chosen("24-bookworm", registryTags("index.docker.io-library-node"))).toEqual(["26-bookworm", "25-bookworm"]);
  });

  it("node: keeps a variant and offers each higher major", () => {
    const out = chosen("22.1.0-alpine", registryTags("index.docker.io-library-node"));
    for (const t of out) expect(t).toMatch(/^\d+\.\d+\.\d+-alpine$/);
    const majors = new Set(out.map((t) => t.split(".")[0]));
    expect([...majors]).toEqual(expect.arrayContaining(["23", "24", "25", "26"]));
  });

  it("mosquitto: does not cross into -openssl", () => {
    for (const t of chosen("2.0.21", registryTags("index.docker.io-library-eclipse-mosquitto"))) expect(t).not.toMatch(/openssl/);
  });

  it("pause: orders 3.10 after 3.9", () => {
    expect(chosen("3.8", registryTags("registry.k8s.io-pause"))).toEqual(["3.10", "3.9"]);
  });
});

describe("a corpus of real-world tags", () => {
  it("gives each tag a sane shape", () => {
    for (const tag of corpus) {
      const p = parseTag(tag);
      expect(p.shape, tag).not.toMatch(/\d/);
      expect(p.kind === "version", tag).toBe(p.numbers.length > 0);
      if (p.kind === "version") {
        expect(compareTags(p, parseTag(tag)), tag).toBe(0);
        expect(chooseCandidates(tag, [tag]), tag).toMatchObject({ mode: "version", candidates: [] });
      }
    }
  });

  it("matches the recorded shapes", async () => {
    const table = corpus.map((tag) => {
      const p = parseTag(tag);
      const flags = [p.kind, ...(p.prerelease ? ["prerelease"] : [])].join(",");
      return `${tag}  ${p.shape}  ${flags}  [${p.numbers.join(" ")}]`;
    });
    await expect(`${table.join("\n")}\n`).toMatchFileSnapshot("fixtures/tag-corpus.shapes.txt");
  });
});
