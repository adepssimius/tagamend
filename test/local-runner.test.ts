import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getConfig } from "@/lib/config";
import { LocalScanRunner, readRegistryCredentials } from "@/lib/scan/local-runner";
import type { RunState, ScanRunner } from "@/lib/scan/runner";

const DIGEST = `sha256:${"a".repeat(64)}`;
const req = { scanId: 7, registry: "index.docker.io", repository: "library/alpine", digest: DIGEST };
const bin = path.join(import.meta.dirname, "fixtures/bin/fake-trivy");
const fixture = path.join(import.meta.dirname, "fixtures/trivy/alpine-3.20.10.json");

function credsDir(host: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), "tagamend-creds-"));
  mkdirSync(path.join(dir, host));
  writeFileSync(path.join(dir, host, "username"), "scanuser\n");
  writeFileSync(path.join(dir, host, "password"), "scanpass\n");
  return dir;
}
const config = (dir = "/nonexistent") =>
  getConfig({ DATABASE_URL: ":memory:", SCANNER: "local", TRIVY_SERVER_URL: "http://localhost:4954", REGISTRY_CREDENTIALS_DIR: dir });

async function settled(r: ScanRunner, handle: string): Promise<RunState> {
  return vi.waitFor(
    async () => {
      const s = await r.check(handle);
      if (s.state === "running") throw new Error("still running");
      return s;
    },
    { timeout: 5000, interval: 10 },
  );
}

describe("LocalScanRunner", () => {
  afterEach(() => {
    delete process.env.FAKE_TRIVY_OUTPUT;
    delete process.env.FAKE_TRIVY_EXIT;
    delete process.env.FAKE_TRIVY_SLEEP;
  });

  it("returns trivy's stdout on success", async () => {
    process.env.FAKE_TRIVY_OUTPUT = fixture;
    const r = new LocalScanRunner(config(), { bin });
    const handle = await r.start(req);
    expect(handle).toMatch(/^local-7-/);
    const s = await settled(r, handle);
    expect(s.state).toBe("succeeded");
    expect((s as { output: string }).output).toContain('"SchemaVersion": 2');
  });

  it("reports the exit code and stderr, including the arguments it was given", async () => {
    process.env.FAKE_TRIVY_EXIT = "1";
    const r = new LocalScanRunner(config(), { bin });
    const s = await settled(r, await r.start(req));
    expect(s.state).toBe("failed");
    const { error } = s as { error: string };
    expect(error).toContain("trivy exited 1");
    expect(error).toContain(
      `args: image --server http://localhost:4954 --format json --quiet --severity CRITICAL,HIGH,MEDIUM --platform linux/amd64 --scanners vuln index.docker.io/library/alpine@${DIGEST}`,
    );
    expect(error).toContain("user: none");
  });

  it("passes credentials from REGISTRY_CREDENTIALS_DIR as env", async () => {
    process.env.FAKE_TRIVY_EXIT = "1";
    const r = new LocalScanRunner(config(credsDir("index.docker.io")), { bin });
    const s = await settled(r, await r.start(req));
    expect((s as { error: string }).error).toContain("user: scanuser");
  });

  it("reports a missing binary as a failure", async () => {
    const r = new LocalScanRunner(config(), { bin: "/nonexistent/trivy" });
    const s = await settled(r, await r.start(req));
    expect(s.state).toBe("failed");
    expect((s as { error: string }).error).toContain("ENOENT");
  });

  it("does not know a handle from an earlier process", async () => {
    expect(await new LocalScanRunner(config(), { bin }).check("local-1-abc")).toEqual({ state: "missing" });
  });

  it("is running while the process is alive", async () => {
    process.env.FAKE_TRIVY_SLEEP = "0.2";
    const r = new LocalScanRunner(config(), { bin });
    const handle = await r.start(req);
    expect(await r.check(handle)).toEqual({ state: "running" });
    await settled(r, handle);
  });

  it("finds Docker Hub credentials under an alias and returns undefined for none", async () => {
    expect(await readRegistryCredentials(credsDir("docker.io"), "index.docker.io")).toEqual({
      username: "scanuser",
      password: "scanpass",
    });
    expect(await readRegistryCredentials(credsDir("ghcr.io"), "lscr.io")).toBeUndefined();
  });
});
