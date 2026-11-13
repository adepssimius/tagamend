import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { stringify } from "yaml";
import type { Values } from "./values";

export interface HelmResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Runs helm with these arguments. Injectable so tests need no helm binary. */
export type HelmRunner = (args: string[], opts: { timeoutMs: number; signal?: AbortSignal }) => Promise<HelmResult>;

export const HELM_TIMEOUT_MS = 60_000;
/** A render of a large chart is a few MB; this guards against a runaway one. */
const MAX_OUTPUT = 64 * 1024 * 1024;

/** Spawns `bin`. A timeout or abort kills it and resolves with what it printed. */
export function spawnHelm(bin: string): HelmRunner {
  return (args, { timeoutMs, signal }) =>
    new Promise((resolve, reject) => {
      const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      let size = 0;
      let killedFor: string | null = null;
      const kill = (why: string) => {
        killedFor ??= why;
        child.kill("SIGKILL");
      };
      child.stdout.on("data", (b: Buffer) => {
        size += b.length;
        if (size > MAX_OUTPUT) kill(`output over ${MAX_OUTPUT} bytes`);
        else out.push(b);
      });
      child.stderr.on("data", (b: Buffer) => err.length < 1000 && err.push(b));
      const timer = setTimeout(() => kill(`timed out after ${timeoutMs}ms`), timeoutMs);
      const onAbort = () => kill("aborted");
      signal?.addEventListener("abort", onAbort, { once: true });
      child.on("error", (e) => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        reject(new Error(`cannot run ${bin}: ${e.message}`));
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        const stderr = Buffer.concat(err).toString("utf8");
        resolve({ code: killedFor ? null : code, stdout: Buffer.concat(out).toString("utf8"), stderr: killedFor ? `${killedFor}\n${stderr}` : stderr });
      });
    });
}

function failure(what: string, r: HelmResult): Error {
  const msg = r.stderr.trim().split("\n").filter(Boolean).slice(-3).join("; ") || `exit ${r.code}`;
  return new Error(`${what}: ${msg.slice(0, 1000)}`);
}

export interface ChartLocation {
  /** A chart name with `repo`, or a full oci:// reference. */
  pullRef: string;
  repo: string | null;
}

/**
 * Pulls and renders charts in a scratch directory under the OS temp dir.
 * A chart version is pulled once per workspace and rendered from the archive
 * as often as needed. Call `close()` to remove the directory.
 */
export class HelmWorkspace {
  private dir: string | undefined;
  private readonly pulled = new Map<string, Promise<string>>();
  private seq = 0;

  constructor(
    private readonly run: HelmRunner,
    private readonly opts: { signal?: AbortSignal; timeoutMs?: number; kubeVersion?: string | null } = {},
  ) {}

  private async root(): Promise<string> {
    this.dir ??= await mkdtemp(path.join(os.tmpdir(), "tagamend-charts-"));
    return this.dir;
  }

  private helm(args: string[]): Promise<HelmResult> {
    return this.run(args, { timeoutMs: this.opts.timeoutMs ?? HELM_TIMEOUT_MS, signal: this.opts.signal });
  }

  /** The path of the chart archive for this version, pulling it on first use. */
  pull(loc: ChartLocation, version: string): Promise<string> {
    const key = `${loc.repo ?? ""} ${loc.pullRef} ${version}`;
    let p = this.pulled.get(key);
    if (!p) {
      p = this.doPull(loc, version);
      // A failed pull is not cached, so a later call can retry it.
      p.catch(() => this.pulled.delete(key));
      this.pulled.set(key, p);
    }
    return p;
  }

  private async doPull(loc: ChartLocation, version: string): Promise<string> {
    const dest = path.join(await this.root(), `pull-${++this.seq}`);
    await mkdir(dest);
    const args = ["pull", loc.pullRef, "--version", version, "--destination", dest];
    if (loc.repo) args.push("--repo", loc.repo);
    const r = await this.helm(args);
    if (r.code !== 0) throw failure(`helm pull ${loc.pullRef} ${version}`, r);
    const files = (await readdir(dest)).filter((f) => f.endsWith(".tgz"));
    if (files.length !== 1) throw new Error(`helm pull ${loc.pullRef} ${version} left ${files.length} archives`);
    return path.join(dest, files[0]!);
  }

  /** `helm template` of a pulled chart with these values. Returns the rendered YAML. */
  async template(chartPath: string, release: { name: string; namespace: string }, values: Values): Promise<string> {
    const file = path.join(await this.root(), `values-${++this.seq}.yaml`);
    await writeFile(file, stringify(values, { aliasDuplicateObjects: false }), { mode: 0o600 });
    try {
      const args = ["template", release.name, chartPath, "--namespace", release.namespace, "--values", file, "--skip-tests"];
      if (this.opts.kubeVersion) args.push("--kube-version", this.opts.kubeVersion);
      const r = await this.helm(args);
      if (r.code !== 0) throw failure(`helm template ${path.basename(chartPath)}`, r);
      return r.stdout;
    } finally {
      await rm(file, { force: true });
    }
  }

  async close(): Promise<void> {
    if (this.dir) await rm(this.dir, { recursive: true, force: true });
    this.dir = undefined;
    this.pulled.clear();
  }
}
