import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Config } from "../config";
import {
  credentialHosts,
  imageRef,
  type RunState,
  SCAN_DEADLINE_SECONDS,
  type ScanRequest,
  type ScanRunner,
  shortError,
  trivyArgs,
} from "./runner";

type LocalConfig = Pick<Config, "TRIVY_SERVER_URL" | "SEVERITIES" | "REGISTRY_CREDENTIALS_DIR">;

/** Reads `<dir>/<host>/{username,password}`; undefined when there is none. */
export async function readRegistryCredentials(
  dir: string,
  registry: string,
): Promise<{ username: string; password: string } | undefined> {
  for (const host of credentialHosts(registry)) {
    try {
      const [username, password] = await Promise.all(
        ["username", "password"].map((f) => readFile(path.join(dir, host, f), "utf8")),
      );
      return { username: username!.trim(), password: password!.trim() };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
  }
  return undefined;
}

const MAX_STDOUT = 64 * 1024 * 1024;

/**
 * Runs the `trivy` binary on this machine (`SCANNER=local`). Scans live in
 * this process, so a restart loses them: `check` then reports `missing`.
 */
export class LocalScanRunner implements ScanRunner {
  readonly kind = "local" as const;
  private readonly runs = new Map<string, RunState>();

  constructor(
    private readonly config: LocalConfig,
    private readonly opts: { bin?: string; signal?: AbortSignal } = {},
  ) {}

  async start(req: ScanRequest): Promise<string> {
    const handle = `local-${req.scanId}-${randomBytes(3).toString("hex")}`;
    const creds = await readRegistryCredentials(this.config.REGISTRY_CREDENTIALS_DIR, req.registry);
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.TRIVY_USERNAME;
    delete env.TRIVY_PASSWORD;
    if (creds) Object.assign(env, { TRIVY_USERNAME: creds.username, TRIVY_PASSWORD: creds.password });

    const child = spawn(this.opts.bin ?? "trivy", trivyArgs(this.config, imageRef(req)), {
      env,
      stdio: ["ignore", "pipe", "pipe"],
      signal: this.opts.signal,
      timeout: SCAN_DEADLINE_SECONDS * 1000,
      killSignal: "SIGKILL",
    });
    this.runs.set(handle, { state: "running" });

    const out: Buffer[] = [];
    let outBytes = 0;
    let err = "";
    child.stdout.on("data", (b: Buffer) => {
      outBytes += b.length;
      if (outBytes <= MAX_STDOUT) out.push(b);
    });
    child.stderr.on("data", (b: Buffer) => {
      err = (err + b.toString("utf8")).slice(-4000);
    });
    const done = (state: RunState) => {
      if (this.runs.get(handle)?.state === "running") this.runs.set(handle, state);
    };
    child.on("error", (e) => done({ state: "failed", error: shortError(`trivy: ${e.message}`) }));
    child.on("close", (code, signal) => {
      if (code === 0 && outBytes <= MAX_STDOUT) {
        done({ state: "succeeded", output: Buffer.concat(out).toString("utf8") });
      } else {
        const why =
          outBytes > MAX_STDOUT
            ? `output larger than ${MAX_STDOUT} bytes`
            : signal
              ? `killed by ${signal}${signal === "SIGKILL" ? ` (deadline ${SCAN_DEADLINE_SECONDS}s)` : ""}`
              : `exited ${code}`;
        done({ state: "failed", error: shortError(`trivy ${why}${err.trim() ? `: ${err.trim()}` : ""}`) });
      }
    });
    return handle;
  }

  async check(handle: string): Promise<RunState> {
    const s = this.runs.get(handle);
    if (!s) return { state: "missing" };
    if (s.state !== "running") this.runs.delete(handle);
    return s;
  }
}
