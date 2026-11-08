import type { Config } from "../config";

/** What a runner needs to start one scan. */
export interface ScanRequest {
  scanId: number;
  /** As stored on `images`: `index.docker.io`, `ghcr.io`, ... */
  registry: string;
  repository: string;
  digest: string;
}

/** The state of a started scan, as seen by its runner. */
export type RunState =
  | { state: "running" }
  /** `output` is the scanner's stdout (or the pod log): the JSON report. */
  | { state: "succeeded"; output: string }
  | { state: "failed"; error: string }
  /** The runner no longer knows the scan: the Job is gone, or the process that ran it restarted. */
  | { state: "missing" };

/**
 * Runs trivy against one image. `start` returns a handle that is stored in
 * `scans.job_name`; `check` takes that handle, including one stored by an
 * earlier worker process.
 */
export interface ScanRunner {
  readonly kind: "job" | "local";
  start(req: ScanRequest): Promise<string>;
  check(handle: string): Promise<RunState>;
}

const DOCKER_HUB = new Set(["docker.io", "index.docker.io", "registry-1.docker.io"]);

export const isDockerHub = (host: string) => DOCKER_HUB.has(host.toLowerCase());

/**
 * The reference trivy pulls. Docker Hub is stored as `index.docker.io` (as
 * trivy-operator reports it), which trivy accepts; an official image stored
 * without its `library/` prefix gets one.
 */
export function imageRef(req: Pick<ScanRequest, "registry" | "repository" | "digest">): string {
  let repo = req.repository.replace(/^\/+|\/+$/g, "");
  if (isDockerHub(req.registry) && !repo.includes("/")) repo = `library/${repo}`;
  if (!/^sha256:[0-9a-f]{64}$/.test(req.digest)) throw new Error(`not a sha256 digest: ${req.digest}`);
  return `${req.registry}/${repo}@${req.digest}`;
}

/** Hosts to look up credentials under, most specific first. */
export function credentialHosts(registry: string): string[] {
  const host = registry.toLowerCase();
  return isDockerHub(host) ? [host, ...[...DOCKER_HUB].filter((h) => h !== host)] : [host];
}

/** Arguments after `trivy`. The same for the Job and the local runner. */
export function trivyArgs(config: Pick<Config, "TRIVY_SERVER_URL" | "SEVERITIES">, ref: string): string[] {
  return [
    "image",
    "--server",
    config.TRIVY_SERVER_URL,
    "--format",
    "json",
    "--quiet",
    "--severity",
    config.SEVERITIES.join(","),
    "--platform",
    "linux/amd64",
    "--scanners",
    "vuln",
    ref,
  ];
}

/** Hard limit on one scan, in both runners. */
export const SCAN_DEADLINE_SECONDS = 600;

/** Keeps stored errors short enough for a table cell. */
export function shortError(s: string, max = 600): string {
  const t = s.trim().replace(/\s+\n/g, "\n");
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}
