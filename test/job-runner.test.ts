import { describe, expect, it, vi } from "vitest";
import type * as k8s from "@kubernetes/client-node";
import { getConfig } from "@/lib/config";
import { buildScanJob, JobScanRunner, type JobRunnerApi } from "@/lib/scan/job-runner";
import { imageRef } from "@/lib/scan/runner";

const DIGEST = "sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11";
const config = getConfig({
  DATABASE_URL: ":memory:",
  SCAN_REGISTRY_SECRETS: "ghcr.io=ghcr-creds/user/token;docker.io=dockerhub/username/password",
  SCAN_EXCLUDED_NODES: "small-node",
});
const req = { scanId: 42, registry: "index.docker.io", repository: "library/alpine", digest: DIGEST };

describe("image references", () => {
  it("keeps index.docker.io and adds library/ to official images", () => {
    expect(imageRef(req)).toBe(`index.docker.io/library/alpine@${DIGEST}`);
    expect(imageRef({ ...req, repository: "alpine" })).toBe(`index.docker.io/library/alpine@${DIGEST}`);
    expect(imageRef({ ...req, registry: "ghcr.io", repository: "alpine" })).toBe(`ghcr.io/alpine@${DIGEST}`);
    expect(() => imageRef({ ...req, digest: "latest" })).toThrow("not a sha256 digest");
  });
});

describe("scan Job spec", () => {
  it("builds the Job", () => {
    expect(buildScanJob(config, req, "tagamend-scan-42-abcdef")).toMatchSnapshot();
  });

  it("sets no affinity when no nodes are excluded", () => {
    const job = buildScanJob({ ...config, SCAN_EXCLUDED_NODES: [] }, req, "n");
    expect(job.spec!.template.spec!.affinity).toBeUndefined();
  });

  it("takes credentials from the Secret for the image's registry host", () => {
    const env = (r: typeof req) =>
      buildScanJob(config, r, "n").spec!.template.spec!.containers[0]!.env!.filter((e) => e.name.startsWith("TRIVY_U") || e.name === "TRIVY_PASSWORD");
    // Docker Hub hosts are aliases of each other.
    expect(env(req).map((e) => [e.name, e.valueFrom?.secretKeyRef?.name, e.valueFrom?.secretKeyRef?.key])).toEqual([
      ["TRIVY_USERNAME", "dockerhub", "username"],
      ["TRIVY_PASSWORD", "dockerhub", "password"],
    ]);
    expect(env({ ...req, registry: "ghcr.io" }).map((e) => e.valueFrom?.secretKeyRef?.key)).toEqual(["user", "token"]);
    expect(env({ ...req, registry: "lscr.io" })).toEqual([]);
  });
});

function fakeApi(job: k8s.V1Job | 404, pods: k8s.V1Pod[] = [], logs: Record<string, string> = {}) {
  const api = {
    batch: {
      createNamespacedJob: vi.fn(async ({ body }: { body: k8s.V1Job }) => body),
      readNamespacedJob: vi.fn(async () => {
        if (job === 404) throw Object.assign(new Error("not found"), { code: 404 });
        return job;
      }),
    },
    core: {
      listNamespacedPod: vi.fn(async (_: { namespace: string; labelSelector: string }) => ({ items: pods })),
      readNamespacedPodLog: vi.fn(async ({ name, tailLines }: { name: string; tailLines?: number }) => {
        const l = logs[name];
        if (l === undefined) throw Object.assign(new Error("no log"), { code: 400 });
        return tailLines ? l.split("\n").slice(-tailLines).join("\n") : l;
      }),
    },
  };
  return api as typeof api & JobRunnerApi;
}

const jobWith = (type?: string, reason?: string, message?: string): k8s.V1Job => ({
  metadata: { name: "j" },
  status: type ? { conditions: [{ type, status: "True", reason, message }] } : {},
});
const pod = (name: string, phase: string, cs?: k8s.V1ContainerStatus): k8s.V1Pod => ({
  metadata: { name },
  status: { phase, containerStatuses: cs ? [cs] : [] },
});

describe("JobScanRunner", () => {
  it("creates the Job in SCAN_NAMESPACE and returns its name", async () => {
    const api = fakeApi(404);
    const name = await new JobScanRunner(config, api).start(req);
    expect(name).toMatch(/^tagamend-scan-42-[0-9a-f]{6}$/);
    const call = api.batch.createNamespacedJob.mock.calls[0]![0] as unknown as { namespace: string; body: k8s.V1Job };
    expect(call.body.metadata?.name).toBe(name);
    expect(call.namespace).toBe("tagamend");
  });

  it("reports a missing Job", async () => {
    expect(await new JobScanRunner(config, fakeApi(404)).check("j")).toEqual({ state: "missing" });
  });

  it("propagates other API errors", async () => {
    const api = fakeApi(404);
    api.batch.readNamespacedJob.mockRejectedValueOnce(Object.assign(new Error("forbidden"), { code: 403 }));
    await expect(new JobScanRunner(config, api).check("j")).rejects.toThrow("forbidden");
  });

  it("reports running until a terminal condition", async () => {
    expect(await new JobScanRunner(config, fakeApi(jobWith())).check("j")).toEqual({ state: "running" });
    // SuccessCriteriaMet comes before Complete; wait for Complete.
    expect(await new JobScanRunner(config, fakeApi(jobWith("SuccessCriteriaMet"))).check("j")).toEqual({ state: "running" });
  });

  it("reads the succeeded pod's log on completion", async () => {
    const api = fakeApi(jobWith("Complete"), [pod("j-abc", "Succeeded")], { "j-abc": '{"SchemaVersion":2}' });
    expect(await new JobScanRunner(config, api).check("j")).toEqual({ state: "succeeded", output: '{"SchemaVersion":2}' });
    expect(api.core.listNamespacedPod.mock.calls[0]![0]).toEqual({
      namespace: "tagamend",
      labelSelector: "batch.kubernetes.io/job-name=j",
    });
    expect(api.core.readNamespacedPodLog.mock.calls[0]![0]).toEqual({ name: "j-abc", namespace: "tagamend", container: "trivy" });
  });

  it("describes a failure from the Job condition, the container, and the log tail", async () => {
    const log = [...Array.from({ length: 15 }, (_, i) => `line ${i}`), "FATAL\tunable to find the specified image"].join("\n");
    const api = fakeApi(
      jobWith("Failed", "BackoffLimitExceeded", "Job has reached the specified backoff limit"),
      [pod("j-abc", "Failed", { name: "trivy", image: "", imageID: "", ready: false, restartCount: 0, state: { terminated: { exitCode: 1, reason: "Error" } } })],
      { "j-abc": log },
    );
    const s = await new JobScanRunner(config, api).check("j");
    expect(s.state).toBe("failed");
    const error = (s as { error: string }).error;
    expect(error).toMatch(/^Job BackoffLimitExceeded: Job has reached the specified backoff limit; container exited 1 \(Error\); line 6\n/);
    expect(error).toContain("unable to find the specified image");
    expect(error).not.toContain("line 5\n");
  });

  it("describes a deadline failure whose pod never started", async () => {
    const api = fakeApi(jobWith("Failed", "DeadlineExceeded", "Job was active longer than specified deadline"), [
      pod("j-abc", "Pending", { name: "trivy", image: "", imageID: "", ready: false, restartCount: 0, state: { waiting: { reason: "ImagePullBackOff" } } }),
    ]);
    expect(await new JobScanRunner(config, api).check("j")).toEqual({
      state: "failed",
      error: "Job DeadlineExceeded: Job was active longer than specified deadline; container waiting: ImagePullBackOff",
    });
  });
});
