import { randomBytes } from "node:crypto";
import type * as k8s from "@kubernetes/client-node";
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

/** The Kubernetes calls the Job runner makes; tests pass a fake. */
export interface JobRunnerApi {
  batch: Pick<k8s.BatchV1Api, "createNamespacedJob" | "readNamespacedJob">;
  core: Pick<k8s.CoreV1Api, "listNamespacedPod" | "readNamespacedPodLog">;
}

type JobConfig = Pick<
  Config,
  "SCAN_NAMESPACE" | "SCAN_EXCLUDED_NODES" | "TRIVY_IMAGE" | "TRIVY_SERVER_URL" | "SEVERITIES" | "SCAN_REGISTRY_SECRETS"
>;

export const MANAGED_BY = { "app.kubernetes.io/managed-by": "tagamend" } as const;
export const SCAN_ID_LABEL = "tagamend.io/scan-id";
const CONTAINER = "trivy";

export function jobName(scanId: number, suffix = randomBytes(3).toString("hex")): string {
  // A suffix keeps a fresh database from colliding with a Job left by an old one.
  return `tagamend-scan-${scanId}-${suffix}`;
}

/** Builds the scan Job. Pure, so the spec can be asserted in tests. */
export function buildScanJob(config: JobConfig, req: ScanRequest, name: string): k8s.V1Job {
  const ref = imageRef(req);
  const labels = { ...MANAGED_BY, "app.kubernetes.io/name": "tagamend-scan", [SCAN_ID_LABEL]: String(req.scanId) };
  const hosts = credentialHosts(req.registry);
  const secret = hosts.map((h) => config.SCAN_REGISTRY_SECRETS.find((s) => s.host.toLowerCase() === h)).find(Boolean);
  const env: k8s.V1EnvVar[] = [
    { name: "HOME", value: "/tmp" },
    { name: "TRIVY_CACHE_DIR", value: "/tmp/trivy" },
    // Below the Job's deadline so trivy reports its own timeout instead of being killed.
    { name: "TRIVY_TIMEOUT", value: `${SCAN_DEADLINE_SECONDS - 60}s` },
    // The report travels through the pod log; the package list is not used.
    { name: "TRIVY_LIST_ALL_PKGS", value: "false" },
  ];
  if (secret) {
    env.push(
      { name: "TRIVY_USERNAME", valueFrom: { secretKeyRef: { name: secret.secret, key: secret.usernameKey } } },
      { name: "TRIVY_PASSWORD", valueFrom: { secretKeyRef: { name: secret.secret, key: secret.passwordKey } } },
    );
  }
  return {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: {
      name,
      namespace: config.SCAN_NAMESPACE,
      labels,
      annotations: { "tagamend.io/image": ref },
    },
    spec: {
      backoffLimit: 0,
      activeDeadlineSeconds: SCAN_DEADLINE_SECONDS,
      ttlSecondsAfterFinished: 3600,
      template: {
        metadata: { labels },
        spec: {
          restartPolicy: "Never",
          automountServiceAccountToken: false,
          enableServiceLinks: false,
          // An empty NotIn list is invalid, so no exclusions means no affinity.
          ...(config.SCAN_EXCLUDED_NODES.length > 0 && {
            affinity: {
              nodeAffinity: {
                requiredDuringSchedulingIgnoredDuringExecution: {
                  nodeSelectorTerms: [
                    {
                      matchExpressions: [
                        { key: "kubernetes.io/hostname", operator: "NotIn", values: config.SCAN_EXCLUDED_NODES },
                      ],
                    },
                  ],
                },
              },
            },
          }),
          securityContext: {
            runAsNonRoot: true,
            runAsUser: 65534,
            runAsGroup: 65534,
            seccompProfile: { type: "RuntimeDefault" },
          },
          containers: [
            {
              name: CONTAINER,
              image: config.TRIVY_IMAGE,
              command: ["trivy"],
              args: trivyArgs(config, ref),
              env,
              resources: {
                requests: { cpu: "100m", memory: "256Mi" },
                limits: { cpu: "1", memory: "1Gi" },
              },
              securityContext: {
                allowPrivilegeEscalation: false,
                privileged: false,
                readOnlyRootFilesystem: true,
                capabilities: { drop: ["ALL"] },
              },
              volumeMounts: [{ name: "tmp", mountPath: "/tmp" }],
            },
          ],
          volumes: [{ name: "tmp", emptyDir: { sizeLimit: "2Gi" } }],
        },
      },
    },
  };
}

const isNotFound = (e: unknown) => (e as { code?: number } | null)?.code === 404;

const condition = (job: k8s.V1Job, type: string) =>
  job.status?.conditions?.find((c) => c.type === type && c.status === "True");

/** Runs each scan as a Job in SCAN_NAMESPACE and reads its result from the pod log. */
export class JobScanRunner implements ScanRunner {
  readonly kind = "job" as const;
  constructor(
    private readonly config: JobConfig,
    private readonly api: JobRunnerApi,
  ) {}

  async start(req: ScanRequest): Promise<string> {
    const name = jobName(req.scanId);
    await this.api.batch.createNamespacedJob({
      namespace: this.config.SCAN_NAMESPACE,
      body: buildScanJob(this.config, req, name),
    });
    return name;
  }

  async check(name: string): Promise<RunState> {
    const namespace = this.config.SCAN_NAMESPACE;
    let job: k8s.V1Job;
    try {
      job = await this.api.batch.readNamespacedJob({ name, namespace });
    } catch (e) {
      if (isNotFound(e)) return { state: "missing" };
      throw e;
    }
    const complete = condition(job, "Complete");
    const failed = condition(job, "Failed");
    if (!complete && !failed) return { state: "running" };

    const pods = (
      await this.api.core.listNamespacedPod({ namespace, labelSelector: `batch.kubernetes.io/job-name=${name}` })
    ).items;

    if (complete) {
      const pod = pods.find((p) => p.status?.phase === "Succeeded") ?? pods[0];
      if (!pod?.metadata?.name) return { state: "failed", error: `Job ${name} completed but its pod is gone` };
      const output = await this.api.core.readNamespacedPodLog({ name: pod.metadata.name, namespace, container: CONTAINER });
      return { state: "succeeded", output };
    }

    // Failed: the Job's reason, the container's exit, and the end of the log.
    const parts = [`Job ${failed!.reason ?? "failed"}${failed!.message ? `: ${failed!.message}` : ""}`];
    const pod = pods[0];
    const cs = pod?.status?.containerStatuses?.find((c) => c.name === CONTAINER);
    const term = cs?.state?.terminated;
    if (term) parts.push(`container exited ${term.exitCode}${term.reason ? ` (${term.reason})` : ""}`);
    else if (cs?.state?.waiting?.reason) parts.push(`container waiting: ${cs.state.waiting.reason}`);
    if (pod?.metadata?.name) {
      try {
        const tail = await this.api.core.readNamespacedPodLog({
          name: pod.metadata.name,
          namespace,
          container: CONTAINER,
          tailLines: 10,
        });
        if (tail.trim()) parts.push(tail.trim());
      } catch {
        // A pod that never started has no log; the reason above is what there is.
      }
    }
    return { state: "failed", error: shortError(parts.join("; ")) };
  }
}
