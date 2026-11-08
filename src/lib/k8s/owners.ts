/** The fields of any Kubernetes object that owner resolution reads. */
export interface K8sObject {
  apiVersion?: string;
  kind?: string;
  metadata?: {
    name?: string;
    namespace?: string;
    ownerReferences?: { apiVersion: string; kind: string; name: string; controller?: boolean }[];
  };
  spec?: { replicas?: number | null } | null;
}

export interface ObjectRef {
  apiVersion: string;
  kind: string;
  namespace: string;
  name: string;
}

/**
 * The Kubernetes reads the report sync needs. Tests pass a fake; the default
 * is `k8sReportSource()` in report-source.ts.
 */
export interface ReportSource {
  /** One page of VulnerabilityReports across all namespaces. */
  listReports(page: { limit: number; continue?: string }): Promise<{ items: unknown[]; continue?: string }>;
  /** Reads one object. Returns null when it does not exist (404); throws on any other error. */
  getObject(ref: ObjectRef): Promise<K8sObject | null>;
}

/**
 * API versions of the kinds trivy-operator puts in its
 * `trivy-operator.resource.kind` label. Owners found further up the chain carry
 * their own apiVersion in the ownerReference.
 */
const LABEL_KIND_API_VERSION: Record<string, string> = {
  Pod: "v1",
  ReplicaSet: "apps/v1",
  ReplicationController: "v1",
  Deployment: "apps/v1",
  StatefulSet: "apps/v1",
  DaemonSet: "apps/v1",
  Job: "batch/v1",
  CronJob: "batch/v1",
};

export type Resolution =
  | { status: "ok"; kind: string; name: string }
  /** The labelled resource exists but is not running anything worth reporting. */
  | { status: "skip"; reason: "scaled_to_zero" | "resource_gone" };

/** Owner chains deeper than this are cut off at the last object read. */
const MAX_DEPTH = 8;

/**
 * Resolves the resource a report names to its top-level owner by following
 * controller ownerReferences: ReplicaSet → Deployment, Job → CronJob, a CNPG
 * instance Pod → its Cluster, and so on.
 *
 * - The labelled resource itself not existing means the report is stale, and
 *   it is skipped. So is a ReplicaSet scaled to zero (left over after a rollout).
 * - An owner that 404s ends the walk at the nearest object that exists.
 * - An owner that is neither a built-in workload kind nor an OpenKruise object
 *   is named as the top level from its ownerReference and never read.
 * - An owner that cannot be read for a reason other than 404 is also
 *   named from its ownerReference, and `errors` counts it.
 *
 * Objects are cached for the life of the resolver, which is one sync.
 */
export class OwnerResolver {
  private readonly objects = new Map<string, Promise<K8sObject | null>>();
  private readonly resolved = new Map<string, Promise<Resolution>>();
  /** Owner lookups that failed with something other than 404. */
  errors = 0;
  /** Objects actually requested from the source. */
  reads = 0;

  constructor(
    private readonly source: ReportSource,
    private readonly onError: (ref: ObjectRef, e: unknown) => void = () => {},
  ) {}

  resolve(namespace: string, kind: string, name: string): Promise<Resolution> {
    const key = `${namespace}/${kind}/${name}`;
    let p = this.resolved.get(key);
    if (!p) {
      p = this.walk(namespace, kind, name);
      this.resolved.set(key, p);
    }
    return p;
  }

  private get(ref: ObjectRef): Promise<K8sObject | null> {
    const key = `${ref.apiVersion}/${ref.kind}/${ref.namespace}/${ref.name}`;
    let p = this.objects.get(key);
    if (!p) {
      this.reads++;
      p = this.source.getObject(ref);
      this.objects.set(key, p);
    }
    return p;
  }

  private async walk(namespace: string, kind: string, name: string): Promise<Resolution> {
    const apiVersion = LABEL_KIND_API_VERSION[kind];
    // A kind trivy-operator does not normally label with: take it as the top.
    if (!apiVersion) return { status: "ok", kind, name };

    let current: K8sObject | null;
    try {
      current = await this.get({ apiVersion, kind, namespace, name });
    } catch (e) {
      this.errors++;
      this.onError({ apiVersion, kind, namespace, name }, e);
      return { status: "ok", kind, name };
    }
    if (!current) return { status: "skip", reason: "resource_gone" };
    if (kind === "ReplicaSet" && current.spec?.replicas === 0) return { status: "skip", reason: "scaled_to_zero" };

    let top = { kind, name };
    for (let depth = 0; depth < MAX_DEPTH; depth++) {
      const refs = current.metadata?.ownerReferences ?? [];
      const owner = refs.find((r) => r.controller) ?? refs[0];
      if (!owner) break;
      // A custom resource (CephCluster, a CNPG Cluster, ...) or a Node ends the
      // chain: its name is in the reference, and reading it would need RBAC on
      // every operator's API group for nothing. Kruise is the exception, because
      // its BroadcastJobs are per-run and the stable name is the AdvancedCronJob
      // above them.
      if (LABEL_KIND_API_VERSION[owner.kind] !== owner.apiVersion && !owner.apiVersion.startsWith("apps.kruise.io/")) {
        top = { kind: owner.kind, name: owner.name };
        break;
      }
      const ref: ObjectRef = { apiVersion: owner.apiVersion, kind: owner.kind, namespace, name: owner.name };
      let next: K8sObject | null;
      try {
        next = await this.get(ref);
      } catch (e) {
        this.errors++;
        this.onError(ref, e);
        top = { kind: owner.kind, name: owner.name };
        break;
      }
      if (!next) break; // 404: the nearest object that exists is the top.
      top = { kind: owner.kind, name: owner.name };
      current = next;
    }
    return { status: "ok", ...top };
  }
}
