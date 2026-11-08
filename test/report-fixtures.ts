import { readFileSync } from "node:fs";
import path from "node:path";
import type { K8sObject, ObjectRef, ReportSource } from "@/lib/k8s/owners";

/**
 * VulnerabilityReports in the exact shape trivy-operator writes, and the
 * metadata of the objects in their owner chains. Namespaces, workload and image
 * names, digests and UIDs are made up.
 */
const dir = path.join(import.meta.dirname, "fixtures", "reports");
const load = <T>(file: string): T => JSON.parse(readFileSync(path.join(dir, file), "utf8")) as T;

export type RawReport = {
  metadata: { name: string; namespace: string; labels: Record<string, string> };
  report: Record<string, any>;
};

export const fixtureReports = (): RawReport[] => load<RawReport[]>("reports.json");
export const fixtureOwners = (): K8sObject[] => load<K8sObject[]>("owners.json");

export const reportNamed = (reports: RawReport[], name: string): RawReport => {
  const r = reports.find((x) => x.metadata.name === name);
  if (!r) throw new Error(`no fixture report ${name}`);
  return r;
};

/** An in-memory ReportSource that pages like the API server and counts reads. */
export class FakeSource implements ReportSource {
  readonly objects = new Map<string, K8sObject>();
  /** ref keys that throw a 403 instead of returning. */
  readonly forbidden = new Set<string>();
  reads: string[] = [];
  pageRequests = 0;

  constructor(
    public reports: unknown[],
    objects: K8sObject[],
  ) {
    for (const o of objects) this.objects.set(FakeSource.key(o), o);
  }

  static key(o: K8sObject | ObjectRef): string {
    const m = "metadata" in o ? o.metadata! : (o as ObjectRef);
    return `${o.apiVersion}/${o.kind}/${m.namespace}/${m.name}`;
  }

  async listReports({ limit, continue: cont }: { limit: number; continue?: string }) {
    this.pageRequests++;
    const start = cont ? Number(cont) : 0;
    const end = start + limit;
    return { items: this.reports.slice(start, end), continue: end < this.reports.length ? String(end) : undefined };
  }

  async getObject(ref: ObjectRef) {
    const k = FakeSource.key(ref);
    this.reads.push(k);
    if (this.forbidden.has(k)) throw Object.assign(new Error("forbidden"), { code: 403 });
    return this.objects.get(k) ?? null;
  }
}
