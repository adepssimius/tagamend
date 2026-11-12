import type { DB } from "../db";
import type { Image, PullRequest, Scan, SyncName, SyncRun } from "../db/schema";
import { KV } from "../kv-keys";

export const LOOPS: SyncName[] = ["report_sync", "tag_sync", "scan_queue", "pr_queue", "kev_sync"];

export interface KvValue {
  value: string;
  updated_at: string;
}

export interface StatusPage {
  runs: Record<SyncName, SyncRun[]>;
  active: (Scan & { registry: string; repository: string })[];
  failed: (Scan & { registry: string; repository: string })[];
  tagSyncErrors: Image[];
  pullRequests: (PullRequest & { registry: string; repository: string })[];
  trivyReportVersion: KvValue | null;
  trivyServerVersion: KvValue | null;
}

export async function getStatusPage(db: DB, runsPerLoop = 10): Promise<StatusPage> {
  const scansBase = () =>
    db.selectFrom("scans").innerJoin("images", "images.id", "scans.image_id").selectAll("scans").select(["images.registry", "images.repository"]);

  const [runLists, active, failed, tagSyncErrors, kv, pullRequests] = await Promise.all([
    Promise.all(
      LOOPS.map((name) =>
        db.selectFrom("sync_runs").selectAll().where("name", "=", name).orderBy("id", "desc").limit(runsPerLoop).execute(),
      ),
    ),
    scansBase().where("scans.status", "in", ["queued", "running"]).orderBy("scans.id", "asc").execute(),
    scansBase().where("scans.status", "=", "failed").orderBy("scans.id", "desc").limit(20).execute(),
    db.selectFrom("images").selectAll().where("tag_sync_error", "is not", null).orderBy("registry").orderBy("repository").execute(),
    db.selectFrom("kv").selectAll().where("key", "in", [KV.trivyReportVersion, KV.trivyServerVersion]).execute(),
    db
      .selectFrom("pull_requests")
      .innerJoin("images", "images.id", "pull_requests.image_id")
      .selectAll("pull_requests")
      .select(["images.registry", "images.repository"])
      .orderBy("pull_requests.id", "desc")
      .limit(20)
      .execute(),
  ]);
  const kvOf = (key: string) => {
    const r = kv.find((k) => k.key === key);
    return r ? { value: r.value, updated_at: r.updated_at } : null;
  };
  return {
    runs: Object.fromEntries(LOOPS.map((n, i) => [n, runLists[i]!])) as Record<SyncName, SyncRun[]>,
    active,
    failed,
    tagSyncErrors,
    pullRequests,
    trivyReportVersion: kvOf(KV.trivyReportVersion),
    trivyServerVersion: kvOf(KV.trivyServerVersion),
  };
}

/** The tag of an image reference: `mirror.gcr.io/aquasec/trivy:0.76.1` -> `0.76.1`. */
export function imageRefTag(ref: string): string | null {
  const noDigest = ref.split("@")[0]!;
  const slash = noDigest.lastIndexOf("/");
  const colon = noDigest.lastIndexOf(":");
  return colon > slash ? noDigest.slice(colon + 1) : null;
}

/** Compares versions loosely: `v0.76.1` and `0.76.1` match. */
export const sameVersion = (a: string, b: string) => a.trim().replace(/^v/, "") === b.trim().replace(/^v/, "");
