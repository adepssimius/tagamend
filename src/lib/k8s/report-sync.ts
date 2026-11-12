import { setKv, storeDigest, upsertImage } from "../db/store";
import { KV } from "../kv-keys";
import { errorMessage } from "../log";
import { parseVulnerabilityReport } from "../trivy/report";
import type { WorkerContext } from "../worker-context";
import { OwnerResolver, type ReportSource } from "./owners";

const PAGE_SIZE = 100;
/** A workload not seen by any sync for this long is marked gone. */
export const GONE_AFTER_MS = 24 * 3_600_000;
/** Log at most this many invalid reports individually per sync. */
const MAX_INVALID_LOGS = 10;

export interface ReportSyncOptions {
  /** Kubernetes access; defaults to the shared client. */
  source?: ReportSource;
  /** Clock for last_seen_at and the gone cutoff. */
  clock?: () => Date;
  pageSize?: number;
}

export interface ReportSyncDetail extends Record<string, unknown> {
  /** VulnerabilityReports listed. */
  reports: number;
  /** Digests whose findings were written (new, or a newer report). */
  changedDigests: number;
  /** Valid reports not stored, by reason. */
  skipped: number;
  skippedReasons: Record<string, number>;
  /** Reports that failed validation. */
  invalid: number;
  /** Distinct (namespace, kind, name, container) rows upserted. */
  workloads: number;
  /** Workload rows newly marked gone. */
  markedGone: number;
  /** Owner lookups that failed with something other than 404. */
  ownerLookupErrors: number;
  /** Objects read from the API to resolve owners. */
  ownerReads: number;
  pages: number;
  /** Workloads whose running tag changed; their images' tags are rechecked next tick. */
  tagChanges?: number;
  /** Workloads whose pods run an older build than the one their report scanned. */
  staleBuilds?: number;
  podListError?: string;
  aborted?: boolean;
}

/**
 * Lists VulnerabilityReports, stores digests and findings, resolves workloads
 * to their top-level owner, marks unseen workloads gone. Returns counts for the
 * sync_runs detail.
 */
export async function syncReports(ctx: WorkerContext, opts: ReportSyncOptions = {}): Promise<ReportSyncDetail> {
  const { db, config, log, signal } = ctx;
  // Imported here so that tests with a fake never load client-node.
  const source = opts.source ?? (await import("./report-source")).k8sReportSource();
  const clock = opts.clock ?? (() => new Date());
  const pageSize = opts.pageSize ?? PAGE_SIZE;

  const owners = new OwnerResolver(source, (ref, e) =>
    log.warn("report sync: owner lookup failed", { ...ref, error: errorMessage(e) }),
  );
  const detail: ReportSyncDetail = {
    reports: 0,
    changedDigests: 0,
    skipped: 0,
    skippedReasons: {},
    invalid: 0,
    workloads: 0,
    markedGone: 0,
    ownerLookupErrors: 0,
    ownerReads: 0,
    pages: 0,
  };
  const seenWorkloads = new Set<string>();
  const imageIds = new Map<string, number>();
  let newest: { at: string; version: string } | undefined;
  const syncStart = clock();
  const seenAt = syncStart.toISOString();

  // What pods actually run, by the resource a report names (pod or its controller).
  const podDigests = new Map<string, Set<string>>();
  if (source.listPodImages) {
    try {
      for (const p of await source.listPodImages()) {
        for (const [kind, name] of [["Pod", p.podName], ...(p.owner ? [[p.owner.kind, p.owner.name]] : [])] as const) {
          const k = `${p.namespace}/${kind}/${name}/${p.container}`;
          let set = podDigests.get(k);
          if (!set) podDigests.set(k, (set = new Set()));
          set.add(p.digest);
        }
      }
    } catch (e) {
      // Without pod data the sync still works; only stale-build detection is lost.
      log.warn("report sync: could not list pods", { error: errorMessage(e) });
      detail.podListError = errorMessage(e);
    }
  }

  let cont: string | undefined;
  do {
    if (signal.aborted) return { ...detail, aborted: true };
    const page = await source.listReports({ limit: pageSize, continue: cont });
    cont = page.continue;
    detail.pages++;

    for (const raw of page.items) {
      if (signal.aborted) return { ...detail, aborted: true };
      detail.reports++;
      const parsed = parseVulnerabilityReport(raw);
      if (!parsed.ok) {
        detail.invalid++;
        if (detail.invalid <= MAX_INVALID_LOGS) {
          log.warn("report sync: invalid VulnerabilityReport", { report: parsed.id, error: parsed.error });
        }
        continue;
      }
      const r = parsed.report;
      const res = r.resource;

      const owner = await owners.resolve(res.namespace, res.kind, res.name);
      if (owner.status === "skip") {
        detail.skipped++;
        detail.skippedReasons[owner.reason] = (detail.skippedReasons[owner.reason] ?? 0) + 1;
        continue;
      }

      const imageKey = `${r.registry}\u0000${r.repository}`;
      let imageId = imageIds.get(imageKey);
      if (imageId === undefined) {
        imageId = await upsertImage(db, r.registry, r.repository);
        imageIds.set(imageKey, imageId);
      }
      const { digestId, changed } = await storeDigest(db, imageId, "operator", r.scan, config.SEVERITIES);
      if (changed) detail.changedDigests++;

      // A tag that moved after the pod started: the report describes what the
      // tag points to now, the pod runs an older build. Once that build has been
      // scanned (a candidate scan of its digest), it is what counts as running.
      const running = podDigests.get(`${res.namespace}/${res.kind}/${res.name}/${res.container}`);
      // Any pod on another build counts: a DaemonSet can be half updated.
      const podDigest = [...(running ?? [])].filter((d) => d !== r.scan.digest).sort()[0] ?? null;
      let runningDigestId = digestId;
      if (podDigest) {
        detail.staleBuilds = (detail.staleBuilds ?? 0) + 1;
        const scanned = await db
          .selectFrom("image_digests")
          .select("id")
          .where("image_id", "=", imageId)
          .where("digest", "=", podDigest)
          .executeTakeFirst();
        if (scanned) runningDigestId = scanned.id;
      }

      if (r.scan.scannerVersion && (!newest || r.scan.scannedAt > newest.at)) {
        newest = { at: r.scan.scannedAt, version: r.scan.scannerVersion };
      }

      // Several reports can map to one row: the instance Pods of one CNPG
      // Cluster, or the old and new ReplicaSet mid-rollout. The last one wins.
      const row = {
        namespace: res.namespace,
        kind: owner.kind,
        name: owner.name,
        container: res.container,
        image_id: imageId,
        tag: r.tag,
        digest_id: runningDigestId,
        last_seen_at: seenAt,
        report_digest: r.scan.digest,
        pod_digest: podDigest,
        gone_at: null,
      };
      // A running tag that changed (an upgrade rolled out) makes the image's
      // candidates stale, so its tags are checked again on the next tick
      // instead of after the full interval.
      const before = await db
        .selectFrom("workloads")
        .select("tag")
        .where("namespace", "=", row.namespace)
        .where("kind", "=", row.kind)
        .where("name", "=", row.name)
        .where("container", "=", row.container)
        .executeTakeFirst();
      if (before && before.tag !== row.tag) {
        await db.updateTable("images").set({ last_tag_sync_at: null }).where("id", "=", imageId).execute();
        detail.tagChanges = (detail.tagChanges ?? 0) + 1;
      }
      await db
        .insertInto("workloads")
        .values(row)
        .onConflict((oc) =>
          oc.columns(["namespace", "kind", "name", "container"]).doUpdateSet({
            image_id: row.image_id,
            tag: row.tag,
            digest_id: row.digest_id,
            last_seen_at: row.last_seen_at,
            report_digest: row.report_digest,
            pod_digest: row.pod_digest,
            gone_at: null,
          }),
        )
        .execute();
      seenWorkloads.add(`${row.namespace}/${row.kind}/${row.name}/${row.container}`);
    }
  } while (cont);

  detail.workloads = seenWorkloads.size;
  detail.ownerLookupErrors = owners.errors;
  detail.ownerReads = owners.reads;

  if (newest) await setKv(db, KV.trivyReportVersion, newest.version);

  // Only after a complete pass: a partial list must not mark anything gone.
  const cutoff = new Date(syncStart.getTime() - GONE_AFTER_MS).toISOString();
  const gone = await db
    .updateTable("workloads")
    .set({ gone_at: seenAt })
    .where("gone_at", "is", null)
    .where("last_seen_at", "<", cutoff)
    .executeTakeFirst();
  detail.markedGone = Number(gone.numUpdatedRows);

  if (detail.invalid > MAX_INVALID_LOGS) {
    log.warn("report sync: more invalid VulnerabilityReports not logged", { count: detail.invalid - MAX_INVALID_LOGS });
  }
  return detail;
}
