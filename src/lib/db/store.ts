import type { Severity } from "../config";
import type { DigestScan } from "../trivy/finding";
import { errorMessage } from "../log";
import { type DB, now } from "./index";
import type { DigestSource, SyncName } from "./schema";

/** Returns the image id for (registry, repository), creating the row if needed. */
export async function upsertImage(db: DB, registry: string, repository: string): Promise<number> {
  const row = await db
    .insertInto("images")
    .values({ registry, repository, last_tag_sync_at: null, tag_sync_error: null })
    .onConflict((oc) => oc.columns(["registry", "repository"]).doUpdateSet({ registry }))
    .returning("id")
    .executeTakeFirstOrThrow();
  return row.id;
}

/**
 * Stores a scanned digest and replaces its vulnerabilities.
 *
 * Findings outside `severities` are dropped, and duplicates of the unique key
 * (trivy can report the same package twice from different targets) are
 * collapsed. When the stored row already has a `report_updated_at` at or after
 * the incoming one, nothing is written and `changed` is false.
 */
export async function storeDigest(
  db: DB,
  imageId: number,
  source: DigestSource,
  scan: DigestScan,
  severities: readonly Severity[],
): Promise<{ digestId: number; changed: boolean }> {
  const existing = await db
    .selectFrom("image_digests")
    .select(["id", "report_updated_at"])
    .where("image_id", "=", imageId)
    .where("digest", "=", scan.digest)
    .executeTakeFirst();
  if (
    existing &&
    scan.reportUpdatedAt &&
    existing.report_updated_at &&
    existing.report_updated_at >= scan.reportUpdatedAt
  ) {
    return { digestId: existing.id, changed: false };
  }

  const keep = new Set<string>(severities);
  const seen = new Set<string>();
  const findings = scan.findings.filter((f) => {
    if (!keep.has(f.severity)) return false;
    const k = `${f.vulnId}\u0000${f.package}\u0000${f.installedVersion}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const count = (s: Severity) => findings.filter((f) => f.severity === s).length;
  const values = {
    image_id: imageId,
    digest: scan.digest,
    os_family: scan.osFamily,
    os_name: scan.osName,
    scanned_at: scan.scannedAt,
    report_updated_at: scan.reportUpdatedAt,
    scanner_version: scan.scannerVersion,
    // An operator report wins over a candidate scan of the same digest: once a
    // candidate is running, it is the running image.
    source,
    critical: count("CRITICAL"),
    high: count("HIGH"),
    medium: count("MEDIUM"),
    low: count("LOW"),
    unknown: count("UNKNOWN"),
  };

  return db.transaction().execute(async (trx) => {
    let digestId: number;
    if (existing) {
      digestId = existing.id;
      await trx.updateTable("image_digests").set(values).where("id", "=", digestId).execute();
      await trx.deleteFrom("vulnerabilities").where("digest_id", "=", digestId).execute();
    } else {
      digestId = (await trx.insertInto("image_digests").values(values).returning("id").executeTakeFirstOrThrow()).id;
    }
    for (let i = 0; i < findings.length; i += 500) {
      await trx
        .insertInto("vulnerabilities")
        .values(
          findings.slice(i, i + 500).map((f) => ({
            digest_id: digestId,
            vuln_id: f.vulnId,
            package: f.package,
            installed_version: f.installedVersion,
            fixed_version: f.fixedVersion,
            severity: f.severity,
            score: f.score,
            title: f.title,
            link: f.link,
          })),
        )
        .execute();
    }
    return { digestId, changed: true };
  });
}

/** Records one run of a background loop for the Status page. */
export async function withSyncRun<T extends Record<string, unknown>>(
  db: DB,
  name: SyncName,
  fn: () => Promise<T>,
): Promise<T | undefined> {
  const { id } = await db
    .insertInto("sync_runs")
    .values({ name, started_at: now(), finished_at: null, ok: null, error: null, detail: null })
    .returning("id")
    .executeTakeFirstOrThrow();
  try {
    const detail = await fn();
    await db
      .updateTable("sync_runs")
      .set({ finished_at: now(), ok: 1, detail: JSON.stringify(detail) })
      .where("id", "=", id)
      .execute();
    return detail;
  } catch (e) {
    await db
      .updateTable("sync_runs")
      .set({ finished_at: now(), ok: 0, error: errorMessage(e) })
      .where("id", "=", id)
      .execute();
    throw e;
  }
}

export async function setKv(db: DB, key: string, value: string): Promise<void> {
  await db
    .insertInto("kv")
    .values({ key, value, updated_at: now() })
    .onConflict((oc) => oc.column("key").doUpdateSet({ value, updated_at: now() }))
    .execute();
}

export async function getKv(db: DB, key: string): Promise<string | undefined> {
  return (await db.selectFrom("kv").select("value").where("key", "=", key).executeTakeFirst())?.value;
}

/** Keep the last N runs per loop. */
export async function pruneSyncRuns(db: DB, keep = 200): Promise<void> {
  for (const name of ["report_sync", "tag_sync", "scan_queue", "pr_queue", "kev_sync"] as const) {
    const cutoff = await db
      .selectFrom("sync_runs")
      .select("id")
      .where("name", "=", name)
      .orderBy("id", "desc")
      .offset(keep)
      .limit(1)
      .executeTakeFirst();
    if (cutoff) await db.deleteFrom("sync_runs").where("name", "=", name).where("id", "<=", cutoff.id).execute();
  }
}
