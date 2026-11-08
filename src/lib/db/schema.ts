import type { ColumnType, Generated, Insertable, Selectable, Updateable } from "kysely";

/**
 * All timestamps are ISO-8601 UTC strings (`new Date().toISOString()`), stored
 * as text on both SQLite and Postgres. They sort correctly as strings, and the
 * same queries return the same JavaScript type on both dialects.
 *
 * Booleans are stored as integers (0/1) for the same reason.
 */
type Timestamp = string;
type Bool = number;

export type DigestSource = "operator" | "candidate";
export type ScanStatus = "queued" | "running" | "done" | "failed";
export type SyncName = "report_sync" | "tag_sync" | "scan_queue";

export interface ImagesTable {
  id: Generated<number>;
  /** As trivy reports it: `index.docker.io`, `ghcr.io`, `lscr.io`, ... */
  registry: string;
  /** `library/nginx`, `linuxserver/sonarr`, ... */
  repository: string;
  last_tag_sync_at: Timestamp | null;
  tag_sync_error: string | null;
}

export interface ImageDigestsTable {
  id: Generated<number>;
  image_id: number;
  digest: string;
  os_family: string | null;
  os_name: string | null;
  scanned_at: Timestamp;
  /** The report's own updateTimestamp, used to skip unchanged reports. */
  report_updated_at: Timestamp | null;
  scanner_version: string | null;
  source: DigestSource;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface VulnerabilitiesTable {
  id: Generated<number>;
  digest_id: number;
  vuln_id: string;
  package: string;
  installed_version: string;
  fixed_version: string | null;
  severity: string;
  score: number | null;
  title: string | null;
  link: string | null;
}

export interface WorkloadsTable {
  id: Generated<number>;
  namespace: string;
  /** Top-level owner kind: Deployment, StatefulSet, DaemonSet, CronJob, Job, Pod, or an operator CR such as CephCluster. */
  kind: string;
  name: string;
  container: string;
  image_id: number;
  tag: string | null;
  digest_id: number | null;
  last_seen_at: Timestamp;
  /** Set when a sync no longer sees the workload for 24h; cleared if it returns. */
  gone_at: Timestamp | null;
}

export interface TagsTable {
  id: Generated<number>;
  image_id: number;
  tag: string;
  digest: string | null;
  first_seen_at: Timestamp;
  is_candidate: Bool;
  /** Why this tag is or is not a candidate, shown in the UI. */
  reason: string | null;
}

export interface ScansTable {
  id: Generated<number>;
  image_id: number;
  tag: string;
  digest: string;
  status: ScanStatus;
  requested_by: string | null;
  requested_at: Timestamp;
  started_at: Timestamp | null;
  finished_at: Timestamp | null;
  job_name: string | null;
  error: string | null;
  result_digest_id: number | null;
}

/** One row per run of a background loop, for the Status page. */
export interface SyncRunsTable {
  id: Generated<number>;
  name: SyncName;
  started_at: Timestamp;
  finished_at: Timestamp | null;
  ok: Bool | null;
  error: string | null;
  /** Free-form JSON text: counts, skipped items. */
  detail: string | null;
}

/** Small key/value facts, such as the Trivy server version. */
export interface KvTable {
  key: string;
  value: string;
  updated_at: Timestamp;
}

export interface Database {
  images: ImagesTable;
  image_digests: ImageDigestsTable;
  vulnerabilities: VulnerabilitiesTable;
  workloads: WorkloadsTable;
  tags: TagsTable;
  scans: ScansTable;
  sync_runs: SyncRunsTable;
  kv: KvTable;
}

export type Image = Selectable<ImagesTable>;
export type ImageDigest = Selectable<ImageDigestsTable>;
export type Vulnerability = Selectable<VulnerabilitiesTable>;
export type NewVulnerability = Insertable<VulnerabilitiesTable>;
export type Workload = Selectable<WorkloadsTable>;
export type Tag = Selectable<TagsTable>;
export type Scan = Selectable<ScansTable>;
export type ScanUpdate = Updateable<ScansTable>;
export type SyncRun = Selectable<SyncRunsTable>;

// Silence "unused" for ColumnType in case a later table needs it.
export type _Unused = ColumnType<never>;
