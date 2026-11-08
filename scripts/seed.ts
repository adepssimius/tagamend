/**
 * Loads synthetic data so the UI has something to show without a cluster.
 * Runs migrations first. Goes through upsertImage/storeDigest like the worker.
 *
 *   npm run seed            # refuses a database that already has images
 *   npm run seed -- --reset # deletes all rows first
 */
import { createHash } from "node:crypto";
import { createDb, type DB, migrate } from "../src/lib/db";
import { setKv, storeDigest, upsertImage } from "../src/lib/db/store";
import type { DigestSource, ScanStatus, SyncName } from "../src/lib/db/schema";
import { KV } from "../src/lib/kv-keys";
import type { Finding } from "../src/lib/trivy/finding";
import type { Severity } from "../src/lib/config";

// `next dev` reads .env.local by itself; this script has to ask. Real env vars win.
try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: use the environment as it is.
}

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM"];
const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
const sha = (s: string) => `sha256:${createHash("sha256").update(s).digest("hex")}`;

const f = (
  vulnId: string,
  pkg: string,
  installedVersion: string,
  fixedVersion: string | null,
  severity: Severity,
  score: number | null,
  title: string,
  link: string | null = `https://avd.aquasec.com/nvd/${vulnId.toLowerCase()}`,
): Finding => ({ vulnId, package: pkg, installedVersion, fixedVersion, severity, score, title, link });

// A CVE shared across images, so the CVE page has something to show.
const OPENSSL = f("CVE-2024-6119", "openssl", "3.0.13-1", "3.0.15-1", "HIGH", 7.5, "openssl: possible denial of service in X.509 name checks");
const ZLIB = f("CVE-2023-45853", "zlib1g", "1:1.2.13", null, "CRITICAL", 9.8, "zlib: integer overflow in zipOpenNewFileInZip4_6");
const CURL = f("CVE-2024-7264", "curl", "8.5.0-2", "8.9.1-1", "MEDIUM", 6.5, "curl: ASN.1 date parser overread");
const GLIBC = f("CVE-2024-33599", "libc6", "2.36-9", "2.36-9+deb12u7", "HIGH", 7.6, "glibc: stack-based buffer overflow in netgroup cache");

async function digest(db: DB, imageId: number, source: DigestSource, name: string, findings: Finding[], minutes: number) {
  const { digestId } = await storeDigest(
    db,
    imageId,
    source,
    {
      digest: sha(name),
      osFamily: "debian",
      osName: "12.8",
      scannedAt: ago(minutes),
      reportUpdatedAt: source === "operator" ? ago(minutes) : null,
      scannerVersion: "0.76.1",
      findings,
    },
    SEVERITIES,
  );
  return digestId;
}

async function workload(
  db: DB,
  w: { ns: string; kind: string; name: string; container?: string; imageId: number; tag: string | null; digestId: number | null; gone?: boolean },
) {
  await db
    .insertInto("workloads")
    .values({
      namespace: w.ns,
      kind: w.kind,
      name: w.name,
      container: w.container ?? w.name,
      image_id: w.imageId,
      tag: w.tag,
      digest_id: w.digestId,
      last_seen_at: w.gone ? ago(60 * 40) : ago(4),
      gone_at: w.gone ? ago(60 * 16) : null,
    })
    .execute();
}

async function tag(db: DB, imageId: number, name: string, digestSeed: string | null, isCandidate: boolean, reason: string) {
  await db
    .insertInto("tags")
    .values({
      image_id: imageId,
      tag: name,
      digest: digestSeed ? sha(digestSeed) : null,
      first_seen_at: ago(60 * 24 * 3),
      is_candidate: isCandidate ? 1 : 0,
      reason,
    })
    .execute();
}

async function scan(
  db: DB,
  s: { imageId: number; tag: string; digestSeed: string; status: ScanStatus; resultDigestId?: number; error?: string; job?: string },
) {
  const finished = s.status === "done" || s.status === "failed";
  await db
    .insertInto("scans")
    .values({
      image_id: s.imageId,
      tag: s.tag,
      digest: sha(s.digestSeed),
      status: s.status,
      requested_by: "ben",
      requested_at: ago(90),
      started_at: s.status === "queued" ? null : ago(85),
      finished_at: finished ? ago(80) : null,
      job_name: s.job ?? null,
      error: s.error ?? null,
      result_digest_id: s.resultDigestId ?? null,
    })
    .execute();
}

async function syncRun(db: DB, name: SyncName, minutes: number, ok: 0 | 1, detail: object | null, error: string | null = null) {
  await db
    .insertInto("sync_runs")
    .values({
      name,
      started_at: ago(minutes),
      finished_at: ago(minutes - 0.5),
      ok,
      error,
      detail: detail ? JSON.stringify(detail) : null,
    })
    .execute();
}

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is not set (put it in .env.local or the environment)");
  const db = await createDb(url);
  await migrate(db);

  const existing = await db.selectFrom("images").select("id").limit(1).executeTakeFirst();
  if (existing && !process.argv.includes("--reset")) {
    throw new Error("the database already has images; pass --reset to delete all rows first (npm run seed -- --reset)");
  }
  for (const t of ["scans", "tags", "workloads", "vulnerabilities", "image_digests", "images", "sync_runs", "kv"] as const) {
    await db.deleteFrom(t).execute();
  }

  // sonarr: a candidate with a done scan (fixed, still present with a fix upstream, one new), plus a gone workload.
  const sonarr = await upsertImage(db, "lscr.io", "linuxserver/sonarr");
  const sonarrRun = await digest(db, sonarr, "operator", "sonarr-290", [
    ZLIB,
    OPENSSL,
    CURL,
    GLIBC,
    f("CVE-2024-45490", "libexpat1", "2.5.0-1", "2.5.0-1+deb12u1", "CRITICAL", 9.8, "libexpat: negative length for XML_ParseBuffer"),
    f("GHSA-hq86-3gqw-5gvh", "Newtonsoft.Json", "13.0.1", "13.0.3", "HIGH", 7.5, "Improper handling of exceptional conditions in Newtonsoft.Json", null),
    f("CVE-2024-2961", "libc6", "2.36-9", "2.36-9+deb12u7", "HIGH", 8.8, "glibc: out of bounds write in iconv"),
    f("CVE-2023-50495", "libtinfo6", "6.4-4", null, "MEDIUM", 6.5, "ncurses: segmentation fault in _nc_wrap_entry"),
  ], 30);
  const sonarrCand = await digest(db, sonarr, "candidate", "sonarr-291", [
    ZLIB,
    { ...OPENSSL, installedVersion: "3.0.14-1" },
    f("CVE-2023-50495", "libtinfo6", "6.4-4", null, "MEDIUM", 6.5, "ncurses: segmentation fault in _nc_wrap_entry"),
    f("CVE-2025-1234", "libxml2", "2.9.14", "2.9.14+deb12u1", "HIGH", 7.8, "libxml2: heap use after free in xmlSchemaIDCFillNodeTables"),
  ], 80);
  await workload(db, { ns: "media", kind: "Deployment", name: "sonarr", imageId: sonarr, tag: "4.0.15.2941-ls290", digestId: sonarrRun });
  await workload(db, { ns: "media", kind: "Deployment", name: "sonarr-4k", imageId: sonarr, tag: "4.0.15.2941-ls290", digestId: sonarrRun });
  await workload(db, { ns: "media-old", kind: "Deployment", name: "sonarr-legacy", imageId: sonarr, tag: "3.0.10.1567-ls180", digestId: sonarrRun, gone: true });
  await tag(db, sonarr, "4.0.16.2944-ls291", "sonarr-291", true, "same shape N.N.N.N-lsN, newer than running");
  await tag(db, sonarr, "4.0.15.2943-ls291", "sonarr-291b", true, "same shape N.N.N.N-lsN, newer than running");
  await tag(db, sonarr, "develop-4.1.0.3000-ls12", "sonarr-dev", false, "different shape: not comparable with N.N.N.N-lsN");
  await scan(db, { imageId: sonarr, tag: "4.0.16.2944-ls291", digestSeed: "sonarr-291", status: "done", resultDigestId: sonarrCand, job: "tagamend-scan-sonarr-1" });

  // nginx: two digests running (the union case), candidate queued.
  const nginx = await upsertImage(db, "index.docker.io", "library/nginx");
  const nginxA = await digest(db, nginx, "operator", "nginx-a", [
    OPENSSL,
    CURL,
    f("CVE-2024-24990", "nginx", "1.27.3", "1.27.4", "HIGH", 7.5, "nginx: HTTP/3 worker crash"),
  ], 20);
  const nginxB = await digest(db, nginx, "operator", "nginx-b", [
    // Same CVE and package as digest A, but worse here: counts once, as critical.
    { ...f("CVE-2024-24990", "nginx", "1.27.2", "1.27.4", "CRITICAL", 9.1, "nginx: HTTP/3 worker crash") },
    OPENSSL,
    f("CVE-2024-3596", "libpam0g", "1.5.2-6", "1.5.2-6+deb12u2", "MEDIUM", 5.5, "RADIUS protocol forgery"),
  ], 22);
  await workload(db, { ns: "ingress", kind: "Deployment", name: "edge-proxy", container: "nginx", imageId: nginx, tag: "1.27.3-alpine", digestId: nginxA });
  await workload(db, { ns: "web", kind: "Deployment", name: "docs", container: "nginx", imageId: nginx, tag: "1.27.2-alpine", digestId: nginxB });
  await workload(db, { ns: "web", kind: "Deployment", name: "landing", container: "nginx", imageId: nginx, tag: "1.27.2-alpine", digestId: nginxB });
  await tag(db, nginx, "1.29.0-alpine", "nginx-129", true, "same shape N.N.N-alpine, newer than running");
  await tag(db, nginx, "1.29.0-bookworm", "nginx-129-b", false, "different shape: variant change is a decision, not an update");
  await scan(db, { imageId: nginx, tag: "1.29.0-alpine", digestSeed: "nginx-129", status: "queued" });
  // A done scan on an image with two running digests, for the union / single-digest diff.
  await tag(db, nginx, "1.28.1-alpine", "nginx-128", true, "newest of minor 1.28");
  const nginxCand = await digest(db, nginx, "candidate", "nginx-128", [OPENSSL], 95);
  await scan(db, { imageId: nginx, tag: "1.28.1-alpine", digestSeed: "nginx-128", status: "done", resultDigestId: nginxCand, job: "tagamend-scan-nginx-3" });

  // home-assistant: failed scan, Scan button becomes Retry.
  const ha = await upsertImage(db, "ghcr.io", "home-assistant/home-assistant");
  const haRun = await digest(db, ha, "operator", "ha-1", [
    OPENSSL,
    GLIBC,
    f("GHSA-74m5-2c7w-9w3x", "aiohttp", "3.9.1", "3.9.4", "HIGH", 7.5, "aiohttp: directory traversal in static routes", null),
    f("CVE-2024-27306", "aiohttp", "3.9.1", "3.9.4", "MEDIUM", 6.1, "aiohttp: XSS on index pages"),
  ], 45);
  await workload(db, { ns: "home", kind: "StatefulSet", name: "home-assistant", imageId: ha, tag: "2026.9.1", digestId: haRun });
  await tag(db, ha, "2026.10.2", "ha-2", true, "same shape N.N.N, newer than running");
  await tag(db, ha, "2026.11.0", "ha-3", true, "newest of major 2026");
  await scan(db, {
    imageId: ha,
    tag: "2026.11.0",
    digestSeed: "ha-3",
    status: "failed",
    error: "scan job tagamend-scan-ha-7 failed: TOOMANYREQUESTS: rate limit exceeded pulling ghcr.io/home-assistant/home-assistant",
    job: "tagamend-scan-ha-7",
  });

  // node-exporter: tag sync error, no candidates.
  const nodeExporter = await upsertImage(db, "quay.io", "prometheus/node-exporter");
  const nodeRun = await digest(db, nodeExporter, "operator", "node-1", [
    f("CVE-2024-24790", "stdlib", "1.21.4", "1.21.11", "CRITICAL", 9.8, "golang: net/netip: unexpected behavior from Is methods for IPv4-mapped IPv6 addresses"),
    CURL,
  ], 60);
  await workload(db, { ns: "monitoring", kind: "DaemonSet", name: "node-exporter", imageId: nodeExporter, tag: "v1.9.0", digestId: nodeRun });
  await db
    .updateTable("images")
    .set({ tag_sync_error: "list tags: 401 Unauthorized from quay.io (token request denied for repository:prometheus/node-exporter:pull)", last_tag_sync_at: ago(180) })
    .where("id", "=", nodeExporter)
    .execute();

  // inventory: pinned by digest, no tag.
  const inventory = await upsertImage(db, "ghcr.io", "example/inventory");
  const inventoryRun = await digest(db, inventory, "operator", "inventory-1", [
    f("CVE-2024-34156", "stdlib", "1.22.5", "1.22.7", "HIGH", 7.5, "golang: encoding/gob: stack exhaustion in Decoder.Decode"),
    CURL,
  ], 50);
  await workload(db, { ns: "home", kind: "Deployment", name: "inventory", imageId: inventory, tag: null, digestId: inventoryRun });

  // valkey: running :latest and the registry's digest has moved.
  const valkey = await upsertImage(db, "index.docker.io", "valkey/valkey");
  const valkeyRun = await digest(db, valkey, "operator", "valkey-old", [
    f("CVE-2024-46981", "valkey", "8.0.1", "8.0.2", "HIGH", 7.0, "valkey: Lua script use-after-free"),
    OPENSSL,
  ], 70);
  await workload(db, { ns: "iam", kind: "StatefulSet", name: "valkey", imageId: valkey, tag: "latest", digestId: valkeyRun });
  await tag(db, valkey, "latest", "valkey-new", true, "latest: the registry's digest differs from the one running");

  // ingress-nginx: clean image, a running scan.
  const ingress = await upsertImage(db, "registry.k8s.io", "ingress-nginx/controller");
  const ingressRun = await digest(db, ingress, "operator", "ingress-1", [], 35);
  await workload(db, { ns: "ingress", kind: "Deployment", name: "ingress-nginx-controller", container: "controller", imageId: ingress, tag: "v1.12.0", digestId: ingressRun });
  await tag(db, ingress, "v1.14.1", "ingress-114", true, "same shape vN.N.N, newer than running");
  await scan(db, { imageId: ingress, tag: "v1.14.1", digestSeed: "ingress-114", status: "running", job: "tagamend-scan-ingress-9" });

  // A workload with no vulnerability report yet.
  const app = await upsertImage(db, "ghcr.io", "example/webapp");
  await workload(db, { ns: "apps", kind: "Deployment", name: "webapp", imageId: app, tag: "main-212-ab12cd3", digestId: null });

  // readarr: only gone workloads, so it must not appear on the Overview.
  const readarr = await upsertImage(db, "lscr.io", "linuxserver/readarr");
  const readarrRun = await digest(db, readarr, "operator", "readarr-1", [OPENSSL], 60 * 24);
  await workload(db, { ns: "media", kind: "Deployment", name: "readarr", imageId: readarr, tag: "0.4.0-ls10", digestId: readarrRun, gone: true });

  await db.updateTable("images").set({ last_tag_sync_at: ago(47) }).where("tag_sync_error", "is", null).execute();

  for (let i = 8; i >= 0; i--) {
    await syncRun(db, "report_sync", 5 * i + 3, i === 4 ? 0 : 1, i === 4 ? null : { reports: 612, changed: 8 - i, skipped: 3 }, i === 4 ? "list VulnerabilityReports: context deadline exceeded" : null);
  }
  await syncRun(db, "tag_sync", 12, 1, { images: 4, registryCalls: 9 });
  await syncRun(db, "tag_sync", 3, 0, null, "1 of 3 images failed: quay.io 401 Unauthorized");
  await syncRun(db, "scan_queue", 1, 1, { started: 1, finished: 0 });

  await setKv(db, KV.trivyReportVersion, "0.76.1");
  await setKv(db, KV.trivyServerVersion, "0.76.2");

  const n = await db.selectFrom("vulnerabilities").select((eb) => eb.fn.countAll<number>().as("n")).executeTakeFirstOrThrow();
  console.log(`seeded: ${Number(n.n)} vulnerability rows`);
  await db.destroy();
}

await main();
