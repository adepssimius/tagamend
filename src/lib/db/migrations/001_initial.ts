import { type Kysely, sql } from "kysely";
import { idColumn } from "../dialect";

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema
    .createTable("images")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("registry", "text", (c) => c.notNull())
    .addColumn("repository", "text", (c) => c.notNull())
    .addColumn("last_tag_sync_at", "text")
    .addColumn("tag_sync_error", "text")
    .addUniqueConstraint("images_registry_repository_uq", ["registry", "repository"])
    .execute();

  await db.schema
    .createTable("image_digests")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("image_id", "integer", (c) => c.notNull().references("images.id").onDelete("cascade"))
    .addColumn("digest", "text", (c) => c.notNull())
    .addColumn("os_family", "text")
    .addColumn("os_name", "text")
    .addColumn("scanned_at", "text", (c) => c.notNull())
    .addColumn("report_updated_at", "text")
    .addColumn("scanner_version", "text")
    .addColumn("source", "text", (c) => c.notNull())
    .addColumn("critical", "integer", (c) => c.notNull().defaultTo(0))
    .addColumn("high", "integer", (c) => c.notNull().defaultTo(0))
    .addColumn("medium", "integer", (c) => c.notNull().defaultTo(0))
    .addColumn("low", "integer", (c) => c.notNull().defaultTo(0))
    .addColumn("unknown", "integer", (c) => c.notNull().defaultTo(0))
    .addUniqueConstraint("image_digests_image_digest_uq", ["image_id", "digest"])
    .execute();

  await db.schema
    .createTable("vulnerabilities")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("digest_id", "integer", (c) => c.notNull().references("image_digests.id").onDelete("cascade"))
    .addColumn("vuln_id", "text", (c) => c.notNull())
    .addColumn("package", "text", (c) => c.notNull())
    .addColumn("installed_version", "text", (c) => c.notNull())
    .addColumn("fixed_version", "text")
    .addColumn("severity", "text", (c) => c.notNull())
    .addColumn("score", "real")
    .addColumn("title", "text")
    .addColumn("link", "text")
    .addUniqueConstraint("vulnerabilities_uq", ["digest_id", "vuln_id", "package", "installed_version"])
    .execute();
  await db.schema.createIndex("vulnerabilities_vuln_id_idx").on("vulnerabilities").column("vuln_id").execute();

  await db.schema
    .createTable("workloads")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("namespace", "text", (c) => c.notNull())
    .addColumn("kind", "text", (c) => c.notNull())
    .addColumn("name", "text", (c) => c.notNull())
    .addColumn("container", "text", (c) => c.notNull())
    .addColumn("image_id", "integer", (c) => c.notNull().references("images.id").onDelete("cascade"))
    .addColumn("tag", "text")
    .addColumn("digest_id", "integer", (c) => c.references("image_digests.id").onDelete("set null"))
    .addColumn("last_seen_at", "text", (c) => c.notNull())
    .addColumn("gone_at", "text")
    .addUniqueConstraint("workloads_uq", ["namespace", "kind", "name", "container"])
    .execute();
  await db.schema.createIndex("workloads_image_id_idx").on("workloads").column("image_id").execute();

  await db.schema
    .createTable("tags")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("image_id", "integer", (c) => c.notNull().references("images.id").onDelete("cascade"))
    .addColumn("tag", "text", (c) => c.notNull())
    .addColumn("digest", "text")
    .addColumn("first_seen_at", "text", (c) => c.notNull())
    .addColumn("is_candidate", "integer", (c) => c.notNull().defaultTo(0))
    .addColumn("reason", "text")
    .addUniqueConstraint("tags_uq", ["image_id", "tag"])
    .execute();

  await db.schema
    .createTable("scans")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("image_id", "integer", (c) => c.notNull().references("images.id").onDelete("cascade"))
    .addColumn("tag", "text", (c) => c.notNull())
    .addColumn("digest", "text", (c) => c.notNull())
    .addColumn("status", "text", (c) => c.notNull())
    .addColumn("requested_by", "text")
    .addColumn("requested_at", "text", (c) => c.notNull())
    .addColumn("started_at", "text")
    .addColumn("finished_at", "text")
    .addColumn("job_name", "text")
    .addColumn("error", "text")
    .addColumn("result_digest_id", "integer", (c) => c.references("image_digests.id").onDelete("set null"))
    .execute();
  await db.schema.createIndex("scans_status_idx").on("scans").column("status").execute();

  await db.schema
    .createTable("sync_runs")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("name", "text", (c) => c.notNull())
    .addColumn("started_at", "text", (c) => c.notNull())
    .addColumn("finished_at", "text")
    .addColumn("ok", "integer")
    .addColumn("error", "text")
    .addColumn("detail", "text")
    .execute();
  await db.schema.createIndex("sync_runs_name_started_idx").on("sync_runs").columns(["name", "started_at"]).execute();

  await db.schema
    .createTable("kv")
    .addColumn("key", "text", (c) => c.primaryKey())
    .addColumn("value", "text", (c) => c.notNull())
    .addColumn("updated_at", "text", (c) => c.notNull())
    .execute();

  void sql; // keep the import available to later migrations that copy this file
}

export async function down(db: Kysely<any>): Promise<void> {
  for (const t of ["kv", "sync_runs", "scans", "tags", "workloads", "vulnerabilities", "image_digests", "images"]) {
    await db.schema.dropTable(t).ifExists().execute();
  }
}
