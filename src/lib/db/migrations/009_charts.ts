import type { Kysely } from "kysely";
import { idColumn } from "../dialect";

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema
    .createTable("charts")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("namespace", "text", (c) => c.notNull())
    .addColumn("name", "text", (c) => c.notNull())
    .addColumn("chart", "text", (c) => c.notNull())
    .addColumn("version", "text", (c) => c.notNull())
    .addColumn("installed_version", "text")
    .addColumn("source_kind", "text", (c) => c.notNull())
    .addColumn("source_url", "text", (c) => c.notNull())
    .addColumn("last_sync_at", "text")
    .addColumn("sync_error", "text")
    .addColumn("current_images", "text")
    .addColumn("render_note", "text")
    .addColumn("gone_at", "text")
    .addUniqueConstraint("charts_uq", ["namespace", "name"])
    .execute();

  await db.schema
    .createTable("chart_candidates")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("chart_id", "integer", (c) => c.notNull().references("charts.id").onDelete("cascade"))
    .addColumn("version", "text", (c) => c.notNull())
    .addColumn("app_version", "text")
    .addColumn("first_seen_at", "text", (c) => c.notNull())
    .addColumn("is_candidate", "integer", (c) => c.notNull().defaultTo(0))
    .addColumn("reason", "text")
    .addColumn("rendered_at", "text")
    .addColumn("render_error", "text")
    .addColumn("changes", "text")
    .addColumn("pinned", "text")
    .addUniqueConstraint("chart_candidates_uq", ["chart_id", "version"])
    .execute();

  await db.schema
    .createTable("chart_pull_requests")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("chart_id", "integer", (c) => c.notNull().references("charts.id").onDelete("cascade"))
    .addColumn("candidate_id", "integer", (c) => c.notNull().references("chart_candidates.id").onDelete("cascade"))
    .addColumn("to_version", "text", (c) => c.notNull())
    .addColumn("update_pins", "integer", (c) => c.notNull().defaultTo(0))
    .addColumn("status", "text", (c) => c.notNull())
    .addColumn("requested_by", "text")
    .addColumn("requested_at", "text", (c) => c.notNull())
    .addColumn("started_at", "text")
    .addColumn("finished_at", "text")
    .addColumn("branch", "text")
    .addColumn("pr_number", "integer")
    .addColumn("pr_url", "text")
    .addColumn("pr_state", "text")
    .addColumn("pr_state_checked_at", "text")
    .addColumn("edits", "text")
    .addColumn("error", "text")
    .execute();
  await db.schema.createIndex("chart_pull_requests_status_idx").on("chart_pull_requests").column("status").execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  for (const t of ["chart_pull_requests", "chart_candidates", "charts"]) await db.schema.dropTable(t).ifExists().execute();
}
