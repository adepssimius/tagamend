import type { Kysely } from "kysely";
import { idColumn } from "../dialect";

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable("charts").addColumn("image_keys", "text").execute();
  await db.schema
    .createTable("chart_image_prs")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("chart_id", "integer", (c) => c.notNull().references("charts.id").onDelete("cascade"))
    .addColumn("targets", "text", (c) => c.notNull())
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
  await db.schema.createIndex("chart_image_prs_status_idx").on("chart_image_prs").column("status").execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.dropTable("chart_image_prs").ifExists().execute();
  await db.schema.alterTable("charts").dropColumn("image_keys").execute();
}
