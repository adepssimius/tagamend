import type { Kysely } from "kysely";
import { idColumn } from "../dialect";

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema
    .createTable("pull_requests")
    .addColumn("id", idColumn(db), (c) => c.primaryKey())
    .addColumn("image_id", "integer", (c) => c.notNull().references("images.id").onDelete("cascade"))
    .addColumn("scan_id", "integer", (c) => c.notNull().references("scans.id").onDelete("cascade"))
    .addColumn("to_tag", "text", (c) => c.notNull())
    .addColumn("to_digest", "text", (c) => c.notNull())
    .addColumn("status", "text", (c) => c.notNull())
    .addColumn("requested_by", "text")
    .addColumn("requested_at", "text", (c) => c.notNull())
    .addColumn("started_at", "text")
    .addColumn("finished_at", "text")
    .addColumn("branch", "text")
    .addColumn("pr_number", "integer")
    .addColumn("pr_url", "text")
    .addColumn("edits", "text")
    .addColumn("skipped", "text")
    .addColumn("error", "text")
    .execute();
  await db.schema.createIndex("pull_requests_status_idx").on("pull_requests").column("status").execute();
  await db.schema.createIndex("pull_requests_image_idx").on("pull_requests").column("image_id").execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.dropTable("pull_requests").ifExists().execute();
}
