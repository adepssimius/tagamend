import type { Kysely } from "kysely";

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema
    .createTable("kev")
    .addColumn("cve_id", "text", (c) => c.primaryKey())
    .addColumn("vulnerability_name", "text")
    .addColumn("vendor_project", "text")
    .addColumn("product", "text")
    .addColumn("date_added", "text", (c) => c.notNull())
    .addColumn("due_date", "text")
    .addColumn("known_ransomware", "integer", (c) => c.notNull().defaultTo(0))
    .addColumn("short_description", "text")
    .execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.dropTable("kev").ifExists().execute();
}
