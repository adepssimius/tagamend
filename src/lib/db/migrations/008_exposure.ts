import type { Kysely } from "kysely";

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable("workloads").addColumn("exposure", "text").execute();
  await db.schema.alterTable("workloads").addColumn("exposure_summary", "text").execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable("workloads").dropColumn("exposure_summary").execute();
  await db.schema.alterTable("workloads").dropColumn("exposure").execute();
}
