import type { Kysely } from "kysely";

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable("workloads").addColumn("report_digest", "text").execute();
  await db.schema.alterTable("workloads").addColumn("pod_digest", "text").execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable("workloads").dropColumn("pod_digest").execute();
  await db.schema.alterTable("workloads").dropColumn("report_digest").execute();
}
