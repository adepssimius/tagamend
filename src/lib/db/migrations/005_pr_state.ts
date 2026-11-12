import type { Kysely } from "kysely";

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable("pull_requests").addColumn("pr_state", "text").execute();
  await db.schema.alterTable("pull_requests").addColumn("pr_state_checked_at", "text").execute();
  // Every PR opened so far was open when it was opened.
  await db.updateTable("pull_requests").set({ pr_state: "open" }).where("status", "=", "opened").execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable("pull_requests").dropColumn("pr_state_checked_at").execute();
  await db.schema.alterTable("pull_requests").dropColumn("pr_state").execute();
}
