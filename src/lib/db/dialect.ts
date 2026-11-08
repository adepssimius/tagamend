import { type Kysely, PostgresAdapter, sql } from "kysely";

export function isPostgres(db: Kysely<any>): boolean {
  return db.getExecutor().adapter instanceof PostgresAdapter;
}

/** An auto-incrementing integer primary key column type for either dialect. */
export function idColumn(db: Kysely<any>) {
  // SQLite: INTEGER PRIMARY KEY is the rowid alias and auto-assigns.
  return isPostgres(db) ? sql`serial` : sql`integer`;
}
