import { sql } from "kysely";
import { createDb, migrate, type DB } from "@/lib/db";

/**
 * The database URLs the suite runs against. SQLite in memory always; Postgres
 * too when TEST_POSTGRES_URL is set (CI sets it). Each Postgres test gets a
 * fresh database so tests do not see each other's rows.
 */
export function testDatabases(): { name: string; url: string }[] {
  const out = [{ name: "sqlite", url: ":memory:" }];
  if (process.env.TEST_POSTGRES_URL) out.push({ name: "postgres", url: process.env.TEST_POSTGRES_URL });
  return out;
}

export async function freshDb(url: string): Promise<DB> {
  if (url === ":memory:") {
    const db = await createDb(url);
    await migrate(db);
    return db;
  }
  // A database per test, not a schema: Kysely's Migrator looks for its tables
  // across every schema, finds another test's, and then does not create its own.
  const name = `t_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const admin = await createDb(url);
  await sql`create database ${sql.id(name)}`.execute(admin);
  await admin.destroy();
  const u = new URL(url);
  u.pathname = `/${name}`;
  const db = await createDb(u.toString());
  await migrate(db);
  return db;
}
