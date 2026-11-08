import { Kysely, PostgresDialect, SqliteDialect } from "kysely";
import { Migrator, type MigrationProvider } from "kysely/migration";
import { getConfig } from "../config";
import { migrations } from "./migrations";
import type { Database } from "./schema";

export type DB = Kysely<Database>;

/** Builds a Kysely instance; the URL scheme picks the dialect. */
export async function createDb(url: string): Promise<DB> {
  if (url.startsWith("postgres://") || url.startsWith("postgresql://")) {
    const { default: pg } = await import("pg");
    return new Kysely<Database>({
      dialect: new PostgresDialect({ pool: new pg.Pool({ connectionString: url, max: 5 }) }),
    });
  }
  if (url.startsWith("file:") || url === ":memory:") {
    const { default: Sqlite } = await import("better-sqlite3");
    const file = url === ":memory:" ? ":memory:" : url.slice("file:".length);
    const sqlite = new Sqlite(file);
    sqlite.pragma("journal_mode = WAL");
    sqlite.pragma("foreign_keys = ON");
    sqlite.pragma("busy_timeout = 5000");
    return new Kysely<Database>({ dialect: new SqliteDialect({ database: sqlite }) });
  }
  throw new Error(`DATABASE_URL: unsupported scheme in "${url.replace(/:[^:@/]*@/, ":***@")}"`);
}

const provider: MigrationProvider = { getMigrations: async () => migrations };

export async function migrate(db: DB): Promise<void> {
  const migrator = new Migrator({ db, provider });
  const { error, results } = await migrator.migrateToLatest();
  for (const r of results ?? []) {
    if (r.status === "Error") console.error(`migration ${r.migrationName} failed`);
    else if (r.status === "Success") console.log(`migration ${r.migrationName} applied`);
  }
  if (error) throw error;
}

// One instance per process. `globalThis` keeps it across Next.js dev reloads.
const g = globalThis as unknown as { __tagamendDb?: Promise<DB> };

export function getDb(): Promise<DB> {
  g.__tagamendDb ??= createDb(getConfig().DATABASE_URL);
  return g.__tagamendDb;
}

export const now = () => new Date().toISOString();
