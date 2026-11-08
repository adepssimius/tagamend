import { sql } from "kysely";
import { getDb } from "@/lib/db";

export const dynamic = "force-dynamic";

/** Liveness and readiness: the process is up and the database answers. */
export async function GET() {
  try {
    const db = await getDb();
    await sql`select 1`.execute(db);
    return Response.json({ ok: true });
  } catch (e) {
    return Response.json({ ok: false, error: e instanceof Error ? e.message : String(e) }, { status: 503 });
  }
}
