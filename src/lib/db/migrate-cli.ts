import { getDb, migrate } from "./index";

const db = await getDb();
await migrate(db);
await db.destroy();
