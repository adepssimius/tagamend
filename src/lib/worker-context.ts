import type { Config } from "./config";
import type { DB } from "./db";
import type { Log } from "./log";

/** What each background loop receives from the worker. */
export interface WorkerContext {
  db: DB;
  config: Config;
  log: Log;
  /** Aborted on SIGTERM; long operations should stop at the next safe point. */
  signal: AbortSignal;
}
