import type { DB } from "./db";
import { getKv, setKv } from "./db/store";

/**
 * Settings changed from the Settings page, stored in `kv` so the web and the
 * worker read the same values. Everything defaults to off.
 */
export interface Settings {
  /** Queue a scan of each image's best candidate as soon as tag discovery finds it. */
  autoScanBestCandidate: boolean;
  /** Queue a scan of the build a pod runs when it is older than its tag. */
  autoScanRunningBuild: boolean;
}

const KEYS: Record<keyof Settings, string> = {
  autoScanBestCandidate: "setting.auto_scan_best_candidate",
  autoScanRunningBuild: "setting.auto_scan_running_build",
};

export async function getSettings(db: DB): Promise<Settings> {
  const out = {} as Settings;
  for (const [k, key] of Object.entries(KEYS) as [keyof Settings, string][]) out[k] = (await getKv(db, key)) === "1";
  return out;
}

export async function setSettings(db: DB, s: Settings): Promise<void> {
  for (const [k, key] of Object.entries(KEYS) as [keyof Settings, string][]) await setKv(db, key, s[k] ? "1" : "0");
}
