import type { DB } from "./db";
import { getKv, setKv } from "./db/store";

/**
 * Settings changed from the Settings page, stored in `kv` so the web and the
 * worker read the same values. Everything defaults to off except fluxManagedOnly.
 */
export interface Settings {
  /** Queue a scan of each image's best candidate as soon as tag discovery finds it. */
  autoScanBestCandidate: boolean;
  /** Queue a scan of the build a pod runs when it is older than its tag. */
  autoScanRunningBuild: boolean;
  /**
   * Show and act on only workloads Flux manages (on by default). Workloads
   * whose manager is unknown stay in scope; only ones known not to be Flux's
   * are left out.
   */
  fluxManagedOnly: boolean;
}

/** Settings that are on when never saved. */
const DEFAULT_ON: (keyof Settings)[] = ["fluxManagedOnly"];

const KEYS: Record<keyof Settings, string> = {
  autoScanBestCandidate: "setting.auto_scan_best_candidate",
  autoScanRunningBuild: "setting.auto_scan_running_build",
  fluxManagedOnly: "setting.flux_managed_only",
};

export async function getSettings(db: DB): Promise<Settings> {
  const out = {} as Settings;
  for (const [k, key] of Object.entries(KEYS) as [keyof Settings, string][]) {
    const v = await getKv(db, key);
    out[k] = v === undefined ? DEFAULT_ON.includes(k) : v === "1";
  }
  return out;
}

export async function setSettings(db: DB, s: Settings): Promise<void> {
  for (const [k, key] of Object.entries(KEYS) as [keyof Settings, string][]) await setKv(db, key, s[k] ? "1" : "0");
}
