import type { DB } from "./db";
import { getKv, setKv } from "./db/store";

export type Reach = "internet" | "lan";

/**
 * Settings changed from the Settings page, stored in `kv` so the web and the
 * worker read the same values. Nothing here is specific to one cluster: the
 * defaults assume nothing about its network.
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
  /**
   * Ingress host patterns only the local network can reach, such as
   * `*.internal.example.com`. `*` matches one or more DNS labels. Hosts that
   * match none count as reachable from the internet.
   */
  internalHostPatterns: string[];
  /** Who can reach a LoadBalancer or NodePort service. */
  loadBalancerReach: Reach;
  /**
   * Where OIDC clients are configured, as "namespace/configmap/key". Hosts in
   * its `redirect_uris` are marked as logging in through OIDC. Empty: off.
   */
  oidcClientsSource: string;
}

const DEFAULTS: Settings = {
  autoScanBestCandidate: false,
  autoScanRunningBuild: false,
  fluxManagedOnly: true,
  internalHostPatterns: [],
  loadBalancerReach: "lan",
  oidcClientsSource: "",
};

const KEYS: Record<keyof Settings, string> = {
  autoScanBestCandidate: "setting.auto_scan_best_candidate",
  autoScanRunningBuild: "setting.auto_scan_running_build",
  fluxManagedOnly: "setting.flux_managed_only",
  internalHostPatterns: "setting.internal_host_patterns",
  loadBalancerReach: "setting.load_balancer_reach",
  oidcClientsSource: "setting.oidc_clients_source",
};

function decode<K extends keyof Settings>(k: K, v: string | undefined): Settings[K] {
  if (v === undefined) return DEFAULTS[k];
  const d = DEFAULTS[k];
  if (typeof d === "boolean") return (v === "1") as Settings[K];
  if (Array.isArray(d)) return v.split("\n").map((s) => s.trim()).filter(Boolean) as Settings[K];
  if (k === "loadBalancerReach") return (v === "internet" ? "internet" : "lan") as Settings[K];
  return v as Settings[K];
}

function encode(v: Settings[keyof Settings]): string {
  if (typeof v === "boolean") return v ? "1" : "0";
  if (Array.isArray(v)) return v.join("\n");
  return v;
}

export async function getSettings(db: DB): Promise<Settings> {
  const out = {} as Record<keyof Settings, unknown>;
  for (const k of Object.keys(KEYS) as (keyof Settings)[]) out[k] = decode(k, await getKv(db, KEYS[k]));
  return out as Settings;
}

/** Saves the fields given; others keep their stored value. */
export async function setSettings(db: DB, s: Partial<Settings>): Promise<void> {
  for (const k of Object.keys(s) as (keyof Settings)[]) {
    const v = s[k];
    if (v !== undefined) await setKv(db, KEYS[k], encode(v));
  }
}
