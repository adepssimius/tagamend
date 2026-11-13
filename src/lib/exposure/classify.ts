import type { Reach } from "../settings";

/** How a workload can be reached. Each workload has zero or more routes. */
export interface Route {
  via: "ingress" | "loadbalancer" | "nodeport";
  /** Ingress host (and path), or LoadBalancer address:port. */
  address: string;
  /** The object that exposes it: "Ingress ns/name" or "Service ns/name". */
  object: string;
  reach: "internet" | "lan" | "tailnet";
  /**
   * forward-auth: the proxy asks an auth service before passing the request
   * (an auth-url annotation). oidc: the app logs users in through an OIDC
   * provider. app: neither is visible, so the app's own login, if any.
   */
  auth: "forward-auth" | "oidc" | "app";
  /** forward-auth: the auth service's host. */
  authBy?: string;
}

/** Worst first: what a workload's summary shows. */
export const EXPOSURE_ORDER = ["internet-app", "internet-oidc", "internet-forward-auth", "tailnet", "lan", "none"] as const;
export type Exposure = (typeof EXPOSURE_ORDER)[number];

export function exposureOf(routes: Route[]): Exposure {
  let worst: Exposure = "none";
  for (const r of routes) {
    const e: Exposure = r.reach === "internet" ? (`internet-${r.auth}` as Exposure) : r.reach;
    if (EXPOSURE_ORDER.indexOf(e) < EXPOSURE_ORDER.indexOf(worst)) worst = e;
  }
  return worst;
}

/** `*` matches one or more DNS labels; matching ignores case. */
export function hostMatches(host: string, pattern: string): boolean {
  const re = new RegExp(
    `^${pattern
      .trim()
      .toLowerCase()
      .split("*")
      .map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join("[a-z0-9.-]+")}$`,
  );
  return re.test(host.toLowerCase());
}

export function hostReach(host: string, internalPatterns: string[]): Reach {
  return internalPatterns.some((p) => hostMatches(host, p)) ? "lan" : "internet";
}

/**
 * The hosts of every redirect URI in an OIDC provider's config text: the
 * entries of each `redirect_uris:` list (YAML block or flow style). Generic
 * enough for Authelia, Dex and similar configs.
 */
export function oidcRedirectHosts(config: string): Set<string> {
  const hosts = new Set<string>();
  const lines = config.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)-?\s*redirect_uris\s*:\s*(.*)$/.exec(lines[i]!);
    if (!m) continue;
    const indent = m[1]!.length;
    const inline = m[2]!.trim();
    const take = (s: string) => {
      for (const u of s.match(/https?:\/\/[^\s'",\]]+/g) ?? []) {
        try {
          hosts.add(new URL(u).hostname.toLowerCase());
        } catch {
          /* not a URL */
        }
      }
    };
    if (inline) {
      take(inline);
      continue;
    }
    for (let j = i + 1; j < lines.length; j++) {
      const l = lines[j]!;
      if (!l.trim()) continue;
      const ind = l.length - l.trimStart().length;
      if (ind < indent || (ind === indent && !l.trimStart().startsWith("-"))) break;
      if (!l.trimStart().startsWith("-")) break;
      take(l);
    }
  }
  return hosts;
}
