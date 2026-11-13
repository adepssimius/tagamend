import type { Exposure, Route } from "@/lib/exposure/classify";

const LABEL: Record<Exposure, { text: string; cls: string; title: string }> = {
  "internet-app": {
    text: "Internet · app login",
    cls: "border-red-600 text-red-700 dark:border-red-500 dark:text-red-400",
    title: "Reachable from the internet with no auth in front of it: the app's own login, if it has one",
  },
  "internet-oidc": {
    text: "Internet · OIDC",
    cls: "border-amber-600 text-amber-700 dark:border-amber-500 dark:text-amber-300",
    title: "Reachable from the internet; the app logs users in through OIDC",
  },
  "internet-forward-auth": {
    text: "Internet · forward auth",
    cls: "border-sky-600 text-sky-700 dark:border-sky-500 dark:text-sky-300",
    title: "Reachable from the internet; the proxy checks an auth service before passing requests",
  },
  tailnet: { text: "Tailnet", cls: "border-zinc-400 text-zinc-600 dark:border-zinc-600 dark:text-zinc-300", title: "Reachable over Tailscale" },
  lan: { text: "LAN", cls: "border-zinc-400 text-zinc-600 dark:border-zinc-600 dark:text-zinc-300", title: "Reachable from the local network" },
  none: { text: "Not exposed", cls: "border-transparent text-zinc-400 dark:text-zinc-600", title: "No Ingress or LoadBalancer reaches it" },
};

/** A workload's or image's exposure: the worst of its routes. */
export function ExposureBadge({ exposure }: { exposure: Exposure | null }) {
  if (!exposure) return <span className="text-xs text-zinc-400">—</span>;
  const l = LABEL[exposure];
  return (
    <span title={l.title} className={`inline-block whitespace-nowrap rounded border px-1 text-[11px] leading-4 ${l.cls}`}>
      {l.text}
    </span>
  );
}

const AUTH: Record<Route["auth"], string> = { "forward-auth": "forward auth", oidc: "OIDC", app: "app login" };

export function routeAuth(r: Route): string {
  return r.auth === "forward-auth" && r.authBy ? `forward auth (${r.authBy})` : AUTH[r.auth];
}
