import { errorMessage } from "../log";
import { OwnerResolver, type ReportSource } from "../k8s/owners";
import { getSettings } from "../settings";
import type { WorkerContext } from "../worker-context";
import { exposureOf, hostReach, oidcRedirectHosts, type Route } from "./classify";

type Labels = Record<string, string>;

export interface NetPod {
  namespace: string;
  name: string;
  labels: Labels;
  /** The pod's controller (ReplicaSet, StatefulSet, ...), or null for a bare pod. */
  controller: { kind: string; name: string } | null;
}
export interface NetService {
  namespace: string;
  name: string;
  type: string;
  selector: Labels | null;
  loadBalancerClass: string | null;
  annotations: Labels;
  addresses: string[];
  ports: { port: number; nodePort?: number }[];
}
export interface NetIngress {
  namespace: string;
  name: string;
  className: string | null;
  annotations: Labels;
  rules: { host: string | null; paths: { path: string | null; service: string | null }[] }[];
  defaultService: string | null;
}

/** The Kubernetes reads the exposure sync needs. Tests pass a fake. */
export interface ExposureSource {
  owners: Pick<ReportSource, "getObject">;
  listPods(): Promise<NetPod[]>;
  listServices(): Promise<NetService[]>;
  listIngresses(): Promise<NetIngress[]>;
  /** IngressClass name to controller, and the default class name if any. */
  listIngressClasses(): Promise<{ controllers: Map<string, string>; defaultClass: string | null }>;
  /** A ConfigMap key's text, or null. */
  readConfigMap(namespace: string, name: string, key: string): Promise<string | null>;
}

const matches = (selector: Labels, labels: Labels) =>
  Object.entries(selector).every(([k, v]) => labels[k] === v);

/**
 * Works out how each workload can be reached and records it on its rows:
 * Ingresses that route to a Service selecting its pods, and LoadBalancer or
 * NodePort Services. Reach and auth follow the Settings page (internal host
 * patterns, LoadBalancer reach, OIDC client source), so nothing here assumes
 * a particular cluster.
 */
export async function syncExposure(ctx: WorkerContext, opts: { source?: ExposureSource } = {}): Promise<Record<string, unknown>> {
  const { db, log } = ctx;
  const source = opts.source ?? (await import("./source")).k8sExposureSource();
  const settings = await getSettings(db);

  const [pods, services, ingresses, classes] = await Promise.all([
    source.listPods(),
    source.listServices(),
    source.listIngresses(),
    source.listIngressClasses(),
  ]);

  let oidcHosts = new Set<string>();
  let oidcError: string | undefined;
  const [ns, cm, key] = settings.oidcClientsSource.split("/");
  if (ns && cm && key) {
    try {
      oidcHosts = oidcRedirectHosts((await source.readConfigMap(ns, cm, key)) ?? "");
    } catch (e) {
      oidcError = errorMessage(e);
      log.warn("exposure sync: could not read the OIDC client source", { source: settings.oidcClientsSource, error: oidcError });
    }
  }

  // Pods to the workload (top-level owner) that runs them.
  const resolver = new OwnerResolver(source.owners);
  const workloadOfPod = new Map<string, string>();
  for (const p of pods) {
    const r = p.controller
      ? await resolver.resolve(p.namespace, p.controller.kind, p.controller.name)
      : await resolver.resolve(p.namespace, "Pod", p.name);
    if (r.status === "ok") workloadOfPod.set(`${p.namespace}/${p.name}`, `${p.namespace}/${r.kind}/${r.name}`);
  }
  // Services to the workloads whose pods they select.
  const workloadsOfService = new Map<string, Set<string>>();
  for (const s of services) {
    if (!s.selector || Object.keys(s.selector).length === 0) continue;
    const set = new Set<string>();
    for (const p of pods) {
      if (p.namespace !== s.namespace || !matches(s.selector, p.labels)) continue;
      const w = workloadOfPod.get(`${p.namespace}/${p.name}`);
      if (w) set.add(w);
    }
    workloadsOfService.set(`${s.namespace}/${s.name}`, set);
  }

  const routes = new Map<string, Route[]>();
  const add = (service: string, route: Route) => {
    for (const w of workloadsOfService.get(service) ?? []) {
      const list = routes.get(w) ?? [];
      if (!list.some((r) => r.address === route.address && r.via === route.via)) list.push(route);
      routes.set(w, list);
    }
  };

  for (const s of services) {
    const tailnet = s.loadBalancerClass?.includes("tailscale") || s.annotations["tailscale.com/expose"] === "true";
    if (s.type === "LoadBalancer" || tailnet) {
      for (const port of s.ports) {
        for (const addr of s.addresses.length ? s.addresses : ["pending"]) {
          add(`${s.namespace}/${s.name}`, {
            via: "loadbalancer",
            address: `${addr}:${port.port}`,
            object: `Service ${s.namespace}/${s.name}`,
            reach: tailnet ? "tailnet" : settings.loadBalancerReach,
            auth: "app",
          });
        }
      }
    } else if (s.type === "NodePort") {
      for (const port of s.ports) {
        if (!port.nodePort) continue;
        add(`${s.namespace}/${s.name}`, {
          via: "nodeport",
          address: `node:${port.nodePort}`,
          object: `Service ${s.namespace}/${s.name}`,
          reach: settings.loadBalancerReach,
          auth: "app",
        });
      }
    }
  }

  for (const ing of ingresses) {
    const cls = ing.className ?? ing.annotations["kubernetes.io/ingress.class"] ?? classes.defaultClass;
    const tailnet = !!cls && (classes.controllers.get(cls) ?? "").includes("tailscale");
    const authUrl = Object.entries(ing.annotations).find(([k]) => k.endsWith("/auth-url"))?.[1];
    let authBy: string | undefined;
    if (authUrl) {
      try {
        authBy = new URL(authUrl).hostname;
      } catch {
        authBy = authUrl;
      }
    }
    const object = `Ingress ${ing.namespace}/${ing.name}`;
    const routeFor = (host: string | null, path: string | null): Route => {
      const h = (host ?? "*").toLowerCase();
      return {
        via: "ingress",
        address: `${h}${path && path !== "/" ? path : ""}`,
        object,
        reach: tailnet ? "tailnet" : host ? hostReach(h, settings.internalHostPatterns) : "internet",
        auth: authUrl ? "forward-auth" : oidcHosts.has(h) ? "oidc" : "app",
        ...(authBy ? { authBy } : {}),
      };
    };
    for (const rule of ing.rules) {
      for (const p of rule.paths) if (p.service) add(`${ing.namespace}/${p.service}`, routeFor(rule.host, p.path));
    }
    if (ing.defaultService) add(`${ing.namespace}/${ing.defaultService}`, routeFor(null, null));
  }

  // Write every live workload row: routes, or none.
  const live = await db.selectFrom("workloads").select(["id", "namespace", "kind", "name"]).where("gone_at", "is", null).execute();
  let exposed = 0;
  for (const w of live) {
    const r = routes.get(`${w.namespace}/${w.kind}/${w.name}`) ?? [];
    const summary = exposureOf(r);
    if (summary !== "none") exposed++;
    await db.updateTable("workloads").set({ exposure: JSON.stringify(r), exposure_summary: summary }).where("id", "=", w.id).execute();
  }
  return {
    workloads: live.length,
    exposed,
    ingresses: ingresses.length,
    oidcHosts: oidcHosts.size,
    ...(oidcError ? { oidcError } : {}),
  };
}
