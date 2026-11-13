import * as k8s from "@kubernetes/client-node";
import { getK8s } from "../k8s/client";
import { k8sReportSource } from "../k8s/report-source";
import type { ExposureSource } from "./sync";

/** The real ExposureSource, using the shared Kubernetes client. */
export function k8sExposureSource(): ExposureSource {
  const { kc, core } = getK8s();
  const net = kc.makeApiClient(k8s.NetworkingV1Api);
  return {
    owners: k8sReportSource(),
    async listPods() {
      const out = [];
      let cont: string | undefined;
      do {
        const res = await core.listPodForAllNamespaces({ limit: 500, _continue: cont });
        for (const p of res.items) {
          if (p.status?.phase !== "Running") continue;
          const c = p.metadata?.ownerReferences?.find((o) => o.controller) ?? null;
          out.push({
            namespace: p.metadata?.namespace ?? "",
            name: p.metadata?.name ?? "",
            labels: p.metadata?.labels ?? {},
            controller: c ? { kind: c.kind, name: c.name } : null,
          });
        }
        cont = res.metadata?._continue || undefined;
      } while (cont);
      return out;
    },
    async listServices() {
      const res = await core.listServiceForAllNamespaces();
      return res.items.map((s) => ({
        namespace: s.metadata?.namespace ?? "",
        name: s.metadata?.name ?? "",
        type: s.spec?.type ?? "ClusterIP",
        selector: s.spec?.selector ?? null,
        loadBalancerClass: s.spec?.loadBalancerClass ?? null,
        annotations: s.metadata?.annotations ?? {},
        addresses: (s.status?.loadBalancer?.ingress ?? []).map((i) => i.ip ?? i.hostname ?? "").filter(Boolean),
        ports: (s.spec?.ports ?? []).map((p) => ({ port: p.port, nodePort: p.nodePort })),
      }));
    },
    async listIngresses() {
      const res = await net.listIngressForAllNamespaces();
      return res.items.map((i) => ({
        namespace: i.metadata?.namespace ?? "",
        name: i.metadata?.name ?? "",
        className: i.spec?.ingressClassName ?? null,
        annotations: i.metadata?.annotations ?? {},
        rules: (i.spec?.rules ?? []).map((r) => ({
          host: r.host ?? null,
          paths: (r.http?.paths ?? []).map((p) => ({ path: p.path ?? null, service: p.backend.service?.name ?? null })),
        })),
        defaultService: i.spec?.defaultBackend?.service?.name ?? null,
      }));
    },
    async listIngressClasses() {
      const res = await net.listIngressClass();
      const controllers = new Map<string, string>();
      let defaultClass: string | null = null;
      for (const c of res.items) {
        const name = c.metadata?.name ?? "";
        controllers.set(name, c.spec?.controller ?? "");
        if (c.metadata?.annotations?.["ingressclass.kubernetes.io/is-default-class"] === "true") defaultClass = name;
      }
      return { controllers, defaultClass };
    },
    async readConfigMap(namespace, name, key) {
      const cm = await core.readNamespacedConfigMap({ namespace, name });
      return cm.data?.[key] ?? null;
    },
  };
}
