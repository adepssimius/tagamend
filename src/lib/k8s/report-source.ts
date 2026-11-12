import * as k8s from "@kubernetes/client-node";
import { getK8s } from "./client";
import type { K8sObject, PodImage, ReportSource } from "./owners";

/** HTTP status of a client-node error, if it has one. */
function statusCode(e: unknown): number | undefined {
  const code = (e as { code?: unknown } | null)?.code;
  return typeof code === "number" ? code : undefined;
}

/** The real `ReportSource`, using the shared Kubernetes client. */
export function k8sReportSource(): ReportSource {
  const { kc, custom, core } = getK8s();
  const objects = k8s.KubernetesObjectApi.makeApiClient(kc);
  return {
    async listReports({ limit, continue: cont }) {
      const res = (await custom.listClusterCustomObject({
        group: "aquasecurity.github.io",
        version: "v1alpha1",
        plural: "vulnerabilityreports",
        limit,
        _continue: cont,
      })) as { items?: unknown[]; metadata?: { continue?: string } };
      return { items: res.items ?? [], continue: res.metadata?.continue || undefined };
    },
    async listPodImages() {
      const out: PodImage[] = [];
      let cont: string | undefined;
      do {
        const res = await core.listPodForAllNamespaces({ limit: 500, _continue: cont });
        for (const pod of res.items) {
          const ref = pod.metadata?.ownerReferences?.find((o) => o.controller) ?? pod.metadata?.ownerReferences?.[0];
          for (const cs of [...(pod.status?.containerStatuses ?? []), ...(pod.status?.initContainerStatuses ?? [])]) {
            const m = /@(sha256:[0-9a-f]{64})$/.exec(cs.imageID ?? "");
            if (!m) continue;
            out.push({
              namespace: pod.metadata?.namespace ?? "",
              podName: pod.metadata?.name ?? "",
              owner: ref ? { kind: ref.kind, name: ref.name } : null,
              container: cs.name,
              digest: m[1]!,
            });
          }
        }
        cont = res.metadata?._continue || undefined;
      } while (cont);
      return out;
    },
    async getObject(ref) {
      try {
        return (await objects.read({
          apiVersion: ref.apiVersion,
          kind: ref.kind,
          metadata: { name: ref.name, namespace: ref.namespace },
        })) as K8sObject;
      } catch (e) {
        if (statusCode(e) === 404) return null;
        throw e;
      }
    },
  };
}
