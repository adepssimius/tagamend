import * as k8s from "@kubernetes/client-node";
import { getK8s } from "../k8s/client";
import type { K8sObject } from "./discover";
import type { ChartSource } from "./sync";

function statusCode(e: unknown): number | undefined {
  const code = (e as { code?: unknown } | null)?.code;
  return typeof code === "number" ? code : undefined;
}

/** The real ChartSource, using the shared Kubernetes client. Read-only. */
export function k8sChartSource(): ChartSource {
  const { kc, core, custom } = getK8s();
  const versionApi = kc.makeApiClient(k8s.VersionApi);

  async function listAll(group: string, version: string, plural: string): Promise<K8sObject[]> {
    const out: K8sObject[] = [];
    let cont: string | undefined;
    do {
      const res = (await custom.listClusterCustomObject({ group, version, plural, limit: 500, _continue: cont })) as {
        items?: K8sObject[];
        metadata?: { continue?: string };
      };
      out.push(...(res.items ?? []));
      cont = res.metadata?.continue || undefined;
    } while (cont);
    return out;
  }

  /** Tries each version in order; a 404 means the cluster does not serve it. */
  async function listFirst(group: string, versions: string[], plural: string): Promise<K8sObject[]> {
    for (const v of versions) {
      try {
        return await listAll(group, v, plural);
      } catch (e) {
        if (statusCode(e) !== 404) throw e;
      }
    }
    return [];
  }

  return {
    listHelmReleases: () => listFirst("helm.toolkit.fluxcd.io", ["v2", "v2beta2"], "helmreleases"),
    async listSources() {
      const [repos, ocis] = await Promise.all([
        listFirst("source.toolkit.fluxcd.io", ["v1", "v1beta2"], "helmrepositories"),
        listFirst("source.toolkit.fluxcd.io", ["v1", "v1beta2"], "ocirepositories"),
      ]);
      return [
        ...repos.map((o) => ({ ...o, kind: o.kind ?? "HelmRepository" })),
        ...ocis.map((o) => ({ ...o, kind: o.kind ?? "OCIRepository" })),
      ];
    },
    async getConfigMap(namespace, name) {
      try {
        const cm = await core.readNamespacedConfigMap({ namespace, name });
        return cm.data ?? {};
      } catch (e) {
        if (statusCode(e) === 404) return null;
        throw e;
      }
    },
    async kubeVersion() {
      const v = await versionApi.getCode();
      return v.gitVersion || null;
    },
  };
}
