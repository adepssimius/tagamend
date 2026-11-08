import * as k8s from "@kubernetes/client-node";

/**
 * Kubernetes clients for the worker. In-cluster config when KUBECONFIG is
 * unset and the process runs in a pod; otherwise the default kubeconfig.
 */
export interface K8sClients {
  kc: k8s.KubeConfig;
  core: k8s.CoreV1Api;
  apps: k8s.AppsV1Api;
  batch: k8s.BatchV1Api;
  custom: k8s.CustomObjectsApi;
}

let cached: K8sClients | undefined;

export function getK8s(): K8sClients {
  if (cached) return cached;
  const kc = new k8s.KubeConfig();
  // loadFromCluster() does not throw outside a cluster, it just builds a config
  // for https://undefined:undefined, so test for the cluster's own env var.
  if (!process.env.KUBECONFIG && process.env.KUBERNETES_SERVICE_HOST) kc.loadFromCluster();
  else kc.loadFromDefault();
  cached = {
    kc,
    core: kc.makeApiClient(k8s.CoreV1Api),
    apps: kc.makeApiClient(k8s.AppsV1Api),
    batch: kc.makeApiClient(k8s.BatchV1Api),
    custom: kc.makeApiClient(k8s.CustomObjectsApi),
  };
  return cached;
}
