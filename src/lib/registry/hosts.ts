/** Registry host names as trivy reports them, and the hosts their API answers on. */

const DOCKER_HUB = new Set(["index.docker.io", "docker.io", "registry-1.docker.io", "registry.hub.docker.com"]);

export function isDockerHub(registry: string): boolean {
  return DOCKER_HUB.has(registry);
}

/** The host that serves `/v2/` for a registry. Docker Hub's API is not on the name trivy reports. */
export function apiHost(registry: string): string {
  return isDockerHub(registry) ? "registry-1.docker.io" : registry;
}

export interface ImageRef {
  /** As trivy reports it: `index.docker.io` for Docker Hub. */
  registry: string;
  repository: string;
  tag: string | null;
  digest: string | null;
}

/**
 * Parses an image reference the way a container runtime does: no host means
 * Docker Hub, and a single-component Docker Hub name is under `library/`.
 */
export function parseImageRef(ref: string): ImageRef {
  let rest = ref.trim();
  let digest: string | null = null;
  const at = rest.indexOf("@");
  if (at >= 0) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  let tag: string | null = null;
  const colon = rest.lastIndexOf(":");
  if (colon > rest.lastIndexOf("/")) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
  }
  const slash = rest.indexOf("/");
  const first = slash >= 0 ? rest.slice(0, slash) : "";
  let registry = "index.docker.io";
  if (slash >= 0 && (first.includes(".") || first.includes(":") || first === "localhost")) {
    registry = first;
    rest = rest.slice(slash + 1);
  }
  if (isDockerHub(registry)) {
    registry = "index.docker.io";
    if (!rest.includes("/")) rest = `library/${rest}`;
  }
  return { registry, repository: rest, tag, digest };
}
