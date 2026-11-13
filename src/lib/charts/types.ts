/**
 * Shared shapes for chart upgrades. The worker (charts/sync.ts) writes them as
 * JSON text into charts.current_images, chart_candidates.changes and
 * chart_candidates.pinned; the web and the PR queue read them.
 */

/** An image a rendered chart runs. */
export interface ChartImage {
  /**
   * Where in the rendered output: "<Kind>/<name>:<field path>", for example
   * "Deployment/immich-server:spec.template.spec.containers[0].image".
   * Stable between versions of a chart, so current and candidate compare by it.
   */
  key: string;
  /** The rendered object's kind and name (the workload, or an operator CR). */
  kind: string;
  name: string;
  /** The image reference as rendered, e.g. "ghcr.io/immich-app/immich-server:v2.5.6". */
  ref: string;
  /** As stored in `images`: index.docker.io for Docker Hub. */
  registry: string;
  repository: string;
  tag: string | null;
  /** Resolved from the registry for candidates (HEAD of the tag); null if unknown. */
  digest: string | null;
}

/** An image that a candidate version changes. */
export interface ChartImageChange {
  key: string;
  kind: string;
  name: string;
  /** What the installed version renders; null when the image is new in the candidate. */
  from: ChartImage | null;
  /** What the candidate renders; null when the candidate drops the image. */
  to: ChartImage | null;
}

/** An image the HelmRelease's values pin with a `tag:` key. */
export interface PinnedImage {
  key: string;
  kind: string;
  name: string;
  /** Path of the pinned key inside spec.values, e.g. ["server", "controllers", "main", "containers", "main", "image", "tag"]. */
  valuesPath: (string | number)[];
  pinnedTag: string;
  /** What the candidate chart renders for this image with the pin removed. */
  chartDefault: ChartImage | null;
}
