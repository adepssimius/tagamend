import { z } from "zod";

/** Parses "30s", "5m", "6h", "1d" into milliseconds. */
export function parseDuration(value: string): number {
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(value.trim());
  if (!m) throw new Error(`not a duration: ${value}`);
  const n = Number(m[1]);
  const unit = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "ms" | "s" | "m" | "h" | "d"];
  return n * unit;
}

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

const duration = z.string().transform((v, ctx) => {
  try {
    return parseDuration(v);
  } catch {
    ctx.addIssue({ code: "custom", message: `expected a duration like 5m or 6h, got "${v}"` });
    return z.NEVER;
  }
});

const csv = z
  .string()
  .transform((v) => v.split(",").map((s) => s.trim()).filter(Boolean));

const schema = z.object({
  DATABASE_URL: z.string().min(1),
  KUBECONFIG: z.string().optional(),
  TRIVY_SERVER_URL: z.string().url().default("http://trivy-service.trivy-system:4954"),
  TRIVY_IMAGE: z.string().default("mirror.gcr.io/aquasec/trivy:0.76.1"),
  SCANNER: z.enum(["job", "local"]).default("job"),
  SCAN_NAMESPACE: z.string().default("tagamend"),
  SCAN_CONCURRENCY: z.coerce.number().int().min(1).default(1),
  // Node names scan Jobs must not run on, comma-separated.
  SCAN_EXCLUDED_NODES: csv.default([]),
  SEVERITIES: csv
    .pipe(z.array(z.enum(SEVERITY_ORDER)).min(1))
    .default(["CRITICAL", "HIGH", "MEDIUM"]),
  REPORT_SYNC_INTERVAL: duration.default(5 * 60_000),
  TAG_SYNC_INTERVAL: duration.default(6 * 3_600_000),
  REGISTRY_CREDENTIALS_DIR: z.string().default("/secrets/registries"),
  // For scan Jobs, which read credentials from Secrets in SCAN_NAMESPACE rather
  // than from files. Format: "host=secret/usernameKey/passwordKey;host=...".
  SCAN_REGISTRY_SECRETS: z
    .string()
    .default("")
    .transform((v, ctx) => {
      const out: { host: string; secret: string; usernameKey: string; passwordKey: string }[] = [];
      for (const part of v.split(";").map((s) => s.trim()).filter(Boolean)) {
        const m = /^([^=]+)=([^/]+)\/([^/]+)\/([^/]+)$/.exec(part);
        if (!m) {
          ctx.addIssue({ code: "custom", message: `expected host=secret/usernameKey/passwordKey, got "${part}"` });
          return z.NEVER;
        }
        out.push({ host: m[1]!, secret: m[2]!, usernameKey: m[3]!, passwordKey: m[4]! });
      }
      return out;
    }),
  OIDC_ISSUER: z.string().url().optional(),
  OIDC_CLIENT_ID: z.string().optional(),
  OIDC_CLIENT_SECRET: z.string().optional(),
  OIDC_ALLOWED_GROUPS: csv.optional(),
  AUTH_SECRET: z.string().optional(),
  AUTH_DEV_USER: z.string().optional(),
  NODE_ENV: z.string().default("development"),
});

export type Config = z.infer<typeof schema>;

let cached: Config | undefined;

/**
 * Validated configuration. Read lazily so that `next build` does not need the
 * runtime environment. A missing or invalid value throws, naming the variable.
 */
export function getConfig(env: Record<string, string | undefined> = process.env): Config {
  if (cached && env === process.env) return cached;
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`);
    throw new Error(`invalid configuration:\n${lines.join("\n")}`);
  }
  const config = parsed.data;
  if (config.AUTH_DEV_USER && config.NODE_ENV === "production") {
    throw new Error("invalid configuration:\n  AUTH_DEV_USER: refused when NODE_ENV=production");
  }
  if (env === process.env) cached = config;
  return config;
}
