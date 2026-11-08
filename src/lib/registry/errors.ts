/** Registry failures, typed so the caller can tell a rate limit from a missing tag. */

export type RegistryErrorKind = "rate_limit" | "auth" | "not_found" | "other";

export class RegistryError extends Error {
  readonly kind: RegistryErrorKind;
  readonly host: string;
  readonly status: number | undefined;
  constructor(kind: RegistryErrorKind, host: string, message: string, status?: number) {
    super(message);
    this.name = "RegistryError";
    this.kind = kind;
    this.host = host;
    this.status = status;
  }
}

/** HTTP 429, or Docker Hub's TOOMANYREQUESTS error code. */
export class RegistryRateLimitError extends RegistryError {
  /** From Retry-After when the registry sent one. */
  readonly retryAfterMs: number | undefined;
  constructor(host: string, message: string, status?: number, retryAfterMs?: number) {
    super("rate_limit", host, message, status);
    this.name = "RegistryRateLimitError";
    this.retryAfterMs = retryAfterMs;
  }
}

/** Refused credentials, a refused token, or a private repository without credentials. */
export class RegistryAuthError extends RegistryError {
  constructor(host: string, message: string, status?: number) {
    super("auth", host, message, status);
    this.name = "RegistryAuthError";
  }
}

/** The repository, tag or manifest does not exist. */
export class RegistryNotFoundError extends RegistryError {
  constructor(host: string, message: string, status?: number) {
    super("not_found", host, message, status);
    this.name = "RegistryNotFoundError";
  }
}

/** Parses Retry-After: either seconds or an HTTP date. */
export function parseRetryAfter(value: string | null, nowMs: number): number | undefined {
  if (!value) return undefined;
  if (/^\d+$/.test(value.trim())) return Number(value.trim()) * 1000;
  const t = Date.parse(value);
  return Number.isNaN(t) ? undefined : Math.max(0, t - nowMs);
}
