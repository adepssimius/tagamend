import { readFile } from "node:fs/promises";
import path from "node:path";
import { isDockerHub } from "./hosts";

export interface Credential {
  username: string;
  password: string;
}

/** Looks up the credential for a registry host as trivy names it. Undefined means anonymous. */
export type CredentialLookup = (registry: string) => Promise<Credential | undefined>;

export const anonymous: CredentialLookup = async () => undefined;

const HOST = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d+)?$/i;

async function readTrimmed(file: string): Promise<string | undefined> {
  try {
    return (await readFile(file, "utf8")).replace(/\r?\n$/, "");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT" || (e as NodeJS.ErrnoException).code === "ENOTDIR") return undefined;
    throw e;
  }
}

/**
 * Reads `<dir>/<host>/username` and `<dir>/<host>/password`. A missing
 * directory, host directory or file means anonymous access. Docker Hub is
 * found under any of its names (index.docker.io first, as trivy reports it).
 *
 * Values are read on each lookup, so a rotated Secret is picked up without a
 * restart. They are never logged.
 */
export function fileCredentials(dir: string): CredentialLookup {
  return async (registry) => {
    const names = isDockerHub(registry) ? ["index.docker.io", "docker.io", "registry-1.docker.io"] : [registry];
    for (const host of names) {
      if (!HOST.test(host)) continue;
      const base = path.join(dir, host);
      const username = await readTrimmed(path.join(base, "username"));
      const password = await readTrimmed(path.join(base, "password"));
      if (username !== undefined && password !== undefined) return { username, password };
    }
    return undefined;
  };
}
