import { describe, expect, it } from "vitest";
import { getConfig, parseDuration } from "@/lib/config";

describe("config", () => {
  it("parses durations", () => {
    expect(parseDuration("5m")).toBe(300_000);
    expect(parseDuration("6h")).toBe(21_600_000);
    expect(() => parseDuration("5 minutes")).toThrow();
  });

  it("names the bad variable", () => {
    expect(() => getConfig({ DATABASE_URL: "file:x", SEVERITIES: "HIGH,BOGUS" })).toThrow(/SEVERITIES/);
  });

  it("parses scan registry secrets", () => {
    const c = getConfig({
      DATABASE_URL: "file:x",
      SCAN_REGISTRY_SECRETS: "ghcr.io=ghcr-registry/GHCR_USERNAME/GHCR_TOKEN; index.docker.io=dh/U/P",
    });
    expect(c.SCAN_REGISTRY_SECRETS).toEqual([
      { host: "ghcr.io", secret: "ghcr-registry", usernameKey: "GHCR_USERNAME", passwordKey: "GHCR_TOKEN" },
      { host: "index.docker.io", secret: "dh", usernameKey: "U", passwordKey: "P" },
    ]);
  });

  it("refuses the dev login in production", () => {
    expect(() => getConfig({ DATABASE_URL: "file:x", AUTH_DEV_USER: "me", NODE_ENV: "production" })).toThrow(/AUTH_DEV_USER/);
  });
});
