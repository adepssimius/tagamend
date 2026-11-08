/**
 * Plain JS on purpose: the runtime image has no dev dependencies, and Next.js
 * needs the `typescript` package to load a next.config.ts.
 *
 * @type {import("next").NextConfig}
 */
const config = {
  // Native and Node-only modules stay out of the server bundle.
  serverExternalPackages: ["better-sqlite3", "pg", "@kubernetes/client-node"],
  poweredByHeader: false,
};

export default config;
