# One image, two processes. The default command is the web server; the worker
# Deployment overrides it with `node dist/worker.js`.
FROM node:22-bookworm-slim AS build
WORKDIR /app
# better-sqlite3 is a native module; prebuilt binaries cover linux/amd64, the
# toolchain is the fallback.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ curl ca-certificates && rm -rf /var/lib/apt/lists/*

# helm, for chart sync's `helm pull` and `helm template`. The checksum comes
# from get.helm.sh alongside the archive and is checked before unpacking.
ARG HELM_VERSION=v3.22.1
ARG TARGETARCH=amd64
RUN set -eu; \
    tarball="helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    cd /tmp; \
    curl -fsSLO "https://get.helm.sh/${tarball}"; \
    curl -fsSLO "https://get.helm.sh/${tarball}.sha256sum"; \
    sha256sum -c "${tarball}.sha256sum"; \
    tar -xzf "${tarball}" "linux-${TARGETARCH}/helm"; \
    install -m 0755 "linux-${TARGETARCH}/helm" /usr/local/bin/helm; \
    rm -rf "${tarball}" "${tarball}.sha256sum" "linux-${TARGETARCH}"; \
    helm version --short
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000
# The root filesystem is read-only; helm keeps its cache, config and plugins under /tmp.
ENV HELM_CACHE_HOME=/tmp/helm/cache HELM_CONFIG_HOME=/tmp/helm/config HELM_DATA_HOME=/tmp/helm/data
COPY --from=build /usr/local/bin/helm /usr/local/bin/helm
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/dist ./dist
COPY --from=build /app/next.config.mjs ./
USER node
EXPOSE 3000
CMD ["node_modules/.bin/next", "start"]
