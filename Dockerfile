# One image, two processes. The default command is the web server; the worker
# Deployment overrides it with `node dist/worker.js`.
FROM node:22-bookworm-slim AS build
WORKDIR /app
# better-sqlite3 is a native module; prebuilt binaries cover linux/amd64, the
# toolchain is the fallback.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/dist ./dist
COPY --from=build /app/next.config.mjs ./
USER node
EXPOSE 3000
CMD ["node_modules/.bin/next", "start"]
