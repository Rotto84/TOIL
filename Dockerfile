FROM node:24-bookworm-slim
ENV NODE_ENV=production PORT=3000 DB_PATH=/data/toil.db NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /app

# Dependencies first so this layer is cached until package files change
COPY package.json package-lock.json ./
# --ignore-scripts: better-sqlite3 ships a prebuilt binary, and without this flag npm tries to compile it
# (the slim image has no compiler, so the build would fail).
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error --cache /tmp/npm-cache \
 && rm -rf /tmp/npm-cache

COPY server.js ./
COPY public ./public

# SQLite lives on a volume so data survives container rebuilds
RUN mkdir -p /data && chown -R node:node /data /app
USER node
VOLUME /data
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
