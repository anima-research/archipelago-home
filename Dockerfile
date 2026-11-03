# archipelago-home on Railway (README: "Deploying a second home node on Railway").
# One volume at /data holds everything that must outlive a deploy: the issuer
# key, principals, accounts, invites, codes, the minted log and the config.
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim
WORKDIR /app
# No runtime npm dependencies: dist/ runs on node alone.
ENV NODE_ENV=production \
    PORT=8080 \
    HN_BIND=0.0.0.0 \
    HN_DATA_DIR=/data/hn/data \
    HN_CONFIG_DIR=/data/hn/config \
    HN_CLIENT_IP_HEADER=x-real-ip
# The service user. The container starts as root only so the entrypoint can
# take ownership of the volume, then drops to `hn` (see deploy/railway/).
RUN groupadd --system hn && useradd --system --gid hn --home-dir /data/hn --shell /usr/sbin/nologin hn
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY bin ./bin
COPY config ./config
COPY docs/AGENTS.md ./docs/AGENTS.md
COPY deploy/railway/entrypoint.sh /usr/local/bin/hn-entrypoint
COPY deploy/railway/hn /usr/local/bin/hn
RUN chmod 755 /usr/local/bin/hn-entrypoint /usr/local/bin/hn
EXPOSE 8080
ENTRYPOINT ["hn-entrypoint"]
CMD ["serve"]
