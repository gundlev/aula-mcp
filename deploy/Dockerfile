# Standalone / Coolify image for a single-household, read-only aula-mcp.
#
# Builds the checked-out fork (this repository) with the frozen lockfile.
# Does not clone github.com/Casperjuel/aula-mcp — that would silently pick
# up moving upstream main.
#
# Node is used for `pnpm install` because some workspace packages import
# `node:sqlite` at install time. Bun is the runtime (`Bun.serve`).

FROM oven/bun:1.3-debian AS bun-bin

FROM node:24-bookworm-slim

COPY --from=bun-bin /usr/local/bin/bun /usr/local/bin/bun

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates gosu \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 aula \
  && useradd --uid 10001 --gid aula --home-dir /var/lib/aula-mcp --create-home --shell /usr/sbin/nologin aula

RUN corepack enable \
  && corepack prepare pnpm@11.1.3 --activate

WORKDIR /app

# Copy manifests first so dependency layers stay cached when only source changes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.json tsconfig.base.json ./
COPY packages/aula-auth/package.json packages/aula-auth/package.json
COPY packages/aula-client/package.json packages/aula-client/package.json
COPY packages/mcp-server/package.json packages/mcp-server/package.json
COPY apps/cli/package.json apps/cli/package.json

RUN pnpm install --frozen-lockfile

COPY packages packages
COPY apps apps

# Drop the bits a production server never needs. Source stays because Bun
# runs TypeScript directly.
RUN rm -rf apps/cli/src/commands/*.test.ts packages/*/src/*.test.ts

COPY deploy/docker-entrypoint.sh /usr/local/bin/aula-mcp-entrypoint
RUN chmod 0755 /usr/local/bin/aula-mcp-entrypoint \
  && mkdir -p /var/lib/aula-mcp /var/tmp/aula-attachments \
  && chown -R aula:aula /var/lib/aula-mcp /var/tmp/aula-attachments /app

ENV AULA_MCP_DIR=/var/lib/aula-mcp \
    AULA_MCP_ATTACHMENTS_DIR=/var/tmp/aula-attachments \
    AULA_MCP_HOST=0.0.0.0 \
    AULA_MCP_PORT=7878 \
    AULA_MCP_NO_KEYCHAIN=1

# The process binds 7878 inside the container. Do not publish it on the
# host — Coolify's HTTPS proxy reaches it on the compose network.
EXPOSE 7878

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/aula-mcp-entrypoint"]
