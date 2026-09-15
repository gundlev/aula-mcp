# Standalone / Coolify image for a single-household, read-only aula-mcp.
#
# Builds the checked-out fork (this repository) with the frozen lockfile.
# Does not clone github.com/Casperjuel/aula-mcp — that would silently pick
# up moving upstream main.
#
# Node is used for `pnpm install` because some workspace packages import
# `node:sqlite` at install time. Bun is the runtime (`Bun.serve`) and is
# installed from a version-pinned GitHub release (not bun.sh/install, which
# would float). A multi-stage `COPY --from=oven/bun` is avoided so the
# image still builds on overlayfs-limited hosts.

FROM node:24-bookworm-slim

ARG BUN_VERSION=1.3.3

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl gosu unzip \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 aula \
  && useradd --uid 10001 --gid aula --home-dir /var/lib/aula-mcp --create-home --shell /usr/sbin/nologin aula \
  && arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
       amd64) bun_arch=x64 ;; \
       arm64) bun_arch=aarch64 ;; \
       *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
     esac \
  && curl -fsSL "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-${bun_arch}.zip" -o /tmp/bun.zip \
  && unzip -q /tmp/bun.zip -d /tmp \
  && install -m 0755 "/tmp/bun-linux-${bun_arch}/bun" /usr/local/bin/bun \
  && rm -rf /tmp/bun.zip "/tmp/bun-linux-${bun_arch}" \
  && bun --version

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
