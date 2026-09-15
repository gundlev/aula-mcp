#!/bin/sh
# Home Assistant add-on entry. Translates HA-style options (read from
# /data/options.json, populated by Supervisor) into the env vars aula-mcp's
# server entry expects, then exec's into the long-running MCP server.
#
# This script is the HA add-on entrypoint only. The Coolify/Hetzner image
# uses deploy/docker-entrypoint.sh and never enables the setup UI.
set -eu

OPTIONS_FILE=/data/options.json

if [ -f "$OPTIONS_FILE" ]; then
  AULA_MCP_KEY="$(jq -r '.aula_mcp_key // empty' "$OPTIONS_FILE")"
  LOG="$(jq -r '.log // false' "$OPTIONS_FILE")"
  ALLOW_REMOTE="$(jq -r '.allow_remote // true' "$OPTIONS_FILE")"
  AUTH_TOKEN="$(jq -r '.mcp_auth_token // empty' "$OPTIONS_FILE")"
  ALLOWED_HOSTS="$(jq -r '.allowed_hosts // empty' "$OPTIONS_FILE")"
else
  # Running outside Supervisor (e.g. local docker test). Fall back to env.
  AULA_MCP_KEY="${AULA_MCP_KEY:-}"
  LOG="${LOG:-false}"
  ALLOW_REMOTE="${ALLOW_REMOTE:-true}"
  AUTH_TOKEN="${AULA_MCP_AUTH_TOKEN:-}"
  ALLOWED_HOSTS="${AULA_MCP_ALLOWED_HOSTS:-}"
fi

# `/config/aula-mcp/` is mapped from Supervisor's /config volume. The user
# copies their `tokens.json` + `.key` here after running `aula tokens export`
# on a workstation — see homeassistant-addon/README.md.
export AULA_MCP_DIR="/config/aula-mcp"
mkdir -p "$AULA_MCP_DIR"

# The MCP server refuses non-loopback binds by default; HA's whole point is
# serving the LAN, so the default `allow_remote: true` opens it up. Setting
# `allow_remote: false` keeps the MCP traffic loopback-only inside the
# container — useful if you front it with HA Ingress / a reverse proxy, but
# in that case the LAN can't reach :7878 directly so HA's MCP client
# integration won't either. Don't flip unless you know what you're doing.
#
# allow_remote is NOT authentication. A bearer token is required whenever
# the server is reachable from another host.
if [ "$ALLOW_REMOTE" = "true" ]; then
  export AULA_MCP_HOST="0.0.0.0"
  export AULA_MCP_ALLOW_REMOTE=1
  if [ -z "$AUTH_TOKEN" ]; then
    echo "aula-mcp: mcp_auth_token is required when allow_remote is true." >&2
    echo "Generate one with: openssl rand -hex 32" >&2
    exit 2
  fi
  if [ -z "$ALLOWED_HOSTS" ]; then
    ALLOWED_HOSTS="homeassistant.local,homeassistant"
  fi
  export AULA_MCP_ALLOWED_HOSTS="$ALLOWED_HOSTS"
else
  export AULA_MCP_HOST="127.0.0.1"
fi

if [ -n "$AUTH_TOKEN" ]; then
  export AULA_MCP_AUTH_TOKEN="$AUTH_TOKEN"
elif [ "$ALLOW_REMOTE" != "true" ]; then
  export AULA_MCP_AUTH=none
fi

# Home Assistant's official MCP client still speaks the legacy SSE dialect.
export AULA_MCP_LEGACY_SSE=1

# Boot the in-addon setup/login UI on the port HA Ingress proxies to.
# config.yaml's `ingress_port` MUST stay in sync with this value.
# Only the Ingress proxy's TCP peer is trusted (audit finding 5).
export AULA_MCP_INGRESS_PORT=8099
export AULA_MCP_INGRESS_HOST="0.0.0.0"
export AULA_MCP_SETUP_AUTH=ingress

if [ "$LOG" = "true" ]; then
  export AULA_MCP_LOG=1
fi

if [ -n "$AULA_MCP_KEY" ]; then
  export AULA_MCP_KEY
fi

cd /app
exec bun packages/mcp-server/src/server.ts
