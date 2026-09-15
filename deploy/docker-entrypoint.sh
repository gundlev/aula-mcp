#!/bin/sh
# Coolify / standalone container entrypoint. Not the Home Assistant add-on
# script — that one lives in homeassistant-addon/run.sh and turns the setup
# UI on. This image never opens the login UI.
set -eu

TOKEN_DIR="${AULA_MCP_DIR:-/var/lib/aula-mcp}"
ATTACH_DIR="${AULA_MCP_ATTACHMENTS_DIR:-/var/tmp/aula-attachments}"

# Volumes often arrive root-owned. Create them before dropping privileges.
install -d -o aula -g aula -m 0700 "$TOKEN_DIR" "$ATTACH_DIR"

# Read-only household deploy: never honour write/raw flags baked into the
# Coolify UI by mistake. Re-enable only by running a different image.
unset AULA_MCP_RAW || true
unset AULA_MCP_WRITE || true
unset AULA_MCP_INGRESS_PORT || true
unset AULA_MCP_INGRESS_HOST || true

export AULA_MCP_DIR="$TOKEN_DIR"
export AULA_MCP_ATTACHMENTS_DIR="$ATTACH_DIR"
export AULA_MCP_HOST="${AULA_MCP_HOST:-0.0.0.0}"
export AULA_MCP_PORT="${AULA_MCP_PORT:-7878}"
export AULA_MCP_ALLOW_REMOTE=1
export AULA_MCP_NO_KEYCHAIN=1

if [ -z "${AULA_MCP_AUTH_TOKEN:-}" ] && [ -z "${AULA_MCP_AUTH_TOKEN_FILE:-}" ]; then
  echo "aula-mcp: AULA_MCP_AUTH_TOKEN (or AULA_MCP_AUTH_TOKEN_FILE) is required." >&2
  echo "Generate one with: openssl rand -hex 32" >&2
  echo "MCP clients send it as: Authorization: Bearer <token>" >&2
  exit 2
fi

if [ -z "${AULA_MCP_ALLOWED_HOSTS:-}" ]; then
  echo "aula-mcp: AULA_MCP_ALLOWED_HOSTS is required (the public hostname clients use)." >&2
  exit 2
fi

if [ -z "${AULA_MCP_KEY:-}" ] && [ ! -f "$TOKEN_DIR/.key" ]; then
  echo "aula-mcp: no AULA_MCP_KEY and no $TOKEN_DIR/.key yet." >&2
  echo "Import a bundle (aula tokens export/import) or set AULA_MCP_KEY to a 64-char hex secret." >&2
  echo "The process will generate a key file on first token write; /readyz will stay 503 until tokens exist." >&2
fi

cd /app
if [ "$(id -u)" = 0 ]; then
  exec gosu aula bun packages/mcp-server/src/server.ts
fi
exec bun packages/mcp-server/src/server.ts
