# Coolify / Hetzner deploy

This directory is the **standalone, read-only** image for a single household.
It is not the Home Assistant add-on. The add-on entrypoint
(`homeassistant-addon/run.sh`) turns the MitID login UI on; this image
never sets `AULA_MCP_INGRESS_PORT` and refuses `AULA_MCP_RAW` /
`AULA_MCP_WRITE`.

The finished image is an application artifact. It is **not** a logged-in
production service. `/healthz` is process liveness. `/readyz` is usable
Aula credentials on the token volume. Until you import tokens, `/readyz`
returns 503.

## What you get

- One authenticated HTTPS MCP endpoint, terminated by Coolify's proxy.
- Port 7878 is **not** published on the host. Do not add a `ports:` mapping
  for 7878 or 8099 — that would skip TLS and the proxy.
- Non-root process (`uid 10001`), read-only root filesystem, dropped
  capabilities, 512 MiB / 1 CPU / 256 pids.
- Persistent volume for `tokens.json` only. Attachments live on a size-capped
  tmpfs and are evicted by quota + TTL.
- Client bearer token and `AULA_MCP_KEY` come from Coolify secrets, not
  from the image or the token-volume backup.

## Secrets (generate, never commit)

| Secret | How | Used for |
| --- | --- | --- |
| `AULA_MCP_AUTH_TOKEN` | `openssl rand -hex 32` | MCP clients send `Authorization: Bearer <token>`. ≥ 32 characters. |
| `AULA_MCP_KEY` | `openssl rand -hex 32` | AES-256-GCM key for `tokens.json`. Keep it **off** the token volume and **out** of volume backups. |
| `AULA_MCP_ALLOWED_HOSTS` | public hostname | Host header allow-list, e.g. `aula-mcp.example.com`. Required for any non-loopback bind. |

Optional: `AULA_MCP_ALLOWED_ORIGINS` (`https://…`) if a browser-based client
sends `Origin`. Non-browser clients omit Origin and are accepted.

`AULA_MCP_ALLOW_REMOTE=1` only permits binding to `0.0.0.0`. It is **not**
authentication.

## Coolify

1. Create an application from this repository. Dockerfile path:
   `deploy/Dockerfile`. Build context: repository root.
2. Do **not** enable "publish ports" for 7878. Attach Coolify's HTTPS
   proxy to container port 7878.
3. Set the three secrets above plus `AULA_MCP_DIR=/var/lib/aula-mcp`.
4. Persistent storage: host/volume path → `/var/lib/aula-mcp` (mode 0700).
5. One replica. Do not scale or run two stacks against the same tokens.
6. Health check path: `/healthz`. Treat `/readyz` as "has Aula tokens",
   not as "process is up".

Compose equivalent (local or a VM Coolify is not managing):

```sh
export AULA_MCP_AUTH_TOKEN="$(openssl rand -hex 32)"
export AULA_MCP_KEY="$(openssl rand -hex 32)"
export AULA_MCP_ALLOWED_HOSTS=aula-mcp.example.com
docker compose -f deploy/docker-compose.yml up --build
```

## First login (workstation → server)

Hosting IPs often hit STIL's bot defense. Do **not** try to bypass it.
Log in interactively on a normal workstation, then transfer the bundle.

```sh
# On a laptop, after a successful MitID login:
AULA_MCP_NO_KEYCHAIN=1 pnpm aula tokens export ./aula-bundle
# Inspect that both tokens.json and .key exist, then copy only those two
# files onto the server volume. Delete the local bundle afterwards.
scp aula-bundle/tokens.json aula-bundle/.key root@hetzner:/var/lib/aula-mcp/
rm -rf aula-bundle
```

The bundle carries its **own** `.key`. The server decrypts with that file
and re-encrypts with `AULA_MCP_KEY` only if you run `aula tokens import`
on the server. A straight `scp` of both files is enough: the running
server reads `tokens.json` with `$AULA_MCP_DIR/.key`.

If the server already has `AULA_MCP_KEY` set and you scp'd a bundle `.key`
alongside `tokens.json`, **either**:

- leave `AULA_MCP_KEY` unset and use the bundle `.key`, or
- on a trusted host run `AULA_MCP_DIR=/var/lib/aula-mcp AULA_MCP_KEY=… aula tokens import ./aula-bundle`
  so the volume is re-encrypted with the server key, then delete the bundle `.key`.

Do **not** copy `cookies.json`. Cookie persistence is opt-in
(`AULA_MCP_PERSIST_COOKIES=1`) and only for workstation `aula refresh-stepup`.
The server refreshes with the OAuth refresh token alone.

## MCP client

```
URL:    https://aula-mcp.example.com/mcp
Header: Authorization: Bearer <AULA_MCP_AUTH_TOKEN>
```

Legacy `/sse` is off. Do not enable `AULA_MCP_LEGACY_SSE` here.

`/healthz` → `{ ok: true, name: "aula-mcp" }` with no credential.
`/readyz` → `200 { ready: true }` or `503 { ready: false, reason: "no_tokens"|"refresh_failing"|"store_error" }`.
Reasons never include usernames or token material.

## Recovery

- Lost `AULA_MCP_AUTH_TOKEN`: generate a new one, update Coolify and every
  MCP client. Existing sessions die.
- Lost `AULA_MCP_KEY` / `.key`: the volume is unreadable. Re-import a bundle
  or run `aula login` on a workstation and transfer again.
- Lost refresh token (Aula-side): workstation MitID login + export. There is
  no headless login that bypasses STIL.

Read-only MCP tools do not reduce the Aula credential's privileges. Anyone
who can present the bearer token is the household.

## What this does not validate

A successful `docker build` and a `/healthz` 200 are not a production
login. Real MitID, Aula refresh-token rotation, and Hetzner STIL behaviour
still need an authorized test against live services.
