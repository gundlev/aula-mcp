/**
 * Hono + MCP Streamable HTTP server. Runs on Bun.
 *
 * Routes (see http-app.ts for the request pipeline):
 *   POST /mcp             — MCP JSON-RPC requests (Streamable HTTP transport)
 *   GET  /mcp             — Streamable HTTP SSE channel
 *   DELETE /mcp           — session close
 *   GET  /sse             — Legacy MCP SSE transport (Home Assistant's MCP
 *                           client integration speaks this dialect); only
 *                           when AULA_MCP_LEGACY_SSE=1
 *   POST /messages        — Client→server channel for the /sse session
 *   GET  /healthz         — liveness probe (process is up)
 *   GET  /readyz          — readiness probe (usable Aula credentials on disk)
 *
 * Every MCP route requires `Authorization: Bearer <AULA_MCP_AUTH_TOKEN>`.
 * The server refuses to start without a token unless AULA_MCP_AUTH=none is
 * set explicitly for a loopback-only bind.
 *
 * For stdio transport (e.g. spawn-by-agent-runtime use cases like Claude
 * Desktop, Cursor, Cline), see `server-stdio.ts` — same tool surface,
 * different transport.
 *
 * Env:
 *   AULA_MCP_PORT             — port to bind for MCP traffic (default 7878)
 *   AULA_MCP_HOST             — interface to bind (default 127.0.0.1)
 *   AULA_MCP_ALLOW_REMOTE=1   — permit binding to a non-loopback address.
 *                               This is NOT authentication; it only lifts
 *                               the bind guard.
 *   AULA_MCP_AUTH_TOKEN       — bearer token MCP clients must present
 *                               (≥ 32 chars; `openssl rand -hex 32`)
 *   AULA_MCP_AUTH_TOKEN_FILE  — read the token from a file instead
 *   AULA_MCP_AUTH=none        — disable client auth; loopback bind only
 *   AULA_MCP_ALLOWED_HOSTS    — comma-separated Host header values accepted
 *                               (required for non-loopback binds; loopback
 *                               names are always accepted)
 *   AULA_MCP_ALLOWED_ORIGINS  — comma-separated Origins accepted when a
 *                               request carries an Origin header
 *   AULA_MCP_LEGACY_SSE=1     — enable /sse + /messages (off by default)
 *   AULA_MCP_MAX_BODY_BYTES, AULA_MCP_REQUESTS_PER_MINUTE,
 *   AULA_MCP_AUTH_FAILURES_PER_MINUTE, AULA_MCP_MAX_CONCURRENT_REQUESTS,
 *   AULA_MCP_HTTP_MAX_SESSIONS, AULA_MCP_HTTP_IDLE_MS,
 *   AULA_MCP_SSE_MAX_SESSIONS, AULA_MCP_SSE_IDLE_MS — limits (see config.ts)
 *   AULA_MCP_DIR              — config dir (default ~/.config/aula-mcp)
 *   AULA_MCP_KEY              — encryption key for the token store
 *   AULA_MCP_RAW=1            — enable the aula.raw_request escape hatch
 *   AULA_MCP_WRITE=1          — enable write tools; read-only without it
 *   AULA_MCP_LOG=1            — verbose console logs from auth/client layers
 *   AULA_MCP_INGRESS_PORT     — if set, also boots the setup/login UI on this
 *                               port. Bound to AULA_MCP_INGRESS_HOST (default
 *                               127.0.0.1); the HA addon sets 0.0.0.0 for
 *                               Ingress. Unset in standalone deployments.
 */

import { consoleLogger, silentLogger } from '@aula-mcp/aula-auth';
import { AulaContext } from './aula-context.ts';
import { ConfigError, loadServerConfig } from './config.ts';
import { createHttpApp } from './http-app.ts';
import { createSetupApp, SetupConfigError } from './setup-ui.ts';

let config: ReturnType<typeof loadServerConfig>;
try {
  config = loadServerConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    process.stderr.write(`aula-mcp: ${err.message}\n`);
    process.exit(2);
  }
  throw err;
}

const logger = config.log ? consoleLogger('aula-mcp') : silentLogger;

// One long-lived context answers /readyz. It shares the process-wide token
// refresher with the per-session contexts, so a failing refresh anywhere is
// visible here without this probe issuing its own refreshes.
const probeContext = new AulaContext({ logger });

const httpApp = createHttpApp({
  config,
  logger,
  readiness: () => probeContext.readiness(),
});

logger.info('aula-mcp.listening', {
  host: config.host,
  port: config.port,
  auth: config.auth.mode,
  legacySse: config.legacySse,
});
process.stdout.write(
  `aula-mcp listening on http://${config.host}:${config.port}/mcp ` +
    `(auth: ${config.auth.mode}; healthz at /healthz, readyz at /readyz)\n`,
);

const server = Bun.serve({
  port: config.port,
  hostname: config.host,
  // MCP's Streamable HTTP transport holds the GET /mcp connection open for
  // SSE; Bun's default 10 s idleTimeout closes it mid-session and prints
  // "request timed out after 10 seconds." Bump to 4 min — long enough for
  // typical client poll cadences, short enough to clean up dead peers.
  idleTimeout: 240,
  // Request bodies are additionally capped by the app; this is the outer
  // bound Bun enforces before a byte is parsed.
  maxRequestBodySize: Math.max(config.maxBodyBytes * 2, 64 * 1024),
  fetch: httpApp.fetch,
});

// Optional setup/login UI. The HA addon sets AULA_MCP_INGRESS_PORT to 8099 and
// AULA_MCP_INGRESS_HOST to 0.0.0.0 so HA Supervisor's Ingress proxy can reach
// it. Skipped when unset so standalone deployments never open the extra port
// (audit finding 5).
let setupServer: ReturnType<typeof Bun.serve> | null = null;
let setupApp: ReturnType<typeof createSetupApp> | null = null;
if (config.setupUi) {
  const uiHost = config.setupUi.host;
  const uiPort = config.setupUi.port;
  try {
    setupApp = createSetupApp({ logger, bindHost: uiHost });
  } catch (err) {
    if (err instanceof SetupConfigError) {
      process.stderr.write(`aula-mcp: ${err.message}\n`);
      process.exit(2);
    }
    throw err;
  }
  const ui = setupApp;
  setupServer = Bun.serve({
    port: uiPort,
    hostname: uiHost,
    // The setup UI streams login progress over SSE; Bun's 10 s default
    // closes it mid-flow and the browser loses the QR refreshes.
    idleTimeout: 240,
    maxRequestBodySize: 16 * 1024,
    fetch: (request, srv) =>
      ui.fetch(request, { remoteAddress: srv.requestIP(request)?.address ?? null }),
  });
  logger.info('aula-mcp.setup_ui.listening', { host: uiHost, port: uiPort });
  process.stdout.write(`aula-mcp setup UI listening on http://${uiHost}:${uiPort}/\n`);
}

// Graceful shutdown — finish in-flight requests before exiting.
let shuttingDown = false;
async function shutdown(signal: NodeJS.Signals): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`\n${signal} received — shutting down gracefully…\n`);
  try {
    await httpApp.shutdown();
    probeContext.dispose();
    await server.stop();
    if (setupApp) await setupApp.close();
    if (setupServer) await setupServer.stop();
  } catch (err) {
    logger.error('aula-mcp.shutdown_error', { error: (err as Error).message });
  }
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
