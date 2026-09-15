/**
 * HTTP server configuration, parsed once at boot and validated so the
 * process refuses to start in an unsafe state rather than degrading.
 *
 * The rules that matter (audit finding 1):
 *   - Every MCP route requires `Authorization: Bearer <AULA_MCP_AUTH_TOKEN>`
 *     unless the operator sets `AULA_MCP_AUTH=none`, which is only honoured
 *     for a loopback bind. `AULA_MCP_ALLOW_REMOTE=1` merely permits binding
 *     to another interface; it is not authentication.
 *   - Binding to a non-loopback interface requires an explicit list of
 *     acceptable `Host` header values (`AULA_MCP_ALLOWED_HOSTS`).
 *   - The legacy `/sse` + `/messages` transport is off unless
 *     `AULA_MCP_LEGACY_SSE=1`.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}

export type AuthConfig = { mode: 'bearer'; tokenDigest: Buffer } | { mode: 'none' };

export interface ServerConfig {
  host: string;
  port: number;
  allowRemote: boolean;
  auth: AuthConfig;
  /** Lower-cased `host` or `host:port` values accepted in the Host header.
   *  Loopback names are always accepted in addition. */
  allowedHosts: string[];
  /** Lower-cased origins (`scheme://host[:port]`) accepted when a request
   *  carries an Origin header. Requests without Origin are accepted. */
  allowedOrigins: string[];
  legacySse: boolean;
  maxBodyBytes: number;
  /** Requests per minute across all clients (the server is single-household). */
  requestsPerMinute: number;
  /** Failed authentications per minute before unauthenticated requests get 429. */
  authFailuresPerMinute: number;
  /** In-flight POST /mcp and /messages requests. */
  maxConcurrentRequests: number;
  httpMaxSessions: number;
  httpIdleMs: number;
  sseMaxSessions: number;
  sseIdleMs: number;
  /** Optional setup/login UI (`AULA_MCP_INGRESS_PORT`). */
  setupUi: { port: number; host: string } | null;
  log: boolean;
}

export const MIN_TOKEN_LENGTH = 32;

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost', '[::1]']);

export function isLoopbackHost(host: string): boolean {
  return LOOPBACK_HOSTS.has(host.toLowerCase());
}

export function loadServerConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const host = env.AULA_MCP_HOST ?? '127.0.0.1';
  const port = intEnv(env.AULA_MCP_PORT, 7878, 1, 65535, 'AULA_MCP_PORT');
  const allowRemote = env.AULA_MCP_ALLOW_REMOTE === '1';
  const loopback = isLoopbackHost(host);

  if (!loopback && !allowRemote) {
    throw new ConfigError(
      `Refusing to bind to non-loopback address (${host}). The MCP server is single-user ` +
        'and exposes your Aula tokens to anyone who can reach /mcp. Set ' +
        'AULA_MCP_ALLOW_REMOTE=1 together with AULA_MCP_AUTH_TOKEN and AULA_MCP_ALLOWED_HOSTS ' +
        'if you understand the implications.',
    );
  }

  const auth = loadAuth(env, loopback);

  const allowedHosts = listEnv(env.AULA_MCP_ALLOWED_HOSTS).map(normaliseHostEntry);
  if (!loopback && allowedHosts.length === 0) {
    throw new ConfigError(
      'AULA_MCP_ALLOWED_HOSTS is required when binding to a non-loopback address. Set it to ' +
        'the hostname clients use (e.g. aula-mcp.example.com). Requests whose Host header ' +
        'does not match are rejected to defeat DNS rebinding.',
    );
  }
  if (allowedHosts.includes('*')) {
    throw new ConfigError('AULA_MCP_ALLOWED_HOSTS must list hostnames; "*" is not accepted.');
  }

  const allowedOrigins = listEnv(env.AULA_MCP_ALLOWED_ORIGINS).map(normaliseOrigin);

  let setupUi: ServerConfig['setupUi'] = null;
  if (env.AULA_MCP_INGRESS_PORT) {
    const uiPort = intEnv(env.AULA_MCP_INGRESS_PORT, 0, 1, 65535, 'AULA_MCP_INGRESS_PORT');
    // Home Assistant's Ingress proxy reaches the addon over the container
    // network, so the addon sets AULA_MCP_INGRESS_HOST=0.0.0.0 explicitly.
    // Everywhere else the UI stays on loopback (audit finding 5).
    const uiHost = env.AULA_MCP_INGRESS_HOST ?? '127.0.0.1';
    setupUi = { port: uiPort, host: uiHost };
  }

  return {
    host,
    port,
    allowRemote,
    auth,
    allowedHosts,
    allowedOrigins,
    legacySse: env.AULA_MCP_LEGACY_SSE === '1',
    maxBodyBytes: intEnv(
      env.AULA_MCP_MAX_BODY_BYTES,
      1024 * 1024,
      1024,
      64 * 1024 * 1024,
      'AULA_MCP_MAX_BODY_BYTES',
    ),
    requestsPerMinute: intEnv(
      env.AULA_MCP_REQUESTS_PER_MINUTE,
      600,
      1,
      1_000_000,
      'AULA_MCP_REQUESTS_PER_MINUTE',
    ),
    authFailuresPerMinute: intEnv(
      env.AULA_MCP_AUTH_FAILURES_PER_MINUTE,
      20,
      1,
      100_000,
      'AULA_MCP_AUTH_FAILURES_PER_MINUTE',
    ),
    maxConcurrentRequests: intEnv(
      env.AULA_MCP_MAX_CONCURRENT_REQUESTS,
      16,
      1,
      10_000,
      'AULA_MCP_MAX_CONCURRENT_REQUESTS',
    ),
    httpMaxSessions: intEnv(
      env.AULA_MCP_HTTP_MAX_SESSIONS,
      16,
      1,
      10_000,
      'AULA_MCP_HTTP_MAX_SESSIONS',
    ),
    httpIdleMs: intEnv(
      env.AULA_MCP_HTTP_IDLE_MS,
      300_000,
      1_000,
      86_400_000,
      'AULA_MCP_HTTP_IDLE_MS',
    ),
    sseMaxSessions: intEnv(
      env.AULA_MCP_SSE_MAX_SESSIONS,
      16,
      1,
      10_000,
      'AULA_MCP_SSE_MAX_SESSIONS',
    ),
    sseIdleMs: intEnv(env.AULA_MCP_SSE_IDLE_MS, 300_000, 1_000, 86_400_000, 'AULA_MCP_SSE_IDLE_MS'),
    setupUi,
    log: env.AULA_MCP_LOG === '1',
  };
}

function loadAuth(env: NodeJS.ProcessEnv, loopback: boolean): AuthConfig {
  const mode = env.AULA_MCP_AUTH ?? 'bearer';
  if (mode === 'none') {
    if (!loopback) {
      throw new ConfigError(
        'AULA_MCP_AUTH=none is only allowed when binding to loopback. A server reachable ' +
          'from other machines must set AULA_MCP_AUTH_TOKEN.',
      );
    }
    return { mode: 'none' };
  }
  if (mode !== 'bearer') {
    throw new ConfigError(`AULA_MCP_AUTH="${mode}" is not understood (use "bearer" or "none").`);
  }
  let token = env.AULA_MCP_AUTH_TOKEN ?? '';
  const file = env.AULA_MCP_AUTH_TOKEN_FILE;
  if (!token && file) {
    try {
      token = readFileSync(file, 'utf8').trim();
    } catch (e) {
      throw new ConfigError(
        `AULA_MCP_AUTH_TOKEN_FILE (${file}) could not be read: ${(e as Error).message}`,
      );
    }
  }
  if (!token) {
    throw new ConfigError(
      'No client credential configured. Set AULA_MCP_AUTH_TOKEN (or AULA_MCP_AUTH_TOKEN_FILE) ' +
        `to a random secret of at least ${MIN_TOKEN_LENGTH} characters; MCP clients send it as ` +
        '"Authorization: Bearer <token>". For a loopback-only development server you may set ' +
        'AULA_MCP_AUTH=none explicitly.',
    );
  }
  if (token.length < MIN_TOKEN_LENGTH) {
    throw new ConfigError(
      `AULA_MCP_AUTH_TOKEN is too short (${token.length} chars); use at least ` +
        `${MIN_TOKEN_LENGTH}. Generate one with: openssl rand -hex 32`,
    );
  }
  if (/\s/.test(token)) {
    throw new ConfigError('AULA_MCP_AUTH_TOKEN must not contain whitespace.');
  }
  return { mode: 'bearer', tokenDigest: digest(token) };
}

/** SHA-256 of a credential — compared with timingSafeEqual, never as a string. */
export function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

function listEnv(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/** `Example.com:443` → `example.com:443`; a bare `[::1]` keeps its brackets. */
export function normaliseHostEntry(value: string): string {
  return value.toLowerCase().replace(/\.(?=:|$)/, '');
}

export function normaliseOrigin(value: string): string {
  try {
    const u = new URL(value);
    return u.origin.toLowerCase();
  } catch {
    throw new ConfigError(`AULA_MCP_ALLOWED_ORIGINS entry "${value}" is not a valid origin.`);
  }
}

function intEnv(
  raw: string | undefined,
  fallback: number,
  min: number,
  max: number,
  name: string,
): number {
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new ConfigError(`${name}="${raw}" must be an integer between ${min} and ${max}.`);
  }
  return n;
}
