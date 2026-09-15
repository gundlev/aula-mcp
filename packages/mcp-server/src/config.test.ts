/**
 * The server must refuse to start in any configuration where /mcp would be
 * reachable without a client credential (audit finding 1). These tests pin
 * the fail-closed rules; `AULA_MCP_ALLOW_REMOTE=1` alone is never enough.
 */

import { describe, expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ConfigError,
  isLoopbackHost,
  loadServerConfig,
  MIN_TOKEN_LENGTH,
  normaliseHostEntry,
} from './config.ts';

const TOKEN = 'synthetic-client-token-0123456789abcdef0123456789abcdef';

const remote = (extra: Record<string, string> = {}) => ({
  AULA_MCP_HOST: '0.0.0.0',
  AULA_MCP_ALLOW_REMOTE: '1',
  AULA_MCP_AUTH_TOKEN: TOKEN,
  AULA_MCP_ALLOWED_HOSTS: 'aula-mcp.example.com',
  ...extra,
});

describe('loadServerConfig — fail closed', () => {
  test('loopback with no credential configured refuses to start', () => {
    expect(() => loadServerConfig({})).toThrow(ConfigError);
    expect(() => loadServerConfig({})).toThrow(/No client credential/);
  });

  test('loopback may opt out of auth explicitly', () => {
    const cfg = loadServerConfig({ AULA_MCP_AUTH: 'none' });
    expect(cfg.auth).toEqual({ mode: 'none' });
    expect(cfg.host).toBe('127.0.0.1');
    expect(cfg.port).toBe(7878);
    expect(cfg.legacySse).toBe(false);
    expect(cfg.setupUi).toBeNull();
  });

  test('a non-loopback bind without AULA_MCP_ALLOW_REMOTE refuses', () => {
    expect(() => loadServerConfig({ AULA_MCP_HOST: '0.0.0.0', AULA_MCP_AUTH_TOKEN: TOKEN })).toThrow(
      /Refusing to bind/,
    );
  });

  test('AULA_MCP_ALLOW_REMOTE=1 is not authentication: still needs a token', () => {
    expect(() =>
      loadServerConfig({
        AULA_MCP_HOST: '0.0.0.0',
        AULA_MCP_ALLOW_REMOTE: '1',
        AULA_MCP_ALLOWED_HOSTS: 'aula-mcp.example.com',
      }),
    ).toThrow(/No client credential/);
  });

  test('AULA_MCP_AUTH=none is refused on a non-loopback bind', () => {
    expect(() => loadServerConfig(remote({ AULA_MCP_AUTH: 'none' }))).toThrow(
      /only allowed when binding to loopback/,
    );
  });

  test('a non-loopback bind requires an explicit Host allow-list', () => {
    expect(() => loadServerConfig(remote({ AULA_MCP_ALLOWED_HOSTS: '' }))).toThrow(
      /AULA_MCP_ALLOWED_HOSTS is required/,
    );
    expect(() => loadServerConfig(remote({ AULA_MCP_ALLOWED_HOSTS: '*' }))).toThrow(/"\*" is not accepted/);
  });

  test('short or whitespace-bearing tokens are rejected', () => {
    expect(() => loadServerConfig(remote({ AULA_MCP_AUTH_TOKEN: 'short' }))).toThrow(
      new RegExp(`at least ${MIN_TOKEN_LENGTH}`),
    );
    expect(() => loadServerConfig(remote({ AULA_MCP_AUTH_TOKEN: `${TOKEN} trailing` }))).toThrow(
      /whitespace/,
    );
  });

  test('unknown auth modes are rejected rather than treated as "none"', () => {
    expect(() => loadServerConfig(remote({ AULA_MCP_AUTH: 'basic' }))).toThrow(/not understood/);
  });

  test('a valid remote configuration keeps only a digest of the token', () => {
    const cfg = loadServerConfig(remote());
    expect(cfg.auth.mode).toBe('bearer');
    expect(JSON.stringify(cfg)).not.toContain(TOKEN);
    expect(cfg.allowedHosts).toEqual(['aula-mcp.example.com']);
    expect(cfg.allowRemote).toBe(true);
  });

  test('the token may come from a file (Docker/Coolify secrets)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aula-cfg-'));
    const file = join(dir, 'token');
    await writeFile(file, `${TOKEN}\n`, { mode: 0o600 });
    const cfg = loadServerConfig(remote({ AULA_MCP_AUTH_TOKEN: '', AULA_MCP_AUTH_TOKEN_FILE: file }));
    expect(cfg.auth.mode).toBe('bearer');
    expect(() =>
      loadServerConfig(remote({ AULA_MCP_AUTH_TOKEN: '', AULA_MCP_AUTH_TOKEN_FILE: join(dir, 'missing') })),
    ).toThrow(/could not be read/);
  });

  test('host entries and origins are normalised; bad origins are rejected', () => {
    const cfg = loadServerConfig(
      remote({
        AULA_MCP_ALLOWED_HOSTS: 'Aula-MCP.Example.com., other.example:8443',
        AULA_MCP_ALLOWED_ORIGINS: 'https://Assistant.Example.com/some/path',
      }),
    );
    expect(cfg.allowedHosts).toEqual(['aula-mcp.example.com', 'other.example:8443']);
    expect(cfg.allowedOrigins).toEqual(['https://assistant.example.com']);
    expect(() => loadServerConfig(remote({ AULA_MCP_ALLOWED_ORIGINS: 'not an origin' }))).toThrow(
      /not a valid origin/,
    );
    expect(normaliseHostEntry('Example.COM.')).toBe('example.com');
  });

  test('numeric limits are validated and default sensibly', () => {
    const cfg = loadServerConfig(remote());
    expect(cfg.maxBodyBytes).toBe(1024 * 1024);
    expect(cfg.requestsPerMinute).toBe(600);
    expect(cfg.authFailuresPerMinute).toBe(20);
    expect(cfg.maxConcurrentRequests).toBe(16);
    expect(cfg.httpMaxSessions).toBe(16);
    expect(() => loadServerConfig(remote({ AULA_MCP_PORT: '70000' }))).toThrow(/AULA_MCP_PORT/);
    expect(() => loadServerConfig(remote({ AULA_MCP_MAX_BODY_BYTES: 'lots' }))).toThrow(
      /AULA_MCP_MAX_BODY_BYTES/,
    );
  });

  test('the setup UI, when enabled, stays on loopback unless told otherwise', () => {
    const cfg = loadServerConfig(remote({ AULA_MCP_INGRESS_PORT: '8099' }));
    expect(cfg.setupUi).toEqual({ port: 8099, host: '127.0.0.1' });
    const ha = loadServerConfig(remote({ AULA_MCP_INGRESS_PORT: '8099', AULA_MCP_INGRESS_HOST: '0.0.0.0' }));
    expect(ha.setupUi).toEqual({ port: 8099, host: '0.0.0.0' });
  });

  test('isLoopbackHost', () => {
    expect(isLoopbackHost('127.0.0.1')).toBe(true);
    expect(isLoopbackHost('::1')).toBe(true);
    expect(isLoopbackHost('LOCALHOST')).toBe(true);
    expect(isLoopbackHost('0.0.0.0')).toBe(false);
    expect(isLoopbackHost('127.0.0.2')).toBe(false);
  });
});
