/**
 * Security regression tests for debug-trace redaction (audit finding 4).
 *
 * The September 2026 audit showed synthetic OAuth codes surviving in
 * `Location` headers and synthetic SAML / CSRF material surviving in HTML
 * response bodies. Every marker below is synthetic; the assertion in each
 * case is simply that the marker is gone from whatever gets persisted.
 */

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AulaHttpClient } from './http.ts';
import {
  InMemoryTracer,
  JsonlFileTracer,
  redactText,
  sanitizeHeaders,
  sanitizeLogMeta,
  sanitizeRequestBody,
  sanitizeResponseBody,
  sanitizeUrl,
} from './wire-tracer.ts';

const CODE = 'SYNTH-AUTH-CODE-7f3a9c';
const STATE = 'SYNTH-STATE-51d0';
const SAML = 'U1lOVEgtU0FNTC1SRVNQT05TRQ==SYNTHSAML';
const CSRF = 'SYNTH-CSRF-2b9e';
const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJTWU5USCJ9.SYNTH-SIGNATURE-c0ffee';

describe('URL-bearing headers', () => {
  test('Location with an OAuth code and state is redacted', () => {
    const out = sanitizeHeaders({
      location: `https://www.aula.dk/auth/callback?code=${CODE}&state=${STATE}&keep=1`,
    });
    expect(out.location).not.toContain(CODE);
    expect(out.location).not.toContain(STATE);
    expect(out.location).toContain('keep=1');
    expect(out.location).toContain('https://www.aula.dk/auth/callback');
  });

  test('relative Location values are handled too', () => {
    const out = sanitizeHeaders({ location: `/cb?code=${CODE}` });
    expect(out.location).not.toContain(CODE);
    expect(out.location?.startsWith('/cb?')).toBe(true);
  });

  test('Referer and a fragment-carried token are redacted', () => {
    const out = sanitizeHeaders({
      referer: `https://broker.unilogin.dk/#access_token=${JWT}&state=${STATE}`,
    });
    expect(out.referer).not.toContain('SYNTH-SIGNATURE');
    expect(out.referer).not.toContain(STATE);
  });

  test('Headers object with a mixed-case Location is redacted', () => {
    const h = new Headers();
    h.set('Location', `https://x.test/?code=${CODE}`);
    expect(sanitizeHeaders(h).location).not.toContain(CODE);
  });

  test('a JWT in an arbitrary header is redacted', () => {
    const out = sanitizeHeaders({ 'x-debug': `token ${JWT} issued` });
    expect(out['x-debug']).not.toContain('SYNTH-SIGNATURE');
    expect(out['x-debug']).toContain('issued');
  });
});

describe('HTML response bodies', () => {
  const html = `<!doctype html><html><body>
<form method="post" action="https://www.aula.dk/saml/acs">
  <input type="hidden" name="SAMLResponse" value="${SAML}" />
  <input type='hidden' name='RelayState' value='${STATE}'>
  <input type="hidden" name="__RequestVerificationToken" value="${CSRF}">
  <input type="hidden" id="antiForgeryNonce" value="${CSRF}-nonce">
  <input type="text" name="search" value="visible-and-harmless">
  <input type="password" name="pwd" value="hunter2">
  <noscript><input type="submit" value="Continue"></noscript>
</form>
<meta name="csrf-token" content="${CSRF}-meta">
<script>window.__STATE__ = {"access_token":"${JWT}","expires_in":3600};
var authCode = "${CODE}"; var code='${CODE}';</script>
<a href="https://www.aula.dk/cb?code=${CODE}&amp;state=${STATE}">continue</a>
</body></html>`;

  test('hidden SAML / CSRF inputs, meta tags and inline JSON are redacted', () => {
    const { text } = sanitizeResponseBody(html, 1_000_000);
    expect(text).not.toContain(SAML);
    expect(text).not.toContain(STATE);
    expect(text).not.toContain(CSRF);
    expect(text).not.toContain(JWT);
    expect(text).not.toContain('SYNTH-SIGNATURE');
    expect(text).not.toContain(CODE);
    expect(text).not.toContain('hunter2');
    // Structure and harmless content survive so the transcript stays useful.
    expect(text).toContain('name="SAMLResponse"');
    expect(text).toContain('action="https://www.aula.dk/saml/acs"');
    expect(text).toContain('visible-and-harmless');
    expect(text).toContain('"expires_in":3600');
  });

  test('Aula identifiers that merely end in "Code" are kept', () => {
    const body = JSON.stringify({
      institutionCode: 'D12345',
      countryCode: 'DK',
      token_type: 'Bearer',
      accessToken: 'SYNTH-CAMEL-TOKEN',
      authCode: CODE,
    });
    const { text } = sanitizeResponseBody(body);
    expect(text).toContain('D12345');
    expect(text).toContain('"countryCode":"DK"');
    expect(text).toContain('"token_type":"Bearer"');
    expect(text).not.toContain('SYNTH-CAMEL-TOKEN');
    expect(text).not.toContain(CODE);
    const url = redactText(`https://x.test/?institutionCode=D12345&accessToken=SYNTH-URL-TOKEN`);
    expect(url).toContain('institutionCode=D12345');
    expect(url).not.toContain('SYNTH-URL-TOKEN');
  });

  test('redaction happens before truncation', () => {
    // The secret sits well past the cap: a truncate-first implementation
    // would drop it by accident here but keep it whenever the body is short.
    const body = `${'x'.repeat(200)}<input type="hidden" name="SAMLResponse" value="${SAML}">`;
    const { text, bytes } = sanitizeResponseBody(body, 100);
    expect(bytes).toBe(body.length);
    expect(text).not.toContain(SAML);
    const { text: full } = sanitizeResponseBody(body, 10_000);
    expect(full).not.toContain(SAML);
    expect(full).toContain('name="SAMLResponse"');
  });

  test('form-urlencoded strings and JSON error bodies are redacted', () => {
    const form = `grant_type=authorization_code&code=${CODE}&code_verifier=SYNTH-VERIFIER&redirect_uri=https%3A%2F%2Fx`;
    expect(sanitizeRequestBody(form)).not.toContain(CODE);
    expect(sanitizeRequestBody(form)).not.toContain('SYNTH-VERIFIER');
    expect(sanitizeRequestBody(form)).toContain('grant_type=authorization_code');

    const err = JSON.stringify({
      error: 'invalid_grant',
      error_description: `Rejected Bearer ${JWT}; request was code=${CODE}&state=${STATE}`,
      details: { samlResponse: SAML, code: CODE, nested: [{ refresh_token: 'SYNTH-RT' }] },
    });
    const { text } = sanitizeResponseBody(err);
    expect(text).not.toContain(CODE);
    expect(text).not.toContain(STATE);
    expect(text).not.toContain(JWT);
    expect(text).not.toContain(SAML);
    expect(text).not.toContain('SYNTH-RT');
    expect(text).toContain('invalid_grant');
  });

  test('an HTML body is never percent-encoded by the URL sanitiser', () => {
    const { text } = sanitizeResponseBody(`<p>see ?code=${CODE}</p>`, 10_000);
    expect(text.startsWith('<p>see ')).toBe(true);
    expect(text).not.toContain(CODE);
  });

  test('redactText is idempotent', () => {
    const once = redactText(html);
    expect(redactText(once)).toBe(once);
    const url = sanitizeUrl(`https://x.test/?code=${CODE}`);
    expect(sanitizeUrl(url)).toBe(url);
  });
});

describe('log meta', () => {
  test('a Location-shaped string nested in meta is redacted', () => {
    const meta = sanitizeLogMeta({
      hops: [{ location: `https://x.test/cb?code=${CODE}&state=${STATE}` }],
      html: `<input type="hidden" name="SAMLResponse" value="${SAML}">`,
    });
    const s = JSON.stringify(meta);
    expect(s).not.toContain(CODE);
    expect(s).not.toContain(STATE);
    expect(s).not.toContain(SAML);
  });
});

describe('network error entries', () => {
  test('the failure message recorded by AulaHttpClient carries no token', async () => {
    const tracer = new InMemoryTracer();
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.reject(
        new Error(`connect ECONNREFUSED for https://x.test/?access_token=${JWT}`),
      )) as unknown as typeof globalThis.fetch;
    try {
      const http = new AulaHttpClient({ tracer });
      await expect(http.request(`https://x.test/?access_token=${JWT}`)).rejects.toThrow();
    } finally {
      globalThis.fetch = realFetch;
    }
    const entry = tracer.entries[0];
    expect(entry).toBeDefined();
    const serialised = JSON.stringify(entry);
    expect(serialised).not.toContain(JWT);
    expect(serialised).not.toContain('SYNTH-SIGNATURE');
    expect(entry?.status).toBe(0);
  });
});

describe('JsonlFileTracer', () => {
  let dir: string | undefined;
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = undefined;
  });

  const entry = (seq: number, body = 'ok') => ({
    ts: new Date().toISOString(),
    seq,
    method: 'GET',
    url: 'https://x.test/',
    requestHeaders: {},
    requestBody: null,
    status: 200,
    responseHeaders: {},
    responseBody: body,
    responseBodyBytes: body.length,
    durationMs: 1,
  });

  test('creates the transcript 0600 inside a 0700 directory', async () => {
    dir = await mkdtemp(join(tmpdir(), 'aula-tracer-'));
    const path = join(dir, 'nested', 'login.jsonl');
    const tracer = new JsonlFileTracer(path);
    tracer.record(entry(1));
    await tracer.flush();
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(join(dir, 'nested'))).mode & 0o777).toBe(0o700);
    expect((await readFile(path, 'utf8')).trim().split('\n')).toHaveLength(1);
  });

  test('stops at the size cap and records that it did', async () => {
    dir = await mkdtemp(join(tmpdir(), 'aula-tracer-'));
    const path = join(dir, 'login.jsonl');
    const tracer = new JsonlFileTracer(path, { maxBytes: 600 });
    for (let i = 0; i < 20; i++) tracer.record(entry(i, 'y'.repeat(100)));
    await tracer.flush();
    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    const last = JSON.parse(lines[lines.length - 1] ?? '{}') as { truncated?: boolean };
    expect(last.truncated).toBe(true);
    expect(lines.length).toBeLessThan(20);
    expect((await stat(path)).size).toBeLessThan(600 + 200);
  });
});
