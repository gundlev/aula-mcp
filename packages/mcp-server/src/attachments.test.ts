/**
 * Security regression tests for attachment downloads (audit findings 2 and
 * 6). The audit made the server fetch a localhost URL, follow a redirect to
 * an internal PDF, and return its text; it also buffered whole responses
 * before checking the size cap. Every case here uses a fake transport and
 * fake resolver — no sockets are opened, and every "internal" destination
 * is synthetic.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import type { IncomingMessage } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import {
  type AttachmentPolicy,
  AttachmentStore,
  DEFAULT_ATTACHMENT_POLICY,
  downloadAttachment,
  hostAllowed,
  isPublicAddress,
  type LookupFn,
  type RequestFn,
  resolvePinnedAddress,
  safeFilename,
  validateAttachmentUrl,
} from './attachments.ts';

const PUBLIC_IP = '93.184.216.34';

const policy: AttachmentPolicy = {
  ...DEFAULT_ATTACHMENT_POLICY,
  allowedHosts: ['.aula.dk', '.cloudfront.net'],
  maxBytes: 64 * 1024,
  maxRedirects: 3,
  headersTimeoutMs: 500,
  idleTimeoutMs: 200,
  totalTimeoutMs: 5_000,
  maxErrorBodyBytes: 100,
};

const publicLookup: LookupFn = async () => [PUBLIC_IP];

interface FakeResponseOptions {
  status: number;
  headers?: Record<string, string>;
  body?: string | Buffer | Readable;
}

/**
 * Something shaped enough like `http.IncomingMessage` for the downloader:
 * a Readable with `statusCode` and `headers`. `destroyed` is tracked so a
 * test can assert the socket was dropped.
 */
function fakeResponse(opts: FakeResponseOptions): IncomingMessage {
  const body =
    opts.body instanceof Readable
      ? opts.body
      : Readable.from([Buffer.from(opts.body ?? '')], { objectMode: false });
  return Object.assign(body, {
    statusCode: opts.status,
    headers: Object.fromEntries(
      Object.entries(opts.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
    ),
  }) as unknown as IncomingMessage;
}

/** A body that emits `chunks` chunks of `chunkSize` bytes and then hangs. */
function endlessBody(chunkSize: number, chunks = Number.POSITIVE_INFINITY): Readable {
  let sent = 0;
  return new Readable({
    read() {
      if (sent < chunks) {
        sent++;
        this.push(Buffer.alloc(chunkSize, 0x41));
      }
      // Never push null: the peer "keeps sending" (or stalls).
    },
  });
}

interface Recorded {
  address: string;
  hostname: string;
  url: string;
}

/** Route fake responses by URL and record every connection attempt. */
function fakeTransport(
  routes: Record<string, (target: Recorded) => IncomingMessage | Promise<IncomingMessage>>,
): { request: RequestFn; recorded: Recorded[] } {
  const recorded: Recorded[] = [];
  const request: RequestFn = async ({ address, hostname, url }) => {
    const target = { address, hostname, url: url.toString() };
    recorded.push(target);
    const key = `${url.origin}${url.pathname}`;
    const handler = routes[key] ?? routes[url.toString()];
    if (!handler) throw new Error(`no fake route for ${url}`);
    return handler(target);
  };
  return { request, recorded };
}

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aula-att-test-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Static URL checks
// ---------------------------------------------------------------------------

describe('validateAttachmentUrl', () => {
  test('accepts an https URL on an allowed host (and its subdomains)', () => {
    expect(validateAttachmentUrl('https://aula.dk/x', policy).ok).toBe(true);
    expect(validateAttachmentUrl('https://files.aula.dk/x?sig=1', policy).ok).toBe(true);
    expect(validateAttachmentUrl('https://d1.cloudfront.net/a/b.pdf', policy).ok).toBe(true);
    // A trailing dot is the same host.
    expect(validateAttachmentUrl('https://files.aula.dk./x', policy).ok).toBe(true);
  });

  test('rejects every non-https scheme', () => {
    for (const url of [
      'http://files.aula.dk/x',
      'ftp://files.aula.dk/x',
      'file:///etc/passwd',
      'javascript:alert(1)',
      'gopher://files.aula.dk/',
    ]) {
      const r = validateAttachmentUrl(url, policy);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(['scheme_not_https', 'invalid_url']).toContain(r.reason);
    }
  });

  test('rejects loopback and other hosts that are not Aula storage', () => {
    for (const url of [
      'https://localhost/x',
      'https://localhost:443/x',
      'https://evil.example/x',
      'https://aula.dk.evil.example/x',
      'https://notaula.dk/x',
      'https://metadata.google.internal/computeMetadata/v1/',
    ]) {
      const r = validateAttachmentUrl(url, policy);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('host_not_allowed');
    }
  });

  test('rejects IP literals regardless of the allowlist', () => {
    const permissive = { ...policy, allowedHosts: ['127.0.0.1', '::1', '169.254.169.254'] };
    for (const url of [
      'https://127.0.0.1/x',
      'https://[::1]/x',
      'https://169.254.169.254/latest/meta-data/',
      'https://[::ffff:127.0.0.1]/x',
    ]) {
      const r = validateAttachmentUrl(url, permissive);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('ip_literal_not_allowed');
    }
  });

  test('rejects credentials and non-443 ports', () => {
    const creds = validateAttachmentUrl('https://user:pw@files.aula.dk/x', policy);
    expect(creds.ok).toBe(false);
    if (!creds.ok) expect(creds.reason).toBe('credentials_in_url');
    const port = validateAttachmentUrl('https://files.aula.dk:8443/x', policy);
    expect(port.ok).toBe(false);
    if (!port.ok) expect(port.reason).toBe('port_not_allowed');
    expect(validateAttachmentUrl('https://files.aula.dk:443/x', policy).ok).toBe(true);
  });

  test('rejects garbage', () => {
    const r = validateAttachmentUrl('not a url', policy);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('invalid_url');
  });

  test('hostAllowed: exact entries match only themselves', () => {
    expect(hostAllowed('cdn.example', ['cdn.example'])).toBe(true);
    expect(hostAllowed('sub.cdn.example', ['cdn.example'])).toBe(false);
    expect(hostAllowed('sub.cdn.example', ['.cdn.example'])).toBe(true);
    expect(hostAllowed('cdn.example', ['.cdn.example'])).toBe(true);
    expect(hostAllowed('xcdn.example', ['.cdn.example'])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Address checks
// ---------------------------------------------------------------------------

describe('isPublicAddress', () => {
  test('blocks loopback, private, link-local, metadata, CGNAT, multicast and reserved v4', () => {
    for (const ip of [
      '127.0.0.1',
      '127.255.255.254',
      '10.0.0.1',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254',
      '169.254.0.1',
      '100.64.0.1',
      '0.0.0.0',
      '0.1.2.3',
      '224.0.0.1',
      '239.255.255.255',
      '240.0.0.1',
      '255.255.255.255',
      '192.0.0.1',
      '198.18.0.1',
    ]) {
      expect(isPublicAddress(ip)).toBe(false);
    }
  });

  test('blocks loopback, unspecified, ULA, link-local, multicast and embedded-v4 v6 forms', () => {
    for (const ip of [
      '::1',
      '::',
      'fe80::1',
      'fc00::1',
      'fd12:3456::1',
      'ff02::1',
      '2001:db8::1',
      '100::1',
      '::ffff:127.0.0.1', // v4-mapped loopback
      '::ffff:10.0.0.1', // v4-mapped RFC 1918
      '::ffff:169.254.169.254', // v4-mapped metadata
      '::ffff:7f00:1', // same, hex form
      '::127.0.0.1', // v4-compatible
      '64:ff9b::127.0.0.1', // NAT64 loopback
      '64:ff9b::a00:1', // NAT64 10.0.0.1
      '2002:7f00:1::', // 6to4 embedding 127.0.0.1
      '2002:a9fe:a9fe::', // 6to4 embedding 169.254.169.254
      '2001::1', // Teredo
    ]) {
      expect(isPublicAddress(ip)).toBe(false);
    }
  });

  test('allows ordinary public addresses', () => {
    for (const ip of [
      '93.184.216.34',
      '8.8.8.8',
      '1.1.1.1',
      '2606:4700::1111',
      '2a00:1450:4001:80b::200e',
      '::ffff:8.8.8.8',
      '64:ff9b::808:808',
      '2002:0808:0808::',
    ]) {
      expect(isPublicAddress(ip)).toBe(true);
    }
  });

  test('rejects things that are not addresses at all', () => {
    expect(isPublicAddress('localhost')).toBe(false);
    expect(isPublicAddress('')).toBe(false);
    expect(isPublicAddress('999.1.1.1')).toBe(false);
  });
});

describe('resolvePinnedAddress', () => {
  test('pins to the first answer when every answer is public', async () => {
    const r = await resolvePinnedAddress('cdn.aula.dk', async () => [PUBLIC_IP, '8.8.8.8']);
    expect(r).toEqual({ ok: true, address: PUBLIC_IP, family: 4 });
  });

  test('refuses when any answer is non-public (rebinding via mixed answers)', async () => {
    const r = await resolvePinnedAddress('cdn.aula.dk', async () => [PUBLIC_IP, '127.0.0.1']);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('blocked_address');
  });

  test('refuses a v6 loopback answer', async () => {
    const r = await resolvePinnedAddress('cdn.aula.dk', async () => ['::1']);
    expect(r.ok).toBe(false);
  });

  test('reports resolver failures and empty answers', async () => {
    const failed = await resolvePinnedAddress('cdn.aula.dk', async () => {
      throw new Error('ENOTFOUND');
    });
    expect(failed.ok).toBe(false);
    if (!failed.ok) expect(failed.reason).toBe('dns_failed');
    const empty = await resolvePinnedAddress('cdn.aula.dk', async () => []);
    expect(empty.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Downloader
// ---------------------------------------------------------------------------

describe('downloadAttachment', () => {
  test('streams a valid attachment to disk with owner-only permissions, pinned to the resolved IP', async () => {
    const { request, recorded } = fakeTransport({
      'https://files.aula.dk/plan.pdf': () =>
        fakeResponse({
          status: 200,
          headers: { 'content-type': 'application/pdf', 'content-length': '16' },
          body: '%PDF-1.7 madplan',
        }),
    });
    const dest = join(dir, 'plan.pdf');
    const r = await downloadAttachment('https://files.aula.dk/plan.pdf?sig=abc', dest, policy, {
      request,
      lookup: publicLookup,
    });
    expect(r).toEqual({
      ok: true,
      bytes: 16,
      contentType: 'application/pdf',
      finalUrl: 'https://files.aula.dk/plan.pdf?sig=abc',
    });
    expect(await readFile(dest, 'utf8')).toBe('%PDF-1.7 madplan');
    expect((await stat(dest)).mode & 0o777).toBe(0o600);
    // The connection went to the address we checked, with the hostname for SNI.
    expect(recorded).toEqual([
      {
        address: PUBLIC_IP,
        hostname: 'files.aula.dk',
        url: 'https://files.aula.dk/plan.pdf?sig=abc',
      },
    ]);
    // No temp file left behind.
    expect(await readdir(dir)).toEqual(['plan.pdf']);
  });

  test('never connects to a URL that fails the static checks', async () => {
    const { request, recorded } = fakeTransport({});
    for (const url of [
      'http://files.aula.dk/plan.pdf',
      'https://127.0.0.1/plan.pdf',
      'https://localhost:443/plan.pdf',
      'https://attacker.example/plan.pdf',
    ]) {
      const r = await downloadAttachment(url, join(dir, 'x'), policy, {
        request,
        lookup: publicLookup,
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toBe('url_rejected');
    }
    expect(recorded).toEqual([]);
  });

  test('refuses an allowed hostname that resolves to loopback or metadata', async () => {
    const { request, recorded } = fakeTransport({});
    for (const answer of ['127.0.0.1', '169.254.169.254', '10.1.2.3', '::1', '::ffff:127.0.0.1']) {
      const r = await downloadAttachment('https://files.aula.dk/plan.pdf', join(dir, 'x'), policy, {
        request,
        lookup: async () => [answer],
      });
      expect(r).toEqual({
        ok: false,
        error: 'address_rejected',
        reason: 'blocked_address',
        hop: 0,
      });
    }
    expect(recorded).toEqual([]);
  });

  test('a redirect to an internal http URL is rejected without being followed', async () => {
    // The audit's chain: a "valid" first hop redirecting to an internal PDF.
    const { request, recorded } = fakeTransport({
      'https://files.aula.dk/plan.pdf': () =>
        fakeResponse({ status: 302, headers: { location: 'http://127.0.0.1:8080/secret.pdf' } }),
    });
    const r = await downloadAttachment('https://files.aula.dk/plan.pdf', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r).toEqual({ ok: false, error: 'url_rejected', reason: 'scheme_not_https', hop: 1 });
    expect(recorded.map((t) => t.url)).toEqual(['https://files.aula.dk/plan.pdf']);
  });

  test('a redirect to an https host off the allowlist is rejected', async () => {
    const { request, recorded } = fakeTransport({
      'https://files.aula.dk/plan.pdf': () =>
        fakeResponse({ status: 307, headers: { location: 'https://localhost/secret.pdf' } }),
    });
    const r = await downloadAttachment('https://files.aula.dk/plan.pdf', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r).toEqual({ ok: false, error: 'url_rejected', reason: 'host_not_allowed', hop: 1 });
    expect(recorded).toHaveLength(1);
  });

  test('a redirect to an allowed host that resolves internally is rejected (DNS rebinding)', async () => {
    const { request, recorded } = fakeTransport({
      'https://files.aula.dk/plan.pdf': () =>
        fakeResponse({ status: 301, headers: { location: 'https://internal.aula.dk/secret.pdf' } }),
    });
    const lookup: LookupFn = async (host) =>
      host === 'internal.aula.dk' ? ['169.254.169.254'] : [PUBLIC_IP];
    const r = await downloadAttachment('https://files.aula.dk/plan.pdf', join(dir, 'x'), policy, {
      request,
      lookup,
    });
    expect(r).toEqual({ ok: false, error: 'address_rejected', reason: 'blocked_address', hop: 1 });
    expect(recorded).toHaveLength(1);
  });

  test('a valid redirect chain is followed, re-resolving every hop', async () => {
    const { request, recorded } = fakeTransport({
      'https://files.aula.dk/plan.pdf': () =>
        fakeResponse({ status: 302, headers: { location: '/moved/plan.pdf' } }),
      'https://files.aula.dk/moved/plan.pdf': () =>
        fakeResponse({
          status: 302,
          headers: { location: 'https://d1.cloudfront.net/final.pdf?sig=1' },
        }),
      'https://d1.cloudfront.net/final.pdf': () =>
        fakeResponse({ status: 200, body: '%PDF-final' }),
    });
    const looked: string[] = [];
    const r = await downloadAttachment('https://files.aula.dk/plan.pdf', join(dir, 'x'), policy, {
      request,
      lookup: async (host) => {
        looked.push(host);
        return [PUBLIC_IP];
      },
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.finalUrl).toBe('https://d1.cloudfront.net/final.pdf?sig=1');
    expect(looked).toEqual(['files.aula.dk', 'files.aula.dk', 'd1.cloudfront.net']);
    expect(recorded.map((t) => t.hostname)).toEqual([
      'files.aula.dk',
      'files.aula.dk',
      'd1.cloudfront.net',
    ]);
  });

  test('stops after maxRedirects hops', async () => {
    const { request, recorded } = fakeTransport({
      'https://files.aula.dk/loop': () =>
        fakeResponse({ status: 302, headers: { location: 'https://files.aula.dk/loop' } }),
    });
    const r = await downloadAttachment('https://files.aula.dk/loop', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r).toEqual({ ok: false, error: 'too_many_redirects', hop: 3 });
    expect(recorded).toHaveLength(4);
  });

  test('reads at most maxErrorBodyBytes of a non-2xx body and drops the socket', async () => {
    const body = endlessBody(1024);
    const { request } = fakeTransport({
      'https://files.aula.dk/denied': () => fakeResponse({ status: 403, body }),
    });
    const r = await downloadAttachment('https://files.aula.dk/denied', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r.ok).toBe(false);
    if (!r.ok && r.error === 'download_failed') {
      expect(r.httpStatus).toBe(403);
      expect(r.body.length).toBeLessThanOrEqual(policy.maxErrorBodyBytes);
    } else {
      throw new Error(`unexpected ${JSON.stringify(r)}`);
    }
    expect(body.destroyed).toBe(true);
    expect(await readdir(dir)).toEqual([]);
  });

  test('rejects on a declared Content-Length over the cap before reading the body', async () => {
    let reads = 0;
    const body = new Readable({
      read() {
        reads++;
        this.push(Buffer.alloc(1024));
      },
    });
    const { request } = fakeTransport({
      'https://files.aula.dk/big': () =>
        fakeResponse({
          status: 200,
          headers: { 'content-length': String(policy.maxBytes + 1) },
          body,
        }),
    });
    const r = await downloadAttachment('https://files.aula.dk/big', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r).toEqual({
      ok: false,
      error: 'attachment_too_large',
      bytes: policy.maxBytes + 1,
      maxBytes: policy.maxBytes,
    });
    expect(reads).toBe(0);
    expect(body.destroyed).toBe(true);
  });

  test('a chunked body with no Content-Length is cut off at the cap while streaming', async () => {
    const body = endlessBody(4096);
    const { request } = fakeTransport({
      'https://files.aula.dk/chunked': () => fakeResponse({ status: 200, body }),
    });
    const dest = join(dir, 'chunked.bin');
    const r = await downloadAttachment('https://files.aula.dk/chunked', dest, policy, {
      request,
      lookup: publicLookup,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('attachment_too_large');
    expect(body.destroyed).toBe(true);
    // Neither the final file nor the .part survives.
    expect(await readdir(dir)).toEqual([]);
  });

  test('a misleading small Content-Length does not disable the byte counter', async () => {
    const body = endlessBody(8192);
    const { request } = fakeTransport({
      'https://files.aula.dk/lying': () =>
        fakeResponse({ status: 200, headers: { 'content-length': '10' }, body }),
    });
    const r = await downloadAttachment('https://files.aula.dk/lying', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('attachment_too_large');
    expect(body.destroyed).toBe(true);
  });

  test('a stalled body hits the idle deadline and is cancelled', async () => {
    const body = endlessBody(16, 1); // one chunk, then silence
    const { request } = fakeTransport({
      'https://files.aula.dk/stall': () => fakeResponse({ status: 200, body }),
    });
    const started = Date.now();
    const r = await downloadAttachment('https://files.aula.dk/stall', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r).toEqual({ ok: false, error: 'download_timeout', phase: 'body' });
    expect(Date.now() - started).toBeLessThan(policy.totalTimeoutMs);
    expect(body.destroyed).toBe(true);
    expect(await readdir(dir)).toEqual([]);
  });

  test('a server that never sends headers hits the headers deadline', async () => {
    const request: RequestFn = ({ headersTimeoutMs }) =>
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error('timed out waiting for response headers')),
          headersTimeoutMs,
        ),
      );
    const r = await downloadAttachment('https://files.aula.dk/slow', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r).toEqual({ ok: false, error: 'download_timeout', phase: 'headers' });
  });

  test('the total deadline caps a slow trickle even when chunks keep arriving', async () => {
    const trickle = new Readable({
      read() {
        setTimeout(() => this.push(Buffer.alloc(16)), 50);
      },
    });
    const { request } = fakeTransport({
      'https://files.aula.dk/trickle': () => fakeResponse({ status: 200, body: trickle }),
    });
    const r = await downloadAttachment(
      'https://files.aula.dk/trickle',
      join(dir, 'x'),
      {
        ...policy,
        idleTimeoutMs: 1_000,
        totalTimeoutMs: 300,
      },
      { request, lookup: publicLookup },
    );
    expect(r).toEqual({ ok: false, error: 'download_timeout', phase: 'total' });
    expect(trickle.destroyed).toBe(true);
  });

  test('a network error mid-body removes the partial file', async () => {
    const body = new Readable({
      read() {
        this.push(Buffer.alloc(100));
        this.destroy(new Error('ECONNRESET'));
      },
    });
    const { request } = fakeTransport({
      'https://files.aula.dk/reset': () => fakeResponse({ status: 200, body }),
    });
    const r = await downloadAttachment('https://files.aula.dk/reset', join(dir, 'x'), policy, {
      request,
      lookup: publicLookup,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('network_error');
    expect(await readdir(dir)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

describe('AttachmentStore', () => {
  function storeWith(
    routes: Parameters<typeof fakeTransport>[0],
    options: Partial<ConstructorParameters<typeof AttachmentStore>[0]> = {},
  ): { store: AttachmentStore; recorded: Recorded[] } {
    const { request, recorded } = fakeTransport(routes);
    const store = new AttachmentStore({
      rootDir: join(dir, 'store'),
      policy,
      deps: { request, lookup: publicLookup },
      ...options,
    });
    return { store, recorded };
  }

  const pdfRoute = (bytes = 16) => ({
    'https://files.aula.dk/plan.pdf': () =>
      fakeResponse({
        status: 200,
        headers: { 'content-type': 'application/pdf' },
        body: Buffer.alloc(bytes, 0x50),
      }),
  });

  test('stores a download under an opaque id inside its own 0700 root and never records the URL', async () => {
    const { store } = storeWith(pdfRoute());
    const r = await store.fetch({
      url: 'https://files.aula.dk/plan.pdf?sig=SECRET',
      filename: 'Madplan uge 38.pdf',
      source: { kind: 'post', id: 314, index: 0 },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.entry.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(r.entry.path).toBe(join(dir, 'store', `att-${r.entry.id}`, 'Madplan uge 38.pdf'));
    expect(r.entry.filename).toBe('Madplan uge 38.pdf');
    expect(r.entry.mediaType).toBe('application/pdf');
    expect(r.entry.bytes).toBe(16);
    expect(JSON.stringify(r.entry)).not.toContain('SECRET');
    expect((await stat(join(dir, 'store'))).mode & 0o777).toBe(0o700);
    expect((await stat(r.entry.path)).mode & 0o777).toBe(0o600);
    const resolved = await store.resolve(r.entry.id);
    expect(resolved.ok).toBe(true);
    if (resolved.ok) expect(resolved.size).toBe(16);
    await store.dispose();
  });

  test('scrubs traversal out of the on-disk name but keeps the display name', async () => {
    const { store } = storeWith(pdfRoute());
    const r = await store.fetch({
      url: 'https://files.aula.dk/plan.pdf',
      filename: '../../etc/passwd',
      source: { kind: 'thread', id: 1, index: 0 },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.entry.filename).toBe('../../etc/passwd');
    expect(r.entry.path.startsWith(join(dir, 'store', 'att-'))).toBe(true);
    expect(r.entry.path.endsWith('/.._.._etc_passwd')).toBe(true);
    await store.dispose();
  });

  test('a rejected download leaves nothing on disk and returns the policy reason', async () => {
    const { store } = storeWith({});
    const r = await store.fetch({
      url: 'https://127.0.0.1/secret.pdf',
      filename: 'secret.pdf',
      source: { kind: 'post', id: 1, index: 0 },
    });
    expect(r).toEqual({
      ok: false,
      error: 'url_rejected',
      reason: 'ip_literal_not_allowed',
      hop: 0,
    });
    expect(store.size).toBe(0);
    expect(await readdir(join(dir, 'store'))).toEqual([]);
  });

  test('init purges leftover att-* directories from a previous process but nothing else', async () => {
    const root = join(dir, 'store');
    await mkdir(join(root, 'att-stale'), { recursive: true });
    await writeFile(join(root, 'att-stale', 'old.pdf'), 'x');
    await writeFile(join(root, 'unrelated.txt'), 'keep me');
    const { store } = storeWith({});
    await store.init();
    expect((await readdir(root)).sort()).toEqual(['unrelated.txt']);
    await store.dispose();
  });

  test('evicts the oldest entries to stay under the total-bytes quota', async () => {
    const { store } = storeWith(pdfRoute(1000), { maxTotalBytes: 2500 });
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const r = await store.fetch({
        url: 'https://files.aula.dk/plan.pdf',
        filename: `f${i}.pdf`,
        source: { kind: 'post', id: i, index: 0 },
      });
      expect(r.ok).toBe(true);
      if (r.ok) ids.push(r.entry.id);
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    expect(store.size).toBe(2);
    expect(store.totalBytes).toBe(2000);
    expect((await store.resolve(ids[0] as string)).ok).toBe(false);
    expect((await store.resolve(ids[2] as string)).ok).toBe(true);
    // The evicted file is gone from disk, not just from the map.
    expect(await readdir(join(dir, 'store'))).toHaveLength(2);
    await store.dispose();
  });

  test('caps the number of live entries', async () => {
    const { store } = storeWith(pdfRoute(10), { maxEntries: 2 });
    for (let i = 0; i < 3; i++) {
      await store.fetch({
        url: 'https://files.aula.dk/plan.pdf',
        filename: `f${i}.pdf`,
        source: { kind: 'post', id: i, index: 0 },
      });
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    expect(store.size).toBe(2);
    await store.dispose();
  });

  test('refuses a single attachment larger than the whole quota', async () => {
    const { store } = storeWith(pdfRoute(3000), { maxTotalBytes: 2000 });
    const r = await store.fetch({
      url: 'https://files.aula.dk/plan.pdf',
      filename: 'huge.pdf',
      source: { kind: 'post', id: 1, index: 0 },
    });
    expect(r).toEqual({ ok: false, error: 'storage_quota_exceeded', maxTotalBytes: 2000 });
    expect(await readdir(join(dir, 'store'))).toEqual([]);
    await store.dispose();
  });

  test('limits concurrent downloads', async () => {
    const stalls: Readable[] = [];
    const { store } = storeWith(
      {
        'https://files.aula.dk/slow.pdf': () => {
          const body = endlessBody(16, 1);
          stalls.push(body);
          return fakeResponse({ status: 200, body });
        },
      },
      { maxConcurrentDownloads: 1 },
    );
    const first = store.fetch({
      url: 'https://files.aula.dk/slow.pdf',
      filename: 'a.pdf',
      source: { kind: 'post', id: 1, index: 0 },
    });
    // Give the first download a tick to be counted as active.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const second = await store.fetch({
      url: 'https://files.aula.dk/slow.pdf',
      filename: 'b.pdf',
      source: { kind: 'post', id: 2, index: 0 },
    });
    expect(second).toEqual({ ok: false, error: 'too_many_downloads', maxConcurrent: 1 });
    const r = await first;
    expect(r.ok).toBe(false); // the stall times out
    await store.dispose();
  });

  test('expired entries are swept and their files removed', async () => {
    const { store } = storeWith(pdfRoute(), { ttlMs: 30 });
    const r = await store.fetch({
      url: 'https://files.aula.dk/plan.pdf',
      filename: 'plan.pdf',
      source: { kind: 'post', id: 1, index: 0 },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    await new Promise((resolve) => setTimeout(resolve, 40));
    const resolved = await store.resolve(r.entry.id);
    expect(resolved).toEqual({ ok: false, error: 'attachment_expired' });
    expect(store.size).toBe(0);
    expect(await readdir(join(dir, 'store'))).toEqual([]);
    await store.dispose();
  });

  test('resolve rejects unknown ids, symlink escapes and non-regular files', async () => {
    const { store } = storeWith(pdfRoute());
    expect(await store.resolve('00000000-0000-4000-8000-000000000000')).toEqual({
      ok: false,
      error: 'unknown_attachment',
    });

    const r = await store.fetch({
      url: 'https://files.aula.dk/plan.pdf',
      filename: 'plan.pdf',
      source: { kind: 'post', id: 1, index: 0 },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;

    // Swap the stored file for a symlink pointing outside the root.
    const outside = join(dir, 'private.pdf');
    await writeFile(outside, '%PDF-1.4 private');
    await rm(r.entry.path);
    await symlink(outside, r.entry.path);
    const viaSymlink = await store.resolve(r.entry.id);
    expect(viaSymlink.ok).toBe(false);
    if (!viaSymlink.ok) expect(viaSymlink.error).toBe('attachment_unreadable');

    // A directory in place of the file.
    await rm(r.entry.path);
    await mkdir(r.entry.path);
    const viaDir = await store.resolve(r.entry.id);
    expect(viaDir.ok).toBe(false);
    if (!viaDir.ok) expect(viaDir.error).toBe('attachment_unreadable');

    // Gone entirely.
    await rm(r.entry.path, { recursive: true });
    const gone = await store.resolve(r.entry.id);
    expect(gone.ok).toBe(false);
    await store.dispose();
  });

  test('resolve refuses a file that grew past the policy cap after download', async () => {
    const { store } = storeWith(pdfRoute());
    const r = await store.fetch({
      url: 'https://files.aula.dk/plan.pdf',
      filename: 'plan.pdf',
      source: { kind: 'post', id: 1, index: 0 },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    await writeFile(r.entry.path, Buffer.alloc(policy.maxBytes + 1));
    const resolved = await store.resolve(r.entry.id);
    expect(resolved.ok).toBe(false);
    if (!resolved.ok) expect(resolved.detail).toContain('policy cap');
    await store.dispose();
  });

  test('dispose removes every live file', async () => {
    const { store } = storeWith(pdfRoute());
    await store.fetch({
      url: 'https://files.aula.dk/plan.pdf',
      filename: 'plan.pdf',
      source: { kind: 'post', id: 1, index: 0 },
    });
    expect(store.size).toBe(1);
    await store.dispose();
    expect(store.size).toBe(0);
    expect(await readdir(join(dir, 'store'))).toEqual([]);
  });
});

describe('safeFilename', () => {
  test('keeps letters (including Danish), digits, dot, dash, underscore and space', () => {
    expect(safeFilename('Bålhytten på Ærø - lørdag.pdf')).toBe('Bålhytten på Ærø - lørdag.pdf');
    expect(safeFilename('plan_v2.pdf')).toBe('plan_v2.pdf');
  });

  test('scrubs separators, traversal and control characters', () => {
    expect(safeFilename('../../etc/pas swd.pdf')).toBe('.._.._etc_pas swd.pdf');
    expect(safeFilename('..\\..\\win.ini')).toBe('.._.._win.ini');
    expect(safeFilename('a\u0000b.pdf')).toBe('a_b.pdf');
    expect(safeFilename('x/y')).toBe('x_y');
  });

  test('never yields an empty or dot-only name', () => {
    expect(safeFilename('')).toBe('attachment.bin');
    expect(safeFilename('.')).toBe('attachment.bin');
    expect(safeFilename('..')).toBe('attachment.bin');
    expect(safeFilename('   ')).toBe('attachment.bin');
    expect(safeFilename('...')).toBe('attachment.bin');
    // A run of separators collapses to a single underscore — harmless.
    expect(safeFilename('///')).toBe('_');
  });

  test('bounds the length', () => {
    expect(safeFilename('a'.repeat(500)).length).toBe(120);
  });
});
