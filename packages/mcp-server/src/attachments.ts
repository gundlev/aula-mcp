/**
 * Attachment downloads, bounded and pinned.
 *
 * Aula hands out CloudFront-style presigned URLs for message and post
 * attachments. Before the September 2026 audit the MCP tools fetched
 * whatever URL they were given (including caller-supplied ones), followed
 * every redirect, and only checked the size after buffering the whole
 * response. This module is the single path every attachment download takes:
 *
 *   1. `validateAttachmentUrl` — https only, no credentials, hostname on the
 *      allowlist, never an IP literal.
 *   2. `resolvePinnedAddress` — resolve the hostname, refuse if *any* answer
 *      is loopback / private / link-local / metadata / multicast, and pin the
 *      connection to the address that was checked. The TLS handshake still
 *      validates the certificate against the original hostname (SNI), so a
 *      DNS answer that changes between check and connect cannot redirect us.
 *   3. `downloadAttachment` — streams to disk with a hard byte counter,
 *      connect / idle / total deadlines, a bounded error-body read, and
 *      re-runs steps 1–2 for every redirect hop.
 *
 * `AttachmentStore` owns the on-disk files: every download lands under an
 * opaque server-issued id inside a dedicated directory, with a total-bytes
 * quota, an entry cap and a TTL, so the temp dir cannot grow without bound
 * and a later tool call can only reach files this process downloaded.
 */

import { lookup } from 'node:dns/promises';
import { lstat, mkdir, open, readdir, realpath, rename, rm, stat } from 'node:fs/promises';
import type { IncomingMessage } from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve as resolvePath, sep } from 'node:path';
import type { Logger } from '@aula-mcp/aula-auth';
import { silentLogger } from '@aula-mcp/aula-auth';

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export interface AttachmentPolicy {
  /** Hostname suffixes (leading dot = any subdomain) or exact hostnames. */
  allowedHosts: readonly string[];
  /** Hard cap on the bytes written to disk for one attachment. */
  maxBytes: number;
  /** Redirect hops to follow; each hop is re-validated. */
  maxRedirects: number;
  /** Time allowed for connect + TLS + response headers. */
  headersTimeoutMs: number;
  /** Time allowed between two body chunks. */
  idleTimeoutMs: number;
  /** Wall-clock budget for the whole download including redirects. */
  totalTimeoutMs: number;
  /** How much of a non-2xx body is read before the socket is dropped. */
  maxErrorBodyBytes: number;
}

/**
 * Where Aula serves attachments from. The presigned links are CloudFront /
 * S3 URLs on AWS-owned domains plus Aula's own. The suffixes are broad on
 * purpose — Aula does not document which distribution it uses — but the
 * URL itself always comes from an authenticated Aula API response, never
 * from the caller, and every resolved address is still checked. Tighten
 * with AULA_MCP_ATTACHMENT_HOSTS once the real hostnames are known.
 */
export const DEFAULT_ATTACHMENT_HOSTS: readonly string[] = [
  '.aula.dk',
  '.cloudfront.net',
  '.amazonaws.com',
];

export const DEFAULT_ATTACHMENT_POLICY: AttachmentPolicy = {
  allowedHosts: DEFAULT_ATTACHMENT_HOSTS,
  maxBytes: 50 * 1024 * 1024,
  maxRedirects: 3,
  headersTimeoutMs: 15_000,
  idleTimeoutMs: 15_000,
  totalTimeoutMs: 60_000,
  maxErrorBodyBytes: 4 * 1024,
};

/** Build the policy from the environment (`AULA_MCP_ATTACHMENT_*`). */
export function attachmentPolicyFromEnv(env: NodeJS.ProcessEnv = process.env): AttachmentPolicy {
  const hosts = (env.AULA_MCP_ATTACHMENT_HOSTS ?? '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  return {
    ...DEFAULT_ATTACHMENT_POLICY,
    allowedHosts: hosts.length ? hosts : DEFAULT_ATTACHMENT_HOSTS,
    maxBytes: positiveInt(env.AULA_MCP_ATTACHMENT_MAX_BYTES, DEFAULT_ATTACHMENT_POLICY.maxBytes),
    totalTimeoutMs: positiveInt(
      env.AULA_MCP_ATTACHMENT_TIMEOUT_MS,
      DEFAULT_ATTACHMENT_POLICY.totalTimeoutMs,
    ),
  };
}

function positiveInt(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

export type AttachmentUrlRejection =
  | 'invalid_url'
  | 'scheme_not_https'
  | 'credentials_in_url'
  | 'port_not_allowed'
  | 'ip_literal_not_allowed'
  | 'host_not_allowed';

export type UrlCheck = { ok: true; url: URL } | { ok: false; reason: AttachmentUrlRejection };

/** Static checks on a URL string — no network. */
export function validateAttachmentUrl(raw: string, policy: AttachmentPolicy): UrlCheck {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid_url' };
  }
  if (url.protocol !== 'https:') return { ok: false, reason: 'scheme_not_https' };
  if (url.username || url.password) return { ok: false, reason: 'credentials_in_url' };
  if (url.port && url.port !== '443') return { ok: false, reason: 'port_not_allowed' };
  const host = normaliseHost(url.hostname);
  if (!host) return { ok: false, reason: 'invalid_url' };
  if (isIP(host) || host.startsWith('[')) return { ok: false, reason: 'ip_literal_not_allowed' };
  if (!hostAllowed(host, policy.allowedHosts)) return { ok: false, reason: 'host_not_allowed' };
  return { ok: true, url };
}

function normaliseHost(hostname: string): string {
  return hostname.toLowerCase().replace(/\.$/, '');
}

export function hostAllowed(host: string, allowed: readonly string[]): boolean {
  for (const entry of allowed) {
    const e = normaliseHost(entry);
    if (!e) continue;
    if (e.startsWith('.')) {
      if (host === e.slice(1) || host.endsWith(e)) return true;
    } else if (host === e) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Address checks
// ---------------------------------------------------------------------------

interface V4Range {
  net: number;
  bits: number;
}
interface V6Range {
  net: bigint;
  bits: number;
}

/** IPv4 ranges that are never a legitimate attachment host. */
const BLOCKED_V4: readonly V4Range[] = (
  [
    ['0.0.0.0', 8], // "this" network
    ['10.0.0.0', 8], // RFC 1918
    ['100.64.0.0', 10], // carrier-grade NAT
    ['127.0.0.0', 8], // loopback
    ['169.254.0.0', 16], // link-local, incl. cloud metadata 169.254.169.254
    ['172.16.0.0', 12], // RFC 1918
    ['192.0.0.0', 24], // IETF protocol assignments
    ['192.0.2.0', 24], // TEST-NET-1
    ['192.88.99.0', 24], // 6to4 relay anycast
    ['192.168.0.0', 16], // RFC 1918
    ['198.18.0.0', 15], // benchmarking
    ['198.51.100.0', 24], // TEST-NET-2
    ['203.0.113.0', 24], // TEST-NET-3
    ['224.0.0.0', 4], // multicast
    ['240.0.0.0', 4], // reserved + broadcast
  ] as const
).map(([net, bits]) => ({ net: v4ToInt(net), bits }));

/** IPv6 ranges that are never a legitimate attachment host. */
const BLOCKED_V6: readonly V6Range[] = (
  [
    ['::', 128], // unspecified
    ['::1', 128], // loopback
    ['100::', 64], // discard-only
    ['2001::', 32], // Teredo (embeds an arbitrary v4 address)
    ['2001:db8::', 32], // documentation
    ['fc00::', 7], // unique local
    ['fe80::', 10], // link-local
    ['fec0::', 10], // deprecated site-local
    ['ff00::', 8], // multicast
  ] as const
).map(([net, bits]) => ({ net: v6ToBigInt(net), bits }));

const V4_MAPPED_PREFIX = v6ToBigInt('::ffff:0.0.0.0') >> 32n;
const NAT64_PREFIX = v6ToBigInt('64:ff9b::') >> 32n;
const SIX_TO_FOUR_PREFIX = v6ToBigInt('2002::') >> 112n;

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !inBlockedV4(v4ToInt(address));
  if (family !== 6) return false;
  const value = v6ToBigInt(address);
  // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d), NAT64
  // (64:ff9b::a.b.c.d) and 6to4 (2002:AABB:CCDD::) all embed a v4 address
  // whose own rules decide.
  if (value >> 32n === V4_MAPPED_PREFIX) return !inBlockedV4(Number(value & 0xffffffffn));
  if (value >> 32n === 0n && value > 1n) return !inBlockedV4(Number(value & 0xffffffffn));
  if (value >> 32n === NAT64_PREFIX) return !inBlockedV4(Number(value & 0xffffffffn));
  if (value >> 112n === SIX_TO_FOUR_PREFIX) {
    return !inBlockedV4(Number((value >> 80n) & 0xffffffffn));
  }
  for (const { net, bits } of BLOCKED_V6) {
    const mask = ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
    if ((value & mask) === (net & mask)) return false;
  }
  return true;
}

function inBlockedV4(ip: number): boolean {
  for (const { net, bits } of BLOCKED_V4) {
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    if ((ip & mask) >>> 0 === (net & mask) >>> 0) return true;
  }
  return false;
}

function v4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    throw new Error(`not an IPv4 address: ${ip}`);
  }
  return (
    (((parts[0] as number) << 24) >>> 0) +
    ((parts[1] as number) << 16) +
    ((parts[2] as number) << 8) +
    (parts[3] as number)
  );
}

function v6ToBigInt(ip: string): bigint {
  let text = ip.toLowerCase();
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);
  // Embedded dotted-quad tail (::ffff:1.2.3.4) → two hextets.
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = v4ToInt(tail);
    text = `${text.slice(0, lastColon + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) throw new Error(`not an IPv6 address: ${ip}`);
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) {
    throw new Error(`not an IPv6 address: ${ip}`);
  }
  const groups = [...head, ...Array<string>(missing).fill('0'), ...rest];
  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) throw new Error(`not an IPv6 address: ${ip}`);
    value = (value << 16n) | BigInt(Number.parseInt(g, 16));
  }
  return value;
}

export type LookupFn = (hostname: string) => Promise<string[]>;

/** Default resolver: every A/AAAA answer, not just the first. */
export const systemLookup: LookupFn = async (hostname) => {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map((a) => a.address);
};

export type PinnedAddress =
  | { ok: true; address: string; family: 4 | 6 }
  | { ok: false; reason: 'dns_failed' | 'blocked_address'; detail?: string };

/**
 * Resolve `hostname` and pick the address the socket will be pinned to.
 * Rejects when any answer is non-public: a resolver that mixes a public and
 * a private answer is exactly how a rebinding attack sneaks through.
 */
export async function resolvePinnedAddress(
  hostname: string,
  lookupFn: LookupFn = systemLookup,
): Promise<PinnedAddress> {
  let addresses: string[];
  try {
    addresses = await lookupFn(hostname);
  } catch (e) {
    return { ok: false, reason: 'dns_failed', detail: (e as Error).message };
  }
  if (addresses.length === 0) return { ok: false, reason: 'dns_failed', detail: 'no addresses' };
  for (const address of addresses) {
    if (!isPublicAddress(address)) return { ok: false, reason: 'blocked_address', detail: address };
  }
  const address = addresses[0] as string;
  return { ok: true, address, family: isIP(address) === 6 ? 6 : 4 };
}

// ---------------------------------------------------------------------------
// Downloader
// ---------------------------------------------------------------------------

/** How the client opens the TLS connection. Injected so tests can point the
 *  validated request at a local plaintext server; production pins the IP. */
export type RequestFn = (target: {
  address: string;
  family: 4 | 6;
  hostname: string;
  url: URL;
  headersTimeoutMs: number;
}) => Promise<IncomingMessage>;

export const httpsRequest: RequestFn = ({ address, hostname, url, headersTimeoutMs }) =>
  new Promise<IncomingMessage>((resolve, reject) => {
    const req = https.request(
      {
        host: address,
        port: 443,
        servername: hostname,
        method: 'GET',
        path: `${url.pathname}${url.search}`,
        headers: {
          host: hostname,
          accept: '*/*',
          'accept-encoding': 'identity',
          'user-agent': 'aula-mcp attachment fetcher',
        },
        timeout: headersTimeoutMs,
      },
      resolve,
    );
    req.on('timeout', () => req.destroy(new Error('timed out waiting for response headers')));
    req.on('error', reject);
    req.end();
  });

export interface DownloadDeps {
  lookup?: LookupFn;
  request?: RequestFn;
  logger?: Logger;
}

export type DownloadFailure =
  | { ok: false; error: 'url_rejected'; reason: AttachmentUrlRejection; hop: number }
  | { ok: false; error: 'address_rejected'; reason: 'dns_failed' | 'blocked_address'; hop: number }
  | { ok: false; error: 'too_many_redirects'; hop: number }
  | { ok: false; error: 'download_failed'; httpStatus: number; body: string }
  | { ok: false; error: 'attachment_too_large'; bytes: number; maxBytes: number }
  | { ok: false; error: 'download_timeout'; phase: 'headers' | 'body' | 'total' }
  | { ok: false; error: 'network_error'; message: string };

export type DownloadResult =
  | { ok: true; bytes: number; contentType: string | null; finalUrl: string }
  | DownloadFailure;

/**
 * Download `rawUrl` into `destPath` (created 0600, replaced on success,
 * removed on any failure). Never throws for policy or network problems —
 * the caller turns the discriminated result into a tool response.
 */
export async function downloadAttachment(
  rawUrl: string,
  destPath: string,
  policy: AttachmentPolicy,
  deps: DownloadDeps = {},
): Promise<DownloadResult> {
  const logger = deps.logger ?? silentLogger;
  const request = deps.request ?? httpsRequest;
  const lookupFn = deps.lookup ?? systemLookup;
  const deadline = Date.now() + policy.totalTimeoutMs;
  let current = rawUrl;

  for (let hop = 0; ; hop++) {
    const check = validateAttachmentUrl(current, policy);
    if (!check.ok) {
      logger.warn('attachments.url_rejected', { reason: check.reason, hop });
      return { ok: false, error: 'url_rejected', reason: check.reason, hop };
    }
    const hostname = normaliseHost(check.url.hostname);
    const pinned = await resolvePinnedAddress(hostname, lookupFn);
    if (!pinned.ok) {
      logger.warn('attachments.address_rejected', { reason: pinned.reason, hostname, hop });
      return { ok: false, error: 'address_rejected', reason: pinned.reason, hop };
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) return { ok: false, error: 'download_timeout', phase: 'total' };

    let res: IncomingMessage;
    try {
      res = await request({
        address: pinned.address,
        family: pinned.family,
        hostname,
        url: check.url,
        headersTimeoutMs: Math.min(policy.headersTimeoutMs, remaining),
      });
    } catch (e) {
      const message = (e as Error).message;
      if (/timed out/i.test(message))
        return { ok: false, error: 'download_timeout', phase: 'headers' };
      return { ok: false, error: 'network_error', message: message.slice(0, 200) };
    }

    const status = res.statusCode ?? 0;
    if (isRedirect(status)) {
      const location = res.headers.location;
      res.destroy();
      if (hop >= policy.maxRedirects || !location) {
        return { ok: false, error: 'too_many_redirects', hop };
      }
      try {
        current = new URL(location, check.url).toString();
      } catch {
        return { ok: false, error: 'url_rejected', reason: 'invalid_url', hop: hop + 1 };
      }
      continue;
    }

    if (status < 200 || status >= 300) {
      const body = await readBounded(res, policy.maxErrorBodyBytes, policy.idleTimeoutMs);
      return { ok: false, error: 'download_failed', httpStatus: status, body: body.slice(0, 300) };
    }

    const declared = Number(res.headers['content-length'] ?? '0');
    if (Number.isFinite(declared) && declared > policy.maxBytes) {
      res.destroy();
      return {
        ok: false,
        error: 'attachment_too_large',
        bytes: declared,
        maxBytes: policy.maxBytes,
      };
    }

    const contentType = res.headers['content-type'] ?? null;
    const streamed = await streamToFile(res, destPath, policy, deadline);
    if (!streamed.ok) return streamed;
    return { ok: true, bytes: streamed.bytes, contentType, finalUrl: current };
  }
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

/** Read at most `maxBytes` of a body, then drop the socket. */
function readBounded(res: IncomingMessage, maxBytes: number, idleMs: number): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    const finish = (): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      res.destroy();
      resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const timer = setTimeout(finish, idleMs);
    res.on('data', (chunk: Buffer) => {
      const room = maxBytes - total;
      if (room <= 0) return finish();
      const slice = chunk.length > room ? chunk.subarray(0, room) : chunk;
      chunks.push(slice);
      total += slice.length;
      if (total >= maxBytes) finish();
    });
    res.on('end', finish);
    res.on('error', finish);
    res.on('close', finish);
  });
}

async function streamToFile(
  res: IncomingMessage,
  destPath: string,
  policy: AttachmentPolicy,
  deadline: number,
): Promise<{ ok: true; bytes: number } | DownloadFailure> {
  const tmp = `${destPath}.part`;
  await rm(tmp, { force: true });
  const handle = await open(tmp, 'wx', 0o600);
  let bytes = 0;

  const result = await new Promise<{ ok: true; bytes: number } | DownloadFailure>((resolve) => {
    let settled = false;
    let idleTimer: ReturnType<typeof setTimeout> | undefined;
    // Writes are queued in order; the byte counter is checked *before* a
    // chunk is accepted so the on-disk file never exceeds the cap either.
    let writeChain: Promise<unknown> = Promise.resolve();
    const cleanup = (): void => {
      clearTimeout(totalTimer);
      if (idleTimer) clearTimeout(idleTimer);
    };
    const fail = (f: DownloadFailure): void => {
      if (settled) return;
      settled = true;
      cleanup();
      res.destroy();
      resolve(f);
    };
    const totalTimer = setTimeout(
      () => fail({ ok: false, error: 'download_timeout', phase: 'total' }),
      Math.max(1, deadline - Date.now()),
    );
    const armIdle = (): void => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(
        () => fail({ ok: false, error: 'download_timeout', phase: 'body' }),
        policy.idleTimeoutMs,
      );
    };
    armIdle();

    res.on('data', (chunk: Buffer) => {
      if (settled) return;
      if (bytes + chunk.length > policy.maxBytes) {
        fail({
          ok: false,
          error: 'attachment_too_large',
          bytes: bytes + chunk.length,
          maxBytes: policy.maxBytes,
        });
        return;
      }
      bytes += chunk.length;
      armIdle();
      writeChain = writeChain
        .then(() => handle.write(chunk))
        .catch((e: Error) => {
          fail({ ok: false, error: 'network_error', message: `write failed: ${e.message}` });
        });
    });
    res.on('error', (e: Error) => {
      fail({ ok: false, error: 'network_error', message: e.message.slice(0, 200) });
    });
    res.on('end', () => {
      if (settled) return;
      settled = true;
      cleanup();
      void writeChain.then(() => resolve({ ok: true, bytes }));
    });
    res.on('close', () => {
      // 'close' without a prior 'end' means the peer hung up mid-body.
      fail({
        ok: false,
        error: 'network_error',
        message: 'connection closed before the body ended',
      });
    });
  });

  await handle.close();
  if (!result.ok) {
    await rm(tmp, { force: true });
    return result;
  }
  await rename(tmp, destPath);
  return result;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export interface AttachmentSource {
  kind: 'thread' | 'post';
  id: number;
  index: number;
}

export interface AttachmentEntry {
  /** Opaque, server-issued. The only handle a client ever gets. */
  id: string;
  /** Absolute path of the downloaded file inside the store root. */
  path: string;
  /** Name as Aula reported it (display only; the on-disk name is scrubbed). */
  filename: string;
  mediaType: string | null;
  bytes: number;
  createdAt: number;
  expiresAt: number;
  source: AttachmentSource;
}

export interface AttachmentStoreOptions {
  /** Directory the store owns. Default `$AULA_MCP_ATTACHMENTS_DIR` or
   *  `<tmpdir>/aula-attachments`. */
  rootDir?: string;
  /** Total bytes across all live attachments. Default 200 MiB. */
  maxTotalBytes?: number;
  /** Live attachment count. Default 64. */
  maxEntries?: number;
  /** Lifetime of a downloaded file. Default 1 h. */
  ttlMs?: number;
  /** Concurrent downloads. Default 2. */
  maxConcurrentDownloads?: number;
  policy?: AttachmentPolicy;
  deps?: DownloadDeps;
  logger?: Logger;
}

export type FetchResult =
  | { ok: true; entry: AttachmentEntry }
  | DownloadFailure
  | { ok: false; error: 'storage_quota_exceeded'; maxTotalBytes: number }
  | { ok: false; error: 'too_many_downloads'; maxConcurrent: number };

export type ResolveResult =
  | { ok: true; entry: AttachmentEntry; realPath: string; size: number }
  | {
      ok: false;
      error: 'unknown_attachment' | 'attachment_expired' | 'attachment_unreadable';
      detail?: string;
    };

const ENTRY_DIR_PREFIX = 'att-';

export class AttachmentStore {
  readonly rootDir: string;
  readonly policy: AttachmentPolicy;
  private readonly maxTotalBytes: number;
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly maxConcurrent: number;
  private readonly deps: DownloadDeps;
  private readonly logger: Logger;
  private readonly entries = new Map<string, AttachmentEntry>();
  private active = 0;
  private ready: Promise<void> | undefined;
  private sweeper: ReturnType<typeof setInterval> | undefined;

  constructor(options: AttachmentStoreOptions = {}) {
    this.rootDir = resolvePath(
      options.rootDir ?? process.env.AULA_MCP_ATTACHMENTS_DIR ?? join(tmpdir(), 'aula-attachments'),
    );
    this.policy = options.policy ?? attachmentPolicyFromEnv();
    this.maxTotalBytes = options.maxTotalBytes ?? 200 * 1024 * 1024;
    this.maxEntries = options.maxEntries ?? 64;
    this.ttlMs = options.ttlMs ?? 60 * 60 * 1000;
    this.maxConcurrent = options.maxConcurrentDownloads ?? 2;
    this.deps = options.deps ?? {};
    this.logger = options.logger ?? silentLogger;
  }

  /** Create the root (0700) and purge leftovers from earlier processes. */
  init(): Promise<void> {
    if (!this.ready) {
      this.ready = (async () => {
        await mkdir(this.rootDir, { recursive: true, mode: 0o700 });
        let names: string[] = [];
        try {
          names = await readdir(this.rootDir);
        } catch {
          return;
        }
        // Only our own `att-*` directories are touched: an operator who
        // points AULA_MCP_ATTACHMENTS_DIR at a shared directory must not lose
        // unrelated files to our cleanup.
        for (const name of names) {
          if (!name.startsWith(ENTRY_DIR_PREFIX)) continue;
          await rm(join(this.rootDir, name), { recursive: true, force: true }).catch(() => {});
        }
        this.sweeper = setInterval(() => void this.sweep(), Math.max(10_000, this.ttlMs / 6));
        this.sweeper.unref?.();
      })();
    }
    return this.ready;
  }

  /** Stop the TTL sweeper and delete every live file. */
  async dispose(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper);
    this.sweeper = undefined;
    for (const id of Array.from(this.entries.keys())) await this.remove(id);
  }

  get totalBytes(): number {
    let total = 0;
    for (const e of this.entries.values()) total += e.bytes;
    return total;
  }

  get size(): number {
    return this.entries.size;
  }

  list(): AttachmentEntry[] {
    return Array.from(this.entries.values());
  }

  /** Download `url` (already taken from authorised Aula data) into the store. */
  async fetch(args: {
    url: string;
    filename: string;
    mediaType?: string | null;
    source: AttachmentSource;
  }): Promise<FetchResult> {
    await this.init();
    await this.sweep();
    if (this.active >= this.maxConcurrent) {
      return { ok: false, error: 'too_many_downloads', maxConcurrent: this.maxConcurrent };
    }
    this.active++;
    const id = crypto.randomUUID();
    const dir = join(this.rootDir, `${ENTRY_DIR_PREFIX}${id}`);
    try {
      await mkdir(dir, { recursive: false, mode: 0o700 });
      const path = join(dir, safeFilename(args.filename));
      const result = await downloadAttachment(args.url, path, this.policy, {
        ...this.deps,
        logger: this.logger,
      });
      if (!result.ok) {
        await rm(dir, { recursive: true, force: true }).catch(() => {});
        return result;
      }
      if (!(await this.makeRoom(result.bytes))) {
        await rm(dir, { recursive: true, force: true }).catch(() => {});
        return { ok: false, error: 'storage_quota_exceeded', maxTotalBytes: this.maxTotalBytes };
      }
      const now = Date.now();
      const entry: AttachmentEntry = {
        id,
        path,
        filename: args.filename,
        mediaType: args.mediaType ?? result.contentType,
        bytes: result.bytes,
        createdAt: now,
        expiresAt: now + this.ttlMs,
        source: args.source,
      };
      this.entries.set(id, entry);
      this.logger.info('attachments.stored', {
        id,
        bytes: entry.bytes,
        source: entry.source,
        live: this.entries.size,
      });
      return { ok: true, entry };
    } finally {
      this.active--;
    }
  }

  /**
   * Look up an id and re-verify the file: still inside the root after
   * symlink resolution, a regular file, not expired, not larger than the
   * policy cap. Every consumer (PDF extraction, future readers) goes
   * through here rather than trusting the recorded path.
   */
  async resolve(id: string): Promise<ResolveResult> {
    const entry = this.entries.get(id);
    if (!entry) return { ok: false, error: 'unknown_attachment' };
    if (entry.expiresAt <= Date.now()) {
      await this.remove(id);
      return { ok: false, error: 'attachment_expired' };
    }
    try {
      const l = await lstat(entry.path);
      if (l.isSymbolicLink() || !l.isFile()) {
        return { ok: false, error: 'attachment_unreadable', detail: 'not a regular file' };
      }
      const real = await realpath(entry.path);
      const root = await realpath(this.rootDir);
      if (!real.startsWith(root + sep)) {
        return { ok: false, error: 'attachment_unreadable', detail: 'outside attachment root' };
      }
      const s = await stat(real);
      if (!s.isFile()) return { ok: false, error: 'attachment_unreadable', detail: 'not a file' };
      if (s.size > this.policy.maxBytes) {
        return { ok: false, error: 'attachment_unreadable', detail: 'larger than policy cap' };
      }
      return { ok: true, entry, realPath: real, size: s.size };
    } catch (e) {
      return { ok: false, error: 'attachment_unreadable', detail: (e as Error).message };
    }
  }

  async remove(id: string): Promise<void> {
    const entry = this.entries.get(id);
    if (!entry) return;
    this.entries.delete(id);
    await rm(join(this.rootDir, `${ENTRY_DIR_PREFIX}${id}`), {
      recursive: true,
      force: true,
    }).catch(() => {});
  }

  /** Drop expired entries. */
  async sweep(now = Date.now()): Promise<void> {
    for (const [id, entry] of this.entries) {
      if (entry.expiresAt <= now) await this.remove(id);
    }
  }

  /** Evict oldest entries until `incoming` bytes fit; false if they never can. */
  private async makeRoom(incoming: number): Promise<boolean> {
    if (incoming > this.maxTotalBytes) return false;
    const oldestFirst = () =>
      Array.from(this.entries.values()).sort((a, b) => a.createdAt - b.createdAt);
    while (
      this.totalBytes + incoming > this.maxTotalBytes ||
      this.entries.size >= this.maxEntries
    ) {
      const victim = oldestFirst()[0];
      if (!victim) break;
      this.logger.info('attachments.evicted', { id: victim.id, bytes: victim.bytes });
      await this.remove(victim.id);
    }
    return this.totalBytes + incoming <= this.maxTotalBytes;
  }
}

/**
 * On-disk name: Unicode letters/digits, dot, dash, underscore and space
 * survive; separators, traversal and control characters do not. Bounded in
 * length and never empty or dot-only.
 */
export function safeFilename(name: string): string {
  let out = name.replace(/[^\p{L}\p{N}.\-_ ]+/gu, '_').trim();
  if (out.length > 120) out = out.slice(0, 120);
  // `.` / `..` would pass the character class but name a directory.
  if (!out || /^\.+$/.test(out)) return 'attachment.bin';
  return out;
}
