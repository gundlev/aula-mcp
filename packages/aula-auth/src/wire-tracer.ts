/**
 * Wire tracing for the auth flow. When MitID fails (and it will, in subtle
 * ways), Casper needs to see the actual HTTP traffic to figure out why.
 *
 * The tracer gets called by AulaHttpClient before/after every fetch. We
 * redact everything we recognise as authentication material — headers, URL
 * parameters (including redirect targets and fragments), form fields, JSON
 * keys, HTML hidden inputs and meta tags, embedded JSON, JWT-shaped strings —
 * before an entry is persisted. Redaction is a denylist plus heuristics, so
 * it reduces what a transcript leaks; it is not a proof that nothing
 * sensitive remains. Read a transcript before sharing it.
 *
 * Three implementations:
 *   - NoopTracer: default; zero-cost.
 *   - InMemoryTracer: collects all entries in an array. Use for a single CLI
 *     run and dump at the end.
 *   - JsonlFileTracer: appends one JSONL row per entry (0600, bounded size).
 *     Survives crashes.
 *
 * `formatTraceText` turns a trace into a readable terminal report.
 */

import { Buffer } from 'node:buffer';
import { mkdir, open } from 'node:fs/promises';
import { dirname } from 'node:path';

export interface WireEntry {
  /** ISO 8601 timestamp. */
  ts: string;
  /** Sequence number — useful when sorting entries from concurrent calls. */
  seq: number;
  method: string;
  url: string;
  /** Sanitised request headers. */
  requestHeaders: Record<string, string>;
  /** Body summary; full body is replaced by `<redacted N bytes>` for secrets. */
  requestBody: string | null;
  status: number;
  /** Sanitised response headers. */
  responseHeaders: Record<string, string>;
  /** Body summary, possibly truncated. */
  responseBody: string;
  /** Response body length in bytes (before truncation). */
  responseBodyBytes: number;
  /** Wall-clock duration in ms. */
  durationMs: number;
}

export interface WireTracer {
  record(entry: WireEntry): void;
}

export const noopTracer: WireTracer = { record() {} };

/** Collect entries in memory. */
export class InMemoryTracer implements WireTracer {
  readonly entries: WireEntry[] = [];
  record(entry: WireEntry): void {
    this.entries.push(entry);
  }
  clear(): void {
    this.entries.length = 0;
  }
}

/** Default cap on a single transcript file. */
export const DEFAULT_TRANSCRIPT_MAX_BYTES = 25 * 1024 * 1024;

export interface JsonlFileTracerOptions {
  /** Stop writing once the file would exceed this many bytes. A final marker
   *  line records that the transcript was cut. Default 25 MiB. */
  maxBytes?: number;
}

/**
 * Append-only JSONL file tracer. Creates the parent dir (0700) if needed and
 * the file with mode 0600 — a transcript describes an authentication flow,
 * so it gets the same permissions as the token store. Writes are chained so
 * entries land in order even though `record()` is synchronous.
 */
export class JsonlFileTracer implements WireTracer {
  private dirReady = false;
  private bytesWritten = 0;
  private capped = false;
  private chain: Promise<void> = Promise.resolve();
  private readonly maxBytes: number;

  constructor(
    private readonly path: string,
    options: JsonlFileTracerOptions = {},
  ) {
    this.maxBytes = options.maxBytes ?? DEFAULT_TRANSCRIPT_MAX_BYTES;
  }

  record(entry: WireEntry): void {
    this.chain = this.chain.then(() => this.write(entry)).catch(() => {});
  }

  /** Resolves once every recorded entry has been flushed to disk. */
  flush(): Promise<void> {
    return this.chain;
  }

  private async write(entry: WireEntry): Promise<void> {
    if (this.capped) return;
    if (!this.dirReady) {
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
      this.dirReady = true;
    }
    let line = `${JSON.stringify(entry)}\n`;
    if (this.bytesWritten + Buffer.byteLength(line, 'utf8') > this.maxBytes) {
      this.capped = true;
      line = `${JSON.stringify({ truncated: true, reason: 'transcript size cap reached', maxBytes: this.maxBytes })}\n`;
    }
    const handle = await open(this.path, 'a', 0o600);
    try {
      await handle.writeFile(line, 'utf8');
    } finally {
      await handle.close();
    }
    this.bytesWritten += Buffer.byteLength(line, 'utf8');
  }
}

/** Compose multiple tracers — handy for "in memory AND file". */
export class CompositeTracer implements WireTracer {
  constructor(private readonly tracers: WireTracer[]) {}
  record(entry: WireEntry): void {
    for (const t of this.tracers) t.record(entry);
  }
}

// --------------------------------------------------------------------------
// Sanitization
// --------------------------------------------------------------------------

/** Header names whose value is replaced with `<redacted>`. Lower-case. */
const SECRET_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'aula-authorization',
  'cookie',
  'set-cookie',
  'csrfp-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-auth-token',
  'x-api-key',
]);

/**
 * Header names whose value is a URL (or contains one). OAuth authorization
 * codes and `state` travel in `Location` on every redirect of the login
 * chain, so these get the same query/fragment redaction as request URLs.
 */
const URL_HEADERS = new Set(['location', 'referer', 'refresh', 'content-location', 'link']);

/** Body field names (in form-urlencoded or JSON) we redact. */
const SECRET_BODY_FIELDS = [
  'password',
  'pwd',
  'mitidauthcode',
  'authorizationcode',
  'authorization_code',
  'access_token',
  'refresh_token',
  'id_token',
  'token',
  'code',
  'code_verifier',
  'client_secret',
  'nonce',
  'samlrequest',
  'samlresponse',
  'relaystate',
  '__requestverificationtoken',
  'csrf_token',
  'xsrf_token',
  'session_token',
  'auth_token',
  'sessionstorageactivesessionuuid',
  'sessionstorageactivechallenge',
  'm1',
  'flowvalueproof',
  'randoma',
  'identityclaim',
  'chosenoptionjson',
];

const SECRET_BODY_FIELDS_SET = new Set(SECRET_BODY_FIELDS.map((s) => s.toLowerCase()));

/**
 * Query-string keys to redact in URLs before they hit a tracer or a log sink.
 * Aula's API passes `access_token` as a query param (not a header), so without
 * this a transcript — or a single `logger.debug('http.request', { url })` —
 * would leak the JWT in every URL.
 */
const SECRET_URL_PARAMS = new Set([
  'access_token',
  'refresh_token',
  'id_token',
  'token',
  'code',
  'code_verifier',
  'client_secret',
  'state',
  'nonce',
  'samlrequest',
  'samlresponse',
  'relaystate',
  'mitidauthcode',
  '__requestverificationtoken',
  'csrf_token',
  'xsrf_token',
  'session_token',
  'auth_token',
  'ticket',
  'session_code',
]);

/**
 * Every `*_token` field we know about must be redacted in BOTH places — the
 * body denylist and the query-string denylist — because Aula and the broker
 * disagree on where a token travels. Exported for the parity test that keeps
 * the two lists from drifting when a new field shows up.
 */
export const SECRET_BODY_FIELD_NAMES: readonly string[] = SECRET_BODY_FIELDS;
export const SECRET_URL_PARAM_NAMES: readonly string[] = Array.from(SECRET_URL_PARAMS);

/**
 * Name *shapes* that mark a value as authentication material even when the
 * exact spelling is not in the denylist — SAML brokers, anti-forgery
 * frameworks and MitID's pages all invent their own names (`authCode`,
 * `accessToken`, `antiForgeryNonce`). `code` on its own is deliberately
 * qualified: Aula's API is full of harmless `institutionCode` fields a
 * transcript needs to keep.
 */
const SECRET_SUFFIX =
  'token|secret|passw(?:or)?d|pwd|nonce|saml(?:request|response)?|relaystate|csrf|xsrf|' +
  'assertion|signature|verifier|challenge|otp|' +
  '(?:auth(?:orization|z)?|mitid|access|verification|security|sms|pin|one_?time)_?code';

/** Contains-match for hidden `<input>` / `<meta>` names, where even a
 *  `session*` field is a credential rather than an identifier. */
const SECRET_NAME_HINT = new RegExp(`(?:${SECRET_SUFFIX}|session)`, 'i');

/** True for a value we already replaced — keeps sanitising idempotent. */
function isRedacted(value: string): boolean {
  return value.startsWith('<redacted');
}

const RELATIVE_BASE = 'http://relative.invalid';

/**
 * Sanitise a URL by redacting known-secret query-string values. Handles
 * relative URLs (as found in `Location` headers) and secrets carried in the
 * fragment, which is where the implicit OAuth flow puts tokens.
 */
export function sanitizeUrl(url: string): string {
  // Only strings shaped like a single URL are re-serialised through `URL`;
  // anything with whitespace or markup is left for `redactText`, which
  // edits in place instead of percent-encoding the whole thing.
  if (!/^\S+$/.test(url) || /[<>"']/.test(url)) return url;
  const absolute = /^[a-z][a-z0-9+.-]*:/i.test(url);
  if (!absolute && !/^[/?#]/.test(url)) return url;
  let parsed: URL;
  try {
    parsed = absolute ? new URL(url) : new URL(url, RELATIVE_BASE);
  } catch {
    return url;
  }
  let mutated = redactSearchParams(parsed.searchParams);
  if (parsed.hash.length > 1) {
    const fragment = new URLSearchParams(parsed.hash.slice(1));
    if (redactSearchParams(fragment)) {
      parsed.hash = fragment.toString();
      mutated = true;
    }
  }
  if (!mutated) return url;
  const out = parsed.toString();
  return absolute ? out : out.slice(RELATIVE_BASE.length);
}

function redactSearchParams(params: URLSearchParams): boolean {
  let mutated = false;
  for (const key of Array.from(params.keys())) {
    if (SECRET_URL_PARAMS.has(key.toLowerCase())) {
      const v = params.get(key) ?? '';
      if (isRedacted(v)) continue;
      params.set(key, `<redacted ${v.length}>`);
      mutated = true;
    }
  }
  return mutated;
}

// Free-text patterns. Each is anchored on a denylisted name or on the shape
// of a credential, and replaces only the value so the surrounding structure
// (which is what makes a transcript diagnosable) survives.
function alternation(names: Iterable<string>): string {
  return Array.from(new Set(names))
    .map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');
}
const SECRET_BODY_NAME_ALTERNATION = alternation(SECRET_BODY_FIELDS);
const SECRET_ANY_NAME_ALTERNATION = alternation([...SECRET_BODY_FIELDS, ...SECRET_URL_PARAMS]);

/** `"name": "value"` / `name = 'value'` — JSON in scripts, JS assignments. */
const QUOTED_ASSIGNMENT_RE = new RegExp(
  `(["']?)\\b((?:${SECRET_BODY_NAME_ALTERNATION})|[\\w$]*?(?:${SECRET_SUFFIX}))\\b\\1` +
    `(\\s*[:=]\\s*)(["'])((?:(?!\\4)[^\\\\]|\\\\.)*)\\4`,
  'gi',
);
/** `name=value` in query strings, form bodies and URL-encoded blobs (e.g. a
 *  redirect URL quoted inside an HTML page), so the query-param denylist
 *  applies there too. */
const URLENCODED_PAIR_RE = new RegExp(
  `(^|[?&;,\\s])((?:${SECRET_ANY_NAME_ALTERNATION})|\\w*?(?:${SECRET_SUFFIX}))=([^&\\s"'<>]+)`,
  'gi',
);
/** Three base64url segments starting with `eyJ` (= `{"`) — a JWT. */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g;
/** `Bearer <opaque>` anywhere in text. */
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi;
/** `<input …>` and `<meta …>` tags, examined attribute by attribute. */
const HTML_TAG_RE = /<(input|meta)\b[^>]*>/gi;
const HTML_ATTR_RE = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))/g;

/**
 * Redact authentication material from arbitrary text — HTML pages, script
 * blocks, form bodies, error messages. Used as the final pass over every
 * string a tracer or log sink persists, so a secret only has to be
 * recognised once, not once per format.
 */
export function redactText(text: string): string {
  if (!text) return text;
  let out = text;
  out = out.replace(HTML_TAG_RE, redactHtmlTag);
  out = out.replace(
    QUOTED_ASSIGNMENT_RE,
    (_m, q: string, name: string, sep: string, quote: string, value: string) =>
      isRedacted(value)
        ? `${q}${name}${q}${sep}${quote}${value}${quote}`
        : `${q}${name}${q}${sep}${quote}<redacted ${value.length}>${quote}`,
  );
  out = out.replace(URLENCODED_PAIR_RE, (_m, lead: string, name: string, value: string) =>
    isRedacted(decodeURIComponentSafe(value))
      ? `${lead}${name}=${value}`
      : `${lead}${name}=<redacted ${value.length}>`,
  );
  out = out.replace(JWT_RE, (m) => `<redacted jwt ${m.length}>`);
  out = out.replace(BEARER_RE, (m) => `Bearer <redacted ${m.length - 7}>`);
  return out;
}

function redactHtmlTag(tag: string): string {
  const isMeta = /^<meta\b/i.test(tag);
  const identifiers: string[] = [];
  let isHidden = false;
  const attrs: Array<{ raw: string; key: string; value: string }> = [];
  for (const m of tag.matchAll(HTML_ATTR_RE)) {
    const key = (m[1] ?? '').toLowerCase();
    const value = m[3] ?? m[4] ?? m[5] ?? '';
    attrs.push({ raw: m[0], key, value });
    if (key === 'name' || key === 'property' || key === 'id') identifiers.push(value.toLowerCase());
    if (
      key === 'type' &&
      (value.toLowerCase() === 'hidden' || value.toLowerCase() === 'password')
    ) {
      isHidden = true;
    }
  }
  // Hidden inputs and <meta> tags are where SAML brokers and anti-forgery
  // frameworks park their material; for those the name *shape* is enough.
  // Visible inputs need an exact denylist hit so a search box survives.
  const sensitive = identifiers.some(
    (id) => SECRET_BODY_FIELDS_SET.has(id) || ((isHidden || isMeta) && SECRET_NAME_HINT.test(id)),
  );
  if (!sensitive) return tag;
  let out = tag;
  for (const attr of attrs) {
    if (attr.key !== 'value' && attr.key !== 'content') continue;
    if (!attr.value || isRedacted(attr.value)) continue;
    out = out.replace(attr.raw, `${attr.key}="<redacted ${attr.value.length} chars>"`);
  }
  return out;
}

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * Sanitise a logger `meta` object before it reaches a console/stderr sink.
 * Uses the same denylists as the wire tracer: secret-named keys are replaced
 * wholesale, and every string is run through `sanitizeUrl` + `redactText`,
 * so a bare `{ url }` in a debug log is no more exposed than a token in a
 * traced body.
 */
export function sanitizeLogMeta(
  meta: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!meta) return meta;
  return redactJson(meta) as Record<string, unknown>;
}

/** Truncation cap for response bodies (bytes). */
export const DEFAULT_BODY_CAP = 4_096;

export function sanitizeHeaders(headers: Record<string, string> | Headers): Record<string, string> {
  const out: Record<string, string> = {};
  const entries =
    headers instanceof Headers ? Array.from(headers.entries()) : Object.entries(headers);
  for (const [k, v] of entries) {
    const key = k.toLowerCase();
    if (SECRET_HEADERS.has(key)) {
      out[key] = `<redacted ${v.length} chars>`;
    } else if (URL_HEADERS.has(key)) {
      out[key] = redactText(sanitizeUrl(v));
    } else {
      out[key] = redactText(v);
    }
  }
  return out;
}

/** Sanitise a request body whose shape may be form-urlencoded or JSON. */
export function sanitizeRequestBody(
  body: string | URLSearchParams | Uint8Array | undefined,
): string | null {
  if (body === undefined) return null;
  if (body instanceof URLSearchParams) {
    const out = new URLSearchParams();
    for (const [k, v] of body) {
      out.set(
        k,
        SECRET_BODY_FIELDS_SET.has(k.toLowerCase())
          ? `<redacted ${v.length}>`
          : redactText(sanitizeUrl(v)),
      );
    }
    return out.toString();
  }
  if (body instanceof Uint8Array) {
    return `<binary ${body.length} bytes>`;
  }
  // String — try JSON first, then treat as free text.
  return truncateString(redactString(body), DEFAULT_BODY_CAP);
}

/**
 * Redact a response body before it is persisted. JSON is walked key by key;
 * everything (JSON included, after serialisation) then goes through the
 * free-text pass so HTML forms, embedded JSON and JWT-shaped strings are
 * caught regardless of content type. Truncation happens last — cutting a
 * body short is a size measure, not a redaction.
 */
export function sanitizeResponseBody(
  body: string,
  cap = DEFAULT_BODY_CAP,
): {
  text: string;
  bytes: number;
} {
  const bytes = Buffer.byteLength(body, 'utf8');
  return { text: truncateString(redactString(body), cap), bytes };
}

/** JSON-aware redaction of a string, falling back to the free-text pass. */
function redactString(s: string): string {
  if (looksLikeJson(s)) {
    try {
      return redactText(JSON.stringify(redactJson(JSON.parse(s) as unknown)));
    } catch {
      // not JSON after all
    }
  }
  return redactText(sanitizeUrl(s));
}

function redactJson(value: unknown): unknown {
  if (typeof value === 'string') return redactString(value);
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(redactJson);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_BODY_FIELDS_SET.has(k.toLowerCase())) {
      out[k] =
        typeof v === 'string'
          ? `<redacted ${v.length}>`
          : v && typeof v === 'object' && 'value' in (v as object)
            ? `<redacted object with .value>`
            : `<redacted>`;
    } else {
      out[k] = redactJson(v);
    }
  }
  return out;
}

function truncateString(s: string, cap: number): string {
  if (s.length <= cap) return s;
  return `${s.slice(0, cap)}…<+${s.length - cap} chars>`;
}

function looksLikeJson(s: string): boolean {
  const trimmed = s.trimStart();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

// --------------------------------------------------------------------------
// Pretty-printing
// --------------------------------------------------------------------------

/** Render an InMemoryTracer's entries (or any list) as a human-readable log. */
export function formatTraceText(entries: readonly WireEntry[]): string {
  const lines: string[] = [];
  for (const e of entries) {
    lines.push(`\n# ${e.seq.toString().padStart(3, '0')}  ${e.ts}  ${e.method} ${e.url}`);
    lines.push(`  request headers:`);
    for (const [k, v] of Object.entries(e.requestHeaders)) lines.push(`    ${k}: ${v}`);
    if (e.requestBody) lines.push(`  request body: ${e.requestBody}`);
    lines.push(`  → ${e.status} (${e.durationMs} ms, ${e.responseBodyBytes} bytes)`);
    lines.push(`  response headers:`);
    for (const [k, v] of Object.entries(e.responseHeaders)) lines.push(`    ${k}: ${v}`);
    if (e.responseBody) {
      const indented = e.responseBody
        .split('\n')
        .map((l) => `    ${l}`)
        .join('\n');
      lines.push(`  response body:\n${indented}`);
    }
  }
  return lines.join('\n');
}
