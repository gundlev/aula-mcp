/**
 * End-to-end MCP server integration test. Boots the Hono app + Streamable
 * HTTP transport in-process, dispatches real JSON-RPC requests via
 * `app.fetch()`, and asserts the wire shape MCP clients see.
 *
 * The AulaContext is faked so we never hit Aula. No network, no tokens.
 * Covers the dispatcher + transport layer that's otherwise untested.
 *
 * The MCP Streamable HTTP transport needs the Accept header to advertise
 * both `application/json` AND `text/event-stream`, even when
 * enableJsonResponse=true means responses are plain JSON. Real clients do
 * this; we replicate.
 */

import { afterAll, afterEach, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import type { IncomingMessage } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { Readable } from 'node:stream';
import type { AulaTokens } from '@aula-mcp/aula-auth';
import type { AulaClient, AulaPost } from '@aula-mcp/aula-client';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { Hono } from 'hono';
import { AttachmentStore, DEFAULT_ATTACHMENT_POLICY, type RequestFn } from './attachments.ts';
import type { AulaContext } from './aula-context.ts';
import { makeSyntheticPdf } from './test-fixtures.ts';
import { type RegisterToolsOptions, registerTools } from './tools.ts';

const TOKENS: AulaTokens = {
  access_token: 'AT',
  refresh_token: 'RT',
  token_type: 'Bearer',
  expires_in: 3600,
  expires_at: Math.floor(Date.now() / 1000) + 3600,
  obtained_at: Math.floor(Date.now() / 1000),
};

/** Small cap so the streaming tests stay fast. */
const ATTACHMENT_MAX_BYTES = 64 * 1024;

/** One attachment as Aula shapes it inside a thread message. */
interface FakeAttachment {
  file: { name?: string; url?: string; mediaType?: string };
}

/** Thread 77: three attachments spread over three messages, in wire order. */
const THREADS: Record<number, Array<{ attachments?: FakeAttachment[] }>> = {
  77: [
    {
      attachments: [
        { file: { name: 'kostplan.pdf', url: 'https://cdn.test/a', mediaType: 'application/pdf' } },
      ],
    },
    // No attachments at all — the flattening must skip straight past it.
    {},
    {
      attachments: [
        { file: { name: 'seddel.txt', url: 'https://cdn.test/b' } },
        // Path separators, to exercise the on-disk name scrubbing.
        { file: { name: '../../etc/pas swd.pdf', url: 'https://cdn.test/c' } },
      ],
    },
  ],
  78: [{}],
  // Aula data pointing somewhere it never should — the server must still
  // refuse, because the URL check is not about who supplied the URL.
  79: [
    {
      attachments: [
        { file: { name: 'internal.pdf', url: 'http://127.0.0.1:8080/secret.pdf' } },
        { file: { name: 'redirected.pdf', url: 'https://cdn.test/redirect-internal' } },
        { file: { name: 'other-host.pdf', url: 'https://attacker.example/x.pdf' } },
      ],
    },
  ],
};

/** The posts feed, two pages deep. */
const POSTS: AulaPost[][] = [
  [
    {
      id: 314,
      title: 'Sommerfest',
      attachments: [
        { file: { name: 'Sommerfest program.pdf', url: 'https://cdn.test/post-314-0' } },
        { name: 'no-url.pdf' },
        { file: { name: 'Bålhytten på Ærø - lørdag.pdf', url: 'https://cdn.test/post-314-1' } },
      ],
    },
  ],
  [
    {
      id: 42,
      title: 'Side to',
      attachments: [{ file: { name: 'p2.pdf', url: 'https://cdn.test/post-42-0' } }],
    },
  ],
];

interface FakeOptions {
  /** Thread id to its messages, for aula.messages.get_attachment. */
  threads?: Record<number, Array<{ attachments?: FakeAttachment[] }>>;
  /** Pages of the posts feed, for aula.posts.get_attachment. */
  posts?: AulaPost[][];
  /** Every presence.updatePresenceTemplate arg object, in call order. */
  templateWrites?: unknown[];
}

function fakeContext(opts: FakeOptions = {}): AulaContext {
  const fakeClient = {
    currentApiVersion: 22,
    async getProfilesByLogin() {
      return {
        profiles: [
          {
            id: 1,
            name: 'Casper',
            children: [
              {
                id: 1001,
                name: 'Emilie',
                userId: 2001,
                institutionProfile: {
                  id: 9001,
                  institutionName: 'Demo Skole',
                  institutionCode: 'D12345',
                },
              },
            ],
          },
        ],
      };
    },
    async getProfileContext() {
      return {
        userId: 5000,
        pageConfiguration: {
          widgetConfigurations: [
            { widget: { widgetId: '0001' } },
            { widget: { widgetId: '0030' } },
          ],
        },
      };
    },
    async getPresenceTemplates() {
      return {
        presenceWeekTemplates: [{ institutionProfile: { id: 9001 }, dayTemplates: [] }],
      };
    },
    async updatePresenceTemplate(args: unknown) {
      opts.templateWrites?.push(args);
      return { id: 4242, status: 'created' };
    },
    async getMessagesForThread(threadId: number) {
      return { subject: 'Sommerfest', messages: opts.threads?.[threadId] ?? [] };
    },
    async getPosts(args: { index?: number }) {
      const pages = opts.posts ?? [];
      const index = args.index ?? 0;
      return { posts: pages[index] ?? [], moreMessagesExist: index < pages.length - 1 };
    },
  };
  return {
    record: {
      version: 1 as const,
      username: 'cj',
      tokens: TOKENS,
      identityName: 'Forælder',
      saved_at: Math.floor(Date.now() / 1000),
    },
    async getClient(): Promise<AulaClient> {
      return fakeClient as unknown as AulaClient;
    },
    async getGuardianUserId(): Promise<string> {
      return '5000';
    },
  } as unknown as AulaContext;
}

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number;
  result?: unknown;
  error?: { code: number; message: string };
}

interface Harness {
  /** Send one JSON-RPC request over the transport, handshaking first. */
  rpc(req: JsonRpcRequest): Promise<JsonRpcResponse>;
  /** `tools/call` plus JSON.parse of the single text content block. */
  call(id: number, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** Every tool name from `tools/list`. */
  toolNames(id: number): Promise<string[]>;
  close(): Promise<void>;
}

/**
 * A live server + transport pair behind `app.fetch()`. A factory rather than
 * a module-level singleton because the write tools are registered off
 * AULA_MCP_WRITE at `registerTools` time, so covering both states needs two
 * independently-registered servers in the same file.
 */
async function createHarness(
  context: AulaContext,
  options: RegisterToolsOptions = {},
): Promise<Harness> {
  const app = new Hono();
  const mcp = new McpServer(
    { name: 'aula-mcp-test', version: '0.0.0-test' },
    { capabilities: { tools: {} } },
  );
  registerTools(mcp, context, options);
  // Stateful mode — the SDK forbids reusing a stateless transport across
  // requests, which a multi-test suite necessarily does. Mirror what
  // production does in server.ts.
  const transport = new WebStandardStreamableHTTPServerTransport({
    enableJsonResponse: true,
    sessionIdGenerator: () => crypto.randomUUID(),
  });
  await mcp.connect(transport);
  app.post('/mcp', (c) => transport.handleRequest(c.req.raw));
  app.get('/mcp', (c) => transport.handleRequest(c.req.raw));
  app.delete('/mcp', (c) => transport.handleRequest(c.req.raw));

  // Track the session id across requests (the transport echoes one in the
  // initialize response and expects it back on every subsequent call).
  let sessionId: string | undefined;

  function headers(): Record<string, string> {
    const h: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    };
    if (sessionId) h['mcp-session-id'] = sessionId;
    return h;
  }

  async function post(body: unknown): Promise<Response> {
    const res = await app.fetch(
      new Request('http://test/mcp', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify(body),
      }),
    );
    // Capture the session id the server allocates on initialize.
    const echoedSessionId = res.headers.get('mcp-session-id');
    if (echoedSessionId) sessionId = echoedSessionId;
    return res;
  }

  async function send(req: JsonRpcRequest): Promise<JsonRpcResponse> {
    const res = await post(req);
    if (res.status !== 200) {
      const body = await res.text();
      throw new Error(`Transport returned ${res.status}: ${body.slice(0, 500)}`);
    }
    const body = await res.text();
    // Response can be plain JSON or an SSE event with `data: { ... }` line.
    if (res.headers.get('content-type')?.includes('text/event-stream')) {
      const dataLine = body.split('\n').find((l) => l.startsWith('data:'));
      if (!dataLine) throw new Error(`SSE response had no data line: ${body}`);
      return JSON.parse(dataLine.slice(5).trim()) as JsonRpcResponse;
    }
    return JSON.parse(body) as JsonRpcResponse;
  }

  let initialised = false;

  async function init(): Promise<void> {
    if (initialised) return;
    // The MCP transport requires an `initialize` handshake before tool calls.
    await send({
      jsonrpc: '2.0',
      id: 0,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'aula-mcp-test-client', version: '0.0.0' },
      },
    });
    // Per spec, send an `initialized` notification (no id) before tool calls.
    await post({ jsonrpc: '2.0', method: 'notifications/initialized' });
    initialised = true;
  }

  async function rpc(req: JsonRpcRequest): Promise<JsonRpcResponse> {
    await init();
    return send(req);
  }

  return {
    rpc,
    async call(id, name, args) {
      const r = await rpc({
        jsonrpc: '2.0',
        id,
        method: 'tools/call',
        params: { name, arguments: args },
      });
      expect(r.error).toBeUndefined();
      const result = r.result as { content: Array<{ type: string; text: string }> };
      const first = result.content[0];
      if (!first) throw new Error(`${name} returned no content`);
      expect(first.type).toBe('text');
      return JSON.parse(first.text) as Record<string, unknown>;
    },
    async toolNames(id) {
      const r = await rpc({ jsonrpc: '2.0', id, method: 'tools/list' });
      expect(r.error).toBeUndefined();
      const { tools } = r.result as { tools: Array<{ name: string }> };
      return tools.map((t) => t.name);
    },
    async close() {
      await mcp.close();
    },
  };
}

/** Set (or clear) an env var, returning the previous value for restoring. */
function setEnv(key: string, value: string | undefined): string | undefined {
  const previous = process.env[key];
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
  return previous;
}

// ---------------------------------------------------------------------------
// Fake attachment transport
//
// The attachment store is given a fake `request` (what would open the TLS
// connection) and a fake `lookup` (DNS), so the tools run their real
// validation / streaming / storage code against synthetic responses without
// a socket. Every response is routed by URL; the fake records each
// connection so tests can assert what was — and was not — contacted.
// ---------------------------------------------------------------------------

const FAKE_PUBLIC_IP = '93.184.216.34';

interface FakeRoute {
  status?: number;
  headers?: Record<string, string>;
  body?: string | Buffer | (() => Readable);
}

const routes = new Map<string, FakeRoute>();
let connections: Array<{ address: string; hostname: string; url: string }> = [];

const fakeRequest: RequestFn = async ({ address, hostname, url }) => {
  connections.push({ address, hostname, url: url.toString() });
  const route = routes.get(`${url.origin}${url.pathname}`);
  if (!route) throw new Error(`no fake route for ${url}`);
  const body =
    typeof route.body === 'function'
      ? route.body()
      : Readable.from([Buffer.from(route.body ?? '')], { objectMode: false });
  return Object.assign(body, {
    statusCode: route.status ?? 200,
    headers: Object.fromEntries(
      Object.entries(route.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
    ),
  }) as unknown as IncomingMessage;
};

function route(path: string, r: FakeRoute): void {
  routes.set(`https://cdn.test${path}`, r);
}

let attachmentsDir: string;
let attachmentStore: AttachmentStore;
let harness: Harness;

beforeAll(async () => {
  attachmentsDir = await mkdtemp(join(tmpdir(), 'aula-mcp-attachments-'));
  attachmentStore = new AttachmentStore({
    rootDir: attachmentsDir,
    policy: {
      ...DEFAULT_ATTACHMENT_POLICY,
      allowedHosts: ['cdn.test'],
      maxBytes: ATTACHMENT_MAX_BYTES,
      idleTimeoutMs: 500,
      totalTimeoutMs: 5_000,
    },
    deps: { request: fakeRequest, lookup: async () => [FAKE_PUBLIC_IP] },
  });
  harness = await createHarness(fakeContext({ threads: THREADS, posts: POSTS }), {
    attachments: attachmentStore,
    pdfLimits: {
      maxBytes: ATTACHMENT_MAX_BYTES,
      maxPages: 10,
      maxChars: 10_000,
      timeoutMs: 20_000,
    },
  });
});

afterAll(async () => {
  await harness.close();
  await attachmentStore.dispose();
  await rm(attachmentsDir, { recursive: true, force: true });
});

describe('MCP server: tools/list', () => {
  test('returns every registered tool with its name and description', async () => {
    const names = await harness.toolNames(1);
    expect(names).toContain('aula.discover');
    expect(names).toContain('aula.profiles.list');
    expect(names).toContain('aula.presence.today');
    expect(names).toContain('aula.presence.templates');
    expect(names).toContain('aula.calendar.events');
    expect(names).toContain('aula.messages.list_threads');
    expect(names).toContain('aula.messages.get_thread');
    expect(names).toContain('aula.messages.get_attachment');
    expect(names).toContain('aula.notifications.list');
    expect(names).toContain('aula.posts.list');
    expect(names).toContain('aula.posts.get_attachment');
    expect(names).toContain('aula.ugeplan.easyiq');
    expect(names).toContain('aula.ugeplan.meebook');
    expect(names).toContain('aula.ugeplan.easyiq_skoleportal');
    expect(names).toContain('aula.opgaver.minuddannelse');
    expect(names).toContain('aula.ugebrev.minuddannelse');
    expect(names).toContain('aula.huskelisten.systematic');
    // aula.raw_request is NOT in the list because AULA_MCP_RAW isn't set.
    expect(names).not.toContain('aula.raw_request');
    // aula.presence.set_template is gated the same way behind AULA_MCP_WRITE.
    expect(names).not.toContain('aula.presence.set_template');
    // Same gate — reporting a child sick must never register on a read-only server.
    expect(names).not.toContain('aula.presence.report_sick');
  });
});

describe('MCP server: tools/call(aula.discover)', () => {
  test('returns a parseable manifest with our fake context', async () => {
    const manifest = (await harness.call(2, 'aula.discover', {})) as unknown as {
      user: { username: string };
      children: Array<{ name: string }>;
      detectedWidgets: string[];
      capabilities: Record<string, { tools: string[] }>;
    };
    expect(manifest.user.username).toBe('cj');
    expect(manifest.children[0]?.name).toBe('Emilie');
    expect(manifest.detectedWidgets).toEqual(['0001', '0030']);
    // EasyIQ (0001) should be listed first for ugeplan since it's detected.
    expect(manifest.capabilities.ugeplan?.tools[0]).toBe('aula.ugeplan.easyiq');
  });
});

describe('MCP server: tools/call(aula.presence.templates)', () => {
  test('returns the presenceWeekTemplates payload', async () => {
    const data = (await harness.call(5, 'aula.presence.templates', {
      childIds: [9001],
    })) as unknown as {
      presenceWeekTemplates: Array<{ institutionProfile: { id: number } }>;
    };
    expect(data.presenceWeekTemplates[0]?.institutionProfile.id).toBe(9001);
  });
});

describe('MCP server: tools/call validation', () => {
  test('rejects unknown tool name with an error response', async () => {
    const r = await harness.rpc({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'aula.this_does_not_exist', arguments: {} },
    });
    // Either the result is an `isError: true` content payload, or there's a
    // top-level error field. Both are valid MCP shapes; accept either.
    if (r.error) {
      expect(r.error.message.length).toBeGreaterThan(0);
    } else {
      const result = r.result as { isError?: boolean; content?: unknown };
      expect(result.isError).toBe(true);
    }
  });

  test('rejects invalid argument shape (childIds must be non-empty array)', async () => {
    const r = await harness.rpc({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'aula.presence.today', arguments: { childIds: [] } },
    });
    // Zod min(1) → validation error somewhere in the response.
    const text = JSON.stringify(r);
    expect(text.toLowerCase()).toMatch(/error|invalid|too small/);
  });
});

// ---------------------------------------------------------------------------
// aula.presence.set_template — the write gate
// ---------------------------------------------------------------------------

describe('MCP server: tools/call(aula.presence.set_template)', () => {
  let writeHarness: Harness;
  const writes: unknown[] = [];

  beforeAll(async () => {
    // The gate is read at registration time, so flip it around createHarness
    // and put it straight back — nothing else in the file should see it set.
    const previous = setEnv('AULA_MCP_WRITE', '1');
    try {
      writeHarness = await createHarness(fakeContext({ templateWrites: writes }));
    } finally {
      setEnv('AULA_MCP_WRITE', previous);
    }
  });

  afterAll(async () => {
    await writeHarness.close();
  });

  afterEach(() => {
    writes.length = 0;
  });

  test('is advertised in tools/list when AULA_MCP_WRITE=1', async () => {
    const names = await writeHarness.toolNames(10);
    expect(names).toContain('aula.presence.set_template');
    // The other write tools share the one gate, so they arrive together.
    expect(names).toContain('aula.presence.report_sick');
    expect(names).toContain('aula.messages.mark_read');
  });

  test('happy path: routes through to the client and returns { ok: true, result }', async () => {
    const out = await writeHarness.call(11, 'aula.presence.set_template', {
      institutionProfileId: 9001,
      date: '2026-06-01',
      activityType: 'picked_up_by',
      entryTime: '08:00',
      exitTime: '15:30',
      pickedUpBy: 'Farmor',
      comment: 'Farmor henter',
    });
    expect(out.ok).toBe(true);
    expect(out.result).toEqual({ id: 4242, status: 'created' });
    // The tool must hand the client exactly what the caller asked for, with
    // repeatPattern defaulted rather than left undefined.
    expect(writes).toEqual([
      {
        institutionProfileId: 9001,
        date: '2026-06-01',
        activityType: 'picked_up_by',
        repeatPattern: 'never',
        entryTime: '08:00',
        exitTime: '15:30',
        pickedUpBy: 'Farmor',
        comment: 'Farmor henter',
      },
    ]);
  });

  test('a repeating template forwards repeatPattern and repeatUntil', async () => {
    const out = await writeHarness.call(12, 'aula.presence.set_template', {
      institutionProfileId: 9001,
      date: '2026-06-01',
      activityType: 'send_home',
      exitTime: '15:00',
      repeat: 'every_2_weeks',
      repeatUntil: '2026-06-30',
    });
    expect(out.ok).toBe(true);
    expect(writes).toEqual([
      {
        institutionProfileId: 9001,
        date: '2026-06-01',
        activityType: 'send_home',
        repeatPattern: 'every_2_weeks',
        exitTime: '15:00',
        repeatUntil: '2026-06-30',
      },
    ]);
  });

  test('cross-field validation fails before the client is called', async () => {
    const out = await writeHarness.call(13, 'aula.presence.set_template', {
      institutionProfileId: 9001,
      date: '2026-06-01',
      // picked_up_by without pickedUpBy — validateSetTemplateArgs rejects it.
      activityType: 'picked_up_by',
      exitTime: '15:30',
    });
    expect(out.error).toBe('invalid_arguments');
    expect((out.problems as string[])[0]).toContain('pickedUpBy');
    expect(writes).toEqual([]);
  });

  test('Zod rejects a malformed date before the handler runs', async () => {
    const r = await writeHarness.rpc({
      jsonrpc: '2.0',
      id: 14,
      method: 'tools/call',
      params: {
        name: 'aula.presence.set_template',
        arguments: {
          institutionProfileId: 9001,
          date: '01-06-2026',
          activityType: 'send_home',
        },
      },
    });
    expect(JSON.stringify(r).toLowerCase()).toMatch(/error|invalid/);
    expect(writes).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// aula.messages.get_attachment / aula.posts.get_attachment /
// aula.utils.extract_pdf_text
//
// The three tools share one AttachmentStore. The messages tool exercises the
// download path in depth; the posts tool covers its own server-side lookup;
// the PDF tool consumes the ids the other two hand out. Regression coverage
// for audit findings 2, 3 and 6 lives here at the transport level, with the
// unit-level detail in attachments.test.ts and pdf-extract.test.ts.
// ---------------------------------------------------------------------------

/** A body that keeps sending `chunkSize` bytes and never ends. */
function endlessBody(chunkSize: number, chunks = Number.POSITIVE_INFINITY): () => Readable {
  return () => {
    let sent = 0;
    return new Readable({
      read() {
        if (sent < chunks) {
          sent++;
          this.push(Buffer.alloc(chunkSize, 0x41));
        }
      },
    });
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe('MCP server: tools/call(aula.messages.get_attachment)', () => {
  afterEach(() => {
    routes.clear();
    connections = [];
  });

  test('downloads into the attachment store and returns an opaque attachmentId, never the URL', async () => {
    route('/a', {
      headers: { 'content-type': 'application/pdf' },
      body: '%PDF-1.7 madplan',
    });
    const out = await harness.call(20, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 0,
    });

    expect(out.ok).toBe(true);
    expect(out.attachmentId).toMatch(UUID_RE);
    expect(out.filename).toBe('kostplan.pdf');
    expect(out.mediaType).toBe('application/pdf');
    expect(out.bytes).toBe(16);
    expect(typeof out.expiresAt).toBe('string');
    // The file lives in a per-attachment directory under the store root…
    expect(dirname(dirname(out.path as string))).toBe(attachmentsDir);
    expect(basename(out.path as string)).toBe('kostplan.pdf');
    expect(await readFile(out.path as string, 'utf8')).toBe('%PDF-1.7 madplan');
    // …the presigned URL is not echoed anywhere in the result…
    expect(JSON.stringify(out)).not.toContain('cdn.test');
    // …and the connection was pinned to the address that passed the check.
    expect(connections).toEqual([
      { address: FAKE_PUBLIC_IP, hostname: 'cdn.test', url: 'https://cdn.test/a' },
    ]);
  });

  test('attachmentIndex flattens across messages in order', async () => {
    route('/b', { body: 'seddel' });
    const out = await harness.call(21, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 1,
    });
    // Index 1 lives on the *third* message — the empty one in between must
    // not consume an index.
    expect(out.filename).toBe('seddel.txt');
    expect(connections.map((c) => c.url)).toEqual(['https://cdn.test/b']);
    // No mediaType on this attachment and none from the server, so the key
    // is omitted rather than null.
    expect('mediaType' in out).toBe(false);
  });

  test('sanitises path separators out of the on-disk filename', async () => {
    route('/c', { body: 'x' });
    const out = await harness.call(22, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 2,
    });
    // `filename` echoes what Aula sent; only the on-disk name is scrubbed.
    expect(out.filename).toBe('../../etc/pas swd.pdf');
    expect(basename(out.path as string)).toBe('.._.._etc_pas swd.pdf');
    // The whole point: nothing escapes the attachments directory.
    expect(dirname(dirname(out.path as string))).toBe(attachmentsDir);
  });

  test('attachment_not_found when the index is past the end', async () => {
    const out = await harness.call(23, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 99,
    });
    expect(out.error).toBe('attachment_not_found');
    expect(out.threadId).toBe(77);
    expect(out.attachmentIndex).toBe(99);
    expect(out.totalAttachments).toBe(3);
    expect(connections).toEqual([]);
  });

  test('attachment_not_found on a thread with no attachments at all', async () => {
    const out = await harness.call(24, 'aula.messages.get_attachment', {
      threadId: 78,
      attachmentIndex: 0,
    });
    expect(out.error).toBe('attachment_not_found');
    expect(out.totalAttachments).toBe(0);
  });

  test('download_failed carries the upstream status and a bounded body excerpt', async () => {
    route('/a', {
      status: 403,
      body: `<Error><Code>AccessDenied</Code>${'x'.repeat(10_000)}</Error>`,
    });
    const out = await harness.call(25, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 0,
    });
    expect(out.ok).toBe(false);
    expect(out.error).toBe('download_failed');
    expect(out.httpStatus).toBe(403);
    expect(out.filename).toBe('kostplan.pdf');
    expect(out.body).toContain('AccessDenied');
    expect((out.body as string).length).toBeLessThanOrEqual(300);
    expect(out.path).toBeUndefined();
    expect(out.attachmentId).toBeUndefined();
  });

  test('attachment_too_large from the declared content-length, before reading the body', async () => {
    let reads = 0;
    route('/a', {
      headers: { 'content-length': String(ATTACHMENT_MAX_BYTES + 1) },
      body: () =>
        new Readable({
          read() {
            reads++;
            this.push(Buffer.alloc(1024));
          },
        }),
    });
    const out = await harness.call(26, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 0,
    });
    expect(out.error).toBe('attachment_too_large');
    expect(out.bytes).toBe(ATTACHMENT_MAX_BYTES + 1);
    expect(out.maxBytes).toBe(ATTACHMENT_MAX_BYTES);
    expect(out.filename).toBe('kostplan.pdf');
    expect(reads).toBe(0);
  });

  test('attachment_too_large while streaming a chunked body with no content-length', async () => {
    route('/a', { body: endlessBody(4096) });
    const out = await harness.call(27, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 0,
    });
    expect(out.error).toBe('attachment_too_large');
    expect(out.maxBytes).toBe(ATTACHMENT_MAX_BYTES);
    expect(out.path).toBeUndefined();
    // Nothing partial is left in the store root.
    const leftovers = await readdir(attachmentsDir);
    for (const name of leftovers) {
      expect((await readdir(join(attachmentsDir, name))).some((f) => f.endsWith('.part'))).toBe(
        false,
      );
    }
  });

  test('a misleading small content-length does not bypass the byte counter', async () => {
    route('/a', { headers: { 'content-length': '10' }, body: endlessBody(8192) });
    const out = await harness.call(28, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 0,
    });
    expect(out.error).toBe('attachment_too_large');
  });

  test('a stalled download is cancelled on the idle deadline', async () => {
    route('/a', { body: endlessBody(16, 1) });
    const out = await harness.call(29, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 0,
    });
    expect(out.error).toBe('download_timeout');
    expect(out.phase).toBe('body');
  });

  test('a file exactly on the cap is still accepted', async () => {
    route('/b', { body: Buffer.alloc(ATTACHMENT_MAX_BYTES, 0x42) });
    const out = await harness.call(30, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 1,
    });
    expect(out.ok).toBe(true);
    expect(out.bytes).toBe(ATTACHMENT_MAX_BYTES);
  });

  test('refuses an internal http URL even when it comes from Aula data', async () => {
    const out = await harness.call(31, 'aula.messages.get_attachment', {
      threadId: 79,
      attachmentIndex: 0,
    });
    expect(out.error).toBe('url_rejected');
    expect(out.reason).toBe('scheme_not_https');
    expect(connections).toEqual([]);
    // The offending URL is not echoed back.
    expect(JSON.stringify(out)).not.toContain('127.0.0.1');
  });

  test('refuses a redirect from the CDN to an internal address', async () => {
    route('/redirect-internal', {
      status: 302,
      headers: { location: 'http://169.254.169.254/latest/meta-data/' },
    });
    const out = await harness.call(32, 'aula.messages.get_attachment', {
      threadId: 79,
      attachmentIndex: 1,
    });
    expect(out.error).toBe('url_rejected');
    expect(out.hop).toBe(1);
    // Only the first hop was contacted; the redirect target never was.
    expect(connections.map((c) => c.url)).toEqual(['https://cdn.test/redirect-internal']);
  });

  test('refuses an https host that is not on the attachment allowlist', async () => {
    const out = await harness.call(33, 'aula.messages.get_attachment', {
      threadId: 79,
      attachmentIndex: 2,
    });
    expect(out.error).toBe('url_rejected');
    expect(out.reason).toBe('host_not_allowed');
    expect(connections).toEqual([]);
  });
});

describe('MCP server: tools/call(aula.posts.get_attachment)', () => {
  afterEach(() => {
    routes.clear();
    connections = [];
  });

  test('resolves the URL server-side from the post id and index', async () => {
    route('/post-314-0', { body: '%PDF-1.7 nyhed' });
    const out = await harness.call(40, 'aula.posts.get_attachment', {
      postId: 314,
      attachmentIndex: 0,
      profileIds: [1],
    });
    expect(out.ok).toBe(true);
    expect(out.attachmentId).toMatch(UUID_RE);
    expect(out.filename).toBe('Sommerfest program.pdf');
    expect(basename(out.path as string)).toBe('Sommerfest program.pdf');
    expect(out.bytes).toBe(14);
    expect(connections.map((c) => c.url)).toEqual(['https://cdn.test/post-314-0']);
  });

  test('the index counts only attachments with a usable URL, matching aula.posts.list', async () => {
    route('/post-314-1', { body: '%PDF-1.7' });
    const out = await harness.call(41, 'aula.posts.get_attachment', {
      postId: 314,
      attachmentIndex: 1,
      profileIds: [1],
    });
    // Index 1 is "Bålhytten…", because the URL-less attachment in between
    // is dropped by the same filter slimPost uses.
    expect(out.ok).toBe(true);
    expect(out.filename).toBe('Bålhytten på Ærø - lørdag.pdf');
    // Regression guard: Danish letters survive on disk.
    expect(basename(out.path as string)).toBe('Bålhytten på Ærø - lørdag.pdf');
  });

  test('walks the feed pages to find the post', async () => {
    route('/post-42-0', { body: 'p2' });
    const out = await harness.call(42, 'aula.posts.get_attachment', {
      postId: 42,
      attachmentIndex: 0,
      profileIds: [1],
    });
    expect(out.ok).toBe(true);
    expect(out.filename).toBe('p2.pdf');
  });

  test('post_not_found for an id that is not in the feed', async () => {
    const out = await harness.call(43, 'aula.posts.get_attachment', {
      postId: 999,
      attachmentIndex: 0,
      profileIds: [1],
    });
    expect(out.error).toBe('post_not_found');
    expect(connections).toEqual([]);
  });

  test('attachment_not_found for an index past the end', async () => {
    const out = await harness.call(44, 'aula.posts.get_attachment', {
      postId: 314,
      attachmentIndex: 7,
      profileIds: [1],
    });
    expect(out.error).toBe('attachment_not_found');
    expect(out.totalAttachments).toBe(2);
    expect(connections).toEqual([]);
  });

  test('no longer accepts a caller-supplied URL (the audit SSRF)', async () => {
    const r = await harness.rpc({
      jsonrpc: '2.0',
      id: 45,
      method: 'tools/call',
      params: {
        name: 'aula.posts.get_attachment',
        arguments: { postId: 314, url: 'http://127.0.0.1:8080/secret.pdf', filename: 'x.pdf' },
      },
    });
    // attachmentIndex is required, so the schema rejects the old shape…
    expect(JSON.stringify(r).toLowerCase()).toMatch(/error|invalid/);
    // …and nothing was fetched.
    expect(connections).toEqual([]);
  });

  test('surfaces download_failed the same way as the messages tool', async () => {
    route('/post-314-0', { status: 404, body: 'gone' });
    const out = await harness.call(46, 'aula.posts.get_attachment', {
      postId: 314,
      attachmentIndex: 0,
      profileIds: [1],
    });
    expect(out.error).toBe('download_failed');
    expect(out.httpStatus).toBe(404);
  });
});

describe('MCP server: tools/call(aula.utils.extract_pdf_text)', () => {
  afterEach(() => {
    routes.clear();
    connections = [];
  });

  test('extracts text from an attachment downloaded by this server', async () => {
    route('/a', {
      headers: { 'content-type': 'application/pdf' },
      body: makeSyntheticPdf('Madplan uge 38', 2),
    });
    const downloaded = await harness.call(50, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 0,
    });
    expect(downloaded.ok).toBe(true);
    const out = await harness.call(51, 'aula.utils.extract_pdf_text', {
      attachmentId: downloaded.attachmentId,
    });
    expect(out.ok).toBe(true);
    expect(out.filename).toBe('kostplan.pdf');
    expect(out.text).toContain('Madplan uge 38 page 1');
    expect(out.text).toContain('Madplan uge 38 page 2');
    expect(out.pages).toBe(2);
    expect(out.truncated).toBe(false);
  });

  test('refuses an unknown attachment id', async () => {
    const out = await harness.call(52, 'aula.utils.extract_pdf_text', {
      attachmentId: '00000000-0000-4000-8000-000000000000',
    });
    expect(out.ok).toBe(false);
    expect(out.error).toBe('unknown_attachment');
  });

  test('no longer accepts a filesystem path (the audit arbitrary-read)', async () => {
    for (const bad of [
      { path: '/etc/passwd' },
      { attachmentId: '/etc/passwd' },
      { attachmentId: '../../etc/passwd' },
      { attachmentId: `${attachmentsDir}/anything.pdf` },
      { attachmentId: 'not-a-uuid' },
    ]) {
      const r = await harness.rpc({
        jsonrpc: '2.0',
        id: 53,
        method: 'tools/call',
        params: { name: 'aula.utils.extract_pdf_text', arguments: bad },
      });
      expect(JSON.stringify(r).toLowerCase()).toMatch(/error|invalid/);
    }
  });

  test('reports not_a_pdf for a downloaded attachment that is not a PDF', async () => {
    route('/b', { body: 'plain text seddel' });
    const downloaded = await harness.call(54, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 1,
    });
    const out = await harness.call(55, 'aula.utils.extract_pdf_text', {
      attachmentId: downloaded.attachmentId,
    });
    expect(out.ok).toBe(false);
    expect(out.error).toBe('not_a_pdf');
  });

  test('refuses an id whose file has since been removed from the store', async () => {
    route('/a', { body: makeSyntheticPdf('Gone') });
    const downloaded = await harness.call(56, 'aula.messages.get_attachment', {
      threadId: 77,
      attachmentIndex: 0,
    });
    await attachmentStore.remove(downloaded.attachmentId as string);
    const out = await harness.call(57, 'aula.utils.extract_pdf_text', {
      attachmentId: downloaded.attachmentId,
    });
    expect(out.error).toBe('unknown_attachment');
  });
});
