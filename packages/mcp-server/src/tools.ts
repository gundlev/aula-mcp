/**
 * MCP tool registrations. Each tool delegates to AulaContext / AulaClient.
 * Inputs are validated by Zod 4 schemas registered with McpServer.
 */

import type { AulaPost } from '@aula-mcp/aula-client';
import {
  AulaStepUpRequiredError,
  isoDate,
  isoWeekString,
  isoWeekToMonday,
  PRESENCE_STATUS_CODE,
} from '@aula-mcp/aula-client';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  type AttachmentEntry,
  type AttachmentSource,
  AttachmentStore,
  type FetchResult,
} from './attachments.ts';
import type { AulaContext } from './aula-context.ts';
import { resolveCalendarRange } from './calendar-range.ts';
import { buildDiscoverManifest } from './discover.ts';
import { extractPdfText, type PdfLimits, pdfLimitsFromEnv } from './pdf-extract.ts';

export interface RegisterToolsOptions {
  /** Shared attachment store; defaults to the process-wide one. */
  attachments?: AttachmentStore;
  /** PDF parser limits; default from `AULA_MCP_PDF_*`. */
  pdfLimits?: PdfLimits;
}

let sharedAttachmentStore: AttachmentStore | undefined;

/**
 * One attachment store per process. Every MCP session shares it, so an id
 * issued to one session is valid for another — which is the intended model:
 * every client of this server acts for the same household.
 */
export function getSharedAttachmentStore(): AttachmentStore {
  sharedAttachmentStore ??= new AttachmentStore();
  return sharedAttachmentStore;
}

/** Pages of `posts.getAllPosts` scanned when resolving a post id. */
const POST_LOOKUP_MAX_PAGES = 10;
const POST_LOOKUP_PAGE_SIZE = 50;

/**
 * The tool-facing view of a stored attachment. Callers get an opaque id
 * they hand back to `aula.utils.extract_pdf_text`; the presigned URL never
 * appears in a tool result.
 */
function attachmentResult(entry: AttachmentEntry): Record<string, unknown> {
  return {
    ok: true,
    attachmentId: entry.id,
    filename: entry.filename,
    bytes: entry.bytes,
    ...(entry.mediaType ? { mediaType: entry.mediaType } : {}),
    expiresAt: new Date(entry.expiresAt).toISOString(),
    // Informational for local (stdio) users who can open the file
    // themselves; remote clients cannot use it and should not need to.
    path: entry.path,
  };
}

async function fetchAttachment(
  store: AttachmentStore,
  args: {
    url: string;
    filename: string;
    mediaType?: string | null | undefined;
    source: AttachmentSource;
  },
): Promise<Record<string, unknown>> {
  const result: FetchResult = await store.fetch({
    url: args.url,
    filename: args.filename,
    mediaType: args.mediaType ?? null,
    source: args.source,
  });
  if (result.ok) return attachmentResult(result.entry);
  // Policy rejections are reported by category only: the offending URL is
  // Aula's, not the caller's, and echoing it back would leak the signature.
  return { ...result, filename: args.filename };
}

function jsonContent(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

/** Monday..Sunday of the current ISO week as `YYYY-MM-DD` strings. */
function currentWeekRange(): { from: string; to: string } {
  const monday = isoWeekToMonday(isoWeekString());
  const sunday = new Date(monday);
  sunday.setUTCDate(monday.getUTCDate() + 6);
  return { from: isoDate(monday), to: isoDate(sunday) };
}

type ConsentEntry = {
  institutionProfile?: {
    id?: number;
    role?: string; // "guardian" | "child"
  };
};

/**
 * Every institution profile (guardian + child, across all institutions) for
 * the authenticated guardian, read from consents.getConsentResponses — the
 * only endpoint that surfaces the club child identity that profiles.list and
 * discover both omit. Returns a guardian id first so the posts call is
 * authorized. Only the logged-in user's own profiles appear here, so the
 * other parent can never leak in.
 */
async function resolveFamilyProfileIds(
  client: Awaited<ReturnType<AulaContext['getClient']>>,
): Promise<number[]> {
  // rawRequest unwraps the Aula envelope to `.data`, so this is the
  // consent-entry array directly. Guard against either shape regardless.
  const raw = (await client.rawRequest('consents.getConsentResponses', {
    returnOnlyPendingConsentResponses: 'false',
  })) as { data?: ConsentEntry[] } | ConsentEntry[] | null;

  const entries: ConsentEntry[] = Array.isArray(raw) ? raw : (raw?.data ?? []);

  const guardianIds: number[] = [];
  const childIds: number[] = [];
  for (const { institutionProfile: ip } of entries) {
    if (!ip?.id) continue;
    (ip.role === 'guardian' ? guardianIds : childIds).push(ip.id);
  }

  if (guardianIds.length === 0) {
    throw new Error(
      'resolveFamilyProfileIds: consents.getConsentResponses returned no guardian ' +
        'profile to authorize the request.',
    );
  }
  // Guardian(s) first, then children; dedupe.
  return [...new Set([...guardianIds, ...childIds])];
}

/** Strip Aula post HTML down to readable text (keeps line breaks). Exported for tests. */
export function htmlToText(html: string): string {
  return html
    .replace(/<\/(p|div|li|h[1-6])>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * A post's downloadable attachments with the index `aula.posts.get_attachment`
 * takes. The index is stable for a given post because it is computed over
 * the same filtered list here and at download time.
 */
export function postAttachments(post: AulaPost): Array<{
  index: number;
  name: string | undefined;
  url: string;
  mediaType: string | undefined;
}> {
  return (post.attachments ?? [])
    .map((a) => ({
      name: a.file?.name ?? a.name,
      url: a.file?.url ?? a.url,
      mediaType: a.file?.mediaType,
    }))
    .filter(
      (a): a is { name: string | undefined; url: string; mediaType: string | undefined } =>
        typeof a.url === 'string' && a.url.length > 0,
    )
    .map((a, index) => ({ index, ...a }));
}

/** Keep only what a reader (and the attachment-download tool) needs. Exported for tests. */
export function slimPost(post: AulaPost) {
  // The presigned URL stays server-side: the model gets an index to pass to
  // aula.posts.get_attachment, never a URL to echo or mangle.
  const attachments = postAttachments(post).map(({ index, name, mediaType }) => ({
    index,
    name,
    ...(mediaType ? { mediaType } : {}),
  }));

  return {
    id: post.id, // needed for aula.posts.get_attachment's postId
    title: post.title,
    date: post.publishAt ?? post.timestamp,
    author: post.ownerProfile?.fullName,
    // institutionName is the one bit of that block worth keeping —
    // it tells you school vs club at a glance.
    institution: post.ownerProfile?.institution?.institutionName,
    ...(post.isImportant ? { isImportant: true } : {}),
    content: htmlToText(post.content?.html ?? ''),
    ...(attachments.length ? { attachments } : {}),
  };
}

/** `YYYY-MM-DD`. */
const ISO_DATE = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
/** 24-hour `HH:mm`. */
const HH_MM = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/);

/** Komme/gå "henteform" values the write tool accepts. */
const SET_TEMPLATE_ACTIVITY_TYPES = [
  'picked_up_by',
  'self_decider',
  'send_home',
  'go_home_with',
] as const;

/**
 * Subset of aula.presence.set_template's args that has cross-field rules.
 * Optional fields spell out `| undefined` so the tool's Zod-inferred args
 * (which carry explicit `undefined` under `exactOptionalPropertyTypes`)
 * assign cleanly.
 */
export interface SetTemplateArgs {
  activityType: (typeof SET_TEMPLATE_ACTIVITY_TYPES)[number];
  pickedUpBy?: string | undefined;
  selfDeciderStartTime?: string | undefined;
  selfDeciderEndTime?: string | undefined;
  repeat?: 'never' | 'weekly' | 'every_2_weeks' | undefined;
  repeatUntil?: string | undefined;
}

/**
 * Cross-field checks for aula.presence.set_template — the rules a flat Zod
 * schema can't express (a field required only for certain activityTypes).
 * Returns human-readable problems; an empty array means the args cohere.
 */
export function validateSetTemplateArgs(args: SetTemplateArgs): string[] {
  const problems: string[] = [];
  if (
    (args.activityType === 'picked_up_by' || args.activityType === 'go_home_with') &&
    !args.pickedUpBy
  ) {
    problems.push(
      `activityType "${args.activityType}" requires pickedUpBy (who collects the child).`,
    );
  }
  if (
    args.activityType === 'self_decider' &&
    (!args.selfDeciderStartTime || !args.selfDeciderEndTime)
  ) {
    problems.push(
      'activityType "self_decider" requires selfDeciderStartTime and selfDeciderEndTime.',
    );
  }
  const repeat = args.repeat ?? 'never';
  if (repeat !== 'never' && !args.repeatUntil) {
    problems.push(`repeat "${repeat}" requires repeatUntil (the last date the repeat applies).`);
  }
  return problems;
}

export function registerTools(
  server: McpServer,
  context: AulaContext,
  options: RegisterToolsOptions = {},
): void {
  const attachments = options.attachments ?? getSharedAttachmentStore();
  const pdfLimits = options.pdfLimits ?? pdfLimitsFromEnv();

  // --- aula.discover -------------------------------------------------------

  server.registerTool(
    'aula.discover',
    {
      title: 'Discover Aula context',
      description:
        'Returns a typed manifest of the logged-in guardian: children (with names + ids), ' +
        'institutions, API version, detected widgets, and which subordinate aula.* tools to ' +
        'call. Includes a `usage` block with name-resolution and tool-selection rules. ' +
        'Call ONCE per session and reuse the result — do not re-call mid-session.',
      inputSchema: {},
    },
    async () => {
      const manifest = await buildDiscoverManifest(context);
      return jsonContent(manifest);
    },
  );

  // --- aula.profiles.list --------------------------------------------------

  server.registerTool(
    'aula.profiles.list',
    {
      title: 'List Aula profiles',
      description: 'Raw profiles.getProfilesByLogin response — every child + institution.',
      inputSchema: {},
    },
    async () => {
      const client = await context.getClient();
      return jsonContent(await client.getProfilesByLogin());
    },
  );

  // --- aula.presence.today -------------------------------------------------

  server.registerTool(
    'aula.presence.today',
    {
      title: 'Daily presence overview',
      description:
        'Returns presence/check-in/check-out info for the given child IDs. Status codes: ' +
        '0=IKKE_KOMMET (not arrived), 1=SYG (reported sick), 2=FERIE_FRI (holiday/not ' +
        'enrolled), 3=KOMMET (arrived/present), 4=PAA_TUR (on a trip), 5=SOVER (sleeping), ' +
        '6=FRITIDSAKTIVITET, 7=FYSISK_PLACERING, 8=GAAET (picked up/left).',
      inputSchema: {
        childIds: z
          .array(z.number().int().positive())
          .min(1)
          .describe('Aula child IDs (from aula.discover.children[].id)'),
      },
    },
    async (args) => {
      const client = await context.getClient();
      return jsonContent(await client.getDailyOverview(args.childIds));
    },
  );

  // --- aula.presence.templates ---------------------------------------------

  server.registerTool(
    'aula.presence.templates',
    {
      title: 'Komme/gå templates (drop-off & pickup schedule)',
      description:
        'Recurring komme/gå (presence) templates for the given children — the drop-off ' +
        'and pickup times a guardian has registered per day. Pass the same child IDs as ' +
        '`aula.presence.today`. `from`/`to` bound the window (YYYY-MM-DD); they default ' +
        'to the current week. Each returned template carries the `institutionProfile.id` ' +
        'that `aula.presence.set_template` needs. Read this before changing a schedule.',
      inputSchema: {
        childIds: z
          .array(z.number().int().positive())
          .min(1)
          .describe('Aula child IDs (from aula.discover.children[].id)'),
        from: ISO_DATE.optional().describe('Window start YYYY-MM-DD. Defaults to this Monday.'),
        to: ISO_DATE.optional().describe('Window end YYYY-MM-DD. Defaults to this Sunday.'),
      },
    },
    async (args) => {
      const window = args.from && args.to ? { from: args.from, to: args.to } : currentWeekRange();
      const client = await context.getClient();
      return jsonContent(
        await client.getPresenceTemplates({
          institutionProfileIds: args.childIds,
          fromDate: window.from,
          toDate: window.to,
        }),
      );
    },
  );

  // --- aula.presence.set_template (gated, write) ---------------------------
  //
  // The first and only tool that *writes* to Aula. Gated behind
  // AULA_MCP_WRITE=1 so a server stays read-only by default — rescheduling a
  // child's pickup is not something an agent should be able to do unasked.

  if (process.env.AULA_MCP_WRITE === '1') {
    server.registerTool(
      'aula.presence.set_template',
      {
        title: 'Set a komme/gå template (drop-off & pickup time)',
        description:
          "Register or overwrite a child's komme/gå template for one day. WRITES to " +
          'Aula — enabled when AULA_MCP_WRITE=1. Covers one child and one date per call; ' +
          'call once per day to fill a week. Read `aula.presence.templates` first to see ' +
          'the current schedule and confirm the child id. `activityType` picks how the ' +
          'child leaves: picked_up_by ("Hentes af", a named person collects), ' +
          'self_decider ("Selvbestemmer", may leave alone between two times), ' +
          'send_home ("Sendes hjem", leaves alone at exitTime), go_home_with ' +
          '("Går hjem med", leaves with a named person). Set `repeat` to make it recur ' +
          'on that weekday until `repeatUntil`.',
        inputSchema: {
          institutionProfileId: z
            .number()
            .int()
            .positive()
            .describe(
              'Child institution-profile id — the same id passed to aula.presence.today ' +
                'as childIds, and the institutionProfile.id from aula.presence.templates.',
            ),
          date: ISO_DATE.describe(
            'Day the template applies to (YYYY-MM-DD). With repeat set, this is the ' +
              'first occurrence and fixes the weekday.',
          ),
          activityType: z
            .enum(SET_TEMPLATE_ACTIVITY_TYPES)
            .describe('How the child leaves the institution.'),
          entryTime: HH_MM.optional().describe('Drop-off time, HH:mm.'),
          exitTime: HH_MM.optional().describe(
            'Pickup / go-home time, HH:mm. Used by picked_up_by, send_home, go_home_with.',
          ),
          pickedUpBy: z
            .string()
            .min(1)
            .optional()
            .describe(
              'Name of the person collecting the child. Required for ' +
                'picked_up_by and go_home_with.',
            ),
          selfDeciderStartTime: HH_MM.optional().describe(
            'Earliest the child may leave, HH:mm. Required for self_decider.',
          ),
          selfDeciderEndTime: HH_MM.optional().describe(
            'Latest the child may leave, HH:mm. Required for self_decider.',
          ),
          comment: z.string().optional().describe('Free-text note shown to staff.'),
          repeat: z
            .enum(['never', 'weekly', 'every_2_weeks'])
            .optional()
            .describe('Repeat cadence. Defaults to never (the single day only).'),
          repeatUntil: ISO_DATE.optional().describe(
            'Last date the repeat applies (YYYY-MM-DD). Required when repeat is ' +
              'weekly or every_2_weeks.',
          ),
        },
      },
      async (args) => {
        // Cross-field prerequisites Zod can't express — fail here with an
        // actionable message rather than letting Aula reject a half-built
        // template after the round-trip.
        const problems = validateSetTemplateArgs(args);
        if (problems.length > 0) {
          return jsonContent({ error: 'invalid_arguments', problems });
        }
        const repeat = args.repeat ?? 'never';

        const client = await context.getClient();
        const result = await client.updatePresenceTemplate({
          institutionProfileId: args.institutionProfileId,
          date: args.date,
          activityType: args.activityType,
          repeatPattern: repeat,
          ...(args.entryTime ? { entryTime: args.entryTime } : {}),
          ...(args.exitTime ? { exitTime: args.exitTime } : {}),
          ...(args.pickedUpBy ? { pickedUpBy: args.pickedUpBy } : {}),
          ...(args.selfDeciderStartTime ? { selfDeciderStartTime: args.selfDeciderStartTime } : {}),
          ...(args.selfDeciderEndTime ? { selfDeciderEndTime: args.selfDeciderEndTime } : {}),
          ...(args.comment !== undefined ? { comment: args.comment } : {}),
          ...(args.repeatUntil ? { repeatUntil: args.repeatUntil } : {}),
        });
        return jsonContent({ ok: true, result });
      },
    );

    // --- aula.presence.report_sick (gated, write) --------------------------
    //
    // Same gate, and for the same reason: telling a daycare a child is ill is
    // not something an agent should be able to do unasked.
    //
    // One tool for both directions, because Aula has one endpoint for both:
    // reporting sick and taking it back are the same call with a different
    // status.

    server.registerTool(
      'aula.presence.report_sick',
      {
        title: 'Report a child sick (or well again)',
        description:
          'Mark a child as sick for today, or take the report back. WRITES to Aula — ' +
          'enabled when AULA_MCP_WRITE=1. The institution is notified. Applies to today; ' +
          'Aula has no future-dated sick report — use aula.presence.set_template or a ' +
          'vacation registration for a planned absence. An institution can withhold this ' +
          'from guardians, in which case Aula rejects the call.',
        inputSchema: {
          institutionProfileIds: z
            .array(z.number().int().positive())
            .min(1)
            .describe(
              'Child institution-profile ids — the same ids passed to aula.presence.today ' +
                'as childIds, i.e. aula.discover children[].id. Must belong to the ' +
                'logged-in guardian; anything else is rejected. Confirm the child with ' +
                'the user before calling.',
            ),
          sick: z
            .boolean()
            .describe(
              'true reports the child sick. false takes the report back, which sets the ' +
                'child to "ikke kommet" (not arrived) — so it is rejected unless Aula ' +
                'currently reports that child as sick.',
            ),
        },
      },
      async (args) => {
        const client = await context.getClient();

        // Scope the write to this login's own children.
        //
        // Aula happily accepts any institution-profile id the caller has rights
        // to, and the schema takes an array, so a single hallucinated number is
        // enough to tell the wrong institution that someone else's child is
        // ill. Resolve the guardian's actual children first and refuse anything
        // that isn't one of them — a local error beats a phone call from a
        // daycare.
        const profilesData = await client.getProfilesByLogin();
        const ownChildren = new Map<number, string>();
        for (const profile of profilesData.profiles ?? []) {
          for (const child of profile.children ?? []) {
            ownChildren.set(child.id, child.name);
          }
        }
        const unknownIds = args.institutionProfileIds.filter((id) => !ownChildren.has(id));
        if (unknownIds.length > 0) {
          return jsonContent({
            error: 'unknown_child',
            message:
              'Refusing to write: these institution-profile ids are not children of the ' +
              'logged-in guardian. Call aula.discover and use children[].id.',
            unknownIds,
            knownChildren: [...ownChildren].map(([id, name]) => ({ id, name })),
          });
        }

        // Un-reporting is not a free action.
        //
        // Aula's own UI only offers "take the sick report back" from a sick
        // state, so status 0 is safe there. Here nothing constrains it: calling
        // sick:false on a child who is currently checked in would silently flip
        // them to "ikke kommet" and still report ok. Only allow it for a child
        // Aula currently reports as sick.
        if (!args.sick) {
          const overview = await client.getDailyOverview(args.institutionProfileIds);
          const statusById = new Map<number, number>();
          for (const entry of overview) {
            const id = entry.institutionProfile?.id;
            if (id !== undefined) statusById.set(id, entry.status);
          }
          const notSick = args.institutionProfileIds.filter(
            (id) => statusById.get(id) !== PRESENCE_STATUS_CODE.SICK,
          );
          if (notSick.length > 0) {
            return jsonContent({
              error: 'not_reported_sick',
              message:
                'Refusing to write: taking a sick report back sets the child to ' +
                '"ikke kommet" (0), so it is only safe for a child Aula currently reports ' +
                'as sick. These are not. Use aula.presence.today to see the current status.',
              children: notSick.map((id) => ({
                id,
                name: ownChildren.get(id),
                currentStatus: statusById.get(id) ?? null,
              })),
            });
          }
        }

        const result = await client.updatePresenceStatus({
          institutionProfileIds: args.institutionProfileIds,
          status: args.sick ? PRESENCE_STATUS_CODE.SICK : PRESENCE_STATUS_CODE.NOT_PRESENT,
        });
        return jsonContent({ ok: true, result });
      },
    );

    // --- aula.messages.mark_read (gated, write) ----------------------------
    //
    // Lives here rather than next to the other aula.messages.* tools so every
    // write stays behind the one AULA_MCP_WRITE gate. Aula has no "mark as
    // read" verb; see AulaClient.setLastReadMessage for what actually happens.

    server.registerTool(
      'aula.messages.mark_read',
      {
        title: 'Mark a message thread as read',
        description:
          'Move the read marker in a thread to its newest message, clearing the unread ' +
          'badge. WRITES to Aula — enabled when AULA_MCP_WRITE=1. Pass `messageId` from ' +
          '`aula.messages.list_threads` (thread.latestMessage.id); omit it to mark the ' +
          'thread read up to whatever its newest message is right now. Marking read is ' +
          'not reversible through this API — Aula offers no way to set a thread back to ' +
          'unread, so only call this for threads the user has actually seen.',
        inputSchema: {
          threadId: z
            .number()
            .int()
            .positive()
            .describe('Thread id from aula.messages.list_threads.'),
          messageId: z
            .string()
            .min(1)
            .optional()
            .describe(
              'Aula\'s opaque message id (e.g. "6a3d2467304484.24549709"), NOT a number. ' +
                "Defaults to the thread's newest message.",
            ),
        },
      },
      async (args) => {
        const client = await context.getClient();
        // Messaging endpoints 403 until the guardian profile is activated
        // server-side — same priming as aula.messages.get_thread.
        await context.getGuardianUserId();

        let messageId = args.messageId;
        if (!messageId) {
          // Aula pages threads 20 at a time and ignores pageSize, so a single
          // getThreads call only ever sees the newest 20 — walk pages until the
          // thread turns up. Bounded: a caller that already has the thread in
          // hand should pass messageId rather than make us search for it.
          const MAX_PAGES = 10;
          let latest: string | undefined;
          let pagesRead = 0;
          for (let page = 0; page < MAX_PAGES; page++) {
            const { threads, hasMorePages } = await client.getThreadsPage({ page });
            pagesRead = page + 1;
            const found = threads.find((t) => t.id === args.threadId);
            if (found?.latestMessage?.id != null) {
              latest = String(found.latestMessage.id);
              break;
            }
            if (!hasMorePages) break;
          }
          if (latest === undefined) {
            return jsonContent({
              error: 'message_id_unresolved',
              message:
                `Thread ${args.threadId} was not found in the first ${pagesRead} pages ` +
                `(~${pagesRead * 20} threads), or carries no latestMessage.id. Pass ` +
                'messageId explicitly — aula.messages.list_threads returns it as ' +
                'thread.latestMessage.id.',
            });
          }
          messageId = latest;
        }

        const result = await client.setLastReadMessage(args.threadId, messageId);
        return jsonContent({ ok: true, threadId: args.threadId, messageId, result });
      },
    );
  }

  // --- aula.calendar.events ------------------------------------------------

  server.registerTool(
    'aula.calendar.events',
    {
      title: 'Calendar events (school schedule)',
      description:
        'Lessons + events for the given child institution-profile IDs. ' +
        'Call aula.discover first and pass children[].id as profileIds. ' +
        'Pass `range` for a preset window (today/tomorrow/this_week/next_week) ' +
        'OR `start`+`end` for a specific window. Timestamps are formatted as Aula ' +
        'expects: "YYYY-MM-DD HH:MM:SS.0000+ZZZZ". Aula uses Europe/Copenhagen.',
      inputSchema: {
        profileIds: z
          .array(z.number().int().positive())
          .min(1)
          .describe(
            'Child institution-profile IDs from aula.discover children[].id. ' +
              'Do not use children[].userId.',
          ),
        range: z.enum(['today', 'tomorrow', 'this_week', 'next_week']).optional(),
        start: z.string().min(1).optional(),
        end: z.string().min(1).optional(),
        resourceIds: z.array(z.number().int().positive()).optional(),
      },
    },
    async (args) => {
      let start: string;
      let end: string;
      if (args.start && args.end) {
        start = args.start;
        end = args.end;
      } else {
        const window = resolveCalendarRange(args.range ?? 'this_week');
        start = window.start;
        end = window.end;
      }
      const client = await context.getClient();
      const events = await client.getCalendarEvents({
        profileIds: args.profileIds,
        start,
        end,
        ...(args.resourceIds ? { resourceIds: args.resourceIds } : {}),
      });
      return jsonContent(events);
    },
  );

  // --- aula.notifications.list ---------------------------------------------

  server.registerTool(
    'aula.notifications.list',
    {
      title: 'Aula notifications',
      description: 'Unread items + activity for the active guardian profile.',
      inputSchema: {},
    },
    async () => {
      const client = await context.getClient();
      // See aula.messages.get_thread below — guardian profile must be
      // primed or Aula's `*ForActiveProfile` endpoints 403.
      await context.getGuardianUserId();
      return jsonContent(await client.getNotifications());
    },
  );

  // --- aula.posts.list -----------------------------------------------------

  server.registerTool(
    'aula.posts.list',
    {
      title: 'Aula posts (class news feed)',
      description:
        'Teacher posts and class-level updates, across every institution the ' +
        'family belongs to (school and club).',
      inputSchema: {
        limit: z.number().int().min(1).max(50).optional(),
        index: z.number().int().min(0).optional(),
        profileIds: z
          .array(z.number())
          .min(1)
          .optional()
          .describe(
            'Optional. Omit to cover the whole family across all institutions ' +
              'automatically — recommended, and the only way to guarantee club ' +
              'posts appear. Set this only to deliberately narrow the feed.',
          ),
        onlyUnread: z
          .boolean()
          .optional()
          .describe('Only return unread posts. Defaults to false (all posts).'),
      },
    },
    async (args) => {
      const client = await context.getClient();
      // Profile-scoped feed needs the guardian profile activated, or Aula 403s.
      await context.getGuardianUserId();

      const institutionProfileIds = args.profileIds ?? (await resolveFamilyProfileIds(client));

      const result = await client.getPosts({
        ...(args.limit !== undefined ? { limit: args.limit } : {}),
        index: args.index ?? 0,
        onlyUnread: args.onlyUnread === true,
        institutionProfileIds,
      });

      const rawPosts = result?.posts ?? [];
      return jsonContent({
        count: rawPosts.length,
        ...(typeof result?.moreMessagesExist === 'boolean'
          ? { moreMessagesExist: result.moreMessagesExist }
          : {}),
        posts: rawPosts.map(slimPost),
      });
    },
  );

  // --- aula.raw_request (gated) --------------------------------------------

  if (process.env.AULA_MCP_RAW === '1') {
    server.registerTool(
      'aula.raw_request',
      {
        title: 'Raw Aula API call (escape hatch)',
        description:
          'Call any Aula API method directly. Enabled when AULA_MCP_RAW=1. The CSRF token + ' +
          'access_token are added automatically; the response envelope is unwrapped to its ' +
          '`data` field. Use sparingly — most needs have a typed tool.',
        inputSchema: {
          method: z.string().min(1).describe('e.g. "profiles.getProfileContext"'),
          query: z.record(z.string(), z.string()).optional(),
          body: z.unknown().optional(),
        },
      },
      async (args) => {
        const client = await context.getClient();
        return jsonContent(await client.rawRequest(args.method, args.query ?? {}, args.body));
      },
    );
  }

  // --- aula.messages.list_threads ------------------------------------------

  server.registerTool(
    'aula.messages.list_threads',
    {
      title: 'List Aula message threads',
      description:
        'One page of threads, most recent first. Aula serves 20 per page and IGNORES ' +
        '`pageSize` — asking for 50 still returns 20. Returns `{ threads, page, ' +
        'hasMorePages }`: when `hasMorePages` is true there are older threads you have ' +
        'not seen, so keep calling with `page` + 1 before concluding anything about the ' +
        'mailbox as a whole (e.g. "no unread messages"). A single call answers "what ' +
        'arrived recently", never "what does the mailbox contain".',
      inputSchema: {
        page: z.number().int().min(0).default(0).optional(),
        pageSize: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe('Sent through to Aula, which ignores it. Kept in case that changes.'),
      },
    },
    async (args) => {
      const client = await context.getClient();
      // See aula.messages.get_thread below — messaging endpoints 403
      // until the guardian profile is activated server-side.
      await context.getGuardianUserId();
      const page = await client.getThreadsPage({
        ...(args.page !== undefined ? { page: args.page } : {}),
        ...(args.pageSize !== undefined ? { pageSize: args.pageSize } : {}),
      });
      return jsonContent(page);
    },
  );

  // --- aula.ugeplan.* ------------------------------------------------------
  //
  // Each provider has its own tool. The agent picks the right one based on
  // the institution-to-provider mapping (currently: try whichever the
  // school uses; long term, plumb this into discover).

  const integrationContextShape = {
    childIds: z.array(z.number().int().positive()).min(1),
    institutionCodes: z.array(z.string().min(1)).min(1),
    isoWeek: z
      .string()
      .regex(/^\d{4}-W\d{2}$/)
      .optional()
      .describe('ISO week, e.g. "2026-W18". Defaults to the current week.'),
  } as const;

  async function buildIntegrationCtx(args: {
    childIds: number[];
    institutionCodes: string[];
    isoWeek?: string | undefined;
  }) {
    const client = await context.getClient();
    const record = context.record;
    if (!record) throw new Error('AulaContext: no token record loaded');
    // EasyIQ / MU / Meebook want the numeric guardian user-id (from
    // getProfileContext). Systematic uses the literal MitID username for its
    // sessionId — that's the only integration where `sessionId` and the
    // numeric id differ. SystematicClient currently reads `ctx.sessionId`
    // (= username), so we keep that field as the username and put the
    // numeric id under `guardianId` for the other plugins.
    const guardianUserId = await context.getGuardianUserId();

    // SkolePortal's `x-childfilter` header takes the opaque per-child userId
    // (alphanumeric token), not the numeric child profile id. Look it up
    // from the profiles list, aligned with childIds by index. Missing → "".
    const profilesData = await client.getProfilesByLogin();
    const userIdByChildId = new Map<number, string>();
    for (const profile of profilesData.profiles ?? []) {
      for (const child of profile.children ?? []) {
        if (child.userId != null) {
          userIdByChildId.set(child.id, String(child.userId));
        }
      }
    }
    const childUserIds = args.childIds.map((id) => userIdByChildId.get(id) ?? '');

    return {
      isoWeek: args.isoWeek ?? isoWeekString(),
      sessionId: record.username,
      guardianId: guardianUserId,
      childIds: args.childIds,
      childUserIds,
      institutionCodes: args.institutionCodes,
    };
  }

  server.registerTool(
    'aula.ugeplan.easyiq',
    {
      title: 'EasyIQ weekly plan',
      description:
        'Weekly plan from EasyIQ for the given children. Use when the school is on EasyIQ.',
      inputSchema: integrationContextShape,
    },
    async (args) => {
      const easyiq = await context.getEasyIq();
      return jsonContent(await easyiq.getWeekPlan(await buildIntegrationCtx(args)));
    },
  );

  server.registerTool(
    'aula.ugeplan.meebook',
    {
      title: 'Meebook weekly plan',
      description:
        'Weekly plan from Meebook for the given children. Use when the school is on Meebook.',
      inputSchema: integrationContextShape,
    },
    async (args) => {
      const meebook = await context.getMeebook();
      return jsonContent(await meebook.getWeekPlan(await buildIntegrationCtx(args)));
    },
  );

  server.registerTool(
    'aula.ugeplan.easyiq_skoleportal',
    {
      title: 'EasyIQ SkolePortal weekly plan',
      description:
        'Weekly plan from EasyIQ SkolePortal (widget 0128) — a different EasyIQ product than ' +
        '`aula.ugeplan.easyiq` (widget 0001). Use when discover.detectedWidgets contains "0128".',
      inputSchema: integrationContextShape,
    },
    async (args) => {
      const sp = await context.getEasyIqSkoleportal();
      return jsonContent(await sp.getWeekPlan(await buildIntegrationCtx(args)));
    },
  );

  server.registerTool(
    'aula.lektier.easyiq',
    {
      title: 'EasyIQ Lektier (homework)',
      description:
        'Homework items from EasyIQ Lektier (widget 0142) — same vendor as ' +
        '`aula.ugeplan.easyiq_skoleportal` but a separate "Lektier" product. ' +
        'Use when discover.detectedWidgets contains "0142".',
      inputSchema: integrationContextShape,
    },
    async (args) => {
      const lektier = await context.getEasyIqLektier();
      return jsonContent(await lektier.getLektier(await buildIntegrationCtx(args)));
    },
  );

  server.registerTool(
    'aula.opgaver.minuddannelse',
    {
      title: 'Min Uddannelse opgaveliste',
      description: 'Homework / task list from Min Uddannelse for the given children.',
      inputSchema: integrationContextShape,
    },
    async (args) => {
      const mu = await context.getMinUddannelse();
      return jsonContent(await mu.getOpgaver(await buildIntegrationCtx(args)));
    },
  );

  server.registerTool(
    'aula.ugebrev.minuddannelse',
    {
      title: 'Min Uddannelse ugebrev',
      description: 'Weekly newsletter (ugebrev) from Min Uddannelse.',
      inputSchema: integrationContextShape,
    },
    async (args) => {
      const mu = await context.getMinUddannelse();
      return jsonContent(await mu.getUgebrev(await buildIntegrationCtx(args)));
    },
  );

  server.registerTool(
    'aula.huskelisten.systematic',
    {
      title: 'Systematic Huskelisten reminders',
      description:
        'Homework reminders from Systematic. Args may include `from`/`to` ISO YYYY-MM-DD dates.',
      inputSchema: {
        ...integrationContextShape,
        fromDate: z
          .string()
          .regex(/^\d{4}-\d{2}-\d{2}$/)
          .optional(),
        toDate: z
          .string()
          .regex(/^\d{4}-\d{2}-\d{2}$/)
          .optional(),
      },
    },
    async (args) => {
      const sys = await context.getSystematic();
      const baseCtx = await buildIntegrationCtx(args);
      return jsonContent(
        await sys.getReminders({
          ...baseCtx,
          ...(args.fromDate ? { fromDate: args.fromDate } : {}),
          ...(args.toDate ? { toDate: args.toDate } : {}),
        }),
      );
    },
  );

  // --- aula.messages.get_thread --------------------------------------------

  server.registerTool(
    'aula.messages.get_thread',
    {
      title: 'Read a single thread',
      description:
        'Returns subject + every message in the thread. If the thread is sensitive, ' +
        'this tool returns an error code that means the user must MitID step-up to read it ' +
        '(currently a fresh `aula login` from the CLI).',
      inputSchema: {
        threadId: z.number().int().positive(),
        page: z.number().int().min(0).default(0).optional(),
      },
    },
    async (args) => {
      const client = await context.getClient();
      // Prime the guardian profile before fetching. Aula's
      // messaging.getMessagesForThread returns HTTP 403 if the
      // guardian profile hasn't been activated on the server side
      // this session, even with a fully step-up'd bearer. aula.discover
      // implicitly primes via getGuardianUserId() — but if the agent
      // calls get_thread directly (cached threadId from a prior turn,
      // skipping discover), no priming has happened. getGuardianUserId
      // memoises after the first call, so this is a no-op once primed.
      await context.getGuardianUserId();
      try {
        return jsonContent(
          await client.getMessagesForThread(args.threadId, {
            ...(args.page !== undefined ? { page: args.page } : {}),
          }),
        );
      } catch (e) {
        if (e instanceof AulaStepUpRequiredError) {
          return jsonContent({
            error: 'step_up_required',
            message: e.message,
            hint: 'Run `aula login` again to refresh your session, then retry.',
          });
        }
        throw e;
      }
    },
  );

  // --- aula.messages.get_attachment ----------------------------------------
  //
  // Download a message attachment server-side and hand back an opaque
  // attachment id. Aula attachment URLs are CloudFront presigned links with
  // long opaque signatures; LLMs frequently corrupt them when echoing the URL
  // into other tool calls. Keeping the URL server-side avoids that — and,
  // since the September 2026 audit, is also what keeps the download path
  // from being pointed at anything other than Aula's own storage: the URL
  // is resolved from the authenticated thread, validated (https, allowed
  // host, public address, every redirect) and streamed under hard limits.

  server.registerTool(
    'aula.messages.get_attachment',
    {
      title: 'Download a thread attachment',
      description:
        'Download an attachment from a thread message into the server\u2019s bounded ' +
        'attachment store and return an `attachmentId` for `aula.utils.extract_pdf_text`. ' +
        '`attachmentIndex` is zero-based across all attachments in the thread, flattened ' +
        'message-by-message in the order returned by `aula.messages.get_thread`. ' +
        'Downloaded files expire after about an hour.',
      inputSchema: {
        threadId: z.number().int().positive(),
        attachmentIndex: z.number().int().min(0),
      },
    },
    async (args) => {
      const client = await context.getClient();
      await context.getGuardianUserId();
      // Re-fetch the thread to get a fresh URL; presigned URLs age out
      // within ~1h and we never want to download against a cached one.
      const { messages } = await client.getMessagesForThread(args.threadId);
      const flat = messages.flatMap((m) => m.attachments ?? []);
      const att = flat[args.attachmentIndex];
      if (!att?.file?.url) {
        return jsonContent({
          error: 'attachment_not_found',
          threadId: args.threadId,
          attachmentIndex: args.attachmentIndex,
          totalAttachments: flat.length,
        });
      }
      return jsonContent(
        await fetchAttachment(attachments, {
          url: att.file.url,
          filename: att.file.name ?? `attachment-${args.attachmentIndex}.bin`,
          mediaType: att.file.mediaType,
          source: { kind: 'thread', id: args.threadId, index: args.attachmentIndex },
        }),
      );
    },
  );

  // --- aula.posts.get_attachment -------------------------------------------
  //
  // The caller names a post and an attachment index; the URL is looked up
  // server-side in the authenticated posts feed. Accepting a URL here was
  // the audit's SSRF finding — the tool would fetch (and follow redirects
  // from) anything, including localhost.

  server.registerTool(
    'aula.posts.get_attachment',
    {
      title: 'Download a post attachment',
      description:
        'Download an attachment from a news feed post into the server\u2019s bounded ' +
        'attachment store and return an `attachmentId` for `aula.utils.extract_pdf_text`. ' +
        'Pass the `id` of the post and the `index` of the attachment exactly as returned ' +
        'by `aula.posts.list`. The post is looked up again on the server; URLs are never ' +
        'accepted.',
      inputSchema: {
        postId: z.number().int().describe('The post id from aula.posts.list.'),
        attachmentIndex: z
          .number()
          .int()
          .min(0)
          .describe('attachments[].index from aula.posts.list for that post.'),
        profileIds: z
          .array(z.number())
          .min(1)
          .optional()
          .describe(
            'Optional. Same meaning as in aula.posts.list — narrow the feed the post is ' +
              'looked up in. Omit to search the whole family feed.',
          ),
      },
    },
    async (args) => {
      const client = await context.getClient();
      await context.getGuardianUserId();
      const institutionProfileIds = args.profileIds ?? (await resolveFamilyProfileIds(client));

      let post: AulaPost | undefined;
      let pagesRead = 0;
      for (let index = 0; index < POST_LOOKUP_MAX_PAGES && !post; index++) {
        const page = await client.getPosts({
          limit: POST_LOOKUP_PAGE_SIZE,
          index,
          onlyUnread: false,
          institutionProfileIds,
        });
        pagesRead++;
        const posts = page?.posts ?? [];
        post = posts.find((p) => p.id === args.postId);
        if (posts.length === 0 || page?.moreMessagesExist === false) break;
      }
      if (!post) {
        return jsonContent({
          error: 'post_not_found',
          postId: args.postId,
          message:
            `Post ${args.postId} was not found in the first ${pagesRead} pages of the feed ` +
            'for these profiles. Call aula.posts.list to confirm the id.',
        });
      }
      const candidates = postAttachments(post);
      const att = candidates[args.attachmentIndex];
      if (!att) {
        return jsonContent({
          error: 'attachment_not_found',
          postId: args.postId,
          attachmentIndex: args.attachmentIndex,
          totalAttachments: candidates.length,
        });
      }
      return jsonContent(
        await fetchAttachment(attachments, {
          url: att.url,
          filename: att.name ?? `attachment-${args.attachmentIndex}.bin`,
          mediaType: att.mediaType,
          source: { kind: 'post', id: args.postId, index: args.attachmentIndex },
        }),
      );
    },
  );

  // --- aula.utils.extract_pdf_text ------------------------------------------
  //
  // Aula sends a lot of what parents actually need as PDF attachments —
  // menus, packing lists, trip letters — so downloading one is only half the
  // job. The tool takes an attachment id, never a path: the file is resolved
  // through the store (real-path containment, regular file, size cap) and
  // parsed in a separate process with a deadline and page/output caps.

  server.registerTool(
    'aula.utils.extract_pdf_text',
    {
      title: 'Extract text from a downloaded PDF attachment',
      description:
        'Return the text of a PDF previously downloaded with aula.posts.get_attachment or ' +
        'aula.messages.get_attachment, identified by its `attachmentId`. Only files ' +
        'downloaded by this server can be read. Long documents are cut at the server\u2019s ' +
        'page and character limits; `truncated` says when that happened.',
      inputSchema: {
        attachmentId: z
          .string()
          .uuid()
          .describe('The attachmentId returned by a get_attachment tool.'),
      },
    },
    async (args) => {
      const resolved = await attachments.resolve(args.attachmentId);
      if (!resolved.ok) {
        return jsonContent({
          ok: false,
          error: resolved.error,
          ...(resolved.detail ? { detail: resolved.detail } : {}),
          hint: 'Download the attachment again with a get_attachment tool and retry.',
        });
      }
      const result = await extractPdfText(resolved.realPath, resolved.size, pdfLimits);
      if (!result.ok) return jsonContent(result);
      return jsonContent({
        ok: true,
        attachmentId: args.attachmentId,
        filename: resolved.entry.filename,
        text: result.text,
        pages: result.pages,
        pagesParsed: result.pagesParsed,
        truncated: result.truncated,
      });
    },
  );
}
