/**
 * Claude Code adapter — spawns the `claude` CLI in non-interactive
 * stream-json mode and maps its events to OGF's common AgentEvent shape.
 *
 * Pattern mirrors codex.ts so the rest of the daemon (RunManager, SSE,
 * Turn rendering) treats both CLIs identically.
 *
 * Claude Code wire format (verified via official docs):
 *   - Invocation: `claude -p "PROMPT" --output-format stream-json --verbose
 *                 --include-partial-messages`
 *   - Resume: `--resume <session-id>` OR `--session-id <uuid>`
 *   - Stdout: JSONL. Each line is an event object.
 *   - Stderr: human-friendly errors / warnings — surfaced as raw events.
 *   - Exit 0 on success, non-zero on fatal errors.
 *
 * Event types we expect:
 *   - `system` (subtype: `init` | `api_retry` | …) — session bookkeeping
 *   - `assistant` — assistant message; content blocks may be text / tool_use
 *   - `user` — tool_result echoed back (when Claude runs tools)
 *   - `result` — final summary for the turn (cost, usage, session_id)
 *   - `stream_event` — wrapper around raw Anthropic SSE events
 *     (only present when `--include-partial-messages` is set)
 *
 * For text streaming, --include-partial-messages emits `stream_event`
 * objects whose `.event.delta.text` carries text deltas. Without that
 * flag, only whole assistant messages arrive.
 *
 * Refs:
 *   https://code.claude.com/docs/en/cli-reference.md
 *   https://code.claude.com/docs/en/headless.md
 *   https://code.claude.com/docs/en/agent-sdk/streaming-output.md
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import type { AgentEvent } from '@ogf/contracts';
import { makeDebugLogger } from './debug-log.js';

/** Opt-in raw-stream logging. Off unless OGF_CLAUDE_DEBUG_LOG names a
 *  path (audit E16). Bounded + redacted; see debug-log.ts. */
const debugLogLine = makeDebugLogger('OGF_CLAUDE_DEBUG_LOG');

// -------------------- Spawn --------------------

export interface ClaudeCodeRunOptions {
  /** Path to the `claude` binary. */
  bin: string;
  /** Working directory for the run. */
  cwd: string;
  /** Prompt to feed Claude. */
  prompt: string;
  /** Optional model id (e.g. "claude-sonnet-4-5", "claude-opus-4"). */
  model?: string;
  /** When set, resumes that Claude Code session instead of starting a new
   *  thread. Reuses the original conversation context. */
  resumeThreadId?: string;
  env?: NodeJS.ProcessEnv;
}

/** System prompt addendum injected on every Claude Code run.
 *
 *  Why this exists: Claude Code doesn't have Codex's built-in `image_gen`
 *  tool. Even when a project's SKILL.md / agents/anthropic.yaml document
 *  the alternative path (POST /api/gen-image OR `python .agents/tools/gen-image.py`),
 *  Claude's auto-discovery doesn't reliably surface those files in every
 *  conversation — especially for projects bootstrapped BEFORE multi-CLI
 *  shipped, where the template updates never landed.
 *
 *  By injecting this at spawn time we guarantee Claude knows the image-
 *  gen contract regardless of project state. Plain HTTP via curl works
 *  in every project — no dependency on .agents/tools/ existing. */
const OGF_SYSTEM_ADDENDUM = `
=== OGF (Open Game Forge) runtime ===

You ARE able to generate real model-quality images in this environment.

The OGF daemon (already running on localhost:7621) routes image
generation to Gemini 2.5 Flash Image or OpenAI gpt-image-1 using the
user's saved API keys. Use it via Bash + curl whenever the user asks
for sprites, backgrounds, parallax layers, prop art, or any other game
asset.

DO NOT use PIL, Pillow, ImageDraw, ASCII art, geometric primitives, or
any other procedural drawing as a substitute. Those produce visibly
inferior results and frustrate the user — they hired the AI to make
real generated art. Procedural code is ONLY for layout guides /
postprocessing of model output.

How to call the image-gen endpoint:

  curl -s -X POST http://localhost:7621/api/gen-image \\
    -H "content-type: application/json" \\
    -d '{
      "prompt": "<descriptive prompt>",
      "outputPath": "<absolute path .png>",
      "magentaBg": false,
      "refImagePaths": ["<absolute path>"]
    }'

Fields:
- outputPath: ABSOLUTE path. Daemon writes the PNG there.
- magentaBg: true (default) auto-appends "solid #FF00FF background" to
  the prompt — use this for sprites that go through chroma-key. Pass
  false for backgrounds / parallax / scene art that should look normal.
- refImagePaths: optional list of reference images for image-to-image
  / style continuity. Daemon handles base64 / file-upload per provider.
- Response: {"path","provider":"gemini|openai","sizeBytes","model"}.

If \`.agents/tools/gen-image.py\` exists in the project, prefer the
wrapper form:
  python .agents/tools/gen-image.py "<prompt>" <output.png> \\
    [--ref PATH]... [--no-magenta-bg] [--provider gemini|openai]
(But the curl form works in every project, including older ones.)

After generating, run OGF's post-process scripts for chroma-key /
frame extraction / parallax cleanup. Do NOT roll your own:
  python .agents/skills/generate2dsprite/scripts/generate2dsprite.py process ...
  python .agents/skills/generate2dmap/scripts/process_parallax_layer.py ...

If the daemon endpoint returns an error like "No API key configured",
tell the user to add a Gemini or OpenAI key in OGF Settings → Image
generation API keys. Do not fall back to procedural drawing.
`.trim();

/** Curated tool allowlist for OGF flows. We turn OFF Claude Code's
 *  defaults that don't translate to OGF's batch / non-interactive model:
 *
 *  Off — and why:
 *    AskUserQuestion       — needs an interactive UI to answer. In
 *                            `--print` mode Claude marks it as cancelled
 *                            and falls back to a text question anyway,
 *                            so just remove the trial-and-fail step.
 *    EnterPlanMode/ExitPlanMode — Claude's planning UI; the daemon
 *                            doesn't surface it in OGF's run pane.
 *    Cron*, ScheduleWakeup, RemoteTrigger — autonomous scheduling
 *                            features for Claude Code's own runtime;
 *                            OGF runs are user-driven turns.
 *    EnterWorktree/ExitWorktree — git isolation, OGF doesn't need it.
 *    Task, TaskOutput, TaskStop — subagent delegation. Cool but adds
 *                            an event-mapping layer we haven't built.
 *    Monitor, PushNotification — process monitoring / OS notifications,
 *                            unused.
 *    ToolSearch, ListMcpResourcesTool, ReadMcpResourceTool, mcp__*  —
 *                            dynamic tool discovery + MCP servers
 *                            (Gmail / Drive / Figma / Telegram). None
 *                            relevant to game dev under OGF.
 *    NotebookEdit          — Jupyter; OGF projects don't have notebooks.
 *
 *  Kept — the minimum useful set for game-making:
 *    Read, Write, Edit       file ops
 *    Glob, Grep              code search
 *    Bash                    python scripts, npm, generate2dsprite.py …
 *    WebFetch, WebSearch     fetch docs / verify model availability
 *    TodoWrite               agent's internal scratchpad
 *    Skill                   so the agent can invoke OGF skills */
const OGF_ALLOWED_TOOLS = [
  'Read',
  'Write',
  'Edit',
  'Glob',
  'Grep',
  'Bash',
  'WebFetch',
  'WebSearch',
  'TodoWrite',
  'Skill',
];

/** Write the OGF system addendum to a stable file under ~/.ogf and return
 *  its path. We use a file (`--append-system-prompt-file`) instead of
 *  passing the prompt inline (`--append-system-prompt`) because the
 *  Windows cmd shell mangles multi-line strings when args travel through
 *  `cmd.exe /c "<joined-args>"` — observed empirically: short prompts
 *  survive ("PINEAPPLE" test), multi-line prompts silently drop or
 *  truncate. The file path is a single token, no escaping risk.
 *  Re-written on every spawn so live edits to OGF_SYSTEM_ADDENDUM take
 *  effect immediately without daemon restart. */
function writeOgfSystemPromptFile(): string {
  const dir = path.join(homedir(), '.ogf');
  mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, 'claude-system-prompt.txt');
  writeFileSync(filePath, OGF_SYSTEM_ADDENDUM, 'utf8');
  return filePath;
}

export const DEFAULT_CLAUDE_PERMISSION_MODE = 'acceptEdits';

/** Permission mode is an explicit, configurable product setting (audit
 *  E16). Upstream hardcoded `bypassPermissions`; now the default is
 *  `acceptEdits`, and fully-unattended elevated authority is opt-in via
 *  OGF_CLAUDE_PERMISSION_MODE (e.g. `bypassPermissions` in .env.local). */
export function resolveClaudePermissionMode(): string {
  const v = process.env.OGF_CLAUDE_PERMISSION_MODE?.trim();
  return v && v.length > 0 ? v : DEFAULT_CLAUDE_PERMISSION_MODE;
}

export function buildClaudeCodeArgs(
  model?: string,
  resumeThreadId?: string,
  permissionMode: string = resolveClaudePermissionMode(),
): string[] {
  // -p / --print: non-interactive mode
  // --output-format stream-json: emit JSONL events on stdout
  // --verbose: include full turn-by-turn output (required for stream-json)
  // --include-partial-messages: emit raw streaming deltas (text_delta etc.)
  // --permission-mode <permissionMode>: configurable, default acceptEdits.
  //   `bypassPermissions` (elevated tool authority) must be opted into
  //   explicitly rather than being hardcoded (audit E16).
  // --tools: see OGF_ALLOWED_TOOLS above for the curated list. This
  //   controls REGISTRATION — the model literally doesn't see other
  //   tools, so it can't even try them. (The unrelated --allowed-tools
  //   flag is for permission pre-approval and DOESN'T hide tools from
  //   the model — confirmed in `claude --help`. With --allowed-tools
  //   alone Claude still discovers AskUserQuestion in init and tries it
  //   in non-interactive mode, which then fails as "user cancelled".)
  const args: string[] = [
    '-p',
    '--output-format',
    'stream-json',
    '--verbose',
    '--include-partial-messages',
    '--permission-mode',
    permissionMode,
    '--tools',
    OGF_ALLOWED_TOOLS.join(','),
    // Drop user's globally-configured MCP servers (Gmail, Drive, Figma,
    // Telegram, etc.) so they don't bloat tool context for OGF runs. Each
    // MCP tool ships a description that costs tokens, and none of them
    // are relevant to game-making. Combined with no `--mcp-config`, this
    // gives us a clean minimal tool surface.
    '--strict-mcp-config',
    // Inject OGF-specific guidance (image-gen route, post-process scripts)
    // so Claude knows them without relying on per-project SKILL.md
    // discovery — works for old projects too. Via file (see helper above
    // for why inline doesn't survive Windows cmd shell quoting).
    '--append-system-prompt-file',
    writeOgfSystemPromptFile(),
  ];
  if (model) {
    args.push('--model', model);
  }
  if (resumeThreadId) {
    args.push('--resume', resumeThreadId);
  }
  return args;
}

export function spawnClaudeCode(opts: ClaudeCodeRunOptions): ChildProcess {
  const { bin, cwd, prompt, model, resumeThreadId, env } = opts;
  const rawArgs = buildClaudeCodeArgs(model, resumeThreadId);
  const useShell = process.platform === 'win32' && /\.(cmd|bat)$/i.test(bin);
  const args = useShell ? rawArgs.map(quoteForCmdShell) : rawArgs;

  const child = spawn(bin, args, {
    cwd,
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: useShell,
    windowsHide: true,
  });

  if (child.stdin) {
    child.stdin.end(prompt, 'utf8');
  }
  return child;
}

function quoteForCmdShell(arg: string): string {
  if (arg === '') return '""';
  if (!/[\s"]/.test(arg)) return arg;
  return '"' + arg.replace(/"/g, '""') + '"';
}

// -------------------- Event mapping --------------------

interface ClaudeContentBlock {
  type?: string;
  text?: string;
  id?: string;
  name?: string;
  input?: unknown;
  tool_use_id?: string;
  content?: unknown;
  is_error?: boolean;
}

interface ClaudeMessage {
  role?: string;
  content?: ClaudeContentBlock[] | string;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    cache_read_input_tokens?: number;
  };
}

interface ClaudeStreamLine {
  type?: string;
  subtype?: string;
  session_id?: string;
  message?: ClaudeMessage;
  /** stream_event wraps raw Anthropic SSE events */
  event?: {
    type?: string;
    index?: number;
    delta?: {
      type?: string;
      text?: string;
      partial_json?: string;
      stop_reason?: string;
    };
    content_block?: ClaudeContentBlock;
    message?: ClaudeMessage;
    usage?: ClaudeMessage['usage'];
  };
  /** Top-level fields on `result` lines */
  total_cost_usd?: number;
  duration_ms?: number;
  num_turns?: number;
  usage?: ClaudeMessage['usage'];
  is_error?: boolean;
  result?: string;
  error?: string;
  /** Per-event uuid */
  uuid?: string;
  parent_tool_use_id?: string | null;
  [k: string]: unknown;
}

/** Extract a Claude Code session id from a stream line. The id is included
 *  on most events; the first occurrence is what we'll use for `--resume`. */
export function extractClaudeSessionId(raw: ClaudeStreamLine): string | null {
  if (typeof raw.session_id === 'string' && raw.session_id.length > 0) {
    return raw.session_id;
  }
  return null;
}

/** Per-parser state needed to accumulate text/tool deltas across lines. */
interface DeltaState {
  /** index → accumulated tool_use input JSON string */
  toolInputByIndex: Map<number, string>;
  /** index → tool_use metadata captured at content_block_start */
  toolMetaByIndex: Map<number, { id: string; name: string }>;
}

function createDeltaState(): DeltaState {
  return {
    toolInputByIndex: new Map(),
    toolMetaByIndex: new Map(),
  };
}

/** Map a single Claude Code stream line to ZERO OR MORE OGF AgentEvents.
 *  We use an array because a single `assistant` message can contain
 *  multiple content blocks (text + tool_use) that translate to multiple
 *  AgentEvents. */
export function mapClaudeCodeLine(
  raw: ClaudeStreamLine,
  state: DeltaState,
): AgentEvent[] {
  const out: AgentEvent[] = [];
  const t = raw.type;

  // ── system lifecycle ───────────────────────────────────────────────
  if (t === 'system') {
    if (raw.subtype === 'init') out.push({ type: 'status', label: 'initializing' });
    else if (raw.subtype === 'api_retry')
      out.push({ type: 'status', label: 'retrying' });
    return out;
  }

  // ── result / end-of-turn ───────────────────────────────────────────
  if (t === 'result') {
    if (raw.usage) {
      out.push({
        type: 'usage',
        usage: {
          input: raw.usage.input_tokens,
          output: raw.usage.output_tokens,
          cachedRead: raw.usage.cache_read_input_tokens,
        },
      });
    }
    out.push({
      type: 'status',
      label: raw.is_error ? 'error' : 'done',
    });
    return out;
  }

  // ── stream_event: raw Anthropic SSE wrapped by Claude Code ─────────
  // Only present when --include-partial-messages is set. Text streams
  // here as content_block_delta with text_delta; tool inputs stream as
  // input_json_delta.
  if (t === 'stream_event' && raw.event) {
    const ev = raw.event;
    const idx = typeof ev.index === 'number' ? ev.index : 0;

    if (ev.type === 'content_block_start') {
      const block = ev.content_block;
      if (block?.type === 'tool_use') {
        state.toolMetaByIndex.set(idx, {
          id: String(block.id ?? `tool_${idx}`),
          name: String(block.name ?? 'unknown'),
        });
        state.toolInputByIndex.set(idx, '');
      }
      return out;
    }

    if (ev.type === 'content_block_delta' && ev.delta) {
      if (ev.delta.type === 'text_delta' && typeof ev.delta.text === 'string') {
        out.push({ type: 'text_delta', delta: ev.delta.text });
      } else if (
        ev.delta.type === 'input_json_delta' &&
        typeof ev.delta.partial_json === 'string'
      ) {
        const cur = state.toolInputByIndex.get(idx) ?? '';
        state.toolInputByIndex.set(idx, cur + ev.delta.partial_json);
      }
      return out;
    }

    if (ev.type === 'content_block_stop') {
      const meta = state.toolMetaByIndex.get(idx);
      if (meta) {
        // We have a complete tool_use: parse the accumulated JSON input
        // and emit a tool_use event. Use try/catch because Claude
        // occasionally emits malformed partial_json on early termination.
        const rawInput = state.toolInputByIndex.get(idx) ?? '';
        let parsed: unknown = rawInput;
        if (rawInput.trim().length > 0) {
          try {
            parsed = JSON.parse(rawInput);
          } catch {
            parsed = { _rawInput: rawInput };
          }
        }
        out.push({
          type: 'tool_use',
          id: meta.id,
          name: meta.name,
          input: parsed,
        });
        state.toolMetaByIndex.delete(idx);
        state.toolInputByIndex.delete(idx);
      }
      return out;
    }

    if (ev.type === 'message_stop') {
      // End-of-turn signal — the `result` line carries usage/status, so we
      // don't synthesize a status here.
      return out;
    }

    // Other stream_event types (message_start, message_delta, ping) carry
    // metadata we don't surface to the UI yet.
    return out;
  }

  // ── user (tool_result echo) ────────────────────────────────────────
  // After Claude calls a tool, the CLI executes it and feeds the result
  // back as a `user` message containing tool_result content blocks. Map
  // those to OGF tool_result events so the Turn UI shows what came back.
  if (t === 'user' && raw.message && Array.isArray(raw.message.content)) {
    for (const block of raw.message.content) {
      if (block.type === 'tool_result' && block.tool_use_id) {
        const content =
          typeof block.content === 'string'
            ? block.content
            : JSON.stringify(block.content);
        out.push({
          type: 'tool_result',
          toolUseId: block.tool_use_id,
          content: content ?? '',
          isError: block.is_error === true,
        });
      }
    }
    return out;
  }

  // ── assistant (whole-message fallback) ─────────────────────────────
  // When --include-partial-messages IS set, the assistant whole-message
  // event arrives after the stream_event deltas — we've already emitted
  // text_delta + tool_use events for each block, so we can skip. When
  // partial-messages is OFF (future fallback path), this is our only
  // signal for assistant text + tool use; emit accordingly.
  if (t === 'assistant' && raw.message && Array.isArray(raw.message.content)) {
    // Heuristic: if delta state was used (toolMetaByIndex was ever set),
    // we already emitted. Otherwise emit blocks now as whole messages.
    // We can't tell from this line alone — fall back to skipping when
    // partial-messages mode is on (the common case for OGF). If a future
    // build flips that flag off, we'd need a separate code path here.
    return out;
  }

  return out;
}

// -------------------- Parser --------------------

export interface ClaudeJsonlParserCallbacks {
  onEvent: (e: AgentEvent) => void;
  onThreadId?: (id: string) => void;
  onActivity?: () => void;
}

export function createClaudeJsonlParser(cb: ClaudeJsonlParserCallbacks) {
  let buf = '';
  const state = createDeltaState();
  let seenThread = false;

  function consume(line: string) {
    if (!line) return;
    debugLogLine(line);
    cb.onActivity?.();
    let obj: ClaudeStreamLine;
    try {
      obj = JSON.parse(line) as ClaudeStreamLine;
    } catch {
      cb.onEvent({ type: 'raw', raw: line });
      return;
    }
    if (!seenThread) {
      const tid = extractClaudeSessionId(obj);
      if (tid) {
        seenThread = true;
        cb.onThreadId?.(tid);
      }
    }
    const events = mapClaudeCodeLine(obj, state);
    for (const e of events) cb.onEvent(e);
  }

  return {
    feed(chunk: Buffer | string) {
      buf += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        consume(buf.slice(0, nl).trim());
        buf = buf.slice(nl + 1);
      }
    },
    flush() {
      const tail = buf.trim();
      buf = '';
      if (tail) consume(tail);
    },
  };
}
