/**
 * OpenCode adapter — spawns `opencode run --format json` and maps its
 * JSONL events to OGF's common AgentEvent shape.
 *
 * Pattern mirrors codex.ts / claude-code.ts so the rest of the daemon
 * (RunManager, SSE, Turn rendering) treats all three CLIs identically.
 *
 * OpenCode wire format (verified via `opencode run --format json` probes
 * against OpenCode V2, 2026-09-24):
 *   - Invocation: `opencode run --format json --auto [-m provider/model]
 *                 [-s <sessionID>] "<message>"`
 *   - Message travels as the final argv element (no shell on POSIX).
 *   - Resume: `--session <sessionID>`; every event carries `sessionID`
 *     (ses_…) — the first occurrence is the thread id.
 *   - Stdout: JSONL, one event object per line. Stderr: human logs.
 *   - Exit 0 on success, non-zero on fatal errors.
 *
 * Event types observed:
 *   - `step_start`  — a model step begins (bookkeeping only)
 *   - `tool_use`    — ONE event per tool call, emitted at COMPLETION with
 *                     part: { id, tool, state: { status, input, output,
 *                     title, metadata, time } } (state.status is
 *                     "completed" | "error" | …)
 *   - `step_finish` — step end; part: { reason, cost, tokens: { input,
 *                     output, reasoning, cache: { read, write } } }
 *   - `text`        — assistant text; part: { type: "text", text }
 *
 * There is no explicit end-of-run event: process exit ends the turn, so
 * RunManager's exit handling produces OGF's `end`.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import type { AgentEvent } from '@ogf/contracts';

export interface OpenCodeRunOptions {
  /** Path to the `opencode` binary. */
  bin: string;
  /** Working directory for the run. */
  cwd: string;
  /** Prompt to feed the agent. */
  prompt: string;
  /** Model id in `provider/model#variant` form (e.g.
   *  "some-provider/some-model"). Omitted for "default" so the
   *  CLI's own configured default applies. */
  model?: string;
  /** When set, continues that OpenCode session (`--session <sessionID>`)
   *  instead of starting a new thread. */
  resumeThreadId?: string;
  env?: NodeJS.ProcessEnv;
}

export function buildOpenCodeArgs(
  model?: string,
  resumeThreadId?: string,
): string[] {
  // run: non-interactive message mode
  // --format json: JSONL events on stdout (text/tool_use/step_finish…)
  // --auto: auto-approve permissions that aren't explicitly denied —
  //   OGF runs in trusted local mode like Codex's workspace-write config
  //   and Claude Code's bypassPermissions.
  const args: string[] = ['run', '--format', 'json', '--auto'];
  if (model && model !== 'default') {
    args.push('--model', model);
  }
  if (resumeThreadId) {
    args.push('--session', resumeThreadId);
  }
  return args;
}

export function spawnOpenCode(opts: OpenCodeRunOptions): ChildProcess {
  const { bin, cwd, prompt, model, resumeThreadId, env } = opts;
  const rawArgs = buildOpenCodeArgs(model, resumeThreadId);
  const useShell = process.platform === 'win32' && /\.(cmd|bat)$/i.test(bin);
  // The prompt is the final argv element (OpenCode joins positionals into
  // the message). Same Windows cmd-shell quoting caveat as claude-code.ts.
  const positional = useShell ? quoteForCmdShell(prompt) : prompt;
  const args = useShell ? rawArgs.map(quoteForCmdShell) : rawArgs;

  return spawn(bin, [...args, positional], {
    cwd,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: useShell,
    windowsHide: true,
  });
}

function quoteForCmdShell(arg: string): string {
  if (arg === '') return '""';
  if (!/[\s"]/.test(arg)) return arg;
  return '"' + arg.replace(/"/g, '""') + '"';
}

// -------------------- Event mapping --------------------

interface OpenCodePart {
  type?: string;
  id?: string;
  tool?: string;
  text?: string;
  reason?: string;
  cost?: number;
  tokens?: {
    input?: number;
    output?: number;
    reasoning?: number;
    cache?: { read?: number; write?: number };
  };
  state?: {
    status?: string;
    input?: unknown;
    output?: unknown;
    title?: string;
  };
  [k: string]: unknown;
}

interface OpenCodeStreamLine {
  type?: string;
  timestamp?: number;
  sessionID?: string;
  part?: OpenCodePart;
  [k: string]: unknown;
}

/** Extract an OpenCode session id from a stream line. Present on every
 *  event; the first occurrence is what we'll use for `--session`. */
export function extractOpenCodeSessionId(raw: OpenCodeStreamLine): string | null {
  if (typeof raw.sessionID === 'string' && raw.sessionID.length > 0) {
    return raw.sessionID;
  }
  return null;
}

interface OpenCodeLineState {
  seenStepStart: boolean;
}

/** Map a single OpenCode stream line to ZERO OR MORE OGF AgentEvents. */
export function mapOpenCodeLine(
  raw: OpenCodeStreamLine,
  state: OpenCodeLineState,
): AgentEvent[] {
  const out: AgentEvent[] = [];
  const t = raw.type;
  const part = raw.part ?? {};

  if (t === 'step_start') {
    if (!state.seenStepStart) {
      state.seenStepStart = true;
      out.push({ type: 'status', label: 'initializing' });
    }
    return out;
  }

  // One completed tool part per call: emit the call AND its result so the
  // Turn UI shows both sides without needing a delta protocol.
  if (t === 'tool_use') {
    const id = String(part.id ?? part.state?.title ?? `tool_${out.length}`);
    const name = String(part.tool ?? 'unknown');
    out.push({
      type: 'tool_use',
      id,
      name,
      input: (part.state?.input as Record<string, unknown>) ?? {},
    });
    const status = String(part.state?.status ?? '');
    const output = part.state?.output;
    out.push({
      type: 'tool_result',
      toolUseId: id,
      content:
        typeof output === 'string' ? output : JSON.stringify(output ?? ''),
      isError: status !== '' && status !== 'completed',
    });
    return out;
  }

  if (t === 'step_finish') {
    const toks = part.tokens;
    if (toks) {
      out.push({
        type: 'usage',
        usage: {
          input: toks.input,
          output: toks.output,
          cachedRead: toks.cache?.read,
        },
      });
    }
    return out;
  }

  if (t === 'text') {
    if (typeof part.text === 'string' && part.text.length > 0) {
      out.push({ type: 'text_delta', delta: part.text });
    }
    return out;
  }

  if (t === 'error') {
    out.push({ type: 'status', label: 'error' });
    out.push({ type: 'raw', raw: JSON.stringify(raw) });
    return out;
  }

  // Unknown line types pass through verbatim — never drop data silently.
  out.push({ type: 'raw', raw: JSON.stringify(raw) });
  return out;
}

// -------------------- Parser --------------------

export interface OpenCodeJsonlParserCallbacks {
  onEvent: (e: AgentEvent) => void;
  onThreadId?: (id: string) => void;
  onActivity?: () => void;
}

export function createOpenCodeJsonlParser(cb: OpenCodeJsonlParserCallbacks) {
  let buf = '';
  const state: OpenCodeLineState = { seenStepStart: false };
  let seenThread = false;
  let lastByte = Date.now();

  // Keepalive: OpenCode emits no bytes while a model step is still
  // thinking — parts arrive complete, not as deltas — so a healthy long
  // model step can be silent for minutes and trip AGF's 5-minute stall
  // watchdog (observed 2026-09-24: "Stalled — no codex output for 326s.
  // Killing." on a live run). Touch onActivity every 60s while bytes were
  // seen within the last 30 minutes; after 30 minutes of true silence we
  // stop touching and let the watchdog kill the run as designed.
  const keepalive = setInterval(() => {
    if (Date.now() - lastByte < 30 * 60 * 1000) cb.onActivity?.();
    else clearInterval(keepalive);
  }, 60 * 1000);
  keepalive.unref?.();

  function consume(line: string) {
    if (!line) return;
    cb.onActivity?.();
    let obj: OpenCodeStreamLine;
    try {
      obj = JSON.parse(line) as OpenCodeStreamLine;
    } catch {
      cb.onEvent({ type: 'raw', raw: line });
      return;
    }
    if (!seenThread) {
      const tid = extractOpenCodeSessionId(obj);
      if (tid) {
        seenThread = true;
        cb.onThreadId?.(tid);
      }
    }
    for (const e of mapOpenCodeLine(obj, state)) cb.onEvent(e);
  }

  return {
    feed(chunk: Buffer | string) {
      lastByte = Date.now();
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
