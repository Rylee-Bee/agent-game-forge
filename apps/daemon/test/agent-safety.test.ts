/**
 * Agent-trust tests (audit E16): debug logging is off by default and uses
 * restrictive permissions + redaction when opted in; elevated Claude Code
 * permissions are an explicit setting, not a hardcoded bypass.
 *
 * Run: npx tsx --test apps/daemon/test/agent-safety.test.ts
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createJsonlParser } from '../src/codex.js';
import {
  buildClaudeCodeArgs,
  createClaudeJsonlParser,
  DEFAULT_CLAUDE_PERMISSION_MODE,
} from '../src/claude-code.js';

const SECRET = 'sk-abcdefghijklmnopqrstuvwxyz';
const SAMPLE_LINE = JSON.stringify({
  type: 'item.completed',
  item: { type: 'agent_message', text: `token ${SECRET} end` },
});

function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T): T {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('E16: codex stream logging is off by default', () => {
  const fakeHome = mkdtempSync(path.join(tmpdir(), 'ogf-home-'));
  try {
    withEnv(
      {
        HOME: fakeHome,
        OGF_CODEX_DEBUG_LOG: undefined,
      },
      () => {
        const parser = createJsonlParser({ onEvent: () => {} });
        parser.feed(SAMPLE_LINE + '\n');
      },
    );
    // Nothing under the fake home — no default debug file was created.
    assert.equal(existsSync(path.join(fakeHome, '.codex')), false);
  } finally {
    rmSync(fakeHome, { recursive: true, force: true });
  }
});

test('E16: codex opt-in logging is 0600 and redacts secrets', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ogf-cdxlog-'));
  const logPath = path.join(dir, 'codex-debug.jsonl');
  try {
    withEnv({ OGF_CODEX_DEBUG_LOG: logPath }, () => {
      const parser = createJsonlParser({ onEvent: () => {} });
      parser.feed(SAMPLE_LINE + '\n');
    });
    assert.ok(existsSync(logPath), 'expected opt-in log file');
    const content = readFileSync(logPath, 'utf8');
    assert.equal(content.includes(SECRET), false, 'raw secret must not be persisted');
    assert.match(content, /REDACTED/);
    if (process.platform !== 'win32') {
      assert.equal(statSync(logPath).mode & 0o777, 0o600);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('E16: claude stream logging is off by default', () => {
  const fakeHome = mkdtempSync(path.join(tmpdir(), 'ogf-home2-'));
  try {
    withEnv(
      {
        HOME: fakeHome,
        OGF_CLAUDE_DEBUG_LOG: undefined,
      },
      () => {
        const parser = createClaudeJsonlParser({ onEvent: () => {} });
        parser.feed(
          JSON.stringify({ type: 'stream_event', event: { type: 'ping' } }) + '\n',
        );
      },
    );
    assert.equal(existsSync(path.join(fakeHome, '.ogf')), false);
  } finally {
    rmSync(fakeHome, { recursive: true, force: true });
  }
});

test('E16: claude opt-in logging is 0600 and redacts secrets', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ogf-cldlog-'));
  const logPath = path.join(dir, 'claude-debug.jsonl');
  try {
    withEnv({ OGF_CLAUDE_DEBUG_LOG: logPath }, () => {
      const parser = createClaudeJsonlParser({ onEvent: () => {} });
      parser.feed(SAMPLE_LINE + '\n');
    });
    assert.ok(existsSync(logPath), 'expected opt-in log file');
    const content = readFileSync(logPath, 'utf8');
    assert.equal(content.includes(SECRET), false, 'raw secret must not be persisted');
    if (process.platform !== 'win32') {
      assert.equal(statSync(logPath).mode & 0o777, 0o600);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('E16: claude permission mode is non-bypass by default', () => {
  const fakeHome = mkdtempSync(path.join(tmpdir(), 'ogf-home3-'));
  try {
    withEnv({ HOME: fakeHome, OGF_CLAUDE_PERMISSION_MODE: undefined }, () => {
      const args = buildClaudeCodeArgs();
      const i = args.indexOf('--permission-mode');
      assert.ok(i >= 0, 'permission mode must always be passed explicitly');
      assert.equal(args[i + 1], DEFAULT_CLAUDE_PERMISSION_MODE);
      assert.equal(args.includes('bypassPermissions'), false);
    });
  } finally {
    rmSync(fakeHome, { recursive: true, force: true });
  }
});

test('E16: bypassPermissions is explicit opt-in only', () => {
  const fakeHome = mkdtempSync(path.join(tmpdir(), 'ogf-home4-'));
  try {
    withEnv({ HOME: fakeHome, OGF_CLAUDE_PERMISSION_MODE: 'bypassPermissions' }, () => {
      const args = buildClaudeCodeArgs();
      const i = args.indexOf('--permission-mode');
      assert.equal(args[i + 1], 'bypassPermissions');
    });
    // Explicit parameter also wins.
    const explicit = buildClaudeCodeArgs(undefined, undefined, 'bypassPermissions');
    assert.equal(explicit[explicit.indexOf('--permission-mode') + 1], 'bypassPermissions');
  } finally {
    rmSync(fakeHome, { recursive: true, force: true });
  }
});
