/**
 * Opt-in agent-stream debug logging (audit E16).
 *
 * Upstream always appended every raw Codex / Claude stream line — which
 * can contain prompts, file contents, and tool output — to a JSONL file
 * in the user's home directory. That is both implicit and broad. Here:
 *
 *   - Logging is OFF unless the adapter-specific env var names a file
 *     path (`OGF_CODEX_DEBUG_LOG` / `OGF_CLAUDE_DEBUG_LOG`).
 *   - When on, the file is created with mode 0600 inside a 0700 dir and
 *     truncated past 5 MB so retention is bounded.
 *   - Obvious credential shapes are redacted before persisting. This is a
 *     best-effort net, not a guarantee — hence default-off.
 */

import { appendFileSync, chmodSync, mkdirSync, statSync, truncateSync } from 'node:fs';
import path from 'node:path';

const MAX_BYTES = 5 * 1024 * 1024;

/** Redact common secret shapes from a raw stream line. */
export function redactSecrets(line: string): string {
  return line
    .replace(/sk-[A-Za-z0-9_-]{8,}/g, 'sk-REDACTED')
    .replace(/AIza[0-9A-Za-z_-]{20,}/g, 'AIza-REDACTED')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]{8,}/gi, '$1REDACTED')
    .replace(/("?(?:api[_-]?key|token|secret)"?\s*[:=]\s*")([^"]{8,})"/gi, '$1REDACTED"');
}

/**
 * Build a logger bound to `envVar`. The returned function is a no-op
 * unless that env var holds a non-empty path.
 */
export function makeDebugLogger(envVar: string): (line: string) => void {
  let initializedPath: string | null = null;
  return function debugLogLine(line: string): void {
    const p = process.env[envVar];
    if (!p || p.length === 0) return;
    try {
      if (initializedPath !== p) {
        initializedPath = p;
        mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
        try {
          const st = statSync(p);
          if (st.size > MAX_BYTES) truncateSync(p, 0);
        } catch {
          /* fresh file */
        }
        try {
          chmodSync(p, 0o600);
        } catch {
          /* best-effort on platforms without POSIX modes */
        }
      }
      appendFileSync(p, redactSecrets(line) + '\n', { encoding: 'utf8', mode: 0o600 });
    } catch {
      /* never let logging crash the parser */
    }
  };
}
