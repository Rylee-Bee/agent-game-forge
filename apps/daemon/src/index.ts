import path from 'node:path';
import { createServer } from './server.js';
import { openDb } from './db.js';
import { REMOTE_OPT_IN_ENV, resolveSecurityOptions } from './security.js';

const PORT = Number(process.env.OGF_DAEMON_PORT ?? 7621);
const HOST = process.env.OGF_DAEMON_HOST ?? '127.0.0.1';

/**
 * Safe-binding policy (audit E04). The daemon drives agent CLIs and can
 * write secrets + arbitrary project files; it is only safe when reachable
 * from this machine. Binding to a non-loopback interface (e.g. 0.0.0.0,
 * a LAN IP) must be an explicit, documented decision — set
 * `OGF_ALLOW_REMOTE=1`, and ideally pin `OGF_DAEMON_TOKEN` and
 * `OGF_ALLOWED_HOSTS`/`OGF_ALLOWED_ORIGINS` too. Without the opt-in we
 * refuse to start rather than silently expose the machine.
 */
function isLoopbackHost(host: string): boolean {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

if (!isLoopbackHost(HOST) && process.env[REMOTE_OPT_IN_ENV] !== '1') {
  console.error(
    `[ogf-daemon] refusing to bind non-loopback host "${HOST}" without ${REMOTE_OPT_IN_ENV}=1. ` +
      'The daemon can set secrets, write project files, and launch agent CLIs; exposing it ' +
      'requires an explicit, documented decision.',
  );
  process.exit(1);
}

// Resolve the capability token once. `OGF_DAEMON_TOKEN` if provided, else a
// fresh random token printed below. The web UI receives it as an HttpOnly
// cookie through the Vite proxy; scripts send `x-ogf-token`.
const security = resolveSecurityOptions();

const dbPath =
  process.env.OGF_DB_PATH ??
  path.resolve(process.cwd(), '.ogf', 'app.sqlite');

openDb({ filePath: dbPath });
console.log(`[ogf-daemon] db: ${dbPath}`);

// Last-resort crash shields. We've fixed the known SSE socket-write
// path that crashed the daemon (runs.ts / godot.ts now use writeSseSafe),
// but a single unhandled 'error' from any other long-lived socket /
// child_process / FS watcher would still take the whole daemon down.
// Logging + survive is much better than dying mid-session — the user
// loses chat history and any active codex run when the process exits.
process.on('uncaughtException', (err) => {
  console.error('[ogf-daemon] uncaughtException:', err instanceof Error ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[ogf-daemon] unhandledRejection:', reason);
});

const app = createServer(security);
app.listen(PORT, HOST, () => {
  console.log(`[ogf-daemon] listening on http://${HOST}:${PORT}`);
  if (security.tokenGenerated) {
    console.log(`[ogf-daemon] API capability token (generated this session): ${security.token}`);
    console.log(
      '[ogf-daemon] set OGF_DAEMON_TOKEN to pin it across restarts; ' +
        'agents/scripts send it as the x-ogf-token header.',
    );
  } else {
    console.log('[ogf-daemon] API capability token: from OGF_DAEMON_TOKEN');
  }
  if (!isLoopbackHost(HOST)) {
    console.warn(
      `[ogf-daemon] WARNING: bound to non-loopback host "${HOST}". Ensure the token stays ` +
        'private and restrict OGF_ALLOWED_HOSTS / OGF_ALLOWED_ORIGINS.',
    );
  }
});
