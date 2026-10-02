/**
 * Daemon security boundary (audit E04).
 *
 * OGF's Express daemon exposes powerful local capabilities: writing user
 * API keys, opening/creating arbitrary project folders, writing/removing
 * files, and spawning agent CLIs (`POST /api/runs`). None of that had an
 * authorization boundary, so any browser page that could reach
 * `127.0.0.1:7621` — most realistically via DNS rebinding or a hostile
 * page on the local network when the host is reconfigured — could drive
 * it. This module adds three cheap gates:
 *
 *   1. Host / Origin validation — reject requests whose Host header or
 *      browser Origin is not explicitly approved. This is the
 *      DNS-rebinding defense: an attacker's domain resolving to
 *      127.0.0.1 still sends `Host: evil.example`, which we refuse.
 *   2. A capability token for authority-bearing routes. The token comes
 *      from `OGF_DAEMON_TOKEN`, or is generated once at startup and
 *      printed to the console. The web UI (served through the Vite dev
 *      proxy, same-origin from the browser's point of view) receives the
 *      token as an HttpOnly, SameSite=Strict cookie; scripts and agent
 *      runners can send it as `x-ogf-token` or `?token=`.
 *   3. Project-root scope — refuse to open / write / delete outside an
 *      approved root (default: the user's home directory). Explicit
 *      `../` escapes inside an approved root are rejected by the
 *      existing `safeJoin` in files.ts.
 *
 * This is deliberately a local-dev boundary, not an Internet service
 * auth system. Non-loopback binding is refused unless the operator
 * explicitly opts in (see `OGF_ALLOW_REMOTE` in index.ts).
 */

import crypto from 'node:crypto';
import { homedir } from 'node:os';
import path from 'node:path';
import type { NextFunction, Request, Response } from 'express';

export const TOKEN_HEADER = 'x-ogf-token';
export const TOKEN_QUERY = 'token';
export const TOKEN_COOKIE = 'ogf_token';
export const DEFAULT_TOKEN_ENV = 'OGF_DAEMON_TOKEN';
export const REMOTE_OPT_IN_ENV = 'OGF_ALLOW_REMOTE';

/** Ports of the bundled Vite dev server — the browser talks to these, and
 *  Vite proxies /api to the daemon, so these Origins reach the daemon. */
const DEFAULT_WEB_ORIGINS = [
  'http://localhost:7620',
  'http://127.0.0.1:7620',
  'http://[::1]:7620',
];

const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1']);

export interface SecurityOptions {
  /** Capability token. Falls back to OGF_DAEMON_TOKEN, then generated. */
  token?: string;
  /** Browser origins allowed to reach the API (exact match). */
  allowedOrigins?: string[];
  /** Host header values allowed (hostname only; port ignored). */
  allowedHosts?: string[];
  /** Absolute roots under which project paths must resolve. `[]` disables. */
  allowedProjectRoots?: string[];
}

export interface ResolvedSecurity {
  token: string;
  tokenGenerated: boolean;
  allowedOrigins: string[];
  allowedHosts: Set<string>;
  allowedProjectRoots: string[];
}

function splitList(raw: string | undefined, sep = ','): string[] {
  if (!raw) return [];
  return raw
    .split(sep)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Resolve config from explicit options, then env, then safe defaults.
 *  Never logs or returns a token in an error. */
export function resolveSecurityOptions(overrides: SecurityOptions = {}): ResolvedSecurity {
  let token = overrides.token ?? process.env[DEFAULT_TOKEN_ENV] ?? '';
  let tokenGenerated = false;
  if (!token) {
    token = crypto.randomBytes(32).toString('hex');
    tokenGenerated = true;
  }

  const origins =
    overrides.allowedOrigins ??
    (() => {
      const env = splitList(process.env.OGF_ALLOWED_ORIGINS);
      return env.length ? env : DEFAULT_WEB_ORIGINS;
    })();

  const hosts =
    overrides.allowedHosts ?? splitList(process.env.OGF_ALLOWED_HOSTS);
  const hostSet = new Set([
    ...LOOPBACK_HOSTNAMES,
    ...hosts.map(normalizeHostname),
  ]);

  const roots =
    overrides.allowedProjectRoots ??
    (() => {
      const env = splitList(process.env.OGF_PROJECT_ROOTS, path.delimiter);
      return env.length ? env.map((p) => path.resolve(p)) : [homedir()];
    })();

  return {
    token,
    tokenGenerated,
    allowedOrigins: origins.map(stripTrailingSlash),
    allowedHosts: hostSet,
    allowedProjectRoots: roots.map((p) => path.resolve(p)),
  };
}

function stripTrailingSlash(s: string): string {
  return s.endsWith('/') ? s.slice(0, -1) : s;
}

/** Extract the hostname from a Host header, handling IPv6 brackets and
 *  ports: `[::1]:7620` → `::1`, `localhost:7621` → `localhost`. */
export function normalizeHostname(hostHeader: string): string {
  const host = (hostHeader ?? '').trim().toLowerCase();
  if (!host) return '';
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    return end >= 0 ? host.slice(1, end) : host.slice(1);
  }
  // Bare IPv6 without brackets has multiple colons; return as-is.
  if (host.indexOf(':') !== host.lastIndexOf(':')) return host;
  const colon = host.indexOf(':');
  return colon >= 0 ? host.slice(0, colon) : host;
}

function isAllowedHost(hostHeader: string | undefined, sec: ResolvedSecurity): boolean {
  const name = normalizeHostname(hostHeader ?? '');
  return !!name && sec.allowedHosts.has(name);
}

function isAllowedOrigin(origin: string | undefined, sec: ResolvedSecurity): boolean {
  if (!origin) return true; // non-browser clients (curl, agents) send no Origin
  const norm = stripTrailingSlash(origin.toLowerCase());
  return sec.allowedOrigins.some((o) => o.toLowerCase() === norm);
}

function parseCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return null;
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function tokenFromRequest(req: Request): string | null {
  const header = req.header(TOKEN_HEADER);
  if (header) return header;
  const q = req.query?.[TOKEN_QUERY];
  if (typeof q === 'string' && q) return q;
  return parseCookie(req.header('cookie'), TOKEN_COOKIE);
}

/**
 * Authority-bearing routes. Only mutations that can change secrets,
 * files outside the normal editor flow, projects, agents/CLIs, or the
 * Godot process are gated. Deliberately excluded:
 *   - `POST /api/gen-image`: the agent CLIs shell out to it mid-run and
 *     cannot carry the token; see HANDOFF "Security hardening" for the
 *     documented trade-off.
 *   - `POST /api/preferences`: non-sensitive display defaults.
 * Read-only GET/HEAD routes stay open (they only expose already-local
 * project data).
 */
const AUTHORITY_RULES: Array<{ method: string; test: (p: string) => boolean }> = [
  { method: 'POST', test: (p) => p === '/api/secrets' },
  {
    method: 'POST',
    test: (p) => /^\/api\/projects\/(open|create|refactor-copy|rename)$/.test(p),
  },
  { method: 'DELETE', test: (p) => p === '/api/projects' || p === '/api/projects/pending-slices' },
  { method: 'POST', test: (p) => p === '/api/files/content' },
  { method: 'DELETE', test: (p) => p === '/api/files' },
  { method: 'POST', test: (p) => /^\/api\/files\/regen\/(apply|discard|apply-pack|discard-pack)$/.test(p) },
  { method: 'POST', test: (p) => p === '/api/files/refs' },
  { method: 'DELETE', test: (p) => p === '/api/files/refs' },
  { method: 'POST', test: (p) => p === '/api/scenes/save' || p === '/api/scenes/context' },
  { method: 'POST', test: (p) => p === '/api/runs' || /^\/api\/runs\/[^/]+\/cancel$/.test(p) },
  { method: 'POST', test: (p) => p === '/api/godot/run' || /^\/api\/godot\/runs\/[^/]+\/stop$/.test(p) },
  { method: 'POST', test: (p) => p === '/api/conversations' || p === '/api/conversations/import-codex' },
  { method: 'POST', test: (p) => /^\/api\/conversations\/[^/]+\/title$/.test(p) },
  { method: 'DELETE', test: (p) => /^\/api\/conversations\/[^/]+$/.test(p) },
  { method: 'POST', test: (p) => p === '/api/comments' || /^\/api\/comments\/[^/]+\/messages$/.test(p) },
  { method: 'PATCH', test: (p) => /^\/api\/comments\/[^/]+$/.test(p) },
  { method: 'DELETE', test: (p) => /^\/api\/comments\/[^/]+$/.test(p) },
];

export function isAuthorityRoute(method: string, pathname: string): boolean {
  const m = method.toUpperCase();
  const p = stripTrailingSlash(pathname.split('?')[0] || '/');
  return AUTHORITY_RULES.some((r) => r.method === m && r.test(p));
}

/**
 * Gate 1: Host + Origin validation, plus capability-cookie delivery.
 * Rejects disallowed Host headers (DNS rebinding) and disallowed browser
 * Origins. Runs before body parsing so it is cheap and applies to every
 * /api route.
 */
export function hostAndOriginGuard(sec: ResolvedSecurity) {
  const allowOrigin = (origin: string) => isAllowedOrigin(origin, sec);
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isAllowedHost(req.header('host'), sec)) {
      res.status(403).json({ error: 'host not allowed' });
      return;
    }
    const origin = req.header('origin');
    if (origin && !allowOrigin(origin)) {
      res.status(403).json({ error: 'origin not allowed' });
      return;
    }
    // Deliver the same-origin capability cookie. Browsers reach the UI
    // through the Vite proxy on :7620 (same-origin from their view) and
    // either this cookie or the header token authorizes mutations.
    if (!parseCookie(req.header('cookie'), TOKEN_COOKIE)) {
      res.cookie(TOKEN_COOKIE, sec.token, {
        httpOnly: true,
        sameSite: 'strict',
        path: '/',
      });
    }
    next();
  };
}

/** Gate 2: capability token required on authority routes. */
export function authorityGuard(sec: ResolvedSecurity) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isAuthorityRoute(req.method, req.path)) {
      next();
      return;
    }
    const supplied = tokenFromRequest(req);
    if (!supplied || !safeEqual(supplied, sec.token)) {
      res.status(401).json({ error: 'unauthorized: a valid capability token is required' });
      return;
    }
    next();
  };
}

/** Fields across the API that name a project (or arbitrary) filesystem
 *  path. Kept to project-scoped params so binary paths (godotPath) and
 *  relative in-project paths (relPath/packDir) are not misread. */
function candidatePaths(req: Request): string[] {
  const out: string[] = [];
  const add = (v: unknown) => {
    if (typeof v === 'string' && v.length > 0) out.push(v);
  };
  const body = (req.body ?? {}) as Record<string, unknown>;
  const query = req.query ?? {};
  add(body.projectPath);
  add(body.path);
  add(body.sourcePath);
  add(body.destPath);
  add(query.projectPath);
  add(query.path);
  add(query.cwd);
  return out;
}

function withinRoots(candidate: string, roots: string[]): boolean {
  const abs = path.resolve(candidate);
  return roots.some((root) => {
    const r = path.resolve(root);
    return abs === r || abs.startsWith(r + path.sep);
  });
}

/** Gate 3: refuse open / write / delete outside approved project roots. */
export function projectScopeGuard(sec: ResolvedSecurity) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (sec.allowedProjectRoots.length === 0) {
      next();
      return;
    }
    for (const candidate of candidatePaths(req)) {
      if (!withinRoots(candidate, sec.allowedProjectRoots)) {
        res.status(403).json({ error: 'path outside approved project roots' });
        return;
      }
    }
    next();
  };
}
