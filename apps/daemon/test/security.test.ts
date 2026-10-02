/**
 * Security-boundary tests (audit E04).
 *
 * Exercises the daemon over real HTTP on an ephemeral loopback port with
 * disposable directories and a FAKE token. No database, no browser, and
 * no agent CLI is ever spawned: every run-creation assertion stops at the
 * 401 gate.
 *
 * Run: npx tsx --test apps/daemon/test/security.test.ts
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';

const TOKEN = 'FAKE_TEST_TOKEN_DO_NOT_USE_1234567890';

interface RunningServer {
  port: number;
  close: () => Promise<void>;
}

function startServer(allowedProjectRoots: string[]): Promise<RunningServer> {
  const app = createServer({
    token: TOKEN,
    allowedOrigins: ['http://localhost:7620'],
    allowedProjectRoots,
  });
  return new Promise((resolve) => {
    const srv = app.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({
        port,
        close: () => new Promise<void>((r) => srv.close(() => r())),
      });
    });
  });
}

interface HttpResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function request(
  port: number,
  method: string,
  urlPath: string,
  opts: { headers?: Record<string, string>; body?: unknown } = {},
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    let payload: string | undefined;
    if (opts.body !== undefined) {
      payload = JSON.stringify(opts.body);
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(Buffer.byteLength(payload));
    }
    const req = http.request(
      { host: '127.0.0.1', port, method, path: urlPath, headers },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (d) => (body += d));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body }),
        );
      },
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function tmpRoot(prefix: string): string {
  return mkdtempSync(path.join(tmpdir(), `ogf-${prefix}-`));
}

test('E04: health is open and delivers the capability cookie', async () => {
  const root = tmpRoot('health');
  const srv = await startServer([root]);
  try {
    const res = await request(srv.port, 'GET', '/api/health', {
      headers: { origin: 'http://localhost:7620' },
    });
    assert.equal(res.status, 200);
    const cookies = (res.headers['set-cookie'] as string[] | undefined) ?? [];
    assert.ok(
      cookies.some((c) => c.startsWith('ogf_token=')),
      'expected a capability cookie to be set',
    );
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('E04: the capability cookie authorizes authority routes (UI path)', async () => {
  const root = tmpRoot('cookieauth');
  const srv = await startServer([root]);
  try {
    const health = await request(srv.port, 'GET', '/api/health', {
      headers: { origin: 'http://localhost:7620' },
    });
    const cookies = (health.headers['set-cookie'] as string[] | undefined) ?? [];
    const cookie = cookies.find((c) => c.startsWith('ogf_token='));
    assert.ok(cookie, 'expected capability cookie');
    const cookieValue = cookie.split(';')[0];

    const res = await request(srv.port, 'POST', '/api/files/content', {
      headers: { cookie: cookieValue, origin: 'http://localhost:7620' },
      body: { projectPath: root, relPath: 'via-cookie.txt', content: 'ok' },
    });
    assert.equal(res.status, 200);
    assert.ok(existsSync(path.join(root, 'via-cookie.txt')));
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('E04: authority route rejects a missing token', async () => {
  const root = tmpRoot('notoken');
  const srv = await startServer([root]);
  try {
    const res = await request(srv.port, 'POST', '/api/secrets', {
      body: { key: 'openai_api_key', value: 'sk-FAKE-NOT-A-REAL-KEY' },
    });
    assert.equal(res.status, 401);
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('E04: authority route rejects a wrong token', async () => {
  const root = tmpRoot('wrongtoken');
  const srv = await startServer([root]);
  try {
    const res = await request(srv.port, 'POST', '/api/files/content', {
      headers: { 'x-ogf-token': 'not-the-token' },
      body: { projectPath: root, relPath: 'x.txt', content: 'nope' },
    });
    assert.equal(res.status, 401);
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('E04: disallowed browser Origin is rejected even with a valid token', async () => {
  const root = tmpRoot('origin');
  const srv = await startServer([root]);
  try {
    const res = await request(srv.port, 'POST', '/api/files/content', {
      headers: { origin: 'http://evil.example', 'x-ogf-token': TOKEN },
      body: { projectPath: root, relPath: 'x.txt', content: 'nope' },
    });
    assert.equal(res.status, 403);
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('E04: disallowed Host header is rejected (DNS-rebinding defense)', async () => {
  const root = tmpRoot('host');
  const srv = await startServer([root]);
  try {
    const res = await request(srv.port, 'GET', '/api/health', {
      headers: { host: 'evil.example', 'x-ogf-token': TOKEN },
    });
    assert.equal(res.status, 403);
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('E04: unauthorized request cannot set a secret; authorized one can', async () => {
  const root = tmpRoot('secrets');
  const fakeHome = tmpRoot('home');
  const savedHome = process.env.HOME;
  process.env.HOME = fakeHome;
  const srv = await startServer([root]);
  const secretFile = path.join(fakeHome, '.ogf', 'secrets.json');
  try {
    const denied = await request(srv.port, 'POST', '/api/secrets', {
      body: { key: 'gemini_api_key', value: 'FAKE-SECRET-VALUE' },
    });
    assert.equal(denied.status, 401);
    assert.equal(existsSync(secretFile), false, 'no secret file may be written');

    const allowed = await request(srv.port, 'POST', '/api/secrets', {
      headers: { 'x-ogf-token': TOKEN },
      body: { key: 'gemini_api_key', value: 'FAKE-SECRET-VALUE' },
    });
    assert.equal(allowed.status, 200);
    assert.ok(existsSync(secretFile), 'authorized set should persist');
  } finally {
    await srv.close();
    process.env.HOME = savedHome;
    rmSync(root, { recursive: true, force: true });
    rmSync(fakeHome, { recursive: true, force: true });
  }
});

test('E04: authorized file write works; path escapes are refused', async () => {
  const root = tmpRoot('files');
  const srv = await startServer([root]);
  try {
    const ok = await request(srv.port, 'POST', '/api/files/content', {
      headers: { 'x-ogf-token': TOKEN },
      body: { projectPath: root, relPath: 'ok.txt', content: 'hello' },
    });
    assert.equal(ok.status, 200);
    assert.equal(readFileSync(path.join(root, 'ok.txt'), 'utf8'), 'hello');

    const escapeTarget = path.join(path.dirname(root), 'escaped.txt');
    const escaped = await request(srv.port, 'POST', '/api/files/content', {
      headers: { 'x-ogf-token': TOKEN },
      body: { projectPath: root, relPath: '../escaped.txt', content: 'pwned' },
    });
    assert.equal(escaped.status, 400);
    assert.equal(existsSync(escapeTarget), false, 'escape must not write a file');

    const delEscape = await request(
      srv.port,
      'DELETE',
      `/api/files?projectPath=${encodeURIComponent(root)}&relPath=${encodeURIComponent('../escaped.txt')}`,
      { headers: { 'x-ogf-token': TOKEN } },
    );
    assert.equal(delEscape.status, 400);
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('E04: project path outside the approved root is refused', async () => {
  const root = tmpRoot('scoperoot');
  const outside = tmpRoot('outside');
  const srv = await startServer([root]);
  try {
    const res = await request(srv.port, 'POST', '/api/files/content', {
      headers: { 'x-ogf-token': TOKEN },
      body: { projectPath: outside, relPath: 'x.txt', content: 'nope' },
    });
    assert.equal(res.status, 403);
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('E04: unauthorized run creation is refused at the boundary', async () => {
  const root = tmpRoot('runs');
  const srv = await startServer([root]);
  try {
    const res = await request(srv.port, 'POST', '/api/runs', {
      body: { agentId: 'claude-code', prompt: 'do work', projectPath: root },
    });
    assert.equal(res.status, 401);
    assert.match(res.body, /unauthorized/i);
  } finally {
    await srv.close();
    rmSync(root, { recursive: true, force: true });
  }
});
