import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { HomeNode } from '../src/server.js';

const ROOT = join(import.meta.dirname, '..');
const STARTUP_TIMEOUT_MS = 10_000;
const REQUEST_TIMEOUT_MS = 5_000;

async function startServedNode(): Promise<{
  child: ChildProcessByStdio<null, Readable, Readable>;
  port: number;
  stop: () => Promise<void>;
}> {
  const dir = mkdtempSync(join(tmpdir(), 'hn-serve-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({}));
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'serve'], {
    cwd: ROOT,
    env: {
      ...process.env,
      HN_DOMAIN: 'id.test',
      HN_PUBLIC_URL: 'https://id.test',
      HN_BIND: '127.0.0.1',
      HN_PORT: '0',
      HN_DATA_DIR: dir,
      HN_CONFIG_DIR: dir,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const port = await new Promise<number>((resolve, reject) => {
    let err = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      reject(new Error(`hn serve did not listen within ${STARTUP_TIMEOUT_MS}ms: ${err}`));
    }, STARTUP_TIMEOUT_MS);
    const onData = (chunk: Buffer) => {
      err += chunk.toString('utf8');
      const m = /^\[hn\] home node for [^\r\n]* on 127\.0\.0\.1:(\d+) — [^\r\n]*\r?\n/m.exec(err);
      if (m && !settled) {
        settled = true;
        cleanup();
        resolve(Number(m[1]));
      }
    };
    const onError = (spawnErr: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      reject(spawnErr);
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error(`hn serve exited before listening (${code ?? signal}): ${err}`));
    };
    const cleanup = () => {
      clearTimeout(timer);
      child.stderr.off('data', onData);
      child.off('error', onError);
      child.off('exit', onExit);
    };
    child.stderr.on('data', onData);
    child.on('error', onError);
    child.on('exit', onExit);
  });

  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>((resolve) => {
      const killTimer = setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      }, 2_000);
      child.once('exit', () => {
        clearTimeout(killTimer);
        resolve();
      });
      child.kill('SIGTERM');
    });
  };

  return { child, port, stop };
}

function unchunk(raw: string): string {
  let out = '';
  let pos = 0;
  while (pos < raw.length) {
    const lineEnd = raw.indexOf('\r\n', pos);
    if (lineEnd === -1) break;
    const len = parseInt(raw.slice(pos, lineEnd), 16);
    if (!Number.isFinite(len) || len === 0) break;
    const start = lineEnd + 2;
    out += raw.slice(start, start + len);
    pos = start + len + 2;
  }
  return out;
}

function rawGet(
  port: number,
  target: string,
  host: string,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<{ status: number | null; body: string }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const sock = createConnection({ host: '127.0.0.1', port }, () => {
      sock.write(`GET ${target} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
    });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      sock.destroy();
      reject(new Error(`rawGet timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const chunks: Buffer[] = [];
    sock.on('data', (c: Buffer) => chunks.push(c));
    sock.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNRESET') finish(() => resolve({ status: null, body: '' }));
      else finish(() => reject(err));
    });
    sock.on('close', () => {
      finish(() => {
        const raw = Buffer.concat(chunks).toString('utf8');
        const sep = raw.indexOf('\r\n\r\n');
        if (sep === -1) return resolve({ status: null, body: raw });
        const head = raw.slice(0, sep);
        const statusLine = head.slice(0, head.indexOf('\r\n'));
        const m = /^HTTP\/1\.[01] (\d{3})\b/.exec(statusLine);
        const payload = raw.slice(sep + 4);
        const body = /^transfer-encoding:\s*chunked\r?$/im.test(head) ? unchunk(payload) : payload;
        resolve({ status: m ? Number(m[1]) : null, body });
      });
    });
  });
}

test('an unparseable request target gets 400 and the same process answers the next request', async () => {
  const { child, port, stop } = await startServedNode();
  try {
    for (const target of ['//', 'http://[']) {
      const bad = await rawGet(port, target, 'localhost');
      assert.equal(bad.status, 400);
      assert.deepEqual(JSON.parse(bad.body), { error: 'bad request' });

      const next = await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      assert.equal(next.status, 200);
      assert.deepEqual(await next.json(), { ok: true, principals: 0 });
      assert.equal(child.exitCode, null);
      assert.equal(child.signalCode, null);
    }
  } finally {
    await stop();
  }
});

test('an unparseable Host header gets its path answer and the same process answers the next request', async () => {
  const { child, port, stop } = await startServedNode();
  try {
    const ok = await rawGet(port, '/healthz', '[bad');
    assert.equal(ok.status, 200);
    assert.deepEqual(JSON.parse(ok.body), { ok: true, principals: 0 });

    const miss = await rawGet(port, '/nope', 'a b');
    assert.equal(miss.status, 404);
    assert.deepEqual(JSON.parse(miss.body), { error: 'not found' });

    const next = await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    assert.equal(next.status, 200);
    assert.deepEqual(await next.json(), { ok: true, principals: 0 });
    assert.equal(child.exitCode, null);
    assert.equal(child.signalCode, null);
  } finally {
    await stop();
  }
});

test('route inner catch ends a post-header throw with one log line and the server callback catch answers 500 or ends when route rejects', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-catch-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({}));
  const node = new HomeNode({
    iss: 'id.test',
    publicUrl: 'https://id.test',
    bind: '127.0.0.1',
    port: 0,
    dataDir: dir,
    configDir: dir,
  });
  const port = await node.start();
  const base = `http://127.0.0.1:${port}`;
  const origError = console.error;
  const logged: string[] = [];
  console.error = (...args: unknown[]) => {
    logged.push(args.map(String).join(' '));
  };

  node.human.route = async (_req, url, res) => {
    if (url.pathname === '/inner-after-head') {
      res.writeHead(202, { 'content-type': 'text/plain' });
      res.write('partial-inner');
      throw new Error('boom after head');
    }
    if (url.pathname === '/outer-before-head') {
      throw null;
    }
    if (url.pathname === '/outer-after-head') {
      res.writeHead(202, { 'content-type': 'text/plain' });
      res.write('partial-outer');
      throw null;
    }
    return false;
  };

  try {
    const r1 = await fetch(`${base}/inner-after-head`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    assert.equal(r1.status, 202);
    assert.equal(await r1.text(), 'partial-inner');
    assert.deepEqual(logged, ['[hn] GET /inner-after-head error: boom after head']);
    logged.length = 0;

    const r2 = await fetch(`${base}/outer-before-head`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    assert.equal(r2.status, 500);
    assert.deepEqual(await r2.json(), { error: 'internal error' });
    assert.equal(logged.length, 1);
    assert.match(logged[0]!, /^\[hn\] GET request failed: /);
    logged.length = 0;

    const r3 = await fetch(`${base}/outer-after-head`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    assert.equal(r3.status, 202);
    assert.equal(await r3.text(), 'partial-outer');
    assert.equal(logged.length, 1);
    assert.match(logged[0]!, /^\[hn\] GET request failed: /);
    logged.length = 0;

    const next = await fetch(`${base}/healthz`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    assert.equal(next.status, 200);
    assert.deepEqual(await next.json(), { ok: true, principals: 0 });
  } finally {
    console.error = origError;
    node.stop();
  }
});
