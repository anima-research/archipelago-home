import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable } from 'node:stream';

const ROOT = join(import.meta.dirname, '..');

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
    const onData = (chunk: Buffer) => {
      err += chunk.toString('utf8');
      const m = /\[hn\] home node for .* on 127\.0\.0\.1:(\d+)/.exec(err);
      if (m) {
        cleanup();
        resolve(Number(m[1]));
      }
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      reject(new Error(`hn serve exited before listening (${code ?? signal}): ${err}`));
    };
    const cleanup = () => {
      child.stderr.off('data', onData);
      child.off('exit', onExit);
    };
    child.stderr.on('data', onData);
    child.on('exit', onExit);
  });

  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>((resolve) => {
      child.once('exit', () => resolve());
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

function rawGet(port: number, target: string, host: string): Promise<{ status: number | null; body: string }> {
  return new Promise((resolve, reject) => {
    const sock = createConnection({ host: '127.0.0.1', port }, () => {
      sock.write(`GET ${target} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
    });
    const chunks: Buffer[] = [];
    sock.on('data', (c: Buffer) => chunks.push(c));
    sock.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNRESET') resolve({ status: null, body: '' });
      else reject(err);
    });
    sock.on('close', () => {
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
}

test('an unparseable request target gets 400 and the same process answers the next request', async () => {
  const { child, port, stop } = await startServedNode();
  const pid = child.pid;
  try {
    for (const target of ['//', 'http://[']) {
      const bad = await rawGet(port, target, 'localhost');
      assert.equal(bad.status, 400);
      assert.deepEqual(JSON.parse(bad.body), { error: 'bad request' });

      assert.equal(child.exitCode, null);
      assert.equal(child.pid, pid);
      const next = await fetch(`http://127.0.0.1:${port}/healthz`);
      assert.equal(next.status, 200);
      assert.deepEqual(await next.json(), { ok: true, principals: 0 });
    }
  } finally {
    await stop();
  }
});

test('an unparseable Host header gets its path answer and the same process answers the next request', async () => {
  const { child, port, stop } = await startServedNode();
  const pid = child.pid;
  try {
    const ok = await rawGet(port, '/healthz', '[bad');
    assert.equal(ok.status, 200);
    assert.deepEqual(JSON.parse(ok.body), { ok: true, principals: 0 });

    const miss = await rawGet(port, '/nope', 'a b');
    assert.equal(miss.status, 404);
    assert.deepEqual(JSON.parse(miss.body), { error: 'not found' });

    assert.equal(child.exitCode, null);
    assert.equal(child.pid, pid);
    const next = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(next.status, 200);
    assert.deepEqual(await next.json(), { ok: true, principals: 0 });
  } finally {
    await stop();
  }
});
