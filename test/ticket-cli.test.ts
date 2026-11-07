// `hn ticket add | ls | rm`: the real CLI, spawned against a scratch data dir.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TicketStore } from '../src/tickets.js';

const ROOT = join(import.meta.dirname, '..');

function scratch(opts: { defaults?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'hn-ticket-cli-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    members: { redirect: 'https://members.test/auth', requiredScopes: ['members:member'] },
    extra: { redirect: 'https://extra.test/auth' },
  }));
  if (opts.defaults !== false) writeFileSync(join(dir, 'ticket-defaults.json'), JSON.stringify({ audiences: ['members'], scopes: ['members:member'] }));
  const hn = (...args: string[]) => {
    const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'ticket', ...args], {
      cwd: ROOT, encoding: 'utf8', env: { ...process.env, HN_DATA_DIR: dir, HN_CONFIG_DIR: dir, HN_PUBLIC_URL: 'https://id.test' },
    });
    return { status: r.status, out: `${r.stdout}${r.stderr}` };
  };
  return { dir, hn, store: () => new TicketStore(join(dir, 'tickets.json')) };
}

test('cli: ticket add takes the configured defaults, or its own flags; refuses a bad address, an unknown audience, a repeat', () => {
  const { dir, hn, store } = scratch();
  const r = hn('add', 'Pat.Buyer@gmail.com', '--note', 'front row');
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /ticket for Pat\.Buyer@gmail\.com → members \[members:member\]/);
  assert.match(r.out, /\/login\?audience=members&email=Pat\.Buyer%40gmail\.com/);
  const t = store().byEmail('patbuyer@gmail.com')!;
  assert.equal(t.email, 'Pat.Buyer@gmail.com');
  assert.match(t.source, /^admin:/);
  assert.equal(t.note, 'front row');
  assert.deepEqual([t.audiences, t.scopes], [['members'], ['members:member']]);
  assert.equal(statSync(join(dir, 'tickets.json')).mode & 0o777, 0o600);
  const own = hn('add', 'vip@example.org', '--audiences', 'members,extra', '--scopes', 'members:member,extra:use');
  assert.equal(own.status, 0, own.out);
  assert.deepEqual(store().byEmail('vip@example.org')!.audiences, ['members', 'extra']);
  assert.deepEqual(store().byEmail('vip@example.org')!.scopes, ['members:member', 'extra:use']);
  const dup = hn('add', 'patbuyer+again@gmail.com');
  assert.notEqual(dup.status, 0);
  assert.match(dup.out, /already holds a ticket/);
  assert.notEqual(hn('add', 'nope').status, 0);
  assert.match(hn('add', 'x@y.co', '--audiences', 'nowhere').out, /no audience "nowhere"/);
  assert.equal(store().all().length, 2);
});

test('cli: ticket ls shows holders and who took a ticket up; rm stops sign-ups and says the account stays', () => {
  const { hn, store } = scratch();
  hn('add', 'a@example.org');
  hn('add', 'b@example.org');
  store().claim('b@example.org', 'human:email:abc');
  const ls = hn('ls');
  assert.equal(ls.status, 0);
  assert.match(ls.out, /tickets \(2\):/);
  assert.match(ls.out, /a@example\.org .* unused/);
  assert.match(ls.out, /b@example\.org .* taken up by human:email:abc/);
  assert.equal(JSON.parse(hn('ls', '--json').out).length, 2);
  const rmUnused = hn('rm', 'A@example.org');
  assert.equal(rmUnused.status, 0, rmUnused.out);
  assert.match(rmUnused.out, /had not been taken up/);
  const rmUsed = hn('rm', 'b@example.org');
  assert.match(rmUsed.out, /keeps what the ticket gave: hn user disable human:email:abc/);
  assert.equal(store().all().length, 0);
  assert.notEqual(hn('rm', 'b@example.org').status, 0);
});

test('cli: without config/ticket-defaults.json a ticket needs --audiences', () => {
  const { hn, store } = scratch({ defaults: false });
  const r = hn('add', 'a@example.org');
  assert.notEqual(r.status, 0);
  assert.match(r.out, /needs audiences/);
  assert.equal(store().all().length, 0);
  assert.equal(hn('add', 'a@example.org', '--audiences', 'members').status, 0);
  assert.deepEqual(store().byEmail('a@example.org')!.scopes, []);
});
